# SPDX-License-Identifier: GPL-2.0-only
"""Exercise caller checks with the installed least-privilege policy."""

from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CAPABILITIES = {
    "CAP_DAC_READ_SEARCH": 2, "CAP_KILL": 5, "CAP_SETGID": 6,
    "CAP_SETUID": 7, "CAP_IPC_LOCK": 14, "CAP_SYS_PTRACE": 19,
    "CAP_SYS_ADMIN": 21,
}
PROBE = r'''
import ctypes
import os
import select
import sys

libc = ctypes.CDLL(None, use_errno=True)
ready_r, ready_w = os.pipe()
stop_r, stop_w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(ready_r)
    os.close(stop_w)
    os.setgid(1000)
    os.setuid(1000)
    os.write(ready_w, b"ready")
    os.close(ready_w)
    os.read(stop_r, 1)
    os._exit(0)
os.close(ready_w)
os.close(stop_r)
try:
    assert os.read(ready_r, 5) == b"ready"
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32),
                    ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]
    mask = int(sys.argv[1])
    data = (Data * 2)(Data(mask & 0xffffffff, mask & 0xffffffff, 0),
                      Data(mask >> 32, mask >> 32, 0))
    header = Header(0x20080522, 0)
    assert libc.capset(ctypes.byref(header), data) == 0, ctypes.get_errno()
    fd = os.pidfd_open(pid)
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP)
    assert poller.poll(0) == []
    os.write(stop_w, b"stop")
    os.waitpid(pid, 0)
    assert poller.poll(1000)
    os.close(fd)
finally:
    os.close(stop_w)
    os.close(ready_r)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
'''


@unittest.skipUnless(sys.platform == "linux", "Linux capabilities required")
class FprintCapabilitiesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("unshare") is None:
            raise unittest.SkipTest("unshare is unavailable")
        cls.namespace = ["unshare", "--map-auto", "--map-root-user"]
        result = subprocess.run(cls.namespace + ["true"], capture_output=True)
        if result.returncode:
            raise unittest.SkipTest("subordinate user namespaces are unavailable")

    def capabilities(self):
        unit = (ROOT / "systemd/system/fprintd.service").read_text()
        line = next(line for line in unit.splitlines()
                    if line.startswith("CapabilityBoundingSet="))
        return line.split("=", 1)[1].split()

    def test_caller_validation_avoids_signal_and_ptrace_capabilities(self):
        capabilities = self.capabilities()
        self.assertNotIn("CAP_KILL", capabilities)
        self.assertNotIn("CAP_SYS_PTRACE", capabilities)

    def test_can_poll_desktop_caller_pidfd(self):
        mask = sum(1 << CAPABILITIES[name] for name in self.capabilities())
        result = subprocess.run(
            self.namespace + [sys.executable, "-c", PROBE, str(mask)],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
