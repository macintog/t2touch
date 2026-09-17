#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Isolated syscall-filter checks for t2-sep-transport.service."""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = ROOT / "systemd/system/t2-sep-transport.service"

# init_module(2) with null arguments: EFAULT if allowed, SIGSYS if filtered.
_PROBE = textwrap.dedent(
    """\
    import ctypes
    import os
    import sys

    nr = {"x86_64": 175, "aarch64": 105}.get(os.uname().machine)
    if nr is None:
        raise SystemExit(3)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(nr), ctypes.c_long(0), ctypes.c_long(0))
    if result == -1 and ctypes.get_errno() != 0:
        raise SystemExit(0)
    raise SystemExit(4)
    """
)


def _run_sandbox(syscall_filter: str, probe: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "systemd-run",
            "--user",
            "--wait",
            "--pipe",
            "--collect",
            "--quiet",
            f"--property=SystemCallFilter={syscall_filter}",
            "--property=SystemCallArchitectures=native",
            sys.executable,
            str(probe),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@unittest.skipUnless(sys.platform == "linux", "syscall filters are Linux-only")
class SepTransportSyscallFilterTests(unittest.TestCase):
    def test_transport_unit_keeps_module_syscalls(self):
        text = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn("SystemCallFilter=@system-service @module", text)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_MODULE", text)
        self.assertIn("ExecStart=/usr/local/sbin/t2-sep-transport-load", text)

    def test_isolated_sandbox_allows_module_set_and_denies_without_it(self):
        if shutil.which("systemd-run") is None:
            self.skipTest("systemd-run is required for the isolated sandbox")
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe.py"
            probe.write_text(_PROBE, encoding="utf-8")
            denied = _run_sandbox("@system-service", probe)
            if denied.returncode == 125 or "Failed to connect" in denied.stderr:
                self.skipTest("user systemd is not available for systemd-run")
            self.assertNotEqual(
                denied.returncode,
                0,
                msg=f"@system-service should block init_module: {denied.stderr}",
            )
            allowed = _run_sandbox("@system-service @module", probe)
            self.assertEqual(
                allowed.returncode,
                0,
                msg=(
                    "@module should admit init_module as EFAULT, not SIGSYS: "
                    f"rc={allowed.returncode} stderr={allowed.stderr}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
