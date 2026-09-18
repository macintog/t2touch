# SPDX-License-Identifier: GPL-2.0-only
"""Compile the real C open boundary; exercise its subprocess handoff on Linux."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class AKSToolPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        cls.marker = root / "invocation.json"
        helper = root / "release.py"
        helper.write_text(
            "import json, os, sys\n"
            f"open({str(cls.marker)!r}, 'w').write(json.dumps("
            "{'isolated':sys.flags.isolated,'input':sys.stdin.read()}))\n"
            "raise SystemExit(int(os.environ['TEST_RELEASE_EXIT']))\n"
        )
        source_root = Path(__file__).resolve().parents[1] / "src"
        source = (source_root / "t2-aks-tool.c").read_text()
        source = source.replace('"/opt/t2-touchid/.venv/bin/python"', json.dumps(sys.executable))
        source = source.replace('"/opt/t2-touchid/src/t2_preparation_lease.py"', json.dumps(str(helper)))
        device_open = 'open("/dev/t2-aks", O_RDWR | O_CLOEXEC)'
        if source.count(device_open) != 2:
            raise AssertionError("unexpected AKS open boundary")
        source = source.replace(device_open, "fixture_open()")
        prefix = r'''
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static int opens;
static int fixture_open(void) {
    const char *field = opens++ == 0 ? "TEST_INITIAL_ERRNO" : "TEST_RETRY_ERRNO";
    int failure = atoi(getenv(field));
    if (failure) { errno = failure; return -1; }
    return open("/dev/null", O_RDONLY);
}
#define main aks_tool_original_main
'''
        suffix = r'''
#undef main
int main(void) {
    int fd = open_aks_device();
    int error = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    printf("%d %d\n", opens, error);
    return 0;
}
'''
        harness = root / "harness.c"
        harness.write_text(prefix + source + suffix)
        cls.binary = root / "harness"
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(source_root),
                        str(harness), "-o", str(cls.binary)], check=True, capture_output=True)

    def run_case(self, initial, *, release=0, retry=0):
        self.marker.unlink(missing_ok=True)
        environment = dict(os.environ, TEST_INITIAL_ERRNO=str(initial),
                           TEST_RELEASE_EXIT=str(release), TEST_RETRY_ERRNO=str(retry))
        result = subprocess.run([str(self.binary)], env=environment,
                                input="synthetic-input-must-not-reach-child",
                                capture_output=True, text=True, timeout=5, check=True)
        return tuple(map(int, result.stdout.split()))

    def test_busy_owner_uses_isolated_helper_without_password_input(self):
        import errno
        self.assertEqual(self.run_case(errno.EBUSY), (2, 0))
        self.assertEqual(json.loads(self.marker.read_text()), {"isolated": 1, "input": ""})

    def test_failed_release_preserves_busy_and_does_not_retry(self):
        import errno
        self.assertEqual(self.run_case(errno.EBUSY, release=1), (1, errno.EBUSY))

    def test_acknowledgement_does_not_bypass_failed_kernel_reopen(self):
        import errno
        self.assertEqual(self.run_case(errno.EBUSY, retry=errno.EBUSY), (2, errno.EBUSY))

    def test_nonbusy_open_never_invokes_release(self):
        import errno
        for error in (0, errno.EACCES, errno.ENOENT):
            with self.subTest(error=error):
                self.assertEqual(self.run_case(error), (1, error))
                self.assertFalse(self.marker.exists())
