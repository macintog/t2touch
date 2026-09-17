#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CUserspaceAssetTests(unittest.TestCase):
    def test_makefile_hardens_helpers_and_builds_the_observer(self):
        makefile = (ROOT / "src/Makefile").read_text(encoding="utf-8")
        self.assertIn("-fstack-protector-strong", makefile)
        self.assertIn("-Wl,-z,relro,-z,now", makefile)
        self.assertIn("t2-recovery-usb-observer", makefile)
        self.assertIn("all: module t2-aks-tool", makefile)

    def test_ci_builds_all_userspace_c_targets(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("libpam0g-dev", ci)
        self.assertIn("pam_t2touch_action_prompt.so", ci)
        self.assertIn("t2-recovery-usb-observer", ci)

    def test_verify_paths_reject_overlong_passwords(self):
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")
        self.assertIn("read_secret_line(input, secret, 129)", source)
        self.assertGreaterEqual(source.count("protect_secret_buffer(secret"), 5)
        self.assertIn("explicit_bzero(secret, sizeof(secret))", source)
        self.assertIn("munlock(secret, sizeof(secret))", source)
        self.assertNotIn("static int get_device_state(", source)
        self.assertIn("int ret = 2;", source)
        self.assertNotIn("get-device-state HANDLE SELECTOR OUTPUT", source)

    def test_observer_opens_logs_without_following_symlinks(self):
        source = (ROOT / "src/t2-recovery-usb-observer.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("O_NOFOLLOW", source)
        self.assertNotIn('fopen(argv[2], "ae")', source)

    def test_mapping_publish_falls_back_when_renameat2_is_unavailable(self):
        source = (ROOT / "src/t2_user_mapping_admin.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("errno.ENOSYS", source)
        self.assertIn("os.link(source, target", source)

    @unittest.skipUnless(sys.platform == "linux", "userspace C targets build on Linux")
    def test_aks_tool_compiles_with_hardening_werror(self):
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            self.skipTest("C compiler is required")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "t2-aks-tool"
            result = subprocess.run(
                [
                    compiler,
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fstack-protector-strong",
                    "-D_FORTIFY_SOURCE=2",
                    "-fPIE",
                    "-Wformat",
                    "-Wformat-security",
                    "-o",
                    str(output),
                    "t2-aks-tool.c",
                ],
                cwd=ROOT / "src",
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=result.stdout + result.stderr,
            )


if __name__ == "__main__":
    unittest.main()
