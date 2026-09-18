# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_doctor_suspend", ROOT / "src/t2-touchid-doctor.py"
)
DOCTOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = DOCTOR
SPEC.loader.exec_module(DOCTOR)


class SuspendPolicyTests(unittest.TestCase):
    def test_install_and_uninstall_retire_without_selecting_a_mode(self):
        self.assertFalse((ROOT / "systemd/sleep.conf.d/90-t2-touchid-s2idle.conf").exists())
        for filename in ("install.sh", "uninstall.sh"):
            script = (ROOT / filename).read_text()
            self.assertIn('python3 "$source_dir/tools/retire-sleep-policy.py"', script)
            self.assertNotIn("/etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf", script)

    def check_mode(self, modes, config="", returncode=0):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mem_sleep"
            path.write_text(modes, encoding="ascii")
            with (mock.patch.object(DOCTOR, "MEM_SLEEP", path),
                  mock.patch.object(DOCTOR, "run", return_value=mock.Mock(
                      returncode=returncode, stdout=config))):
                return DOCTOR.sleep_mode_check()

    def test_neither_kernel_mode_proves_resume_health(self):
        for modes in ("[s2idle] deep", "s2idle [deep]"):
            check = self.check_mode(modes)
            self.assertEqual(check.status, "warn")
            self.assertIn("suspend/resume unqualified", check.detail)
            self.assertNotIn("use s2idle", check.detail)

    def test_systemd_override_is_checked_even_when_kernel_selects_s2idle(self):
        check = self.check_mode("[s2idle] deep", "[Sleep]\nMemorySleepMode=deep\n")
        self.assertIn("kernel currently selects s2idle", check.detail)
        self.assertIn("systemd MemorySleepMode=deep", check.detail)
        self.assertEqual(check.status, "warn")

    def test_systemd_section_order_reset_and_whitespace(self):
        check = self.check_mode("s2idle [deep]", (
            "[Other]\nMemorySleepMode=deep\n[Sleep]\n"
            "MemorySleepMode=deep\nMemorySleepMode = s2idle\n"))
        self.assertIn("systemd MemorySleepMode=s2idle", check.detail)
        reset = self.check_mode("s2idle [deep]", (
            "[Sleep]\nMemorySleepMode=s2idle\nMemorySleepMode=\n"))
        self.assertIn("no MemorySleepMode override", reset.detail)

    def test_unavailable_or_ambiguous_policy_is_not_a_pass(self):
        check = self.check_mode("s2idle [deep]", returncode=1)
        self.assertIn("systemd sleep policy unavailable", check.detail)
        self.assertEqual(check.status, "warn")
        self.assertEqual(self.check_mode("s2idle deep").status, "warn")

    def test_installer_negotiates_applekeystore_before_keybag_loading(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        loader = (ROOT / "src/t2-sep-transport-load.sh").read_text(encoding="utf-8")
        self.assertNotIn("options t2_sep_transport register_ool=1", installer)
        self.assertIn(
            "register_ool=1 probe_capabilities=1",
            loader,
        )
        self.assertIn("register_acm=1", loader)
        self.assertIn("aks_platform_proc_uniqueid=1", loader)
        self.assertIn("enable_identity_provisioning=1", loader)
        self.assertIn("enable_identity_replacement=1", loader)
        self.assertIn("loaded without creating /dev/t2-acm", loader)


if __name__ == "__main__":
    unittest.main()
