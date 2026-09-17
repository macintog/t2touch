#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DxAuditAssetTests(unittest.TestCase):
    def test_enroll_tui_names_a_full_sensor(self):
        source = (ROOT / "src/t2-fprintd-enroll-tui.py").read_text(encoding="utf-8")
        self.assertIn("All five fingerprint slots are in use", source)
        self.assertIn("sudo t2-touchid-doctor", source)

    def test_contributing_states_linux_only_tests(self):
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("require Linux", text)
        self.assertIn("Dash-named files", text)

    def test_example_conf_does_not_invite_manual_copy(self):
        text = (ROOT / "t2-touchid.conf.example").read_text(encoding="utf-8")
        self.assertIn("T2_TOUCHID_HOST", text)
        self.assertIn("installer fills", text.lower())

    def test_delete_help_is_singular(self):
        source = (ROOT / "src/t2touch.py").read_text(encoding="utf-8")
        self.assertIn('help="delete one enrolled fingerprint"', source)
        self.assertIn("return 2", source)

    def test_enroll_tui_honours_no_color_and_narrow_width(self):
        source = (ROOT / "src/t2-fprintd-enroll-tui.py").read_text(encoding="utf-8")
        self.assertIn("if self.color:", source)
        self.assertIn("compact = size.columns < 50", source)
        self.assertIn('"╭─●◉".encode(encoding)', source)

    def test_qml_patcher_has_restore_and_lint(self):
        source = (ROOT / "tools/install-omarchy-lock-ui.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("def restore_from_receipt", source)
        self.assertIn("def lint_qml", source)

    def test_doctor_can_skip_sudo_reexec(self):
        source = (ROOT / "src/t2-touchid-doctor.py").read_text(encoding="utf-8")
        self.assertIn("--no-sudo", source)

    def test_match_tui_accepts_ctrl_c(self):
        source = (ROOT / "src/t2-match-tui.py").read_text(encoding="utf-8")
        self.assertIn("signal.signal(signal.SIGINT, request_clean_termination)", source)


if __name__ == "__main__":
    unittest.main()
