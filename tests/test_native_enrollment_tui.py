# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src" / "t2-native-enroll-tui.py"
SPEC = importlib.util.spec_from_file_location("t2_native_enroll_tui", SOURCE)
assert SPEC is not None and SPEC.loader is not None
tui = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tui
SPEC.loader.exec_module(tui)

MATCH_SOURCE = Path(__file__).parents[1] / "src" / "t2-match-tui.py"
MATCH_SPEC = importlib.util.spec_from_file_location(
    "t2_native_match_tui", MATCH_SOURCE
)
assert MATCH_SPEC is not None and MATCH_SPEC.loader is not None
match_tui = importlib.util.module_from_spec(MATCH_SPEC)
sys.modules[MATCH_SPEC.name] = match_tui
MATCH_SPEC.loader.exec_module(match_tui)


class NativeEnrollmentTUITests(unittest.TestCase):
    def test_new_finger_selector_skips_valid_non_enrollment_journals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addition = root / "addition.jsonl"
            deletion = root / "deletion.jsonl"
            addition.touch()
            deletion.touch()
            raw = {
                addition: [{"evidence": {"operation_kind": "enroll"}}],
                deletion: [{"evidence": {"operation_kind": "delete-one"}}],
            }
            history = SimpleNamespace(
                phase=match_tui.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
                baseline={"baseline_version": 1},
                terminal_identity_uuid="present",
            )
            with (
                mock.patch.object(match_tui, "MUTATION_ROOT", root),
                mock.patch.object(match_tui.t2_mutation_registry, "scan"),
                mock.patch.object(
                    match_tui.t2_mutation_journal,
                    "read",
                    side_effect=lambda path: raw[path],
                ),
                mock.patch.object(
                    match_tui.t2_enrollment_journal,
                    "validate_history",
                    return_value=history,
                ),
            ):
                self.assertEqual(match_tui._addition_journal(), addition)

    def test_placement_cue_requires_accepted_enrollment_start(self) -> None:
        interface = tui.EnrollmentUI()
        interface.draw = lambda: None
        interface.apply({"event_kind": "enrollment-armed"})
        self.assertEqual(interface.view.title, "STARTING SENSOR CAPTURE")
        interface.apply({"event_kind": "enrollment-active"})
        self.assertEqual(interface.view.title, "PLACE FINGER NOW")

    def test_presence_requests_immediate_lift_without_claiming_progress(self) -> None:
        """Protect D191: sustained-contact guidance caused a live retry loop."""

        interface = tui.EnrollmentUI()
        interface.draw = lambda: None
        interface._feedback({"action": "finger-present"})

        visible = " ".join(
            (interface.view.title, interface.view.detail, interface.view.hint)
        )
        self.assertEqual(interface.view.title, "TOUCH REGISTERED — LIFT FINGER")
        self.assertIn("LIFT", visible)
        self.assertNotIn("HOLD", visible.upper())
        self.assertNotIn("ACCEPTED", visible)
        self.assertEqual(interface.view.progress, 0)

    def test_authorized_launch_starts_without_enter(self) -> None:
        order: list[str] = []

        class Input:
            @staticmethod
            def isatty() -> bool:
                return True

            @staticmethod
            def fileno() -> int:
                return 0

            @staticmethod
            def read(_size: int) -> str:
                order.append("read")
                return "q"

        class Output:
            encoding = "utf-8"

            @staticmethod
            def isatty() -> bool:
                return True

            @staticmethod
            def write(_value: str) -> None:
                return None

            @staticmethod
            def flush() -> None:
                return None

        def run_child(*_args: object) -> int:
            order.append("run")
            return 0

        with (
            mock.patch.object(tui.sys, "argv", ["t2-native-enroll-tui", "--credential-fd", "7"]),
            mock.patch.object(tui.sys, "stdin", Input()),
            mock.patch.object(tui.sys, "stdout", Output()),
            mock.patch.object(tui.os, "geteuid", return_value=0),
            mock.patch.object(tui, "_read_credential", return_value=bytearray(b"test")),
            mock.patch.object(tui, "_run_child", side_effect=run_child),
            mock.patch.object(tui.termios, "tcgetattr", return_value=[]),
            mock.patch.object(tui.termios, "tcsetattr"),
            mock.patch.object(tui.tty, "setcbreak"),
            mock.patch.object(tui.select, "select", return_value=([Input()], [], [])),
        ):
            self.assertEqual(tui.main(), 0)

        self.assertEqual(order, ["run", "read"])


if __name__ == "__main__":
    unittest.main()
