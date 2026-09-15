# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src" / "t2-fprintd-enroll-tui.py"
SPEC = importlib.util.spec_from_file_location("t2_fprintd_enroll_tui", SOURCE)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CompletedUI:
    def __init__(self) -> None:
        self.completed = asyncio.Event()

    async def run(self) -> int:
        self.completed.set()
        return 1

    def render(self, *, bell: bool = False) -> None:
        del bell


class FprintdEnrollmentTUITests(unittest.IsolatedAsyncioTestCase):
    def test_standard_verify_results_map_to_expected_control(self):
        positive = MODULE.EnrollmentUI(
            "finger-1", "mapped", operation="verify"
        )
        self.assertTrue(
            positive._consume_line("Verify result: verify-match (done)")
        )
        self.assertEqual(positive.terminal, "FINGERPRINT MATCHED")

        negative = MODULE.EnrollmentUI(
            "finger-1",
            "mapped",
            operation="verify",
            expect_no_match=True,
        )
        self.assertTrue(
            negative._consume_line("Verify result: verify-no-match (done)")
        )
        self.assertEqual(negative.terminal, "EXPECTED NON-MATCH")

        failed = MODULE.EnrollmentUI(
            "finger-1", "mapped", operation="verify"
        )
        self.assertTrue(
            failed._consume_line(
                "Verify result: verify-unknown-error (done)"
            )
        )
        self.assertEqual(failed.terminal, "VERIFICATION STOPPED")
        self.assertEqual(
            failed.terminal_detail,
            "fprintd reported verify-unknown-error.",
        )
        self.assertEqual(positive._finger_label(), "ANY ENROLLED FINGER")

    def test_enrollment_ui_never_claims_anatomy(self):
        ui = MODULE.EnrollmentUI("finger-1", "mapped")
        self.assertEqual(ui._finger_label(), "NEW FINGER")
        self.assertEqual(ui._finger_heading(), "NEW FINGER")
        ui.assigned_finger = "finger-4"
        self.assertEqual(ui._finger_label(), "FINGER 4")
        self.assertEqual(ui._finger_heading(), "FINGER 4")

    def test_failed_enrollment_does_not_present_partial_progress_as_a_slot(self):
        ui = MODULE.EnrollmentUI("finger-4", "mapped")
        ui.progress_percent = 75
        self.assertTrue(
            ui._consume_line(
                "Enroll result: enroll-failed (done)",
                terminal_errors=("failed",),
            )
        )
        with (
            mock.patch.object(MODULE.shutil, "get_terminal_size") as size,
            mock.patch.object(MODULE.sys.stdout, "write") as write,
            mock.patch.object(MODULE.sys.stdout, "flush"),
            mock.patch.object(MODULE.sys.stdout, "isatty", return_value=False),
        ):
            size.return_value = MODULE.os.terminal_size((76, 28))
            ui.render()
        screen = "".join(call.args[0] for call in write.call_args_list)
        self.assertIn("Enrollment stopped", screen)
        self.assertIn("No fingerprint was saved", screen)
        self.assertNotIn("75%", screen)

    def test_taller_windows_preserve_fingerprint_geometry_and_prompt_space(self):
        ui = MODULE.EnrollmentUI("finger-1", "mapped")
        ui.color = False
        ui.unicode = False
        ui.finger_needed = True
        ui.progress_percent = 38
        reference_art = None
        for columns, rows in ((76, 28), (76, 40), (120, 41), (160, 80)):
            with (
                self.subTest(columns=columns, rows=rows),
                mock.patch.object(MODULE.shutil, "get_terminal_size",
                                  return_value=MODULE.os.terminal_size((columns, rows))),
                mock.patch.object(MODULE.sys.stdout, "write") as write,
                mock.patch.object(MODULE.sys.stdout, "flush"),
                mock.patch.object(MODULE.sys.stdout, "isatty", return_value=False),
            ):
                ui.render()
            screen = "".join(call.args[0] for call in write.call_args_list)
            lines = screen.splitlines()
            art = [line.strip().removesuffix("\x1b[K").strip()
                   for line in lines if "#" in line]
            if reference_art is None:
                reference_art = art
            self.assertEqual(art, reference_art)
            self.assertLessEqual(len(lines), rows)
            self.assertIn("38%", screen)
            self.assertIn(ui._reference_view()[0], screen)

    async def test_terminal_result_remains_present_until_window_closes(self):
        ui = CompletedUI()
        stop = asyncio.Event()
        with mock.patch.object(MODULE.sys.stdout, "isatty", return_value=True):
            presentation = asyncio.create_task(
                MODULE._present_until_closed(ui, stop)
            )
            await ui.completed.wait()
            await asyncio.sleep(0)
            self.assertFalse(presentation.done())
            stop.set()
            self.assertEqual(await presentation, 1)


if __name__ == "__main__":
    unittest.main()
