# SPDX-License-Identifier: GPL-2.0-only

"""Terminal transport contracts; no TUI or hardware operations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("tui_control", Path(__file__).resolve().parents[1] / "tools/tui-control.py")
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class ControlTests(unittest.TestCase):
    def test_transport_exposes_no_keyboard_dispatch(self):
        """Protect D187: transport and operator input must never overlap."""

        self.assertFalse(hasattr(control.Control, "enter"))

    def test_ambiguous_target_and_existing_terminal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(Path(directory), "0")
            with patch.object(client, "remote", return_value='[{"tabs":[{"windows":[{"id":1},{"id":2}]}]}]'):
                with self.assertRaisesRegex(RuntimeError, "exactly one"):
                    client.window()
            with patch.object(client, "hypr", return_value='[{"class":"t2-native-enroll"}]') as hypr:
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    client.launch()
                hypr.assert_called_once_with("-j", "clients")

    def test_fprintd_enrollment_forwards_explicit_neutral_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(
                Path(directory),
                "0",
                control.PROFILES["fprintd-enrollment"],
                ("finger-2",),
            )
            replies = iter(("[]", '{"tiledLayout":"master"}', "ok"))
            with (
                patch.object(client, "hypr", side_effect=lambda *_args: next(replies)) as hypr,
                patch.object(client, "wait", return_value="7"),
            ):
                self.assertEqual(client.launch(), "7")
            dispatched = hypr.call_args_list[-1].args
            self.assertEqual(dispatched[0], "dispatch")
            self.assertIn(
                "/usr/local/sbin/t2-fprintd-enroll-tui-launch finger-2",
                dispatched[1],
            )

    def test_fprintd_deletion_forwards_exact_numbered_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(
                Path(directory),
                "0",
                control.PROFILES["fprintd-deletion"],
                ("finger-3",),
            )
            replies = iter(("[]", '{"tiledLayout":"master"}', "ok"))
            with (
                patch.object(
                    client,
                    "hypr",
                    side_effect=lambda *_args: next(replies),
                ) as hypr,
                patch.object(client, "wait", return_value="7"),
            ):
                self.assertEqual(client.launch(), "7")
            dispatched = hypr.call_args_list[-1].args
            self.assertEqual(dispatched[0], "dispatch")
            self.assertIn(
                "/usr/local/sbin/t2-fprintd-delete-tui-launch finger-3",
                dispatched[1],
            )

    def test_launch_handoff_waits_for_physical_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(Path(directory), "0")
            with patch.object(
                client,
                "screen",
                side_effect=[
                    "STARTING ONE BOUNDED ENROLLMENT",
                    "KEYBAG READY",
                    "PLACE FINGER NOW",
                    "PLACE FINGER NOW",
                ],
            ):
                with (
                    patch.object(control.time, "sleep"),
                    patch.object(client, "backend_active", return_value=True),
                ):
                    self.assertEqual(
                        client.wait_for_physical_readiness("7"),
                        "PLACE FINGER NOW",
                    )

    def test_launch_handoff_rejects_terminal_before_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(Path(directory), "0")
            with patch.object(client, "screen", return_value="ENROLLMENT STOPPED"):
                with self.assertRaisesRegex(
                    RuntimeError, "stopped before physical readiness"
                ):
                    client.wait_for_physical_readiness("7")

    def test_launch_handoff_rejects_stale_ready_screen(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(Path(directory), "0")
            with (
                patch.object(
                    client,
                    "screen",
                    side_effect=["PLACE FINGER NOW", "ENROLLMENT STOPPED"],
                ),
                patch.object(client, "backend_active", return_value=True),
                patch.object(control.time, "sleep"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "stopped before physical readiness"
                ):
                    client.wait_for_physical_readiness("7")

    def test_negative_profile_has_distinct_readiness_and_no_keyboard(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(
                Path(directory), "0", control.PROFILES["negative"]
            )
            with (
                patch.object(
                    client,
                    "screen",
                    side_effect=[
                        "PREPARING NEGATIVE CONTROL",
                        "PLACE UNENROLLED FINGER NOW",
                        "PLACE UNENROLLED FINGER NOW",
                    ],
                ),
                patch.object(client, "backend_active", return_value=True),
                patch.object(control.time, "sleep"),
            ):
                self.assertEqual(
                    client.wait_for_physical_readiness("9"),
                    "PLACE UNENROLLED FINGER NOW",
                )

    def test_sudo_pam_profile_waits_for_the_fixed_sensor_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            client = control.Control(
                Path(directory), "0", control.PROFILES["sudo-pam"]
            )
            prompt = "Touch the fingerprint sensor now."
            with (
                patch.object(client, "screen", side_effect=[prompt, prompt]),
                patch.object(client, "backend_active", return_value=True),
                patch.object(control.time, "sleep"),
            ):
                self.assertEqual(
                    client.wait_for_physical_readiness("11"), prompt
                )
