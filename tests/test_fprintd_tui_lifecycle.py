# SPDX-License-Identifier: GPL-2.0-only
"""Offline lifecycle checks for the direct D-Bus fingerprint companion."""
import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from tests.test_fprintd_enroll_tui import MODULE as tui


def status(member, value):
    return tui.Message(
        message_type=tui.MessageType.SIGNAL, path=tui.DEVICE_PATH,
        interface=tui.DEVICE_INTERFACE, member=member, signature="sb",
        body=[value, True],
    )


def owner_lost():
    return tui.Message(
        message_type=tui.MessageType.SIGNAL, sender="org.freedesktop.DBus",
        path="/org/freedesktop/DBus", interface="org.freedesktop.DBus",
        member="NameOwnerChanged", signature="sss",
        body=[tui.BUS_NAME, ":1.10", ":1.11"],
    )


class DirectBusLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_daemon_replacement_finishes_without_calling_new_owner(self):
        ui = tui.EnrollmentUI("finger-1", "mapped")
        ui.bus = object()
        ui.finger_needed = True
        with patch.object(ui, "render"), patch.object(ui, "_call", new_callable=AsyncMock) as call:
            ui._message(owner_lost())
            self.assertTrue(ui.done.is_set())
            self.assertEqual(ui.operation_result, 1)
            self.assertFalse(ui.finger_needed)
            self.assertEqual(ui.terminal, "ENROLLMENT STOPPED")
            await ui._finish_client(True, True)
            call.assert_not_called()
        # A live but unresponsive service must not keep the terminal's close
        # path waiting forever either. The bus disconnect in run() still owns
        # final caller disappearance; timing out does not certify clean SEP.
        ui.service_available = True
        async def stalled_call(*_args):
            await asyncio.Future()
        with (
            patch.object(tui, "CLEANUP_CALL_TIMEOUT_SECONDS", 0.01),
            patch.object(ui, "_call", side_effect=stalled_call) as call,
        ):
            await asyncio.wait_for(ui._finish_client(True, True), 1)
        self.assertEqual(call.call_count, 2)

    async def test_bus_loss_ends_wait_but_success_does_not_cancel_bus_future(self):
        for disconnected in (True, False):
            with self.subTest(disconnected=disconnected):
                ui = tui.EnrollmentUI("finger-1", "mapped", operation="verify")
                future = asyncio.get_running_loop().create_future()
                async def wait_for_disconnect():
                    await future
                ui.bus = SimpleNamespace(wait_for_disconnect=wait_for_disconnect)
                with patch.object(ui, "render"):
                    waiting = asyncio.create_task(ui._wait_for_completion())
                    await asyncio.sleep(0)
                    if disconnected:
                        future.set_exception(ConnectionError("test disconnect"))
                    else:
                        ui._message(status("VerifyStatus", "verify-match"))
                    await asyncio.wait_for(waiting, 1)
                self.assertTrue(ui.done.is_set())
                self.assertFalse(future.cancelled())
                if disconnected:
                    self.assertEqual(ui.operation_result, 1)
                    self.assertFalse(ui.service_available)
                else:
                    self.assertEqual(ui.operation_result, 0)
                    future.set_result(None)
                    await asyncio.sleep(0)

    def test_other_operation_and_late_status_cannot_change_verdict(self):
        ui = tui.EnrollmentUI("finger-1", "mapped", operation="verify")
        with patch.object(ui, "render"):
            ui._message(status("EnrollStatus", "enroll-completed"))
            self.assertFalse(ui.done.is_set())
            self.assertIsNone(ui.terminal)
            ui._message(status("VerifyStatus", "verify-match"))
            ui._message(status("VerifyStatus", "verify-unknown-error"))
            ui._message(owner_lost())
        self.assertEqual(ui.terminal, "FINGERPRINT MATCHED")
        self.assertEqual(ui.operation_result, 0)
        self.assertFalse(ui.service_available)
