# SPDX-License-Identifier: GPL-2.0-only

import struct
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_mesa_enrollment_preparation as preparation
import t2_enrollment_protocol as enrollment_protocol


USER = 501


def daemon_info(*, calibrated: int = 1) -> bytes:
    output = bytearray(23)
    struct.pack_into("<II", output, 0, 2, 10)
    output[22] = calibrated
    return bytes(output)


def states(*, selected_state: int = 3) -> bytes:
    return struct.pack("<IIII", 0xFFFFFFFF, 3, USER, selected_state)


def system_policy() -> bytes:
    return struct.pack("<7i", -1, -1, -1, 1, 1, 1, 1)


def user_policy() -> bytes:
    return struct.pack("<8i", 1, 1, 1, 0, 1, 1, 1, 0)


def sks_event() -> list[object]:
    data = (
        enrollment_protocol.SERVICE_HEADER.pack(
            0, enrollment_protocol.SERVICE_SKS_LOCK_STATE, 1, 123
        )
        + struct.pack("<IH", USER, 1)
        + bytes(16)
    )
    return [9, enrollment_protocol.BRIDGE_SERVICE_STATUS, data, 0, 0]


def status_event(ordinal: int, detail: bytes = b"") -> list[object]:
    data = (
        enrollment_protocol.SERVICE_HEADER.pack(
            0, enrollment_protocol.SERVICE_STATUS, 1, 123
        )
        + enrollment_protocol.STATUS_PAYLOAD_HEADER.pack(ordinal, len(detail))
        + detail
    )
    return [9, enrollment_protocol.BRIDGE_SERVICE_STATUS, data, 0, 0]


class FakeLease:
    def __init__(self, replies, *, events=None):
        self.connection_generation = "generation"
        self.replies = list(replies)
        self.commands = []
        self.invalidated = False
        self.bridge_replies = []
        self.events = list(events or [])

    def biometric_command(self, command, *, version, value, data, output_capacity):
        self.commands.append((command, version, value, bytes(data), output_capacity))
        events = self.events.pop(0) if self.events else []
        return [0, self.replies.pop(0)], events

    def invalidate(self):
        self.invalidated = True

    def bridge_request(self, payload):
        return self.bridge_replies.pop(0), []


class MesaEnrollmentPreparationTests(unittest.TestCase):
    def ready_lease(self):
        return FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(),
                b"",
                b"",
                daemon_info(),
                states(),
                b"",
                daemon_info(),
                states(),
                system_policy(),
                user_policy(),
            ],
            events=[[sks_event()]],
        )

    def test_exact_working_pre_enrollment_sequence(self):
        lease = self.ready_lease()
        result = preparation.prepare_empty_user_for_enrollment(lease, USER)

        self.assertEqual(
            [command[0] for command in lease.commands],
            [
                0x53,
                0x02,
                0x35,
                0x28,
                0x0C,
                0x31,
                0x28,
                0x3C,
                0x42,
                0x28,
                0x3C,
                0x43,
                0x2E,
            ],
        )
        self.assertEqual(lease.commands[5][3], struct.pack("<I", USER))
        self.assertEqual(lease.commands[8][3], struct.pack("<I", USER))
        self.assertEqual(lease.commands[12][3], struct.pack("<I", USER))
        self.assertEqual(result.identity_count, 0)
        self.assertTrue(result.calibration_loaded)
        self.assertTrue(result.selected_user_secure)
        self.assertFalse(lease.invalidated)

    def test_existing_user_is_not_redeclared_without_a_catacomb(self):
        identity = struct.pack("<I", USER) + bytes(16)
        lease = FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(),
                b"",
                daemon_info(),
                states(),
                identity,
                daemon_info(),
                states(),
                system_policy(),
                user_policy(),
            ]
        )

        result = preparation.prepare_user_for_enrollment(lease, USER, 1)

        self.assertEqual(
            [command[0] for command in lease.commands],
            [0x53, 0x02, 0x35, 0x28, 0x0C, 0x28, 0x3C, 0x42, 0x28, 0x3C, 0x43, 0x2E],
        )
        self.assertNotIn(0x31, [command[0] for command in lease.commands])
        self.assertEqual(result.identity_count, 1)
        self.assertFalse(lease.invalidated)

        empty = FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(),
                b"",
                daemon_info(),
                states(),
                b"",
                daemon_info(),
                states(),
                system_policy(),
                user_policy(),
            ]
        )
        result = preparation.prepare_user_for_enrollment(empty, USER, 0)
        self.assertEqual(result.identity_count, 0)
        self.assertNotIn(0x31, [command[0] for command in empty.commands])
        self.assertFalse(empty.invalidated)

    def test_nonsecure_user_stops_and_invalidates_before_identity_read(self):
        lease = FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(),
                b"",
                b"",
                daemon_info(),
                states(selected_state=1),
            ]
        )

        with self.assertRaisesRegex(
            preparation.MesaEnrollmentPreparationError,
            "not securely loaded",
        ):
            preparation.prepare_empty_user_for_enrollment(lease, USER)

        self.assertEqual(
            [item[0] for item in lease.commands],
            [0x53, 0x02, 0x35, 0x28, 0x0C, 0x31, 0x28, 0x3C],
        )
        self.assertTrue(lease.invalidated)

    def test_calibration_and_policy_are_mandatory(self):
        uncalibrated = FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(calibrated=0),
                b"",
                daemon_info(),
                b"",
                b"",
                daemon_info(),
                states(),
                b"",
                daemon_info(),
                states(),
                system_policy(),
                user_policy(),
            ]
        )
        uncalibrated.bridge_replies = [[b"calibration"]]
        uncalibrated.events = [
            [],
            [],
            [],
            [],
            [status_event(80), status_event(64, bytes(36)), status_event(94)],
        ]
        loaded = preparation.prepare_empty_user_for_enrollment(uncalibrated, USER)
        self.assertTrue(loaded.calibration_loaded)
        self.assertEqual(uncalibrated.commands[4][0], 0x20)
        self.assertEqual(uncalibrated.commands[4][2], 3)

        disabled_system = struct.pack("<7i", -1, -1, -1, 0, 1, 1, 1)
        disabled = FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(),
                b"",
                b"",
                daemon_info(),
                states(),
                b"",
                daemon_info(),
                states(),
                disabled_system,
                user_policy(),
            ]
        )
        with self.assertRaisesRegex(
            preparation.MesaEnrollmentPreparationError,
            "protected policy is not enabled",
        ):
            preparation.prepare_empty_user_for_enrollment(disabled, USER)
        self.assertTrue(disabled.invalidated)

    def test_calibration_status_event_is_rejected_by_other_commands(self):
        lease = self.ready_lease()
        lease.events = [[status_event(80)]]

        with self.assertRaisesRegex(
            preparation.MesaEnrollmentPreparationError,
            "sensor-readiness read emitted an unexpected service event",
        ):
            preparation.prepare_empty_user_for_enrollment(lease, USER)

        self.assertTrue(lease.invalidated)

    def test_calibration_rejects_wrong_status_detail_length(self):
        lease = FakeLease(
            [
                b"\x01",
                b"",
                bytes(12),
                daemon_info(calibrated=0),
                b"",
            ],
            events=[
                [],
                [],
                [],
                [],
                [status_event(64, bytes(35))],
            ],
        )
        lease.bridge_replies = [[b"calibration"]]

        with self.assertRaisesRegex(
            preparation.MesaEnrollmentPreparationError,
            "calibration load emitted an unexpected service event",
        ):
            preparation.prepare_empty_user_for_enrollment(lease, USER)

        self.assertTrue(lease.invalidated)


if __name__ == "__main__":
    unittest.main()
