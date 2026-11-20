# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_biolockout_protocol as biolockout_protocol
import t2_catacomb_protocol as catacomb_protocol
import t2_enrollment_persistence_bridge as bridge


GENERATION = str(uuid.UUID(int=4))


class FakeLease:
    def __init__(self):
        self.connection_generation = GENERATION
        self.calls = []
        self.invalidated = False
        self.replies = iter(
            [
                ([0, (32).to_bytes(4, "little")], []),
                ([0, b"LTFC" + b"u" * 28], []),
                ([0, b""], []),
                ([0, b"HRLB" + b"b" * 101], []),
            ]
        )

    def biometric_command(self, command, *, version, value, data, output_capacity):
        self.calls.append((command, version, value, bytes(data), output_capacity))
        return next(self.replies)

    def invalidate(self):
        self.invalidated = True


class EnrollmentPersistenceBridgeTests(unittest.TestCase):
    def test_routes_catacomb_then_variable_length_biolockout(self):
        lease = FakeLease()
        transport = bridge.EnrollmentPersistenceBridgeTransport(
            lease, protocol_version=2, connection_generation=GENERATION
        )
        descriptor = catacomb_protocol.CatacombComponent.user(501).descriptor
        self.assertEqual(transport.prepare(descriptor), (0, 32))
        status, user_blob = transport.complete(descriptor)
        self.assertEqual((status, len(user_blob)), (0, 32))
        self.assertEqual(transport.confirm(descriptor), 0)

        bio = biolockout_protocol.PERSISTENCE_DESCRIPTOR
        self.assertEqual(transport.prepare(bio), (0, 0x1000))
        status, bio_blob = transport.complete(bio)
        self.assertEqual((status, len(bio_blob)), (0, 105))
        self.assertEqual(transport.confirm(bio), 0)
        self.assertEqual(transport.state, bridge.RouteState.IDLE)
        self.assertEqual(
            [call[0] for call in lease.calls], [0x3D, 0x3E, 0x3F, 0x4A]
        )
        self.assertFalse(lease.invalidated)

    def test_post_capture_routes_presence_notifications(self):
        proto = bridge.protocol
        def callback(status, extra=b""):
            wire = proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, 1, 1)
            wire += proto.STATUS_PAYLOAD_HEADER.pack(status, len(extra)) + extra
            return [9, proto.BRIDGE_SERVICE_STATUS, wire, 0, 0]

        good = [callback(63), callback(64, bytes(36))]
        for callbacks in (good, [callback(67)],
                          good + [callback(70)], [[0]], [[9, 0, b"", 0, 0]]):
            lease = FakeLease()
            lease.replies = iter([([0, b"abc"], callbacks)])
            wrapped = bridge.PostCaptureLease(lease)
            if callbacks == good:
                self.assertEqual(wrapped.biometric_command(
                    1, version=2, value=0, data=b"", output_capacity=3),
                    ([0, b"abc"], []))
            else:
                with self.assertRaises(bridge.EnrollmentPersistenceBridgeError):
                    wrapped.biometric_command(1, version=2, value=0, data=b"", output_capacity=3)
            self.assertEqual(len(lease.calls), 1)

    def test_status_53_at_confirm_preserves_the_correlated_reply(self):
        proto = bridge.protocol
        confirm = catacomb_protocol.COMMAND_CONFIRM_SAVE_CATACOMB
        for command, version, detail, reply, accepted in (
            (confirm, 1, b"", [0, b""], True),
            (confirm, 1, b"", [7, b""], True),
            (confirm, 2, b"", [0, b""], False),
            (confirm, 1, b"x", [0, b""], False),
            (catacomb_protocol.COMMAND_COMPLETE_SAVE_CATACOMB, 1, b"", [0, b""], False),
        ):
            with self.subTest(command=command, version=version, detail=detail, reply=reply):
                wire = proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, version, 1)
                wire += proto.STATUS_PAYLOAD_HEADER.pack(53, len(detail)) + detail
                lease = FakeLease()
                lease.replies = iter([(reply, [[9, proto.BRIDGE_SERVICE_STATUS, wire, None, None]])])
                wrapped = bridge.PostCaptureLease(lease)
                kwargs = dict(version=2, value=0, data=b"", output_capacity=0)
                if accepted:
                    self.assertEqual(wrapped.biometric_command(command, **kwargs), (reply, []))
                else:
                    with self.assertRaises(bridge.EnrollmentPersistenceBridgeError):
                        wrapped.biometric_command(command, **kwargs)
                self.assertEqual(len(lease.calls), 1)

    def test_post_capture_statistics_preserve_correlated_reply(self):
        proto = bridge.protocol
        for command in (0x3D, 0x3E, 0x3F, 0x4A):
            for version, size, status in ((1, 28, 0), (1, 28, 7), (0, 28, 0),
                                          (2, 28, 0), (1, 11, 0)):
                with self.subTest(command=command, version=version, size=size, status=status):
                    wire = proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATISTICS, version, 1)
                    wire += bytes(size)
                    reply = [status, b""]
                    lease = FakeLease()
                    lease.replies = iter([(reply, [[9, proto.BRIDGE_SERVICE_STATUS, wire, None, None]])])
                    wrapped = bridge.PostCaptureLease(lease)
                    kwargs = dict(version=2, value=0, data=b"", output_capacity=0)
                    if version == 1 and size == 28:
                        self.assertEqual(wrapped.biometric_command(command, **kwargs), (reply, []))
                    else:
                        with self.assertRaises(bridge.EnrollmentPersistenceBridgeError):
                            wrapped.biometric_command(command, **kwargs)

    def test_post_capture_rejects_inconsistent_presence_detail_length(self):
        proto = bridge.protocol
        for declared, actual in ((0, 36), (36, 30)):
            with self.subTest(declared=declared, actual=actual):
                wire = proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, 1, 1)
                wire += proto.STATUS_PAYLOAD_HEADER.pack(64, declared) + bytes(actual)
                lease = FakeLease()
                lease.replies = iter([([0, b""], [[9, proto.BRIDGE_SERVICE_STATUS, wire, None, None]])])
                with self.assertRaisesRegex(bridge.EnrollmentPersistenceBridgeError, "invalid status framing"):
                    bridge.PostCaptureLease(lease).biometric_command(
                        catacomb_protocol.COMMAND_CONFIRM_SAVE_CATACOMB,
                        version=2, value=0, data=b"", output_capacity=0,
                    )

    def test_post_capture_presence_does_not_convert_failed_reply_to_success(self):
        proto = bridge.protocol
        wire = (proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, 2, 5)
                + proto.STATUS_PAYLOAD_HEADER.pack(64, 36) + bytes(36))
        lease = FakeLease()
        lease.replies = iter([([7, b""], [[9, proto.BRIDGE_SERVICE_STATUS, wire, 0, 0]])])
        reply, events = bridge.PostCaptureLease(lease).biometric_command(
            1, version=2, value=0, data=b"", output_capacity=4)
        self.assertEqual(reply, [7, b""])
        self.assertEqual(events, [])

    def test_post_capture_never_interprets_the_callback_trailer(self):
        # (None, None) is the hardware-derived fixture shape used by the
        # probe and match-contract tests; (0, 0) was the only shape a guess
        # of this wrapper previously admitted and is what the real
        # MacBookPro16,1 bridgeOS 24.16.6005 save notification disproved.
        proto = bridge.protocol

        def callback(status, trailer):
            wire = proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, 1, 1)
            wire += proto.STATUS_PAYLOAD_HEADER.pack(status, 0)
            return [9, proto.BRIDGE_SERVICE_STATUS, wire, *trailer]

        for trailer in ((0, 0), (None, None), (None, 0), (1, 2),
                        ("unused", "reserved")):
            with self.subTest(trailer=trailer):
                lease = FakeLease()
                lease.replies = iter([
                    ([0, b"abc"], [callback(63, trailer), callback(64, trailer)]),
                ])
                self.assertEqual(bridge.PostCaptureLease(lease).biometric_command(
                    1, version=2, value=0, data=b"", output_capacity=3),
                    ([0, b"abc"], []))

    def test_post_capture_wrapper_rejection_is_precise_and_privacy_preserving(self):
        proto = bridge.protocol
        marker = b"\x00MARKER-EVENT-CONTENT\x00MARKER"
        good_wire = (proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, 1, 1)
                     + proto.STATUS_PAYLOAD_HEADER.pack(63, 0))
        cases = [
            ("opaque", "callback is str, not a 5-item list"),
            ([9, proto.BRIDGE_SERVICE_STATUS, marker],
             "callback is a 3-item list, expected 5"),
            ([8, proto.BRIDGE_SERVICE_STATUS, marker, None, None],
             "callback method is 8, expected 9"),
            (["x", proto.BRIDGE_SERVICE_STATUS, marker, None, None],
             "callback method is a str, expected 9"),
            ([9, proto.BRIDGE_SERVICE_STATUS + 1, marker, None, None],
             f"callback selector is {proto.BRIDGE_SERVICE_STATUS + 1}, "
             f"expected {proto.BRIDGE_SERVICE_STATUS}"),
            ([9, proto.BRIDGE_SERVICE_STATUS, good_wire, None],
             "callback is a 4-item list, expected 5"),
            ([9, proto.BRIDGE_SERVICE_STATUS, "not-bytes", None, None],
             "callback event data is str, expected bytes"),
            ([9, proto.BRIDGE_SERVICE_STATUS, b"short", None, None],
             "callback event data is 5 bytes, expected 24 to 1048600 bytes"),
            ([9, proto.BRIDGE_SERVICE_STATUS, marker, None, None],
             "callback event header is invalid"),
        ]
        for callback, expected in cases:
            with self.subTest(callback=repr(callback)[:40]):
                lease = FakeLease()
                lease.replies = iter([([0, b"abc"], [callback])])
                with self.assertRaises(bridge.EnrollmentPersistenceBridgeError) as caught:
                    bridge.PostCaptureLease(lease).biometric_command(
                        1, version=2, value=0, data=b"", output_capacity=3)
                message = str(caught.exception)
                self.assertIn(expected, message)
                # Diagnostics classify the envelope; they never echo its bytes.
                self.assertNotIn("MARKER-EVENT-CONTENT", message)
                self.assertNotIn(marker.hex(), message)
                self.assertNotIn(repr(marker), message)

    def test_post_capture_classification_reports_header_fields_only(self):
        proto = bridge.protocol

        def callback(status, extra=b""):
            wire = proto.SERVICE_HEADER.pack(0, proto.SERVICE_STATUS, 1, 1)
            wire += proto.STATUS_PAYLOAD_HEADER.pack(status, len(extra)) + extra
            return [9, proto.BRIDGE_SERVICE_STATUS, wire, None, None]

        for status, extra, ordinal in ((67, b"", 67), (70, b"", 70),
                                       (90, b"DETAIL-MARKER", 90)):
            with self.subTest(status=status, extra=bool(extra)):
                lease = FakeLease()
                lease.replies = iter([([0, b"abc"], [callback(status, extra)])])
                with self.assertRaises(bridge.EnrollmentPersistenceBridgeError) as caught:
                    bridge.PostCaptureLease(lease).biometric_command(
                        1, version=2, value=0, data=b"", output_capacity=3)
                message = str(caught.exception)
                self.assertEqual(
                    message,
                    "save callback type=0xe3ff8001 version=1 "
                    f"ordinal={ordinal} payload_length={16 + len(extra)}")
                self.assertNotIn("DETAIL-MARKER", message)

    def test_post_capture_invalid_event_header_fails_closed_in_bridge_error(self):
        # reserved != 0 makes parse_service_event raise ValueError; the lease
        # must surface it as its own fail-closed error type with a framing
        # message, on the hardware null trailer shape.
        proto = bridge.protocol
        wire = (proto.SERVICE_HEADER.pack(1, proto.SERVICE_STATUS, 1, 1)
                + proto.STATUS_PAYLOAD_HEADER.pack(63, 0))
        lease = FakeLease()
        lease.replies = iter([
            ([0, b"abc"], [[9, proto.BRIDGE_SERVICE_STATUS, wire, None, None]]),
        ])
        with self.assertRaises(bridge.EnrollmentPersistenceBridgeError) as caught:
            bridge.PostCaptureLease(lease).biometric_command(
                1, version=2, value=0, data=b"", output_capacity=3)
        self.assertIn("save callback event header is invalid", str(caught.exception))

    def test_route_change_is_rejected_before_second_dispatch(self):
        lease = FakeLease()
        transport = bridge.EnrollmentPersistenceBridgeTransport(
            lease, protocol_version=2, connection_generation=GENERATION
        )
        descriptor = catacomb_protocol.CatacombComponent.user(501).descriptor
        transport.prepare(descriptor)
        with self.assertRaisesRegex(
            bridge.EnrollmentPersistenceBridgeError, "bio-lockout"
        ):
            transport.complete(biolockout_protocol.PERSISTENCE_DESCRIPTOR)
        self.assertEqual([call[0] for call in lease.calls], [0x3D])


if __name__ == "__main__":
    unittest.main()
