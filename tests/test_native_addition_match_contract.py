# SPDX-License-Identifier: GPL-2.0-only
"""Offline producer/consumer contract for a newly added fingerprint."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = load("addition_probe", "bridge-xpc-probe.py")
NATIVE = load("addition_native", "t2-native-match.py")


class AdditionResultTests(unittest.TestCase):
    def raw(self, identity, *, version=2, flags=0x60):
        body = bytearray(0xC84 if version == 1 else 0xC88)
        body[:20] = identity
        struct.pack_into("<I", body, 0x14, flags)
        raw = (struct.pack("<QIIQ", 0, 0xE3FF8002, version, 1)
               + struct.pack("<I4xQ", 0, len(body)) + body)
        return [9, 0xE3FF8000, raw, None, None]

    def summary(self, identity, *, version=2, required=True, flags=0x60):
        wanted = struct.pack("<I", 501) + b"a" * 16
        other = struct.pack("<I", 501) + b"b" * 16
        return PROBE.summarize_event(
            self.raw(identity, version=version, flags=flags), (wanted, other),
            expected_user_id=501, selected_identity_record=wanted,
            required_identity_record=wanted if required else None,
        )

    def validate(self, events):
        return NATIVE._required_identity_public_result(
            json.dumps({"match_events": events}).encode()
        )

    def test_real_probe_marks_only_the_required_identity(self):
        wanted = struct.pack("<I", 501) + b"a" * 16
        other = struct.pack("<I", 501) + b"b" * 16
        for version in (1, 2):
            with self.subTest(version=version):
                correct = self.summary(wanted, version=version)
                self.assertTrue(correct["matches_required_identity"])
                self.validate([correct])
                for event in (self.summary(other, version=version),
                              self.summary(wanted, version=version, required=False)):
                    with self.assertRaises(NATIVE.NativeMatchError):
                        self.validate([event])

    def test_valid_retries_can_precede_the_one_required_match(self):
        wanted = struct.pack("<I", 501) + b"a" * 16
        other = struct.pack("<I", 501) + b"b" * 16
        quality = self.summary(struct.pack("<i", -1) + b"\0" * 16, flags=1)
        matcher = self.summary(struct.pack("<i", -1) + b"\0" * 16, flags=0)
        success = self.summary(wanted)
        self.validate([quality, matcher, quality, matcher, success])
        for events in ([], [quality], [success, success], [success, quality],
                       [self.summary(other), success],
                       [{**quality, "result_valid": False}, success]):
            with self.subTest(events=events), self.assertRaises(NATIVE.NativeMatchError):
                self.validate(events)

    def test_recovery_resummarizes_exact_private_events(self):
        wanted = struct.pack("<I", 501) + b"a" * 16
        other = struct.pack("<I", 501) + b"b" * 16
        raw_events = [
            self.raw(struct.pack("<i", -1) + b"\0" * 16, flags=0),
            self.raw(wanted),
        ]
        retained = [
            PROBE.summarize_event(
                event, (wanted, other), expected_user_id=501,
                selected_identity_record=wanted,
            )
            for event in raw_events
        ]
        recovered = NATIVE._resummarize_saved_addition_result(
            {"match_events": retained},
            {
                "schema": 1,
                "processed_flags": 1,
                "events": PROBE.private_json_value(raw_events),
            },
            apple_user_id=501,
            enrolled_identity_records=(wanted, other),
            required_identity_record=wanted,
            summarizer=PROBE.summarize_event,
        )
        self.validate(json.loads(recovered)["match_events"])
        retained[0] = {**retained[0], "matched": True}
        with self.assertRaises(NATIVE.NativeMatchError):
            NATIVE._resummarize_saved_addition_result(
                {"match_events": retained},
                {
                    "schema": 1,
                    "processed_flags": 1,
                    "events": PROBE.private_json_value(raw_events),
                },
                apple_user_id=501,
                enrolled_identity_records=(wanted, other),
                required_identity_record=wanted,
                summarizer=PROBE.summarize_event,
            )
