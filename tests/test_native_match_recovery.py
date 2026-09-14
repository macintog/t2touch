# SPDX-License-Identifier: GPL-2.0-only
"""Retained-result recovery must accept both actual match artifact producers."""

from pathlib import Path
import json
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_native_match import NATIVE_MATCH as native, BRIDGE_PROBE as probe
from tests.test_bridge_xpc_probe import match_result_event


class SavedMatchRecoveryTests(unittest.TestCase):
    def test_recovery_accepts_both_result_versions_but_rejects_disagreement(self):
        required = struct.pack("<I", 501) + b"a" * 16
        event = [9, 0xE3FF8000, match_result_event(required), None, None]
        current = probe.summarize_event(
            event, (required,), expected_user_id=501,
            selected_identity_record=required, required_identity_record=required,
        )
        legacy = {key: value for key, value in current.items()
                  if key != "matches_required_identity"}
        private = {"schema": 1, "processed_flags": 0x4009,
                   "events": probe.private_json_value([event])}
        for retained in (legacy, current, {**current, "matches_required_identity": False}):
            public = {"match_events": [retained]}
            with self.subTest(required_field=retained.get("matches_required_identity")):
                def recover():
                    return native._resummarize_saved_addition_result(
                        public, private, apple_user_id=501,
                        enrolled_identity_records=(required,), required_identity_record=required,
                        summarizer=probe.summarize_event,
                    )
                if retained.get("matches_required_identity") is False:
                    with self.assertRaisesRegex(native.NativeMatchError, "summary changed"):
                        recover()
                else:
                    recovered = json.loads(recover())
                    self.assertTrue(recovered["match_events"][0]["matches_required_identity"])
                self.assertEqual(public["match_events"], [retained])

    def test_both_producers_resolve_their_exact_private_pair(self):
        token = "12345678-1234-4234-8234-123456789abc"
        names = (
            ("tui-match-20260913T123456123456Z.json",
             "private-tui-match-events-20260913T123456123456Z.json"),
            (f"fprint-addition-match-{token}.json",
             f"private-fprint-addition-match-events-{token}.json"),
        )
        for public_name, private_name in names:
            with self.subTest(producer=public_name.split("-")[0]):
                self.assertEqual(
                    native._private_events_for_saved_match(native.NATIVE_MATCH_ROOT / public_name),
                    native.NATIVE_MATCH_ROOT / private_name,
                )

    def test_recovery_still_rejects_noncanonical_or_stale_results(self):
        root = native.NATIVE_MATCH_ROOT
        token = "12345678-1234-4234-8234-123456789abc"
        public = root / f"fprint-addition-match-{token}.json"
        for candidate in (
            Path("/tmp") / public.name,
            root / "fprint-addition-match-00000000-0000-0000-0000-000000000000.json",
            root / f"fprint-addition-match-{token.upper()}.json",
            root / "fprint-addition-match-not-a-uuid.json",
            root / "private-fprint-addition-match-events-123.json",
        ):
            with self.subTest(candidate=candidate.name), self.assertRaises(native.NativeMatchError):
                native._private_events_for_saved_match(candidate)
        with (
            patch.object(native, "_private", side_effect=[
                SimpleNamespace(st_mtime_ns=9), SimpleNamespace(st_mtime_ns=9),
                SimpleNamespace(st_mtime_ns=10),
            ]),
            patch.object(native, "_append_addition_match_verification") as append,
            self.assertRaisesRegex(native.NativeMatchError, "predates"),
        ):
            native._reconcile_addition_match_result(native.MUTATION_ROOT / f"{token}.jsonl", public)
        append.assert_not_called()
