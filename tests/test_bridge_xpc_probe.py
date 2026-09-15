#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free fail-closed parser tests for BridgeXPC replies."""

import importlib.util
import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch
import uuid


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/bridge-xpc-probe.py"
SPEC = importlib.util.spec_from_file_location("bridge_xpc_probe", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

import t2_bridge_wire as wire
import t2_catacomb_codec as codec
import t2_fprint_match_gate as match_gate
from tests.test_catacomb_codec import fixture


def match_result_event(identity_record: bytes, *, version: int = 2) -> bytes:
    body = bytearray(0xC84 if version == 1 else 0xC88)
    body[:20] = identity_record
    struct.pack_into("<I", body, 0x14, 0x60)
    if version == 2:
        struct.pack_into("<I", body, 0xC84, 0)
    return (
        struct.pack("<QIIQ", 0, 0xE3FF8002, version, 1)
        + struct.pack("<I4xQ", 0, len(body))
        + body
    )


class ReplyTests(unittest.TestCase):
    def test_touch_to_verdict_tracks_each_validated_capture(self):
        timing = {}
        with patch.object(MODULE.t2_performance, "emit") as emit:
            MODULE.observe_touch_to_verdict(
                {"event_kind": "status", "status_semantics": "finger-present"},
                timing,
                observed_at=10.0,
            )
            MODULE.observe_touch_to_verdict(
                {
                    "event_kind": "match_result",
                    "result_valid": True,
                    "no_match_image_quality": True,
                },
                timing,
                observed_at=10.1,
            )
            MODULE.observe_touch_to_verdict(
                {"event_kind": "status", "status_semantics": "finger-present"},
                timing,
                observed_at=20.0,
            )
            MODULE.observe_touch_to_verdict(
                {"event_kind": "match_result", "result_valid": False},
                timing,
                observed_at=20.2,
            )

        self.assertEqual(
            emit.call_args_list,
            [
                call("bridge_match", "touch_to_verdict", 10.0, "ok"),
                call("bridge_match", "touch_to_verdict", 20.0, "invalid"),
            ],
        )
        self.assertEqual(timing, {})

    def test_touch_to_verdict_ignores_unpaired_or_unvalidated_events(self):
        timing = {}
        with patch.object(MODULE.t2_performance, "emit") as emit:
            MODULE.observe_touch_to_verdict(
                {"event_kind": "match_result", "result_valid": True}, timing
            )
            MODULE.observe_touch_to_verdict(
                {"event_kind": "status", "untrusted_status_code": 63},
                timing,
                observed_at=10.0,
            )
        emit.assert_not_called()
        self.assertEqual(timing, {})

    def test_live_addition_verdict_retains_required_identity_boolean(self):
        event = {
            "event_kind": "match_result",
            "result_valid": True,
            "host_accepted_result": True,
            "matched": True,
            "matches_required_identity": True,
            "private_identity": "must-not-appear",
        }
        output = io.StringIO()
        with patch.object(MODULE.sys, "stderr", output):
            MODULE.emit_live_match_feedback(event, "json")
        prefix, payload = output.getvalue().strip().split(" ", 1)
        self.assertEqual(prefix, "T2_MATCH_EVENT")
        projected = json.loads(payload)
        self.assertIs(projected["matches_required_identity"], True)
        self.assertNotIn("private_identity", projected)

    def test_native_match_identity_authority_tracks_current_catacomb_set(self):
        first_uuid = str(uuid.UUID(int=1))
        second_uuid = str(uuid.UUID(int=2))
        store = SimpleNamespace(
            read_committed_components=lambda: {"user_000001f5.cat": b"user"}
        )
        current = SimpleNamespace(
            identities=(
                SimpleNamespace(user_id=501, uuid=first_uuid, name="finger-1"),
                SimpleNamespace(user_id=501, uuid=second_uuid, name="finger-2"),
            )
        )
        renamed = SimpleNamespace(
            identities=(
                SimpleNamespace(user_id=501, uuid=first_uuid, name="anything"),
                SimpleNamespace(user_id=501, uuid=second_uuid, name="else"),
            )
        )
        survivor = SimpleNamespace(
            identities=(
                SimpleNamespace(user_id=501, uuid=second_uuid, name="finger-2"),
            )
        )
        with (
            patch.object(MODULE.t2_catacomb_store, "CatacombStore", return_value=store),
            patch.object(
                MODULE.t2_catacomb_codec,
                "decode_user_catacomb",
                side_effect=(current, renamed, survivor),
            ),
        ):
            initial = MODULE.read_native_identity_records("/native", 501)
            after_rename = MODULE.read_native_identity_records("/native", 501)
            after_delete = MODULE.read_native_identity_records("/native", 501)
        first_record = struct.pack("<I16s", 501, uuid.UUID(first_uuid).bytes)
        second_record = struct.pack("<I16s", 501, uuid.UUID(second_uuid).bytes)
        self.assertEqual(initial, (first_record, second_record))
        self.assertEqual(after_rename, initial)
        self.assertEqual(after_delete, (second_record,))

    def test_native_addition_extends_survivors_after_original_identity_deleted(self):
        first_uuid = str(uuid.UUID(int=1))
        second_uuid = str(uuid.UUID(int=2))
        third_uuid = str(uuid.UUID(int=3))
        authority_history = SimpleNamespace(
            operation_id=str(uuid.UUID(int=10)),
            head_hash="a" * 64,
            terminal_identity_uuid=first_uuid,
        )
        authority = SimpleNamespace(
            selected=SimpleNamespace(
                account_uuid=str(uuid.UUID(int=11)),
                bag_uuid=str(uuid.UUID(int=12)),
            ),
            mapping_set=SimpleNamespace(generation="b" * 64),
        )
        current_authority = SimpleNamespace(
            reference="linux-native-current:" + authority_history.operation_id,
            sha256="c" * 64,
        )
        baseline = {
            "baseline_version": 1,
            "caller_linux_uid": 1000,
            "target_linux_uid": 1000,
            "apple_uid": 501,
            "account_uuid": authority.selected.account_uuid,
            "bag_uuid": authority.selected.bag_uuid,
            "mapping_generation": authority.mapping_set.generation,
            "backup_references": [
                {
                    "reference": current_authority.reference,
                    "sha256": current_authority.sha256,
                }
            ],
            "identity_records": [
                {"uuid": second_uuid},
            ],
        }
        addition = SimpleNamespace(
            operation_id=str(uuid.UUID(int=20)),
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid=third_uuid,
            baseline=baseline,
        )
        with patch.object(
            MODULE.t2_native_mutation_authority,
            "from_baseline",
            return_value=current_authority,
        ):
            expected, required = MODULE.native_addition_identity_records(
                addition, authority_history, authority, 501, 1000
            )
        records = tuple(
            struct.pack("<I16s", 501, uuid.UUID(value).bytes)
            for value in (second_uuid, third_uuid)
        )
        self.assertEqual(expected, records)
        self.assertEqual(required, records[-1])

    def test_native_addition_extends_empty_catalog_after_trusted_external_wipe(self):
        first_uuid = str(uuid.UUID(int=1))
        added_uuid = str(uuid.UUID(int=2))
        authority_history = SimpleNamespace(
            operation_id=str(uuid.UUID(int=10)),
            head_hash="a" * 64,
            terminal_identity_uuid=first_uuid,
        )
        authority = SimpleNamespace(
            selected=SimpleNamespace(
                account_uuid=str(uuid.UUID(int=11)),
                bag_uuid=str(uuid.UUID(int=12)),
            ),
            mapping_set=SimpleNamespace(generation="b" * 64),
        )
        current_authority = SimpleNamespace(
            reference="linux-native-current:" + authority_history.operation_id,
            sha256="c" * 64,
        )
        baseline = {
            "baseline_version": 1,
            "caller_linux_uid": 1000,
            "target_linux_uid": 1000,
            "apple_uid": 501,
            "account_uuid": authority.selected.account_uuid,
            "bag_uuid": authority.selected.bag_uuid,
            "mapping_generation": authority.mapping_set.generation,
            "backup_references": [
                {
                    "reference": current_authority.reference,
                    "sha256": current_authority.sha256,
                }
            ],
            "identity_records": [],
        }
        addition = SimpleNamespace(
            operation_id=str(uuid.UUID(int=20)),
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid=added_uuid,
            baseline=baseline,
        )
        with patch.object(
            MODULE.t2_native_mutation_authority,
            "from_baseline",
            return_value=current_authority,
        ):
            expected, required = MODULE.native_addition_identity_records(
                addition, authority_history, authority, 501, 1000
            )
        record = struct.pack("<I16s", 501, uuid.UUID(added_uuid).bytes)
        self.assertEqual(expected, (record,))
        self.assertEqual(required, record)

    def test_bridge_os_transaction_release_is_exact_and_fail_closed(self):
        result = {}
        sock = object()
        with patch.object(MODULE, "notify") as notify:
            retained = MODULE.release_bridge_os_transaction(sock, True, result)
        self.assertFalse(retained)
        notify.assert_called_once_with(sock, [12, False])
        self.assertIs(
            result["bridge_os_transaction_released_after_match"], True
        )

        result = {}
        with patch.object(MODULE, "notify") as notify:
            retained = MODULE.release_bridge_os_transaction(sock, False, result)
        self.assertFalse(retained)
        notify.assert_not_called()
        self.assertNotIn(
            "bridge_os_transaction_released_after_match", result
        )

        result = {}
        with patch.object(MODULE, "notify", side_effect=OSError("closed")):
            with self.assertRaises(OSError):
                MODULE.release_bridge_os_transaction(sock, True, result)
        self.assertNotIn(
            "bridge_os_transaction_released_after_match", result
        )

    def test_match_request_builder_binds_credential_and_one_target(self):
        identity = bytes(range(20))
        credential = bytes(range(16))
        request, flags, count = MODULE.build_match_request(
            501,
            MODULE.MATCH_FLAG_FOR_UNLOCK,
            credential,
            (identity,),
        )
        self.assertEqual(
            flags,
            MODULE.MATCH_FLAG_FOR_UNLOCK
            | MODULE.MATCH_FLAG_FOR_CREDENTIAL_SET
            | MODULE.MATCH_FLAG_SELECTED_IDENTITIES,
        )
        self.assertEqual(count, 1)
        self.assertEqual(len(request), 68 + 4 + 20)
        self.assertEqual(struct.unpack_from("<III", request), (flags, 501, 16))
        self.assertEqual(request[12:28], credential)
        self.assertEqual(struct.unpack_from("<I", request, 68)[0], 1)
        self.assertEqual(request[72:], identity)

    def test_named_match_request_keeps_only_targeted_identity(self):
        first = b"a" * 20
        second = b"b" * 20
        self.assertEqual(
            MODULE.selected_match_records((first, second), None, second),
            (second,),
        )
        self.assertEqual(
            MODULE.selected_match_records((first, second), first, second),
            (first,),
        )
        self.assertEqual(
            MODULE.selected_match_records((first, second), None, None),
            (first, second),
        )

    def test_native_complete_gate_accepts_named_and_resolved_selectors(self):
        common = {
            "match_seconds": 20.0,
            "initialize": True,
            "biometric_protocol": True,
            "identity_list": True,
            "service_template_sync": True,
            "global_identity_list": True,
            "match_all_enrolled_identities": False,
            "native_addition_journal": None,
            "match_finger_name": None,
            "resolve_any_finger_name": False,
            "resolve_any_identity_slot": False,
        }
        for selector in (
            "match_all_enrolled_identities",
            "native_addition_journal",
            "match_finger_name",
            "resolve_any_finger_name",
            "resolve_any_identity_slot",
        ):
            arguments = dict(common)
            arguments[selector] = (
                "/private/addition.jsonl"
                if selector == "native_addition_journal"
                else "finger-1"
                if selector == "match_finger_name"
                else True
            )
            with self.subTest(selector=selector):
                self.assertTrue(
                    MODULE.native_match_gate_complete(
                        SimpleNamespace(**arguments)
                    )
                )
        self.assertFalse(
            MODULE.native_match_gate_complete(SimpleNamespace(**common))
        )
        incomplete = dict(common)
        incomplete["match_finger_name"] = "finger-1"
        incomplete["identity_list"] = False
        self.assertFalse(
            MODULE.native_match_gate_complete(
                SimpleNamespace(**incomplete)
            )
        )

    def test_public_failure_message_is_bounded_and_identifier_safe(self):
        class SyntheticBridgeError(Exception):
            pass

        self.assertEqual(
            MODULE.public_failure_message(
                ValueError("sensor rejected pre-match cancellation")
            ),
            "sensor rejected pre-match cancellation",
        )
        self.assertEqual(
            MODULE.public_failure_message(
                SyntheticBridgeError("peer closed during framed reply")
            ),
            "peer closed during framed reply",
        )
        self.assertEqual(
            MODULE.public_failure_message(
                RuntimeError("failed below /private/path")
            ),
            "RuntimeError",
        )
        self.assertEqual(
            MODULE.public_failure_message(
                OSError("connect failed at 198.18.0.1")
            ),
            "OSError",
        )
        self.assertEqual(
            MODULE.public_failure_message(
                RuntimeError("operation 00000000-0000-0000-0000-000000000001 failed")
            ),
            "RuntimeError",
        )

    def test_full_inventory_runtime_dependencies_are_available(self):
        self.assertEqual(MODULE.ExitStack.__name__, "ExitStack")
        for name in (
            "t2_acm_device",
            "t2_aks_transport",
            "t2_biolockout_store",
            "t2_catacomb_protocol",
            "t2_enrollment_journal",
            "t2_user_authority",
        ):
            with self.subTest(name=name):
                self.assertIn(name, vars(MODULE))

    def test_compatibility_loaded_empty_state_requires_cold_restart(self):
        managed = (struct.pack("<I16s", 501, uuid.UUID(int=1).bytes),)
        nil_reply = [0, wire.BIOMETRIC_NIL_OUTPUT_SENTINEL]
        live = MODULE.managed_user_identity_records(
            nil_reply, [], 501, "compatibility"
        )
        self.assertEqual(live, ())
        self.assertTrue(MODULE.compatibility_restore_required(live, managed))
        with self.assertRaisesRegex(ValueError, "cold bridgeOS restart required"):
            MODULE.validate_compatibility_restore_state(True, (3, 3))
        MODULE.validate_compatibility_restore_state(True, (1,))
        self.assertFalse(
            MODULE.compatibility_restore_required(managed, managed)
        )

    def test_full_inventory_retries_missing_initial_protocol_payload(self):
        successful = [0, struct.pack("<I", 2)]
        remaining = [
            [0, b""],
            successful,
            [0, b""],
            [0, struct.pack("<I", 5)],
            [0, b""],
            [0, struct.pack("<I", 5)],
            [0, uuid.UUID(int=3).bytes],
            [0, b"\x00" + b"h" * 32],
            [0, b"\0" * 16],
            [0, struct.pack("<I", 552)],
        ]
        with patch.object(
            MODULE,
            "biometric_command",
            side_effect=[(reply, []) for reply in remaining],
        ) as command:
            inventory = MODULE.collect_full_inventory(object(), 501)
        self.assertEqual(inventory["replies"]["protocol"], successful)
        self.assertEqual(command.call_count, 10)

    def test_malformed_command_replies_are_invalid(self):
        for value in (None, {}, [], ["zero"], b"bytes"):
            with self.subTest(value=value):
                self.assertFalse(MODULE.summarize_command_reply(value)["valid"])

    def test_status_and_output_are_summarized_without_payload(self):
        summary = MODULE.summarize_command_reply([0, b"secret payload"])
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["output_length"], 14)
        self.assertNotIn("output", summary)

    def test_nil_placeholder_is_classified_without_disclosure(self):
        sentinel = wire.BIOMETRIC_NIL_OUTPUT_SENTINEL
        summary = MODULE.summarize_command_reply([0, sentinel])
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["output_kind"], "nil-placeholder")
        self.assertIsNone(summary["output_length"])
        self.assertNotIn(sentinel, str(summary))

    def test_command_rejection_reports_stage_status_and_shape_without_payload(self):
        failure = MODULE.command_reply_failure(
            "load-master-catacomb", "command-0x40-response", [257, b"secret"]
        )
        self.assertIn("load-master-catacomb", failure)
        self.assertIn("command-0x40-response", failure)
        self.assertIn("status=257", failure)
        self.assertIn("output_length=6", failure)
        self.assertNotIn("secret", failure)

    def test_service_status_summary_uses_payload_ordinal_not_timestamp(self):
        timestamp = 0x6B158284DB5
        raw = struct.pack("<QIIQ", 0, 0xE3FF8001, 1, timestamp)
        raw += struct.pack("<I4xQ", 90, 0)
        summary = MODULE.summarize_event([9, 0xE3FF8000, raw, None, None])
        self.assertTrue(summary["common_record_valid"])
        self.assertTrue(summary["reserved_zero"])
        self.assertTrue(summary["event_timestamp_present"])
        self.assertEqual(summary["ordinal"], 90)
        self.assertTrue(summary["parsed_ordinal_matches"])
        self.assertNotIn(str(timestamp), str(summary))

    def test_sks_event_summary_exposes_only_shape_and_user_match(self):
        timestamp = 0x6B158284DB5
        raw = struct.pack("<QIIQ", 0, 0xE3FF800A, 1, timestamp)
        raw += struct.pack("<IH", 501, 0x228) + b"opaque"
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None], expected_user_id=501
        )
        self.assertEqual(summary["event_kind"], "sks_lock_state")
        self.assertEqual(summary["event_data_length"], 12)
        self.assertTrue(summary["user_id_matches_configured"])
        self.assertNotIn("501", str(summary))
        self.assertNotIn("552", str(summary))
        self.assertNotIn("opaque", str(summary))

    def test_match_summary_distinguishes_selected_from_other_enrolled_identity(self):
        selected = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        other = struct.pack("<I", 501) + uuid.UUID(int=12).bytes
        raw = match_result_event(other)
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            (selected, other),
            expected_user_id=501,
            selected_identity_record=selected,
        )
        self.assertTrue(summary["matched"])
        self.assertTrue(summary["matches_enrolled_identity"])
        self.assertFalse(summary["matches_selected_identity"])
        self.assertNotIn(selected.hex(), str(summary))
        self.assertNotIn(other.hex(), str(summary))

    def test_match_summary_accepts_only_selected_identity_boolean(self):
        selected = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        other = struct.pack("<I", 501) + uuid.UUID(int=12).bytes
        raw = match_result_event(selected)
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            (selected, other),
            expected_user_id=501,
            selected_identity_record=selected,
        )
        self.assertTrue(summary["matches_selected_identity"])

    def test_any_match_summary_resolves_only_one_canonical_name(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        renamed = codec.decode_user_catacomb(
            original.rename(
                original.identities[0].uuid,
                "finger-1",
            ),
            501,
        )
        local = codec.decode_user_catacomb(
            renamed.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="finger-2",
            ),
            501,
        )
        records = tuple(
            struct.pack("<I", identity.user_id) + uuid.UUID(identity.uuid).bytes
            for identity in local.identities
        )
        global_records = tuple(
            record + struct.pack("<I", 1) + uuid.UUID(int=0).bytes
            for record in records
        )
        gate = match_gate.prepare_all(
            local,
            {"master.cat": b"m", "user_000001f5.cat": b"u"},
            records,
            global_records,
            records,
            global_records,
        )
        raw = match_result_event(records[1])
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            records,
            expected_user_id=501,
            all_match_gate=gate,
        )
        self.assertTrue(summary["matched_finger_name_present"])
        self.assertEqual(summary["matched_finger_name"], local.identities[1].name)
        self.assertNotIn(records[1].hex(), str(summary))

    def test_slot_match_summary_resolves_only_ephemeral_slot(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        local = codec.decode_user_catacomb(
            original.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="Linux enrolled finger",
            ),
            501,
        )
        records = tuple(
            struct.pack("<I", identity.user_id)
            + uuid.UUID(identity.uuid).bytes
            for identity in reversed(local.identities)
        )
        global_records = tuple(
            record + struct.pack("<I", 1) + uuid.UUID(int=0).bytes
            for record in records
        )
        gate = match_gate.prepare_slots(
            local,
            {"master.cat": b"m", "user_000001f5.cat": b"u"},
            records,
            global_records,
            records,
            global_records,
        )
        raw = match_result_event(records[0])
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            records,
            expected_user_id=501,
            slot_match_gate=gate,
        )
        self.assertTrue(summary["matched_identity_slot_present"])
        self.assertIn(summary["matched_identity_slot"], (1, 2))
        self.assertNotIn(records[0].hex(), str(summary))
        self.assertNotIn("finger_name", str(summary))

    def test_strict_identity_records_rejects_status_shape_and_events(self):
        record = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        self.assertEqual(
            MODULE.strict_identity_records([0, record], [], 20, "test"),
            (record,),
        )
        for reply, events, size in (
            ([-1, record], [], 20),
            ([0, record + b"x"], [], 20),
            ([0, record], [object()], 20),
            ([0, record], [], 21),
        ):
            with self.subTest(), self.assertRaises(ValueError):
                MODULE.strict_identity_records(reply, events, size, "test")

    def test_post_match_inventory_retains_separate_late_callbacks(self):
        record = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        callback = [9, 0xE3FF8000, b"opaque", None, None]
        self.assertEqual(
            MODULE.post_match_identity_records(
                [0, record], [callback], 20, "post-match"
            ),
            (record,),
        )
        with self.assertRaisesRegex(ValueError, "callback stream"):
            MODULE.post_match_identity_records(
                [0, record], None, 20, "post-match"
            )

    def full_inventory(self):
        identity = struct.pack("<I", 501) + uuid.UUID(int=1).bytes
        group = struct.pack("<I", 1) + uuid.UUID(int=2).bytes
        replies = {
            "protocol": [0, struct.pack("<I", 2)],
            "global_identities": [0, identity + group],
            "maximum_capacity": [0, struct.pack("<I", 5)],
            "per_user_identities": [0, identity],
            "free_capacity": [0, struct.pack("<I", 2)],
            "catacomb_uuid": [0, uuid.UUID(int=3).bytes],
            "catacomb_hash": [0, b"\x01" + b"h" * 32],
            "catacomb_state": [0, b"\0" * 16],
            "sks_lock_state": [0, struct.pack("<I", 552)],
        }
        return {"replies": replies, "events": {}}

    def test_full_inventory_compares_whole_private_snapshots(self):
        first = self.full_inventory()
        second = self.full_inventory()
        public, private = MODULE.summarize_full_inventory(
            first,
            second,
            501,
            "00000000-0000-0000-0000-000000000010",
            {},
        )
        self.assertTrue(public["full_snapshot_repeat_equal"])
        self.assertTrue(public["private_inventory_complete"])
        self.assertEqual(public["private_inventory_gate_failures"], [])
        self.assertTrue(public["configured_identity_records_reconciled"])
        self.assertEqual(private["per_user_identity_records"][0]["user_id"], 501)
        self.assertNotIn(str(uuid.UUID(int=1)), str(public))

    def test_full_inventory_with_changed_second_snapshot_is_not_private(self):
        first = self.full_inventory()
        second = self.full_inventory()
        second["replies"]["catacomb_hash"] = [0, b"\x01" + b"x" * 32]
        public, private = MODULE.summarize_full_inventory(
            first,
            second,
            501,
            "00000000-0000-0000-0000-000000000010",
            {},
        )
        self.assertFalse(public["full_snapshot_repeat_equal"])
        self.assertFalse(public["private_inventory_complete"])
        self.assertEqual(public["private_inventory_gate_failures"], ["snapshot_stable"])
        self.assertEqual(private, {})

    def test_v2_global_identity_reply_attests_rejected_protocol_query(self):
        first = self.full_inventory()
        second = self.full_inventory()
        rejected = [-536870206, b"\0" * 4]
        first["replies"]["protocol"] = rejected
        second["replies"]["protocol"] = rejected
        public, private = MODULE.summarize_full_inventory(
            first,
            second,
            501,
            "00000000-0000-0000-0000-000000000010",
            {},
        )
        self.assertTrue(public["biometric_protocol_v2_attested"])
        self.assertEqual(
            public["biometric_protocol_attestation"],
            "v2-global-identity-command",
        )
        self.assertTrue(public["private_inventory_complete"])
        self.assertEqual(private["biometric_protocol_version"], 2)


if __name__ == "__main__":
    unittest.main()
