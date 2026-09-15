#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free safety contracts for Linux-native matching."""

import importlib.util
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import Mock, call, patch
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


NATIVE_MATCH = load("t2_native_match_cli", ROOT / "src/t2-native-match.py")
BRIDGE_PROBE = load("bridge_xpc_probe", ROOT / "src/bridge-xpc-probe.py")
CEREMONY = load("t2_second_finger_ceremony", ROOT / "src/t2-second-finger-ceremony.py")
import t2_mutation_registry as MUTATION_REGISTRY


class NativeMatchSafetyTests(unittest.TestCase):
    def test_resident_response_compacts_unbounded_probe_history(self):
        result = {
            "configured_identity_records_reconciled": True,
            "bridge_os_transaction_released_after_match": True,
            "termination_requested": False,
            "match_cleanup_valid": True,
            "match_events": [
                {"event_kind": "status", "detail": "x" * 256}
                for _ in range(400)
            ] + [
                {
                    "event_kind": "match_result",
                    "result_valid": True,
                    "matched": False,
                    "no_match": True,
                }
            ],
        }
        self.assertGreater(len(json.dumps(result)), 65536)
        terminal = NATIVE_MATCH.t2_fprint_result.compact_worker_result(
            result, None, False
        )
        response = {
            "schema_version": 1,
            "request_id": 1,
            "ok": True,
            "result": terminal,
        }
        line = NATIVE_MATCH._worker_response_line(response)
        self.assertLessEqual(len(line), NATIVE_MATCH.MAX_WORKER_RESPONSE_BYTES)
        self.assertEqual(
            NATIVE_MATCH.t2_fprint_result.validate_worker_terminal_result(
                terminal, None, False
            ),
            ("verify-no-match", None),
        )

    def test_successful_cancel_drains_owned_callbacks_to_idle(self):
        """Protect the D206 match-to-enrollment handoff from callback spill."""

        sock = Mock()
        sock.gettimeout.return_value = 60
        events = []
        callback = [9, 2147450880, b"event", 0, 0]
        with (
            patch.object(
                BRIDGE_PROBE,
                "receive_envelope",
                side_effect=[[1, False, "CALLBACK", callback], TimeoutError()],
            ),
            patch.object(BRIDGE_PROBE, "send_message") as acknowledge,
        ):
            drained = BRIDGE_PROBE.drain_post_cancel_service_events(
                sock, events, idle_seconds=0.25
            )

        self.assertEqual(drained, 1)
        self.assertEqual(events, [callback])
        acknowledge.assert_called_once_with(sock, [1, True, "CALLBACK", [0]])
        self.assertEqual(
            sock.settimeout.call_args_list,
            [call(0.25), call(60)],
        )

    def test_schema_two_match_uses_e4_catacomb_and_private_credential_fd(self):
        command = NATIVE_MATCH._probe_command(
            {
                "host": "host",
                "interface": "interface",
                "apple_uid": 501,
                "linux_uid": 1000,
            },
            port=50000,
            credential_fd=9,
            seconds=0,
            private_events="/private/events.json",
        )
        self.assertIn("--native-authority-linux-uid", command)
        self.assertIn("--load-native-catacomb-root", command)
        self.assertIn("--authorized-credential-set-fd", command)
        self.assertIn("--service-template-sync", command)
        self.assertIn("--identity-list", command)
        self.assertIn("--global-identity-list", command)
        self.assertNotIn("--authorized-credential-set-password", command)
        self.assertNotIn("--load-catacomb-archive", command)

    def test_negative_control_stops_on_exact_result_and_retries_quality(self):
        command = NATIVE_MATCH._probe_command(
            {
                "host": "host",
                "interface": "interface",
                "apple_uid": 501,
                "linux_uid": 1000,
            },
            port=50000,
            credential_fd=9,
            seconds=0,
            private_events="/private/events.json",
            expect_no_match=True,
        )
        self.assertIn("--stop-on-match-result", command)
        self.assertIn("--retry-image-quality-no-match", command)
        self.assertNotIn("--stop-on-match-success", command)

        exact = {
            "event_kind": "match_result",
            "result_valid": True,
            "host_accepted_result": True,
            "no_match": True,
            "no_match_matcher": True,
            "matched": False,
        }
        NATIVE_MATCH._validate_negative_result(
            json.dumps({"match_events": [exact]}).encode()
        )
        quality = {
            **exact,
            "no_match_image_quality": True,
            "no_match_matcher": False,
        }
        NATIVE_MATCH._validate_negative_result(
            json.dumps({"match_events": [quality, quality, exact]}).encode()
        )
        for events in (
            [], [quality], [exact, exact], [exact, quality],
            [{**quality, "result_valid": False}, exact],
            [{**quality, "matched": True}, exact],
        ):
            with self.subTest(events=events), self.assertRaisesRegex(
                NATIVE_MATCH.NativeMatchError, "one exact matcher no-match"
            ):
                NATIVE_MATCH._validate_negative_result(
                    json.dumps({"match_events": events}).encode()
                )
        exact["matched"] = True
        with self.assertRaisesRegex(
            NATIVE_MATCH.NativeMatchError, "one exact matcher no-match"
        ):
            NATIVE_MATCH._validate_negative_result(
                json.dumps({"match_events": [exact]}).encode()
            )

    def test_standard_verification_stops_on_first_non_quality_verdict(self):
        command = NATIVE_MATCH._probe_command(
            {
                "host": "host",
                "interface": "interface",
                "apple_uid": 501,
                "linux_uid": 1000,
            },
            port=50000,
            credential_fd=9,
            seconds=15,
            private_events=None,
            stop_on_first_verdict=True,
        )
        self.assertIn("--stop-on-match-result", command)
        self.assertIn("--retry-image-quality-no-match", command)
        self.assertNotIn("--stop-on-match-success", command)

    def test_probe_failure_reason_is_bounded_and_identifier_free(self):
        reason = NATIVE_MATCH._probe_failure_reason(
            json.dumps(
                {
                    "match_rejected": True,
                    "match_start_reply": {
                        "valid": True,
                        "status": -536870160,
                        "status_hex": "0xe00002f0",
                    },
                    "private_identifier": "must-not-appear",
                }
            ).encode()
        )
        self.assertEqual(
            reason,
            "native match start was rejected "
            "(status -536870160, 0xe00002f0)",
        )
        self.assertNotIn("must-not-appear", reason)
        self.assertEqual(
            NATIVE_MATCH._probe_failure_reason(
                json.dumps(
                    {
                        "schema_version": 1,
                        "probe_failed": True,
                        "failure_reason": "sensor rejected pre-match cancellation",
                        "identifiers_redacted": True,
                    }
                ).encode()
            ),
            "native match probe failed: sensor rejected pre-match cancellation",
        )

    def test_addition_match_selects_and_requires_only_new_identity(self):
        command = NATIVE_MATCH._probe_command(
            {
                "host": "host",
                "interface": "interface",
                "apple_uid": 501,
                "linux_uid": 1000,
            },
            port=50000,
            credential_fd=9,
            seconds=0,
            private_events=None,
            addition_journal="/var/lib/t2-touchid/mutations/addition.jsonl",
        )
        self.assertIn("--native-addition-journal", command)
        self.assertNotIn("--match-all-enrolled-identities", command)
        accepted = {
            "event_kind": "match_result",
            "result_structure_valid": True,
            "host_accepted_result": True,
            "result_valid": True,
            "result_ignored": False,
            "no_match": False,
            "matches_enrolled_identity": True,
            "matched": True,
            "matches_required_identity": True,
        }
        NATIVE_MATCH._validate_required_identity_result(
            json.dumps({"match_events": [accepted]}).encode()
        )
        accepted["matches_required_identity"] = False
        with self.assertRaisesRegex(NATIVE_MATCH.NativeMatchError, "newly added"):
            NATIVE_MATCH._validate_required_identity_result(
                json.dumps({"match_events": [accepted]}).encode()
            )

    def test_fprint_selectors_are_mutually_exclusive_and_canonical(self):
        targeted = NATIVE_MATCH._probe_command(
            {"host": "host", "interface": "interface", "apple_uid": 501, "linux_uid": 1000},
            port=50000,
            credential_fd=9,
            seconds=1,
            private_events=None,
            target_finger="finger-2",
        )
        resolved = NATIVE_MATCH._probe_command(
            {"host": "host", "interface": "interface", "apple_uid": 501, "linux_uid": 1000},
            port=50000,
            credential_fd=9,
            seconds=1,
            private_events=None,
            resolve_any_finger=True,
        )
        self.assertIn("--match-finger-name", targeted)
        self.assertIn("finger-2", targeted)
        self.assertNotIn("--match-all-enrolled-identities", targeted)
        self.assertIn("--resolve-any-finger-name", resolved)
        self.assertNotIn("--match-all-enrolled-identities", resolved)

    def test_addition_match_appends_only_complete_same_boot_proof(self):
        public = {
            "match_events": [{
                "event_kind": "match_result",
                "result_structure_valid": True,
                "host_accepted_result": True,
                "result_valid": True,
                "result_ignored": False,
                "no_match": False,
                "matches_enrolled_identity": True,
                "matches_required_identity": True,
                "matched": True,
            }],
            "configured_identity_records_reconciled": True,
            "global_identity_record_count": 2,
            "template_sync_identity_count": 2,
            "match_cleanup_valid": True,
            "bridge_os_transaction_released_after_match": True,
            "private_match_events_written": True,
            "termination_requested": False,
            "post_match_save_biolockout": {
                "reply": {"valid": True, "status": 0},
                "linux_store_generation": 16,
                "linux_store_committed": True,
            },
        }
        encoded = json.dumps(public).encode()
        history = SimpleNamespace(operation_id="operation")
        completed = SimpleNamespace(phase=NATIVE_MATCH.t2_enrollment_journal.EnrollmentPhase.ADDITION_VERIFIED)
        with (
            patch.object(NATIVE_MATCH, "MUTATION_ROOT", Path("/state/mutations")),
            patch.object(NATIVE_MATCH, "_private"),
            patch.object(Path, "read_bytes", return_value=b"private-events"),
            patch.object(NATIVE_MATCH.t2_enrollment_journal, "read", return_value=history),
            patch.object(
                NATIVE_MATCH.t2_enrollment_journal,
                "append_checked",
                return_value=completed,
            ) as append,
        ):
            result = NATIVE_MATCH._append_addition_match_verification(
                Path("/state/mutations/addition.jsonl"),
                encoded,
                Path("/state/native/private-events.json"),
                "00000000-0000-0000-0000-000000000003",
            )
        self.assertIs(result, completed)
        evidence = append.call_args.args[3]
        self.assertEqual(append.call_args.args[2], "ADDITION_MATCH_VERIFIED")
        self.assertTrue(evidence["matches_required_identity"])
        self.assertTrue(evidence["match_cleanup_valid"])
        self.assertEqual(evidence["global_identity_record_count"], 2)
        self.assertEqual(evidence["template_sync_identity_count"], 2)
        self.assertEqual(evidence["biolockout_generation"], 16)

    def test_addition_verified_does_not_block_later_mutations(self):
        history = SimpleNamespace(
            baseline={"baseline_version": 1},
            phase=MUTATION_REGISTRY.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid="redacted",
        )
        with patch.object(
            MUTATION_REGISTRY.t2_enrollment_journal,
            "validate_history",
            return_value=history,
        ):
            pending = MUTATION_REGISTRY._enrollment_entry([])
        self.assertTrue(pending.blocks_new_mutation)
        self.assertFalse(pending.post_reboot_pending)

        history = SimpleNamespace(
            baseline={"baseline_version": 1},
            phase=MUTATION_REGISTRY.t2_enrollment_journal.EnrollmentPhase.ADDITION_VERIFIED,
            terminal_identity_uuid="redacted",
        )
        with patch.object(
            MUTATION_REGISTRY.t2_enrollment_journal,
            "validate_history",
            return_value=history,
        ):
            entry = MUTATION_REGISTRY._enrollment_entry([])
        self.assertFalse(entry.blocks_new_mutation)
        self.assertFalse(entry.post_reboot_pending)

    def test_final_ceremony_match_retains_private_journal_evidence(self):
        root = Path("/private/ceremony")
        with patch.object(
            CEREMONY, "_run_child", return_value=(0, {"matched": True})
        ) as run:
            self.assertTrue(
                CEREMONY._run_match(
                    root,
                    Mock(),
                    "new",
                    Path("/var/lib/t2-touchid/mutations/addition.jsonl"),
                )
            )
        command = run.call_args.kwargs["command"]
        self.assertEqual(
            command[command.index("--private-match-events-output") + 1],
            "/private/ceremony/new-match-private-events.json",
        )
        self.assertIn("--addition-journal", command)

    def test_inherited_credential_set_requires_exact_external_form(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, bytes(range(16)))
        finally:
            os.close(write_fd)
        with patch.object(BRIDGE_PROBE.os, "geteuid", return_value=0):
            value = BRIDGE_PROBE.read_credential_set_fd(read_fd)
        self.assertEqual(value, bytearray(range(16)))

        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"short")
        finally:
            os.close(write_fd)
        with patch.object(BRIDGE_PROBE.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "exactly 16"):
                BRIDGE_PROBE.read_credential_set_fd(read_fd)

    def test_native_biolockout_never_rolls_later_head_back_to_e4(self):
        class Generation:
            def __init__(self, sequence, payload):
                self.sequence = sequence
                self.payload = payload

        class Store:
            def __init__(self):
                self.current_generation = Generation(1, b"HRLB-old")
                self.committed = []

            def current(self):
                return self.current_generation

            def commit(self, payload):
                self.committed.append(payload)
                self.current_generation = Generation(2, payload)
                return self.current_generation

        store = Store()
        generation, state = BRIDGE_PROBE.reconcile_native_biolockout(
            store, b"HRLB-e4"
        )
        self.assertEqual(state, "rolling-head-retained")
        self.assertEqual(generation.sequence, 1)
        self.assertEqual(store.committed, [])

        store.current_generation = Generation(2, b"HRLB-e4")
        generation, state = BRIDGE_PROBE.reconcile_native_biolockout(
            store, b"HRLB-e4"
        )
        self.assertEqual(state, "already-e4")
        self.assertEqual(generation.sequence, 2)
        self.assertEqual(store.committed, [])

    def test_rejected_host_head_recovers_newer_sep_generation_once(self):
        class Generation:
            def __init__(self, sequence, payload):
                self.sequence = sequence
                self.payload = payload
                self.length = len(payload)
                self.sha256 = "0" * 64

        class Store:
            def __init__(self):
                self.committed = []

            def commit(self, payload):
                self.committed.append(payload)
                return Generation(3, payload)

        current = Generation(2, b"HRLB-host")
        store = Store()
        with (
            patch.object(
                BRIDGE_PROBE,
                "biometric_command",
                side_effect=[([22], []), ([0, None], [])],
            ),
            patch.object(
                BRIDGE_PROBE,
                "export_biolockout_record",
                return_value=(b"HRLB-sep", {"reply": {"status": 0}}),
            ),
        ):
            generation, summary, recovery = BRIDGE_PROBE.load_linux_biolockout(
                object(), store, current, allow_sep_ahead_recovery=True
            )
        self.assertEqual(generation.sequence, 3)
        self.assertEqual(summary["reply"]["status"], 0)
        self.assertEqual(store.committed, [b"HRLB-sep"])
        self.assertEqual(recovery["previous_generation"], 2)
        self.assertEqual(recovery["recovered_generation"], 3)

    def test_native_version_one_match_has_exact_body_without_lotl_tail(self):
        identity = struct.pack("<I16s", 501, bytes(range(16)))
        body = bytearray(0xC84)
        body[:20] = identity
        struct.pack_into("<I", body, 0x14, 0x60)
        result_record = struct.pack("<I4xQ", 0, len(body)) + body
        event_data = (
            struct.pack("<QIIQ", 0, 0xE3FF8002, 1, 1)
            + result_record
        )
        summary = BRIDGE_PROBE.summarize_event(
            [9, BRIDGE_PROBE.BRIDGE_SERVICE_STATUS, event_data, 1, 1],
            (identity,),
            expected_user_id=501,
        )
        self.assertTrue(summary["result_structure_valid"])
        self.assertTrue(summary["result_valid"])
        self.assertTrue(summary["matched"])

        short_summary = BRIDGE_PROBE.summarize_event(
            [9, BRIDGE_PROBE.BRIDGE_SERVICE_STATUS, event_data[:-4], 1, 1],
            (identity,),
            expected_user_id=501,
        )
        self.assertFalse(short_summary["result_structure_valid"])
        self.assertFalse(short_summary["result_valid"])


if __name__ == "__main__":
    unittest.main()
