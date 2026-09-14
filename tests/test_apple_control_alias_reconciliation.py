#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest import mock

SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal
import t2_user_readiness
from tests.test_aks_state import state_blob


def identifier(value: int) -> str:
    return str(uuid.UUID(int=value))


class FailedPrestateTransport:
    runtime_generation = identifier(21)

    def observe_alias(self, _alias: int):
        raise RuntimeError("synthetic pre-state failure")


class AmbiguousBindTransport:
    runtime_generation = identifier(22)

    def __init__(self, bag_uuid: str) -> None:
        self.bag_uuid_value = bag_uuid
        self.observations = 0

    def observe_alias(self, _alias: int):
        self.observations += 1
        if self.observations == 1:
            return t2_user_readiness.AliasEvidence(False, None, None, None)
        raise RuntimeError("synthetic typed read-back failure")

    def load_keybag(self, _path: str) -> int:
        return 9

    def bag_uuid(self, _handle: int) -> str:
        return self.bag_uuid_value

    def bind_alias(self, _handle: int, _alias: int) -> int:
        return 0

    def unload_keybag(self, _handle: int) -> int:
        return 0


class ReconciliationTransport:
    runtime_generation = identifier(23)

    def __init__(self, uuids: list[str | None], blob: bytes) -> None:
        self.uuids = uuids
        self.blob = blob
        self.calls: list[str] = []

    def observe_alias_uuid(self, _alias: int) -> str | None:
        self.calls.append("uuid")
        return self.uuids.pop(0)

    def read_alias_state_blob(self, _alias: int) -> bytearray:
        self.calls.append("state")
        return bytearray(self.blob)


class AppleControlAliasReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.oracle = self.root / "oracle"
        self.evidence = keybag_discriminator.OracleEvidence(
            identifier(1), "a" * 64, 1000, 501, identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb", "b" * 64,
        )
        self.matched = alias_discriminator.MatchedKeybagProof(
            identifier(30), identifier(9), identifier(20)
        )
        first = self.oracle / "apple-control-alias-discriminator.jsonl"
        with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
            alias_discriminator.run(
                journal_path=first,
                evidence=self.evidence,
                matched_proof=self.matched,
                linux_boot_uuid=identifier(10),
                transport=FailedPrestateTransport(),
                operation_id=identifier(31),
            )
        plan = alias_discriminator.select_alias_journal(
            self.oracle, self.evidence, self.matched, identifier(11)
        )
        with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
            alias_discriminator.run(
                journal_path=plan.path,
                evidence=self.evidence,
                matched_proof=self.matched,
                linux_boot_uuid=identifier(11),
                transport=AmbiguousBindTransport(self.evidence.bag_uuid),
                operation_id=identifier(32),
                reconciled_prestate_operation_id=(
                    plan.reconciled_prestate_operation_id
                ),
            )
        self.proof = reconciliation.read_ambiguous_bind_proof(
            self.oracle, self.evidence, self.matched
        )
        self.journal = self.oracle / "apple-control-alias-reconciliation.jsonl"
        self.capture = self.oracle / "apple-control-alias-state.der"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_once(self, transport: ReconciliationTransport):
        return reconciliation.run(
            journal_path=self.journal,
            capture_path=self.capture,
            evidence=self.evidence,
            bind_proof=self.proof,
            linux_boot_uuid=identifier(12),
            transport=transport,
            operation_id=identifier(33),
        )

    def test_matching_alias_state_is_captured_decoded_and_reconfirmed(self) -> None:
        blob = state_blob(-501, 1)
        transport = ReconciliationTransport(
            [self.evidence.bag_uuid, self.evidence.bag_uuid], blob
        )
        result = self.run_once(transport)
        self.assertEqual(transport.calls, ["uuid", "state", "uuid"])
        self.assertEqual(result.outcome, "bound-and-reconciled")
        self.assertTrue(result.alias_present)
        self.assertTrue(result.state_decoded)
        self.assertEqual(self.capture.read_bytes(), blob)
        self.assertEqual(self.capture.stat().st_mode & 0o777, 0o600)
        records = t2_mutation_journal.read(self.journal)
        self.assertEqual(
            records[-1]["milestone"], "APPLE_CONTROL_ALIAS_RECONCILE_COMPLETE"
        )
        self.assertFalse(records[-1]["evidence"]["mutation_performed"])
        proof = reconciliation.read_reconciled_alias_proof(
            self.oracle, self.evidence, self.proof
        )
        self.assertEqual(proof.operation_id, identifier(33))
        self.assertEqual(proof.linux_boot_uuid, identifier(12))

    def test_offline_proof_accepts_capture_after_decoder_correction(self) -> None:
        blob = state_blob(-501, 1)
        transport = ReconciliationTransport(
            [self.evidence.bag_uuid, self.evidence.bag_uuid], blob
        )
        with mock.patch.object(
            reconciliation.t2_aks_state,
            "decode",
            side_effect=reconciliation.t2_aks_state.AKSStateError("old codec"),
        ):
            result = self.run_once(transport)
        self.assertEqual(result.outcome, "bound-state-captured")

        proof = reconciliation.read_reconciled_alias_proof(
            self.oracle, self.evidence, self.proof
        )

        self.assertEqual(proof.operation_id, identifier(33))

    def test_offline_proof_rejects_capture_digest_change(self) -> None:
        blob = state_blob(-501, 1)
        transport = ReconciliationTransport(
            [self.evidence.bag_uuid, self.evidence.bag_uuid], blob
        )
        self.run_once(transport)
        self.capture.write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))

        with self.assertRaisesRegex(
            reconciliation.AppleControlAliasReconciliationError,
            "proof is inconsistent",
        ):
            reconciliation.read_reconciled_alias_proof(
                self.oracle, self.evidence, self.proof
            )

    def test_absent_alias_completes_without_state_query(self) -> None:
        transport = ReconciliationTransport([None], b"unused")
        result = self.run_once(transport)
        self.assertEqual(result.outcome, "alias-absent")
        self.assertEqual(transport.calls, ["uuid"])
        self.assertFalse(self.capture.exists())

    def test_undecoded_state_is_preserved_and_uuid_reconfirmed(self) -> None:
        transport = ReconciliationTransport(
            [self.evidence.bag_uuid, self.evidence.bag_uuid], b"not-der"
        )
        result = self.run_once(transport)
        self.assertEqual(result.outcome, "bound-state-captured")
        self.assertTrue(result.state_captured)
        self.assertFalse(result.state_decoded)
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(self.capture.read_bytes(), b"not-der")

    def test_same_boot_rejected_before_transport(self) -> None:
        transport = ReconciliationTransport([None], b"unused")
        with self.assertRaisesRegex(
            reconciliation.AppleControlAliasReconciliationError, "later boot"
        ):
            reconciliation.run(
                journal_path=self.journal,
                capture_path=self.capture,
                evidence=self.evidence,
                bind_proof=self.proof,
                linux_boot_uuid=self.proof.linux_boot_uuid,
                transport=transport,
                operation_id=identifier(33),
            )
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
