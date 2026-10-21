#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
import uuid
import copy
from unittest import mock

SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal
import t2_user_readiness
import t2_compatibility_transition as transition
import t2_apple_control_alias_unlock as unlock


def identifier(value: int) -> str:
    return str(uuid.UUID(int=value))


class MatchedTransport:
    runtime_generation = identifier(20)

    def load_keybag(self, _path: str) -> int:
        return 9

    def bag_uuid(self, _handle: int) -> str:
        return identifier(2)

    def unload_keybag(self, _handle: int) -> int:
        return 0


class AliasTransport:
    def __init__(self, bag_uuid: str) -> None:
        self.runtime_generation = identifier(21)
        self.bag_uuid_value = bag_uuid
        self.bound = False
        self.calls: list[str] = []
        self.fail_bind_readback = False
        self.fail_unload = False
        self.fail_prestate = False

    def observe_alias(self, alias: int) -> t2_user_readiness.AliasEvidence:
        self.calls.append("observe")
        if self.fail_prestate and len(self.calls) == 1:
            raise RuntimeError("synthetic status-visibility failure")
        if not self.bound or self.fail_bind_readback:
            return t2_user_readiness.AliasEvidence(False, None, None, None)
        return t2_user_readiness.AliasEvidence(True, alias, self.bag_uuid_value, 1)

    def load_keybag(self, _path: str) -> int:
        self.calls.append("load")
        return 10

    def bag_uuid(self, _handle: int) -> str:
        self.calls.append("double-uuid")
        return self.bag_uuid_value

    def bind_alias(self, _handle: int, _alias: int) -> int:
        self.calls.append("bind")
        self.bound = True
        return 0

    def unload_keybag(self, _handle: int) -> int:
        self.calls.append("unload")
        if self.fail_unload:
            raise RuntimeError("synthetic ambiguous unload")
        return 0


class AppleControlAliasDiscriminatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.keybag_journal = self.root / "keybag.jsonl"
        self.alias_journal = self.root / "alias.jsonl"
        self.evidence = keybag_discriminator.OracleEvidence(
            identifier(1), "a" * 64, 1000, 501, identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb", "b" * 64,
        )
        keybag_discriminator.run(
            journal_path=self.keybag_journal,
            evidence=self.evidence,
            linux_boot_uuid=identifier(10),
            transport=MatchedTransport(),
            operation_id=identifier(30),
        )
        self.proof = alias_discriminator.read_matched_keybag_proof(
            self.keybag_journal, self.evidence
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_once(self, transport: AliasTransport):
        return alias_discriminator.run(
            journal_path=self.alias_journal,
            evidence=self.evidence,
            matched_proof=self.proof,
            linux_boot_uuid=identifier(11),
            transport=transport,
            operation_id=identifier(31),
        )

    def test_absent_alias_binds_once_and_persists_after_unload(self) -> None:
        transport = AliasTransport(self.evidence.bag_uuid)
        result = self.run_once(transport)
        self.assertEqual(
            transport.calls,
            [
                "observe", "load", "double-uuid", "bind", "observe",
                "unload", "observe",
            ],
        )
        self.assertEqual(result.outcome, "bound-and-persisted")
        self.assertTrue(result.alias_absent_before)
        self.assertTrue(result.alias_bound)
        self.assertTrue(result.alias_persisted)
        self.assertTrue(result.handle_released)
        self.assertFalse(result.reconciliation_required)
        records = t2_mutation_journal.read(self.alias_journal)
        self.assertEqual(records[-1]["milestone"], "APPLE_CONTROL_ALIAS_COMPLETE")
        self.assertFalse(records[-1]["evidence"]["mapping_promoted"])

    def test_same_boot_is_rejected_before_any_transport_call(self) -> None:
        transport = AliasTransport(self.evidence.bag_uuid)
        with self.assertRaisesRegex(
            alias_discriminator.AppleControlAliasDiscriminatorError,
            "later boot",
        ):
            alias_discriminator.run(
                journal_path=self.alias_journal,
                evidence=self.evidence,
                matched_proof=self.proof,
                linux_boot_uuid=self.proof.linux_boot_uuid,
                transport=transport,
                operation_id=identifier(31),
            )
        self.assertEqual(transport.calls, [])
        self.assertFalse(self.alias_journal.exists())

    def test_clean_bind_reader_refuses_standalone_unlock_without_active_handle(self):
        oracle = self.root / "oracle"
        oracle.mkdir(mode=0o700)
        self.alias_journal = oracle / "apple-control-alias-discriminator.jsonl"
        self.keybag_journal.rename(oracle / "apple-control-discriminator.jsonl")
        (self.root / "users.json").write_text("{}")
        self.run_once(AliasTransport(self.evidence.bag_uuid))
        proof = alias_discriminator.read_bound_alias_proof(
            self.alias_journal, self.evidence, self.proof
        )
        self.assertEqual(proof.operation_id, identifier(31))
        with mock.patch.object(transition, "_evidence", return_value=self.evidence):
            status = transition.inspect(
                linux_uid=1000, linux_user="tester", state_root=self.root
            )
            self.assertEqual(status.phase, transition.UNLOCK_RECOVERY_REQUIRED)
            self.assertIsNone(status.next_command)
            with mock.patch.object(transition.t2_aks_transport, "AKSActivationTransport") as hardware:
                for stage in (transition.bind, transition.reconcile):
                    with self.assertRaisesRegex(transition.CompatibilityTransitionError, "run unlock"):
                        stage(linux_uid=1000, state_root=self.root)
                hardware.assert_not_called()
                password = bytearray(b"test")
                with self.assertRaisesRegex(
                    transition.CompatibilityTransitionError, "active keybag handle"
                ):
                    transition.unlock(
                        linux_uid=1000, password=password, state_root=self.root
                    )
                self.assertEqual(password, bytearray(4))
                hardware.assert_not_called()

    def test_clean_bind_reader_rejects_inconsistent_evidence(self):
        self.run_once(AliasTransport(self.evidence.bag_uuid))
        original = t2_mutation_journal.read(self.alias_journal)
        mutations = [
            (0, "linux_boot_uuid", self.proof.linux_boot_uuid),
            (0, "runtime_generation", self.proof.runtime_generation),
            (0, "reconciled_prestate_operation_id", identifier(99)),
            (0, "linux_uid", 1001),
            (0, "matched_keybag_operation_id", identifier(99)),
            (1, "alias_absent", False),
            (2, "keybag_sha256", "c" * 64),
            (3, "handle", True),
            (4, "handle", 11),
            (5, "runtime_generation", identifier(99)),
            (5, "command_status", True),
            (5, "command_raised", True),
            (6, "handle", 11),
            (7, "command_status", 1),
            (8, "bag_uuid_matches", False),
            (9, "mapping_promoted", True),
        ]
        for index, key, value in mutations:
            with self.subTest(index=index, key=key):
                records = copy.deepcopy(original)
                records[index]["evidence"][key] = value
                with mock.patch.object(t2_mutation_journal, "read", return_value=records):
                    with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
                        alias_discriminator.read_bound_alias_proof(
                            self.alias_journal, self.evidence, self.proof
                        )
        for records in (original[:-1], list(reversed(original))):
            with mock.patch.object(t2_mutation_journal, "read", return_value=records):
                with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
                    alias_discriminator.read_bound_alias_proof(
                        self.alias_journal, self.evidence, self.proof
                    )

    def test_preexisting_alias_stops_without_load_or_bind(self) -> None:
        transport = AliasTransport(self.evidence.bag_uuid)
        transport.bound = True
        result = self.run_once(transport)
        self.assertEqual(transport.calls, ["observe"])
        self.assertEqual(result.outcome, "precondition-already-bound")
        self.assertFalse(result.alias_absent_before)
        self.assertFalse(result.alias_bound)

    def test_failed_bind_readback_unloads_once_and_blocks_retry(self) -> None:
        transport = AliasTransport(self.evidence.bag_uuid)
        transport.fail_bind_readback = True
        with self.assertRaisesRegex(
            alias_discriminator.AppleControlAliasDiscriminatorError,
            "do not retry",
        ):
            self.run_once(transport)
        self.assertEqual(transport.calls.count("bind"), 1)
        self.assertEqual(transport.calls.count("unload"), 1)
        self.assertEqual(
            t2_mutation_journal.read(self.alias_journal)[-1]["milestone"],
            "APPLE_CONTROL_ALIAS_OUTCOME_UNKNOWN",
        )
        second = AliasTransport(self.evidence.bag_uuid)
        with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
            self.run_once(second)
        self.assertEqual(second.calls, [])

    def test_ambiguous_unload_is_not_retried(self) -> None:
        transport = AliasTransport(self.evidence.bag_uuid)
        transport.fail_unload = True
        with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
            self.run_once(transport)
        self.assertEqual(transport.calls.count("unload"), 1)
        self.assertEqual(
            t2_mutation_journal.read(self.alias_journal)[-1]["milestone"],
            "APPLE_CONTROL_ALIAS_OUTCOME_UNKNOWN",
        )

    def test_prestate_failure_selects_one_later_boot_recovery_journal(self) -> None:
        oracle = self.root / "oracle"
        first = oracle / "apple-control-alias-discriminator.jsonl"
        transport = AliasTransport(self.evidence.bag_uuid)
        transport.fail_prestate = True
        with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
            alias_discriminator.run(
                journal_path=first,
                evidence=self.evidence,
                matched_proof=self.proof,
                linux_boot_uuid=identifier(11),
                transport=transport,
                operation_id=identifier(31),
            )
        plan = alias_discriminator.select_alias_journal(
            oracle, self.evidence, self.proof, identifier(12)
        )
        self.assertEqual(
            plan.path, oracle / "apple-control-alias-discriminator-2.jsonl"
        )
        self.assertEqual(plan.reconciled_prestate_operation_id, identifier(31))
        with self.assertRaisesRegex(
            alias_discriminator.AppleControlAliasDiscriminatorError,
            "current authority",
        ):
            alias_discriminator.select_alias_journal(
                oracle, self.evidence, self.proof, identifier(11)
            )

    def test_only_exact_matched_keybag_proof_advances(self) -> None:
        records = t2_mutation_journal.read(self.keybag_journal)
        records[-1]["evidence"]["outcome"] = "mismatched"
        alternate = self.root / "alternate.jsonl"
        for index, record in enumerate(records):
            t2_mutation_journal.append(
                alternate,
                record["operation_id"],
                record["milestone"],
                record["evidence"],
                exclusive=index == 0,
            )
        with self.assertRaises(alias_discriminator.AppleControlAliasDiscriminatorError):
            alias_discriminator.read_matched_keybag_proof(alternate, self.evidence)


if __name__ == "__main__":
    unittest.main()
