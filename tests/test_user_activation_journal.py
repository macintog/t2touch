# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_activation_journal as activation
import t2_user_mapping as mapping
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def mapped() -> tuple[mapping.UserMappingSet, mapping.UserMapping]:
    document = {
        "schema_version": 1,
        "mappings": [
            {
                "linux_uid": 1000,
                "linux_account_generation": "a" * 64,
                "apple_uid": 501,
                "account_uuid": identifier(1),
                "bag_uuid": identifier(2),
                "keybag_path": "/var/lib/t2-touchid/users/1000/user.kb",
                "keybag_sha256": "b" * 64,
                "unlock_mode": "password-on-demand",
                "capabilities": ["enroll", "verify"],
                "enabled": True,
            }
        ],
    }
    result = mapping.parse(json.dumps(document, sort_keys=True).encode())
    return result, result.mappings[0]


def persistent() -> readiness.PersistentEvidence:
    return readiness.PersistentEvidence(
        "a" * 64,
        "b" * 64,
        501,
        identifier(1),
        identifier(2),
        True,
    )


class UserActivationJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "activation.jsonl"
        self.mapping_set, self.selected = mapped()
        self.boot = identifier(10)
        self.runtime = identifier(11)

    def tearDown(self):
        self.temp.cleanup()

    def create(self, alias: readiness.AliasEvidence) -> activation.UserActivationHistory:
        return activation.create(
            self.path,
            self.mapping_set,
            self.selected,
            "verify",
            persistent(),
            alias,
            linux_boot_uuid=self.boot,
            runtime_generation=self.runtime,
        )

    def append(self, milestone: str, evidence: dict[str, object]):
        history = activation.read(self.path)
        return activation.append_checked(
            self.path, history.operation_id, milestone, evidence
        )

    def test_absent_alias_reaches_ready_only_through_all_observations(self):
        history = self.create(
            readiness.AliasEvidence(False, None, None, None, None)
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.BASELINE)
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_KEYBAG_HANDLE_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "bag_uuid_matches": True,
            },
        )
        self.append(
            "USER_ALIAS_BIND_INTENT",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_ALIAS_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "account_uuid_matches": True,
                "command_status": 0,
                "command_raised": False,
            },
        )
        self.append(
            "USER_ALIAS_CONFIGURATION_INTENT",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_ALIAS_CONFIGURATION_RESOLVED",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "command_status": 0,
                "command_raised": False,
            },
        )
        self.append(
            "USER_ALIAS_UNLOCK_INTENT",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        history = self.append(
            "USER_ACTIVATION_READY",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "account_uuid_matches": True,
                "readiness_state": "ready",
                "source": "unlock-readback",
                "command_status": 0,
                "command_raised": False,
            },
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.READY)
        self.assertEqual(history.temporary_handle, 7)

    def _absent_through_alias_observed(self) -> None:
        self.create(readiness.AliasEvidence(False, None, None, None, None))
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_KEYBAG_HANDLE_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "bag_uuid_matches": True,
            },
        )
        self.append(
            "USER_ALIAS_BIND_INTENT",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_ALIAS_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "account_uuid_matches": True,
                "command_status": 0,
                "command_raised": False,
            },
        )

    def test_every_mutation_intent_is_a_commit_milestone(self):
        source = Path(activation.__file__).read_text(encoding="utf-8")
        named = set(re.findall(r'"(USER_[A-Z0-9_]+_INTENT)"', source))
        self.assertEqual(named, activation.MUTATION_INTENTS)
        self.assertTrue(activation.MUTATION_INTENTS <= activation.COMMIT_MILESTONES)

    def test_baseline_and_load_intent_are_durable_before_hardware(self):
        with (
            mock.patch.object(activation.journal, "_durable_file_sync") as file_sync,
            mock.patch.object(activation.journal, "_sync_directory") as dir_sync,
        ):
            self.create(readiness.AliasEvidence(False, None, None, None, None))
            self.assertGreaterEqual(file_sync.call_count, 1)
            self.assertGreaterEqual(dir_sync.call_count, 1)
            before_intent = file_sync.call_count
            history = self.append(
                "USER_KEYBAG_LOAD_INTENT",
                {
                    "runtime_generation": self.runtime,
                    "keybag_sha256": "b" * 64,
                    "mutation_possible": True,
                },
            )
            self.assertGreater(file_sync.call_count, before_intent)
            self.assertEqual(history.phase, activation.UserActivationPhase.LOAD_INTENT)
            recovered = activation.read(self.path)
            self.assertEqual(recovered.phase, activation.UserActivationPhase.LOAD_INTENT)

    def test_remaining_mutation_intents_are_durable_before_hardware(self):
        self._absent_through_alias_observed()
        cases = (
            (
                "USER_ALIAS_CONFIGURATION_INTENT",
                {
                    "runtime_generation": self.runtime,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
                activation.UserActivationPhase.CONFIGURATION_INTENT,
            ),
            (
                "USER_KEYBAG_UNLOAD_INTENT",
                {
                    "runtime_generation": self.runtime,
                    "handle": 7,
                    "mutation_possible": True,
                },
                activation.UserActivationPhase.UNLOAD_INTENT,
            ),
        )
        for milestone, evidence, phase in cases:
            with self.subTest(milestone=milestone):
                path = self.path.with_name(f"{milestone.lower()}.jsonl")
                path.write_bytes(self.path.read_bytes())
                path.chmod(0o600)
                with (
                    mock.patch.object(
                        activation.journal, "_durable_file_sync"
                    ) as file_sync,
                    mock.patch.object(activation.journal, "_sync_directory") as dir_sync,
                ):
                    before = file_sync.call_count
                    history = activation.append_checked(
                        path,
                        activation.read(path).operation_id,
                        milestone,
                        evidence,
                    )
                    self.assertGreater(file_sync.call_count, before)
                    self.assertGreaterEqual(dir_sync.call_count, 1)
                    self.assertEqual(history.phase, phase)
                    self.assertEqual(activation.read(path).phase, phase)

        preexisting = Path(self.temp.name) / "unlock.jsonl"
        history = activation.create(
            preexisting,
            self.mapping_set,
            self.selected,
            "verify",
            persistent(),
            readiness.AliasEvidence(True, -501, identifier(2), 1, identifier(1)),
            linux_boot_uuid=self.boot,
            runtime_generation=self.runtime,
        )
        with (
            mock.patch.object(activation.journal, "_durable_file_sync") as file_sync,
            mock.patch.object(activation.journal, "_sync_directory") as dir_sync,
        ):
            before = file_sync.call_count
            history = activation.append_checked(
                preexisting,
                history.operation_id,
                "USER_ALIAS_UNLOCK_INTENT",
                {
                    "runtime_generation": self.runtime,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            )
            self.assertGreater(file_sync.call_count, before)
            self.assertGreaterEqual(dir_sync.call_count, 1)
            self.assertEqual(history.phase, activation.UserActivationPhase.UNLOCK_INTENT)
            self.assertEqual(
                activation.read(preexisting).phase,
                activation.UserActivationPhase.UNLOCK_INTENT,
            )

    def test_power_loss_after_mutation_intent_keeps_recovery_evidence(self):
        disk_synced = {"bytes": b""}

        def file_sync(descriptor: int) -> None:
            sync = getattr(activation.journal.os, "fdatasync", activation.journal.os.fsync)
            sync(descriptor)
            disk_synced["bytes"] = self.path.read_bytes()

        def directory_sync(path: Path) -> None:
            directory_fd = activation.journal.os.open(
                path.parent,
                activation.journal.os.O_RDONLY | activation.journal.os.O_DIRECTORY,
            )
            try:
                activation.journal.os.fsync(directory_fd)
            finally:
                activation.journal.os.close(directory_fd)
            disk_synced["bytes"] = path.read_bytes()

        with (
            mock.patch.object(activation.journal, "_durable_file_sync", file_sync),
            mock.patch.object(activation.journal, "_sync_directory", directory_sync),
        ):
            self.create(
                readiness.AliasEvidence(True, -501, identifier(2), 1, identifier(1))
            )
            self.append(
                "USER_ALIAS_UNLOCK_INTENT",
                {
                    "runtime_generation": self.runtime,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            )
        if disk_synced["bytes"]:
            self.path.write_bytes(disk_synced["bytes"])
        elif self.path.exists():
            self.path.unlink()
        recovered = activation.read(self.path)
        self.assertEqual(recovered.phase, activation.UserActivationPhase.UNLOCK_INTENT)
        activation.append_checked(
            self.path,
            recovered.operation_id,
            "USER_ACTIVATION_OUTCOME_UNKNOWN",
            {
                "runtime_generation": self.runtime,
                "stage": "unlock",
                "reason": "crash-before-readback",
                "mutation_possible": True,
            },
        )
        history = activation.read(self.path)
        self.assertEqual(history.phase, activation.UserActivationPhase.OUTCOME_UNKNOWN)
        self.assertEqual(
            history.terminal_from_phase, activation.UserActivationPhase.UNLOCK_INTENT
        )

    def test_preexisting_locked_alias_skips_load_and_bind(self):
        self.create(
            readiness.AliasEvidence(
                True, -501, identifier(2), 1, identifier(1)
            )
        )
        self.append(
            "USER_ALIAS_UNLOCK_INTENT",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        history = self.append(
            "USER_ACTIVATION_READY",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "account_uuid_matches": True,
                "readiness_state": "ready",
                "source": "unlock-readback",
                "command_status": None,
                "command_raised": True,
            },
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.READY)
        self.assertIsNone(history.temporary_handle)

    def test_outcome_unknown_is_terminal_and_records_no_secret(self):
        history = self.create(
            readiness.AliasEvidence(False, None, None, None, None)
        )
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        history = self.append(
            "USER_ACTIVATION_OUTCOME_UNKNOWN",
            {
                "runtime_generation": self.runtime,
                "stage": "load",
                "reason": "transport-error",
                "mutation_possible": True,
            },
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.OUTCOME_UNKNOWN)
        with self.assertRaises(activation.UserActivationJournalError):
            activation.append_checked(
                self.path,
                history.operation_id,
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": self.runtime,
                    "handle": 7,
                    "bag_uuid_matches": True,
                },
            )
        self.assertNotIn("password", self.path.read_text())

    def test_create_rejects_ready_denied_or_quarantined_mapping(self):
        aliases = (
            readiness.AliasEvidence(
                True, -501, identifier(2), 0, identifier(1)
            ),
            readiness.AliasEvidence(
                True, -502, identifier(2), 0, identifier(1)
            ),
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                with self.assertRaisesRegex(
                    activation.UserActivationJournalError, "not safely actionable"
                ):
                    activation.create(
                        self.path,
                        self.mapping_set,
                        self.selected,
                        "verify",
                        persistent(),
                        alias,
                        linux_boot_uuid=self.boot,
                        runtime_generation=self.runtime,
                    )

    def test_wrong_handle_or_generation_cannot_advance(self):
        history = self.create(
            readiness.AliasEvidence(False, None, None, None, None)
        )
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        with self.assertRaises(activation.UserActivationJournalError):
            activation.append_checked(
                self.path,
                history.operation_id,
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": identifier(99),
                    "handle": 7,
                    "bag_uuid_matches": True,
                },
            )

    def test_terminal_stage_must_match_current_phase(self):
        history = self.create(
            readiness.AliasEvidence(False, None, None, None, None)
        )
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        with self.assertRaisesRegex(
            activation.UserActivationJournalError, "stop evidence"
        ):
            activation.append_checked(
                self.path,
                history.operation_id,
                "USER_ACTIVATION_OUTCOME_UNKNOWN",
                {
                    "runtime_generation": self.runtime,
                    "stage": "unlock",
                    "reason": "impossible-stage",
                    "mutation_possible": True,
                },
            )


if __name__ == "__main__":
    unittest.main()
