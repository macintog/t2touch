# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
import uuid
from pathlib import Path
import sys


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_activation_journal_retention as retention
import t2_user_activation_journal as activation
import t2_user_activation_recovery as recovery
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


class Observer:
    def __init__(self, value, generation=identifier(30)):
        self.value = value
        self.runtime_generation = generation

    def observe_alias(self, special_alias):
        return self.value


class ActivationJournalRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.mapping_set, self.selected = mapped()
        self.boot = identifier(10)
        self.runtime = identifier(11)
        self.now = time.time()

    def tearDown(self):
        self.temp.cleanup()

    def _path(self, number: int) -> Path:
        path = self.root / f"{uuid.UUID(int=number)}.jsonl"
        return path

    def _create(self, path: Path, alias: readiness.AliasEvidence) -> activation.UserActivationHistory:
        return activation.create(
            path,
            self.mapping_set,
            self.selected,
            "verify",
            persistent(),
            alias,
            linux_boot_uuid=self.boot,
            runtime_generation=self.runtime,
        )

    def _append(self, path: Path, milestone: str, evidence: dict[str, object]):
        history = activation.read(path)
        return activation.append_checked(
            path, history.operation_id, milestone, evidence
        )

    def _age(self, path: Path, seconds: int) -> None:
        stamp = self.now - seconds
        os.utime(path, (stamp, stamp))

    def _load_bind_observe(self, path: Path) -> None:
        self._append(
            path,
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
            "USER_KEYBAG_HANDLE_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "bag_uuid_matches": True,
            },
        )
        self._append(
            path,
            "USER_ALIAS_BIND_INTENT",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
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

    def _stopped_journal(self, path: Path) -> Path:
        self._create(path, readiness.AliasEvidence(False, None, None, None, None))
        self._append(
            path,
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
            "USER_ACTIVATION_STOPPED",
            {
                "runtime_generation": self.runtime,
                "stage": "load",
                "reason": "operator-stop",
                "mutation_possible": True,
            },
        )
        os.chmod(path, 0o600)
        return path

    def _ready_journal(self, path: Path) -> Path:
        self._create(
            path,
            readiness.AliasEvidence(True, -501, identifier(2), 1, identifier(1)),
        )
        self._append(
            path,
            "USER_ALIAS_UNLOCK_INTENT",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
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
        os.chmod(path, 0o600)
        return path

    def _unknown_journal(self, path: Path) -> Path:
        self._create(path, readiness.AliasEvidence(False, None, None, None, None))
        self._append(
            path,
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
            "USER_ACTIVATION_OUTCOME_UNKNOWN",
            {
                "runtime_generation": self.runtime,
                "stage": "load",
                "reason": "transport-error",
                "mutation_possible": True,
            },
        )
        os.chmod(path, 0o600)
        return path

    def _handle_released_journal(self, path: Path) -> Path:
        self._create(path, readiness.AliasEvidence(False, None, None, None, None))
        self._load_bind_observe(path)
        self._append(
            path,
            "USER_KEYBAG_UNLOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
            "USER_KEYBAG_HANDLE_RELEASED",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "command_status": 0,
                "command_raised": False,
            },
        )
        os.chmod(path, 0o600)
        return path

    def _recover(self, path: Path, observed: readiness.AliasEvidence):
        return recovery.recover(
            path,
            self.mapping_set,
            self.selected,
            persistent(),
            Observer(observed),
        )

    def _prune(self, **kwargs) -> int:
        options = {
            "now": self.now,
            "max_files": 1,
            "max_age_seconds": 7 * 24 * 60 * 60,
            "min_age_seconds": 60 * 60,
        }
        options.update(kwargs)
        return retention.prune(self.root, **options)

    def test_prune_bounds_growth_by_count_and_age(self):
        template = self._stopped_journal(self._path(1))
        for index in range(2, 81):
            dest = self._path(index)
            shutil.copy2(template, dest)
            os.chmod(dest, 0o600)
        for path in self.root.glob("*.jsonl"):
            self._age(path, 2 * 24 * 60 * 60)
        removed = self._prune(max_files=64)
        remaining = sorted(self.root.glob("*.jsonl"))
        self.assertEqual(removed, 16)
        self.assertEqual(len(remaining), 64)

        stale = remaining[0]
        self._age(stale, 8 * 24 * 60 * 60)
        aged = self._prune(max_files=64)
        self.assertGreaterEqual(aged, 1)
        self.assertLessEqual(len(list(self.root.glob("*.jsonl"))), 64)
        self.assertFalse(stale.exists())

    def test_prune_keeps_recent_in_progress_journals(self):
        for index in range(1, 71):
            path = self._path(index)
            self._create(path, readiness.AliasEvidence(False, None, None, None, None))
            self._append(
                path,
                "USER_KEYBAG_LOAD_INTENT",
                {
                    "runtime_generation": self.runtime,
                    "keybag_sha256": "b" * 64,
                    "mutation_possible": True,
                },
            )
            os.chmod(path, 0o600)
            os.utime(path, (self.now - 10, self.now - 10))
        removed = self._prune(max_files=64)
        self.assertEqual(removed, 0)
        self.assertEqual(len(list(self.root.glob("*.jsonl"))), 70)

    def test_prune_preserves_old_incomplete_journals(self):
        incomplete = self._path(1)
        self._create(incomplete, readiness.AliasEvidence(False, None, None, None, None))
        self._append(
            incomplete,
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        os.chmod(incomplete, 0o600)
        self._age(incomplete, 8 * 24 * 60 * 60)
        self.assertEqual(self._prune(), 0)
        self.assertTrue(incomplete.exists())

    def test_unknown_outcome_is_not_deletable(self):
        path = self._unknown_journal(self._path(1))
        self._age(path, 8 * 24 * 60 * 60)
        self.assertFalse(retention._is_proved_terminal(path))
        self.assertEqual(self._prune(), 0)
        self.assertTrue(path.exists())

    def test_handle_released_is_not_deletable(self):
        path = self._handle_released_journal(self._path(1))
        self._age(path, 8 * 24 * 60 * 60)
        self.assertFalse(retention._is_proved_terminal(path))
        self.assertEqual(self._prune(), 0)
        self.assertTrue(path.exists())

    def test_blocked_and_quarantined_recovery_are_not_deletable(self):
        blocked = self._unknown_journal(self._path(1))
        self._recover(blocked, readiness.AliasEvidence(False, None, None, None, None))
        os.chmod(blocked, 0o600)
        self._age(blocked, 8 * 24 * 60 * 60)
        self.assertEqual(activation.read(blocked).phase, activation.UserActivationPhase.RECOVERY_BLOCKED)
        self.assertFalse(retention._is_proved_terminal(blocked))

        quarantined = self._unknown_journal(self._path(2))
        self._recover(
            quarantined,
            readiness.AliasEvidence(True, -501, identifier(2), 0, identifier(1)),
        )
        os.chmod(quarantined, 0o600)
        self._age(quarantined, 8 * 24 * 60 * 60)
        self.assertEqual(
            activation.read(quarantined).phase, activation.UserActivationPhase.QUARANTINED
        )
        self.assertFalse(retention._is_proved_terminal(quarantined))
        self.assertEqual(self._prune(), 0)
        self.assertTrue(blocked.exists())
        self.assertTrue(quarantined.exists())

    def test_recovered_ready_is_deletable_when_aged(self):
        path = self._path(1)
        self._create(path, readiness.AliasEvidence(False, None, None, None, None))
        self._append(
            path,
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
            "USER_KEYBAG_HANDLE_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "bag_uuid_matches": True,
            },
        )
        self._append(
            path,
            "USER_ALIAS_BIND_INTENT",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self._append(
            path,
            "USER_ACTIVATION_OUTCOME_UNKNOWN",
            {
                "runtime_generation": self.runtime,
                "stage": "bind",
                "reason": "readback-lost",
                "mutation_possible": True,
            },
        )
        self._recover(
            path,
            readiness.AliasEvidence(True, -501, identifier(2), 0, identifier(1)),
        )
        os.chmod(path, 0o600)
        self._age(path, 8 * 24 * 60 * 60)
        self.assertEqual(
            activation.read(path).phase, activation.UserActivationPhase.RECOVERED_READY
        )
        self.assertTrue(retention._is_proved_terminal(path))
        self.assertEqual(self._prune(), 1)
        self.assertFalse(path.exists())

    def test_malformed_and_milestone_only_journals_are_not_deletable(self):
        malformed = self._path(1)
        malformed.write_text('{"milestone": "USER_ACTIVATION_STOPPED"}\n', encoding="ascii")
        os.chmod(malformed, 0o600)
        self._age(malformed, 8 * 24 * 60 * 60)
        unknown_name = self._path(2)
        unknown_name.write_text(
            '{"milestone": "USER_ACTIVATION_OUTCOME_UNKNOWN"}\n'
            '{"milestone": "USER_ACTIVATION_RECOVERY_OBSERVED"}\n',
            encoding="ascii",
        )
        os.chmod(unknown_name, 0o600)
        self._age(unknown_name, 8 * 24 * 60 * 60)
        self.assertFalse(retention._is_proved_terminal(malformed))
        self.assertFalse(retention._is_proved_terminal(unknown_name))
        self.assertEqual(self._prune(), 0)
        self.assertTrue(malformed.exists())
        self.assertTrue(unknown_name.exists())

    def test_ready_and_stopped_journals_are_deletable_when_aged(self):
        ready = self._ready_journal(self._path(1))
        stopped = self._stopped_journal(self._path(2))
        self._age(ready, 8 * 24 * 60 * 60)
        self._age(stopped, 8 * 24 * 60 * 60)
        self.assertTrue(retention._is_proved_terminal(ready))
        self.assertTrue(retention._is_proved_terminal(stopped))
        self.assertEqual(self._prune(), 2)
        self.assertFalse(ready.exists())
        self.assertFalse(stopped.exists())


if __name__ == "__main__":
    unittest.main()
