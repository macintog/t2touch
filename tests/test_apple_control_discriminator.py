#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest
import uuid
from unittest import mock

SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_apple_control_discriminator as discriminator
import t2_apple_control_import
import t2_mutation_journal
import t2_user_mapping
from tests.test_apple_control_import import (
    write_catacomb_archive,
    write_keybag_archive,
)


def identifier(value: int) -> str:
    return str(uuid.UUID(int=value))


class FakeTransport:
    def __init__(self, observed_uuid: str) -> None:
        self.runtime_generation = identifier(20)
        self.observed_uuid = observed_uuid
        self.calls: list[str] = []
        self.fail_uuid = False
        self.fail_unload = False

    def load_keybag(self, path: str) -> int:
        self.calls.append("load")
        return 9

    def bag_uuid(self, handle: int) -> str:
        self.calls.append("double-uuid")
        if self.fail_uuid:
            raise RuntimeError("synthetic UUID timeout")
        return self.observed_uuid

    def unload_keybag(self, handle: int) -> int:
        self.calls.append("unload")
        if self.fail_unload:
            raise RuntimeError("synthetic unload timeout")
        return 0


class AppleControlDiscriminatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.journal = self.root / "journal" / "discriminator.jsonl"
        self.evidence = discriminator.OracleEvidence(
            identifier(1), "a" * 64, 1000, 501, identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb", "b" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_once(self, transport: FakeTransport):
        return discriminator.run(
            journal_path=self.journal,
            evidence=self.evidence,
            linux_boot_uuid=identifier(10),
            transport=transport,
            operation_id=identifier(30),
        )

    def test_match_uses_only_load_double_uuid_and_unload(self) -> None:
        transport = FakeTransport(self.evidence.bag_uuid)
        result = self.run_once(transport)
        self.assertEqual(transport.calls, ["load", "double-uuid", "unload"])
        self.assertEqual(result.outcome, "matched")
        self.assertTrue(result.uuid_matched)
        self.assertTrue(result.handle_released)
        self.assertFalse(result.reconciliation_required)
        records = t2_mutation_journal.read(self.journal)
        self.assertEqual(
            [record["milestone"] for record in records],
            [
                "APPLE_CONTROL_DISCRIMINATOR_BASELINE",
                "APPLE_CONTROL_KEYBAG_LOAD_INTENT",
                "APPLE_CONTROL_KEYBAG_HANDLE_OBSERVED",
                "APPLE_CONTROL_KEYBAG_UUID_OBSERVED",
                "APPLE_CONTROL_KEYBAG_UNLOAD_INTENT",
                "APPLE_CONTROL_KEYBAG_HANDLE_RELEASED",
                "APPLE_CONTROL_DISCRIMINATOR_COMPLETE",
            ],
        )
        self.assertFalse(records[-1]["evidence"]["mapping_promoted"])

    def test_mismatch_is_released_and_not_promoted(self) -> None:
        transport = FakeTransport(identifier(3))
        result = self.run_once(transport)
        self.assertEqual(result.outcome, "mismatched")
        self.assertFalse(result.uuid_matched)
        self.assertEqual(transport.calls, ["load", "double-uuid", "unload"])

    def test_uuid_failure_unloads_once_and_journal_blocks_retry(self) -> None:
        transport = FakeTransport(self.evidence.bag_uuid)
        transport.fail_uuid = True
        with self.assertRaisesRegex(
            discriminator.AppleControlDiscriminatorError, "do not retry"
        ):
            self.run_once(transport)
        self.assertEqual(transport.calls, ["load", "double-uuid", "unload"])
        records = t2_mutation_journal.read(self.journal)
        self.assertEqual(
            records[-1]["milestone"],
            "APPLE_CONTROL_DISCRIMINATOR_OUTCOME_UNKNOWN",
        )
        second = FakeTransport(self.evidence.bag_uuid)
        with self.assertRaises(discriminator.AppleControlDiscriminatorError):
            self.run_once(second)
        self.assertEqual(second.calls, [])

    def test_ambiguous_unload_is_never_retried(self) -> None:
        transport = FakeTransport(self.evidence.bag_uuid)
        transport.fail_unload = True
        with self.assertRaises(discriminator.AppleControlDiscriminatorError):
            self.run_once(transport)
        self.assertEqual(
            transport.calls, ["load", "double-uuid", "unload"]
        )
        records = t2_mutation_journal.read(self.journal)
        self.assertEqual(
            records[-1]["milestone"],
            "APPLE_CONTROL_DISCRIMINATOR_OUTCOME_UNKNOWN",
        )

    def test_import_readback_reconciles_every_protected_artifact(self) -> None:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        keybags = self.root / "keybags.tar.gz"
        catacomb = self.root / "catacomb.tar.gz"
        write_keybag_archive(keybags)
        write_catacomb_archive(catacomb)
        keybag_root = PurePosixPath(str(state / "users"))
        with mock.patch.object(t2_user_mapping, "KEYBAG_ROOT", keybag_root):
            plan, _ = t2_apple_control_import.import_control_archives(
                keybag_archive=keybags,
                catacomb_archive=catacomb,
                linux_uid=1000,
                linux_account_generation="c" * 64,
                apple_uid=501,
                state_root=state,
            )
            evidence = discriminator.read_oracle_import(state, 1000)
        self.assertEqual(evidence.bag_uuid, plan.bag_uuid)
        self.assertEqual(evidence.keybag_sha256, plan.keybag_sha256)

        provenance_path = state / "users/1000/apple-control-import.json"
        provenance = json.loads(provenance_path.read_text())
        provenance["sep_keybag_uuid_verified"] = True
        provenance_path.write_text(json.dumps(provenance))
        provenance_path.chmod(0o600)
        with (
            mock.patch.object(t2_user_mapping, "KEYBAG_ROOT", keybag_root),
            self.assertRaisesRegex(
                discriminator.AppleControlDiscriminatorError, "provenance"
            ),
        ):
            discriminator.read_oracle_import(state, 1000)


if __name__ == "__main__":
    unittest.main()
