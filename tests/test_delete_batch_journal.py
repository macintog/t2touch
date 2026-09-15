# SPDX-License-Identifier: GPL-2.0-only
"""Durable ordering and completion contracts for delete-all."""

import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_identity_delete_batch_journal as batch
import t2_mutation_journal as mutation
import t2_mutation_registry as registry
from tests.test_mutation_journal import baseline


def two_identity_baseline():
    value = baseline()
    value["identity_records"].append(
        {
            "user_id": value["apple_uid"],
            "uuid": "00000000-0000-0000-0000-000000000002",
            "entity": 1,
        }
    )
    value["capacity"]["used"] = 2
    return value


class DeleteBatchJournalTests(unittest.TestCase):
    def test_ordered_items_reconcile_and_release_mutation_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            operation_id = "00000000-0000-0000-0000-000000000081"
            path = root / f"{operation_id}.jsonl"
            mutation.create(
                path, "delete-batch", two_identity_baseline(), operation_id
            )
            history = batch.read(path)
            history = batch.append_checked(
                path,
                history,
                "DELETE_BATCH_STARTED",
                {
                    "finger_names": ["finger-1", "finger-3"],
                    "identity_count": 2,
                    "identifiers_redacted": True,
                },
            )
            for ordinal, name in enumerate(history.finger_names):
                history = batch.append_checked(
                    path,
                    history,
                    "DELETE_BATCH_ITEM_INTENT",
                    {"finger_name": name, "ordinal": ordinal},
                )
                self.assertEqual(history.pending, name)
                self.assertTrue(registry.blocks_new_mutation(root))
                history = batch.append_checked(
                    path,
                    history,
                    "DELETE_BATCH_ITEM_RECONCILED",
                    {
                        "finger_name": name,
                        "ordinal": ordinal,
                        "remaining_count": 1 - ordinal,
                    },
                )
            history = batch.append_checked(
                path,
                history,
                "DELETE_BATCH_RECONCILED",
                {
                    "deleted_count": 2,
                    "identity_count": 0,
                    "identifiers_redacted": True,
                },
            )
            self.assertEqual(history.completed, ("finger-1", "finger-3"))
            self.assertFalse(registry.blocks_new_mutation(root))

    def test_skipped_or_reordered_item_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            operation_id = "00000000-0000-0000-0000-000000000082"
            path = root / f"{operation_id}.jsonl"
            mutation.create(
                path, "delete-batch", two_identity_baseline(), operation_id
            )
            history = batch.read(path)
            history = batch.append_checked(
                path,
                history,
                "DELETE_BATCH_STARTED",
                {
                    "finger_names": ["finger-2", "finger-5"],
                    "identity_count": 2,
                    "identifiers_redacted": True,
                },
            )
            mutation.append(
                path,
                operation_id,
                "DELETE_BATCH_ITEM_INTENT",
                {"finger_name": "finger-5", "ordinal": 0},
            )
            with self.assertRaisesRegex(
                batch.IdentityDeleteBatchJournalError, "misbound"
            ):
                batch.read(path)


if __name__ == "__main__":
    unittest.main()
