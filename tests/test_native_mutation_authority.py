# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_external_delete_reconcile as external_delete
import t2_external_inventory_sync
import t2_native_mutation_authority as authority
import t2_native_state_recovery
from tests.test_external_delete_reconcile import baseline_evidence


class CompletedMutationAuthorityTests(unittest.TestCase):
    def _mapping_bound_head(self, kind: str, *, mapping_generation: str = "1" * 64):
        operation_id = "00000000-0000-0000-0000-000000000095"
        records = [
            {
                "operation_id": operation_id,
                "evidence": {
                    "operation_kind": kind,
                    "apple_uid": 501,
                    "mapping_generation": mapping_generation,
                },
                "record_hash": "2" * 64,
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / f"{operation_id}.jsonl").touch()
            with (
                mock.patch.object(
                    authority.t2_mutation_registry,
                    "scan",
                    return_value=(
                        authority.t2_mutation_registry.MutationEntry(
                            kind, "complete", False, False
                        ),
                    ),
                ),
                mock.patch.object(
                    authority.t2_mutation_journal,
                    "read",
                    return_value=records,
                ),
            ):
                return authority._completed_heads(
                    root,
                    excluded_operation_id=None,
                    apple_user_id=501,
                    account_uuid="account-is-bound-by-mapping-generation",
                    bag_uuid="bag-is-bound-by-mapping-generation",
                    mapping_generation="1" * 64,
                )

    def test_external_delete_uses_its_validated_top_level_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            operation_id = "00000000-0000-0000-0000-000000000093"
            path = root / f"{operation_id}.jsonl"
            external_delete.create_journal(
                path, operation_id, baseline_evidence()
            )

            heads = authority._completed_heads(
                root,
                excluded_operation_id=None,
                apple_user_id=501,
                account_uuid="account-is-bound-by-mapping-generation",
                bag_uuid="bag-is-bound-by-mapping-generation",
                mapping_generation="1" * 64,
            )

            self.assertEqual(len(heads), 1)
            self.assertEqual(heads[0]["kind"], "reconcile-external-delete")

    def test_external_delete_still_rejects_another_mapping_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            operation_id = "00000000-0000-0000-0000-000000000094"
            path = root / f"{operation_id}.jsonl"
            external_delete.create_journal(
                path, operation_id, baseline_evidence()
            )

            with self.assertRaisesRegex(
                authority.NativeMutationAuthorityError,
                "another native authority",
            ):
                authority._completed_heads(
                    root,
                    excluded_operation_id=None,
                    apple_user_id=501,
                    account_uuid="irrelevant",
                    bag_uuid="irrelevant",
                    mapping_generation="9" * 64,
                )

    def test_external_inventory_uses_its_validated_top_level_binding(self):
        heads = self._mapping_bound_head(t2_external_inventory_sync.KIND)

        self.assertEqual(len(heads), 1)
        self.assertEqual(heads[0]["kind"], t2_external_inventory_sync.KIND)

    def test_native_state_recovery_uses_its_validated_top_level_binding(self):
        heads = self._mapping_bound_head(t2_native_state_recovery.KIND)

        self.assertEqual(len(heads), 1)
        self.assertEqual(heads[0]["kind"], t2_native_state_recovery.KIND)

    def test_mapping_bound_history_rejects_another_mapping_generation(self):
        for kind in (
            t2_external_inventory_sync.KIND,
            t2_native_state_recovery.KIND,
        ):
            with self.subTest(kind=kind), self.assertRaisesRegex(
                authority.NativeMutationAuthorityError,
                "another native authority",
            ):
                self._mapping_bound_head(kind, mapping_generation="9" * 64)


if __name__ == "__main__":
    unittest.main()
