# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_external_delete_reconcile as external_delete
import t2_native_mutation_authority as authority
from tests.test_external_delete_reconcile import baseline_evidence


class CompletedMutationAuthorityTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
