# SPDX-License-Identifier: GPL-2.0-only
"""Resume behavior for an outer purge and its journaled child deletion."""

import importlib.util
import hashlib
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location(
    "delete_batch_manager", ROOT / "src/t2-touchid-manage.py"
)
MANAGER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MANAGER)

import t2_identity_delete_batch_journal as batch
import t2_identity_delete_journal as single
import t2_mutation_journal as mutation
from tests.test_delete_batch_journal import two_identity_baseline


class DeleteBatchCommandTests(unittest.TestCase):
    def _pending_batch(self, root: Path):
        operation_id = "00000000-0000-0000-0000-000000000091"
        path = root / f"{operation_id}.jsonl"
        mutation.create(path, "delete-batch", two_identity_baseline(), operation_id)
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
        batch.append_checked(
            path,
            history,
            "DELETE_BATCH_ITEM_INTENT",
            {"finger_name": "finger-1", "ordinal": 0},
        )
        return path

    def test_resume_closes_exact_absent_pending_item_then_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = self._pending_batch(root)
            projection = mock.Mock(
                side_effect=[
                    SimpleNamespace(finger_names=("finger-3",)),
                    SimpleNamespace(finger_names=()),
                ]
            )
            remove = mock.Mock(
                return_value={
                    "delete_succeeded": True,
                    "finger_name": "finger-3",
                    "identity_count": 0,
                }
            )
            with (
                mock.patch.object(MANAGER, "MUTATION_ROOT", root),
                mock.patch.object(MANAGER, "require_mapping_capability"),
                mock.patch.object(
                    MANAGER, "_delete_batch_projection", projection
                ),
                mock.patch.object(MANAGER, "run_delete", remove),
            ):
                result = MANAGER.run_delete_batch(
                    {"authority_mode": "linux-native"}, resume=True
                )
            self.assertTrue(result["purge_succeeded"])
            self.assertEqual(result["deleted_count"], 2)
            remove.assert_called_once_with(
                {"authority_mode": "linux-native"},
                finger_name="finger-3",
                batch_operation_id=path.stem,
            )
            self.assertEqual(
                batch.read(path).phase, batch.IdentityDeleteBatchPhase.RECONCILED
            )

    def test_resume_rejects_any_unrecorded_inventory_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            self._pending_batch(root)
            remove = mock.Mock()
            with (
                mock.patch.object(MANAGER, "MUTATION_ROOT", root),
                mock.patch.object(MANAGER, "require_mapping_capability"),
                mock.patch.object(
                    MANAGER,
                    "_delete_batch_projection",
                    return_value=SimpleNamespace(finger_names=("finger-3", "finger-5")),
                ),
                mock.patch.object(MANAGER, "run_delete", remove),
                self.assertRaisesRegex(
                    MANAGER.IdentityManagementError, "does not match"
                ),
            ):
                MANAGER.run_delete_batch(
                    {"authority_mode": "linux-native"}, resume=True
                )
            remove.assert_not_called()

    def test_child_recovery_must_match_the_outer_pending_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            outer_path = self._pending_batch(root)
            outer = batch.read(outer_path)
            child_id = "00000000-0000-0000-0000-000000000092"
            child_path = root / f"{child_id}.jsonl"
            value = two_identity_baseline()
            mutation.create(child_path, "delete-one", value, child_id)
            single.append_checked(
                child_path,
                child_id,
                "DELETE_INTENT",
                {
                    "connection_generation": value["connection_generation"],
                    "user_id": value["apple_uid"],
                    "identity_uuid": value["identity_records"][0]["uuid"],
                    "entity": value["identity_records"][0]["entity"],
                    "target_name_sha256": hashlib.sha256(
                        b"finger-1"
                    ).hexdigest(),
                    "request_sha256": "2" * 64,
                    "request_length": 20,
                    "survivor_snapshot_sha256": "3" * 64,
                    "survivor_count": 1,
                    "mapping_generation": value["mapping_generation"],
                },
            )
            recover = mock.Mock(
                return_value={"delete_recovery_succeeded": True}
            )
            with (
                mock.patch.object(MANAGER, "MUTATION_ROOT", root),
                mock.patch.object(MANAGER, "_private_root_owned"),
                mock.patch.object(MANAGER, "run_delete_recovery", recover),
            ):
                MANAGER._recover_delete_batch_child({}, outer)
            recover.assert_called_once_with({})

            records = mutation.read(child_path)
            records[-1]["evidence"]["target_name_sha256"] = hashlib.sha256(
                b"finger-3"
            ).hexdigest()
            with (
                mock.patch.object(MANAGER, "MUTATION_ROOT", root),
                mock.patch.object(MANAGER, "_private_root_owned"),
                mock.patch.object(
                    MANAGER,
                    "delete_journals",
                    return_value=[(child_path, single.validate_history(records))],
                ),
                self.assertRaisesRegex(
                    MANAGER.IdentityManagementError, "does not belong"
                ),
            ):
                MANAGER._recover_delete_batch_child({}, outer)


if __name__ == "__main__":
    unittest.main()
