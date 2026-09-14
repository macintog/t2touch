# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_aks_replacement_journal as replacement


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class AKSReplacementJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "journal" / "replacement.jsonl"
        self.operation_id = identifier(1)
        self.initial_boot = identifier(10)
        self.initial_connection = identifier(11)
        replacement.create(
            self.path,
            operation_id=self.operation_id,
            old_account_uuid=identifier(2),
            new_account_uuid=identifier(3),
            old_bag_uuid=identifier(4),
            old_mapping_generation="a" * 64,
            linux_boot_uuid=self.initial_boot,
            connection_generation=self.initial_connection,
            session=7,
            preflight_digest="b" * 64,
            old_primary_matches=True,
            inventory_stable=True,
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "ACTIVATION_MATERIAL_STAGED",
            {
                "activation_material_digest": "c" * 64,
                "activation_material_length": 16,
                "bundle_generation": self.operation_id,
                "pending_directory_synced": True,
            },
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_INTENT",
            {
                "session": 7,
                "old_account_uuid": identifier(2),
                "request_digest": "d" * 64,
                "single_dispatch": True,
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reconcile_delete(self) -> None:
        replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_SUCCEEDED",
            {"session": 7, "old_account_uuid": identifier(2)},
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECONCILED",
            {
                "linux_boot_uuid": self.initial_boot,
                "connection_generation": self.initial_connection,
                "session": 7,
                "old_account_uuid": identifier(2),
                "first_inventory_digest": "e" * 64,
                "second_inventory_digest": "f" * 64,
                "primary_absent": True,
                "inventory_stable": True,
                "direct_reply_observed": True,
            },
        )

    def create_intent(self) -> None:
        replacement.append_checked(
            self.path,
            self.operation_id,
            "CREATE_INTENT",
            {
                "linux_boot_uuid": self.initial_boot,
                "connection_generation": self.initial_connection,
                "session": 7,
                "new_account_uuid": identifier(3),
                "activation_material_digest": "c" * 64,
                "request_digest": "1" * 64,
                "primary_absent": True,
                "inventory_stable": True,
                "single_dispatch": True,
            },
        )

    def create_live_identity(self) -> None:
        self.reconcile_delete()
        self.create_intent()
        replacement.append_checked(
            self.path,
            self.operation_id,
            "CREATE_SUCCEEDED",
            {"session": 7, "live_handle": 42, "kek_length": 0},
        )

    def finish_export(self, handle: int = 42) -> None:
        replacement.append_checked(
            self.path,
            self.operation_id,
            "EXPORT_INTENT",
            {"session": 7, "live_handle": handle, "request_digest": "5" * 64},
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "EXPORT_SUCCEEDED",
            {"saved_keybag_digest": "6" * 64, "saved_keybag_length": 128},
        )

    def test_direct_reply_requires_same_connection_and_two_stable_absences(self) -> None:
        replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_SUCCEEDED",
            {"session": 7, "old_account_uuid": identifier(2)},
        )
        history = replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECONCILED",
            {
                "linux_boot_uuid": self.initial_boot,
                "connection_generation": self.initial_connection,
                "session": 7,
                "old_account_uuid": identifier(2),
                "first_inventory_digest": "e" * 64,
                "second_inventory_digest": "f" * 64,
                "primary_absent": True,
                "inventory_stable": True,
                "direct_reply_observed": True,
            },
        )
        self.assertEqual(history.phase, "delete-reconciled")
        self.assertTrue(history.direct_delete_reply_observed)
        self.assertEqual(history.activation_material_digest, "c" * 64)

    def test_lost_reply_reconciles_only_on_fresh_boot_and_connection(self) -> None:
        replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_OUTCOME_UNKNOWN",
            {"mutation_possible": True, "descriptor_closed": True},
        )
        evidence = {
            "linux_boot_uuid": identifier(12),
            "connection_generation": identifier(13),
            "session": 7,
            "old_account_uuid": identifier(2),
            "first_inventory_digest": "e" * 64,
            "second_inventory_digest": "f" * 64,
            "primary_absent": True,
            "inventory_stable": True,
            "direct_reply_observed": False,
        }
        stale = dict(evidence, linux_boot_uuid=self.initial_boot)
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "fresh boot"
        ):
            replacement.append_checked(
                self.path, self.operation_id, "DELETE_RECONCILED", stale
            )
        history = replacement.append_checked(
            self.path, self.operation_id, "DELETE_RECONCILED", evidence
        )
        self.assertEqual(history.phase, "delete-reconciled")
        self.assertFalse(history.direct_delete_reply_observed)

    def test_unknown_present_closes_not_applied_and_forbids_delete_retry(self) -> None:
        replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_OUTCOME_UNKNOWN",
            {"mutation_possible": True, "descriptor_closed": True},
        )
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "out of order"
        ):
            replacement.append_checked(
                self.path,
                self.operation_id,
                "DELETE_INTENT",
                {
                    "session": 7,
                    "old_account_uuid": identifier(2),
                    "request_digest": "d" * 64,
                    "single_dispatch": True,
                },
            )
        history = replacement.append_checked(
            self.path,
            self.operation_id,
            "DELETE_NOT_APPLIED",
            {
                "linux_boot_uuid": identifier(12),
                "connection_generation": identifier(13),
                "old_account_uuid": identifier(2),
                "first_inventory_digest": "e" * 64,
                "second_inventory_digest": "f" * 64,
                "primary_present": True,
                "inventory_stable": True,
            },
        )
        self.assertEqual(history.phase, "delete-not-applied")
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "out of order"
        ):
            replacement.append_checked(
                self.path,
                self.operation_id,
                "DELETE_INTENT",
                {
                    "session": 7,
                    "old_account_uuid": identifier(2),
                    "request_digest": "d" * 64,
                    "single_dispatch": True,
                },
            )

    def test_direct_create_succeeds_once_after_exact_delete_reconciliation(self) -> None:
        self.reconcile_delete()
        self.create_intent()
        history = replacement.append_checked(
            self.path,
            self.operation_id,
            "CREATE_SUCCEEDED",
            {"session": 7, "live_handle": 42, "kek_length": 0},
        )
        self.assertEqual(history.phase, "identity-live")
        self.assertEqual(history.live_handle, 42)
        self.assertTrue(history.direct_create_reply_observed)
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "out of order"
        ):
            self.create_intent()

    def test_lost_create_reply_recovers_only_exact_new_identity_fresh(self) -> None:
        self.reconcile_delete()
        self.create_intent()
        replacement.append_checked(
            self.path,
            self.operation_id,
            "CREATE_OUTCOME_UNKNOWN",
            {"mutation_possible": True, "descriptor_closed": True},
        )
        evidence = {
            "linux_boot_uuid": identifier(12),
            "connection_generation": identifier(13),
            "session": 7,
            "new_account_uuid": identifier(3),
            "first_inventory_digest": "2" * 64,
            "second_inventory_digest": "3" * 64,
            "primary_matches": True,
            "inventory_stable": True,
            "open_request_digest": "4" * 64,
            "live_handle": 43,
            "bag_uuid": identifier(5),
            "live_uuid_verified": True,
        }
        stale = dict(evidence, linux_boot_uuid=self.initial_boot)
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "fresh"
        ):
            replacement.append_checked(
                self.path, self.operation_id, "IDENTITY_RECOVERED", stale
            )
        history = replacement.append_checked(
            self.path, self.operation_id, "IDENTITY_RECOVERED", evidence
        )
        self.assertEqual(history.phase, "identity-live")
        self.assertEqual(history.live_bag_uuid, identifier(5))
        self.assertFalse(history.direct_create_reply_observed)

    def test_lost_create_reply_can_close_absent_but_never_retry_create(self) -> None:
        self.reconcile_delete()
        self.create_intent()
        replacement.append_checked(
            self.path,
            self.operation_id,
            "CREATE_OUTCOME_UNKNOWN",
            {"mutation_possible": True, "descriptor_closed": True},
        )
        history = replacement.append_checked(
            self.path,
            self.operation_id,
            "CREATE_NOT_APPLIED",
            {
                "linux_boot_uuid": identifier(12),
                "connection_generation": identifier(13),
                "new_account_uuid": identifier(3),
                "first_inventory_digest": "2" * 64,
                "second_inventory_digest": "3" * 64,
                "primary_absent": True,
                "inventory_stable": True,
            },
        )
        self.assertEqual(history.phase, "create-not-applied")
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "out of order"
        ):
            self.create_intent()

    def test_export_bundle_disabled_mapping_and_unload_complete_exact_chain(self) -> None:
        self.create_live_identity()
        self.finish_export()
        replacement.append_checked(
            self.path,
            self.operation_id,
            "LIVE_UUID_VERIFIED",
            {
                "session": 7,
                "live_handle": 42,
                "bag_uuid": identifier(5),
                "uuid_verified": True,
            },
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "BUNDLE_COMMITTED",
            {
                "bundle_generation": self.operation_id,
                "activation_material_digest": "c" * 64,
                "saved_keybag_digest": "6" * 64,
                "saved_keybag_length": 128,
                "manifest_digest": "7" * 64,
                "artifacts_verified": True,
                "publication_reconciled": False,
            },
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "MAPPING_COMMITTED",
            {
                "mapping_generation": "8" * 64,
                "bundle_generation": self.operation_id,
                "bag_uuid": identifier(5),
                "enabled": False,
            },
        )
        history = replacement.append_checked(
            self.path,
            self.operation_id,
            "HANDLE_UNLOADED",
            {"session": 7, "live_handle": 42, "unload_succeeded": True},
        )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(history.mapping_generation, "8" * 64)
        self.assertEqual(history.saved_keybag_digest, "6" * 64)

    def test_lost_export_can_reopen_exact_identity_and_repeat_only_export(self) -> None:
        self.create_live_identity()
        replacement.append_checked(
            self.path,
            self.operation_id,
            "EXPORT_INTENT",
            {"session": 7, "live_handle": 42, "request_digest": "5" * 64},
        )
        replacement.append_checked(
            self.path,
            self.operation_id,
            "EXPORT_OUTCOME_UNKNOWN",
            {"descriptor_closed": True},
        )
        history = replacement.append_checked(
            self.path,
            self.operation_id,
            "IDENTITY_REOPENED",
            {
                "linux_boot_uuid": identifier(12),
                "connection_generation": identifier(13),
                "session": 7,
                "new_account_uuid": identifier(3),
                "first_inventory_digest": "2" * 64,
                "second_inventory_digest": "3" * 64,
                "primary_matches": True,
                "inventory_stable": True,
                "open_request_digest": "4" * 64,
                "live_handle": 43,
                "bag_uuid": identifier(5),
                "live_uuid_verified": True,
            },
        )
        self.assertEqual(history.phase, "identity-live")
        self.assertEqual(history.live_handle, 43)
        self.finish_export(43)
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "out of order"
        ):
            self.create_intent()

    def test_bundle_mapping_and_release_must_match_exported_live_identity(self) -> None:
        self.create_live_identity()
        self.finish_export()
        replacement.append_checked(
            self.path,
            self.operation_id,
            "LIVE_UUID_VERIFIED",
            {
                "session": 7,
                "live_handle": 42,
                "bag_uuid": identifier(5),
                "uuid_verified": True,
            },
        )
        bad_bundle = {
            "bundle_generation": self.operation_id,
            "activation_material_digest": "c" * 64,
            "saved_keybag_digest": "9" * 64,
            "saved_keybag_length": 128,
            "manifest_digest": "7" * 64,
            "artifacts_verified": True,
            "publication_reconciled": False,
        }
        with self.assertRaisesRegex(
            replacement.AKSReplacementJournalError, "differs"
        ):
            replacement.append_checked(
                self.path, self.operation_id, "BUNDLE_COMMITTED", bad_bundle
            )


if __name__ == "__main__":
    unittest.main()
