# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path, PurePosixPath
from unittest import mock


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_activation_bundle as bundle
import t2_aks_replacement_journal as replacement_journal
import t2_aks_replacement_operation as operation
import t2_user_mapping
import t2_user_mapping_store
from t2_aks_replacement_transport import PrimaryObservation


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class FakeTransport:
    def __init__(self, observations: list[tuple[bool, str | None]]) -> None:
        self.connection_generation = identifier(11)
        self.observations = observations
        self.arms: list[tuple[int, bytes | None]] = []
        self.deleted = 0
        self.created = 0
        self.exported = 0
        self.opened = 0
        self.unloaded = 0
        self.invalidated = False
        self.delete_error: BaseException | None = None
        self.create_error: BaseException | None = None
        self.unload_error: BaseException | None = None

    def observe_primary(self, _session: int) -> PrimaryObservation:
        present, account_uuid = self.observations.pop(0)
        digest = hashlib.sha256(
            f"{present}:{account_uuid}:{len(self.observations)}".encode("ascii")
        ).hexdigest()
        return PrimaryObservation(present, account_uuid, digest)

    def arm(self, **values: object) -> None:
        material = values["activation_material"]
        self.arms.append(
            (
                int(values["phase"]),
                None if material is None else bytes(material),
            )
        )

    def delete_identity(self, _session: int, _old_account_uuid: str) -> None:
        self.deleted += 1
        if self.delete_error is not None:
            raise self.delete_error

    def create(self, _request: bytearray) -> tuple[int, bytearray]:
        self.created += 1
        if self.create_error is not None:
            raise self.create_error
        return 0, bytearray(struct.pack("<IiI", 5, 42, 0))

    def export(self, _request: bytearray) -> tuple[int, bytearray]:
        self.exported += 1
        saved = b"replacement-keybag"
        padding = bytes((-len(saved)) & 3)
        return 0, bytearray(struct.pack("<II", 1, len(saved)) + saved + padding)

    def copy_live_uuid(self, _session: int, _live_handle: int) -> str:
        return identifier(5)

    def open_identity(self, _session: int, _new_account_uuid: str) -> int:
        self.opened += 1
        return 43

    def unload_created_identity(self, _session: int, _live_handle: int) -> None:
        self.unloaded += 1
        if self.unload_error is not None:
            raise self.unload_error

    def unload_recovered_identity(self, _session: int, _live_handle: int) -> None:
        self.unloaded += 1

    def invalidate(self) -> None:
        self.invalidated = True

    def require_no_live_handles(self) -> None:
        return None


class AKSReplacementOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.users = self.root / "users"
        self.users.mkdir(mode=0o700)
        self.user_root = self.users / "1000"
        self.user_root.mkdir(mode=0o700)
        self.identities = self.user_root / "identities"
        self.identities.mkdir(mode=0o700)
        self.operation_id = identifier(1)
        self.old_account = identifier(2)
        self.new_account = identifier(3)
        self.journal = self.root / "journal" / "replacement.jsonl"
        self.store = bundle.ActivationBundleStore(
            root=self.identities,
            operation_id=self.operation_id,
            account_uuid=self.new_account,
            linux_uid=1000,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self, transport: FakeTransport, material: bytearray) -> None:
        operation.prepare_replacement(
            journal_path=self.journal,
            operation_id=self.operation_id,
            old_account_uuid=self.old_account,
            new_account_uuid=self.new_account,
            old_bag_uuid=identifier(4),
            old_mapping_generation="a" * 64,
            linux_boot_uuid=identifier(10),
            session=7,
            transport=transport,
        )
        operation.stage_delete_and_reconcile(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(10),
            activation_material=material,
            transport=transport,
            bundle_store=self.store,
        )

    def test_direct_transaction_publishes_disabled_bundle_and_unloads(self) -> None:
        transport = FakeTransport(
            [
                (True, self.old_account),
                (True, self.old_account),
                (False, None),
                (False, None),
                (False, None),
                (False, None),
            ]
        )
        material = bytearray(range(1, 17))
        self.prepare(transport, material)
        transport.unload_error = OSError("synthetic lost unload reply")
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=self.root / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="b" * 64,
            apple_uid=501,
            keybag_path=self.store.final_keybag_path,
            bundle_generation=self.operation_id,
            activation_secret_path=self.store.final_secret_path,
            activation_secret_sha256=hashlib.sha256(bytes(range(1, 17))).hexdigest(),
        )
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            with self.assertRaisesRegex(
                operation.AKSReplacementOperationError, "unload is ambiguous"
            ):
                operation.create_export_commit(
                    journal_path=self.journal,
                    operation_id=self.operation_id,
                    linux_boot_uuid=identifier(10),
                    transport=transport,
                    bundle_store=self.store,
                    mapping_writer=writer,
                )
            recovery = FakeTransport(
                [(True, self.new_account), (True, self.new_account)]
            )
            recovery.connection_generation = identifier(12)
            history = operation.resume_local_commit(
                journal_path=self.journal,
                operation_id=self.operation_id,
                linux_boot_uuid=identifier(13),
                transport=recovery,
                bundle_store=self.store,
                mapping_writer=writer,
            )
            selected = t2_user_mapping.parse(writer.path.read_bytes()).mappings[0]
        self.assertEqual(history.phase, "complete")
        self.assertEqual(material, bytearray(16))
        self.assertEqual([phase for phase, _ in transport.arms], [1, 2])
        self.assertEqual((transport.deleted, transport.created, transport.exported), (1, 1, 1))
        self.assertEqual(transport.unloaded, 1)
        self.assertTrue(transport.invalidated)
        self.assertTrue(self.store.final_manifest_path.exists())
        self.assertFalse(selected.enabled)

    def test_delete_failure_freezes_unknown_and_wipes_material(self) -> None:
        transport = FakeTransport(
            [(True, self.old_account), (True, self.old_account)]
        )
        transport.delete_error = OSError("synthetic lost reply")
        material = bytearray(range(1, 17))
        with self.assertRaisesRegex(operation.AKSReplacementOperationError, "do not retry"):
            self.prepare(transport, material)
        self.assertEqual(material, bytearray(16))
        self.assertTrue(transport.invalidated)
        self.assertEqual(replacement_journal.read(self.journal).phase, "delete-outcome-unknown")

    def test_unknown_delete_reconciles_only_without_redispatch(self) -> None:
        first = FakeTransport([(True, self.old_account), (True, self.old_account)])
        first.delete_error = OSError("synthetic lost reply")
        with self.assertRaises(operation.AKSReplacementOperationError):
            self.prepare(first, bytearray(range(1, 17)))
        second = FakeTransport([(False, None), (False, None)])
        second.connection_generation = identifier(13)
        history = operation.reconcile_delete(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(12),
            transport=second,
        )
        self.assertEqual(history.phase, "delete-reconciled")
        self.assertEqual(first.deleted, 1)
        self.assertEqual(second.deleted, 0)

        second.observations.extend([(False, None), (False, None)])
        second.create_error = OSError("synthetic lost create reply")
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=self.root / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="b" * 64,
            apple_uid=501,
            keybag_path=self.store.final_keybag_path,
            bundle_generation=self.operation_id,
            activation_secret_path=self.store.final_secret_path,
            activation_secret_sha256=hashlib.sha256(bytes(range(1, 17))).hexdigest(),
        )
        with self.assertRaisesRegex(operation.AKSReplacementOperationError, "do not retry"):
            operation.create_export_commit(
                journal_path=self.journal,
                operation_id=self.operation_id,
                linux_boot_uuid=identifier(12),
                transport=second,
                bundle_store=self.store,
                mapping_writer=writer,
            )
        recovery = FakeTransport(
            [(True, self.new_account), (True, self.new_account)]
        )
        recovery.connection_generation = identifier(14)
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            history = operation.recover_create_or_export(
                journal_path=self.journal,
                operation_id=self.operation_id,
                linux_boot_uuid=identifier(15),
                transport=recovery,
                bundle_store=self.store,
                mapping_writer=writer,
            )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(second.created, 1)
        self.assertEqual(recovery.created, 0)
        self.assertEqual(recovery.opened, 1)

    def test_process_loss_after_mutation_intents_recovers_without_redispatch(self) -> None:
        initial = FakeTransport([(True, self.old_account), (True, self.old_account)])
        operation.prepare_replacement(
            journal_path=self.journal,
            operation_id=self.operation_id,
            old_account_uuid=self.old_account,
            new_account_uuid=self.new_account,
            old_bag_uuid=identifier(4),
            old_mapping_generation="a" * 64,
            linux_boot_uuid=identifier(10),
            session=7,
            transport=initial,
        )
        material_digest = self.store.stage(bytearray(range(1, 17)))
        replacement_journal.append_checked(
            self.journal,
            self.operation_id,
            "ACTIVATION_MATERIAL_STAGED",
            {
                "activation_material_digest": material_digest,
                "activation_material_length": 16,
                "bundle_generation": self.operation_id,
                "pending_directory_synced": True,
            },
        )
        replacement_journal.append_checked(
            self.journal,
            self.operation_id,
            "DELETE_INTENT",
            {
                "session": 7,
                "old_account_uuid": self.old_account,
                "request_digest": "d" * 64,
                "single_dispatch": True,
            },
        )
        after_delete = FakeTransport([(False, None), (False, None)])
        after_delete.connection_generation = identifier(12)
        history = operation.reconcile_delete(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(13),
            transport=after_delete,
        )
        self.assertEqual(history.phase, "delete-reconciled")
        self.assertEqual(after_delete.deleted, 0)
        after_crash = FakeTransport([(False, None), (False, None)])
        after_crash.connection_generation = identifier(14)
        history = operation.reconfirm_delete(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(15),
            transport=after_crash,
        )
        self.assertEqual(history.phase, "delete-reconciled")
        replacement_journal.append_checked(
            self.journal,
            self.operation_id,
            "CREATE_INTENT",
            {
                "linux_boot_uuid": identifier(15),
                "connection_generation": identifier(14),
                "session": 7,
                "new_account_uuid": self.new_account,
                "activation_material_digest": material_digest,
                "request_digest": "e" * 64,
                "primary_absent": True,
                "inventory_stable": True,
                "single_dispatch": True,
            },
        )
        recovery = FakeTransport([(True, self.new_account), (True, self.new_account)])
        recovery.connection_generation = identifier(16)
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=self.root / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="b" * 64,
            apple_uid=501,
            keybag_path=self.store.final_keybag_path,
            bundle_generation=self.operation_id,
            activation_secret_path=self.store.final_secret_path,
            activation_secret_sha256=material_digest,
        )
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            history = operation.recover_create_or_export(
                journal_path=self.journal,
                operation_id=self.operation_id,
                linux_boot_uuid=identifier(17),
                transport=recovery,
                bundle_store=self.store,
                mapping_writer=writer,
            )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(recovery.created, 0)
        self.assertEqual(recovery.opened, 1)

    def test_predelete_crash_abandons_only_after_fresh_old_primary_proof(self) -> None:
        initial = FakeTransport([(True, self.old_account), (True, self.old_account)])
        operation.prepare_replacement(
            journal_path=self.journal,
            operation_id=self.operation_id,
            old_account_uuid=self.old_account,
            new_account_uuid=self.new_account,
            old_bag_uuid=identifier(4),
            old_mapping_generation="a" * 64,
            linux_boot_uuid=identifier(10),
            session=7,
            transport=initial,
        )
        recovery = FakeTransport([(True, self.old_account), (True, self.old_account)])
        recovery.connection_generation = identifier(12)
        history = operation.abandon_before_delete(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(13),
            transport=recovery,
        )
        self.assertEqual(history.phase, "abandoned-before-delete")
        with self.assertRaises(replacement_journal.AKSReplacementJournalError):
            replacement_journal.append_checked(
                self.journal,
                self.operation_id,
                "DELETE_INTENT",
                {
                    "session": 7,
                    "old_account_uuid": self.old_account,
                    "request_digest": "d" * 64,
                    "single_dispatch": True,
                },
            )

    def test_stable_absence_reprovisions_without_delete(self) -> None:
        transport = FakeTransport(
            [
                (False, None),
                (False, None),
                (False, None),
                (False, None),
                (False, None),
                (False, None),
            ]
        )
        history = operation.prepare_replacement(
            journal_path=self.journal,
            operation_id=self.operation_id,
            old_account_uuid=self.old_account,
            new_account_uuid=self.new_account,
            old_bag_uuid=identifier(4),
            old_mapping_generation="a" * 64,
            linux_boot_uuid=identifier(10),
            session=7,
            transport=transport,
        )
        self.assertEqual(history.replacement_kind, "reprovision-absent")
        material = bytearray(range(1, 17))
        history = operation.stage_absent_and_reconcile(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(10),
            activation_material=material,
            transport=transport,
            bundle_store=self.store,
        )
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=self.root / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="b" * 64,
            apple_uid=501,
            keybag_path=self.store.final_keybag_path,
            bundle_generation=self.operation_id,
            activation_secret_path=self.store.final_secret_path,
            activation_secret_sha256=history.activation_material_digest,
        )
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            transport.unload_error = OSError("synthetic lost unload reply")
            with self.assertRaisesRegex(
                operation.AKSReplacementOperationError, "unload is ambiguous"
            ):
                operation.create_export_commit(
                    journal_path=self.journal,
                    operation_id=self.operation_id,
                    linux_boot_uuid=identifier(10),
                    transport=transport,
                    bundle_store=self.store,
                    mapping_writer=writer,
                )
            recovery = FakeTransport([(False, None), (False, None)])
            recovery.connection_generation = identifier(12)
            history = operation.resume_local_commit(
                journal_path=self.journal,
                operation_id=self.operation_id,
                linux_boot_uuid=identifier(13),
                transport=recovery,
                bundle_store=self.store,
                mapping_writer=writer,
            )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(history.handle_release_primary_state, "absent")
        self.assertEqual(material, bytearray(16))
        self.assertEqual(transport.deleted, 0)
        self.assertEqual([phase for phase, _material in transport.arms], [2])
        self.assertEqual((recovery.deleted, recovery.created, recovery.exported), (0, 0, 0))

    def test_staged_absence_resumes_fresh_without_delete(self) -> None:
        initial = FakeTransport([(False, None), (False, None)])
        history = operation.prepare_replacement(
            journal_path=self.journal,
            operation_id=self.operation_id,
            old_account_uuid=self.old_account,
            new_account_uuid=self.new_account,
            old_bag_uuid=identifier(4),
            old_mapping_generation="a" * 64,
            linux_boot_uuid=identifier(10),
            session=7,
            transport=initial,
        )
        material_digest = self.store.stage(bytearray(range(1, 17)))
        replacement_journal.append_checked(
            self.journal,
            self.operation_id,
            "ACTIVATION_MATERIAL_STAGED",
            {
                "activation_material_digest": material_digest,
                "activation_material_length": 16,
                "bundle_generation": self.operation_id,
                "pending_directory_synced": True,
            },
        )
        recovery = FakeTransport([(False, None), (False, None)])
        recovery.connection_generation = identifier(12)
        history = operation.reconcile_absence(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(13),
            transport=recovery,
        )
        after_reconcile_crash = FakeTransport(
            [(False, None), (False, None), (False, None), (False, None)]
        )
        after_reconcile_crash.connection_generation = identifier(14)
        history = operation.reconfirm_absence(
            journal_path=self.journal,
            operation_id=self.operation_id,
            linux_boot_uuid=identifier(15),
            transport=after_reconcile_crash,
        )
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=self.root / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="b" * 64,
            apple_uid=501,
            keybag_path=self.store.final_keybag_path,
            bundle_generation=self.operation_id,
            activation_secret_path=self.store.final_secret_path,
            activation_secret_sha256=material_digest,
        )
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            history = operation.create_export_commit(
                journal_path=self.journal,
                operation_id=self.operation_id,
                linux_boot_uuid=identifier(15),
                transport=after_reconcile_crash,
                bundle_store=self.store,
                mapping_writer=writer,
            )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(initial.deleted, 0)
        self.assertEqual(recovery.deleted, 0)
        self.assertEqual(recovery.created, 0)
        self.assertEqual(after_reconcile_crash.deleted, 0)
        self.assertEqual(after_reconcile_crash.created, 1)


if __name__ == "__main__":
    unittest.main()
