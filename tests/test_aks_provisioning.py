# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import struct
import tempfile
import unittest
import uuid
import sys
from pathlib import Path, PurePosixPath
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_aks_provisioning as provisioning
import t2_aks_provisioning_operation as operation
import t2_user_mapping
import t2_user_mapping_store


class FakeTransport:
    create_version = 5
    def __init__(self, generation, bag_uuid):
        self.connection_generation = generation
        self.bag_uuid = bag_uuid
        self.buffers = []
        self.invalidated = False

    def create(self, request):
        self.buffers.append(request)
        expected = operation.codec.minimal_create_request(
            version=self.create_version, session=7, material=bytes(request[24:40]),
            account_uuid=bytes(request[48:64]),
        )
        if request != expected:
            raise AssertionError("unexpected creation request")
        response = bytearray(struct.pack("<IiI", self.create_version, 42, 0))
        self.buffers.append(response)
        return 0, response

    def export(self, request):
        self.buffers.append(request)
        response = bytearray(struct.pack("<II", 1, 12) + b"saved-keybag")
        self.buffers.append(response)
        return 0, response

    def copy_live_uuid(self, session, live_handle):
        if (session, live_handle) != (7, 42):
            raise AssertionError("operation binding changed")
        return self.bag_uuid

    def invalidate(self):
        self.invalidated = True


class AKSProvisioningTests(unittest.TestCase):
    def test_torn_reply_keeps_create_intent_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provision.jsonl"
            operation_id = str(uuid.UUID(int=1))
            before = provisioning.create(
                path, operation_id=operation_id,
                account_uuid=str(uuid.UUID(int=2)),
                linux_boot_uuid=str(uuid.UUID(int=3)),
                connection_generation=str(uuid.UUID(int=4)),
                preflight_sha256="a" * 64, session=7, request_sha256="b" * 64,
                xart_ready=True, primary_identity_absent=True, inventory_stable=True,
            )
            with path.open("ab") as stream:
                stream.write(b'{"milestone":"AKS_CREATE_SUCC')
            recovered = provisioning.read(path)
            self.assertEqual(recovered.phase, before.phase)
            self.assertEqual(recovered.record_count, before.record_count + 1)
            self.assertEqual(provisioning.read(path), recovered)

    def test_v4_operation_reaches_mapping_with_wiped_buffers(self):
        with patch.object(FakeTransport, "create_version", 4):
            self.test_operation_owns_create_export_buffers_and_fresh_owner_gate()

    def test_create_export_store_mapping_and_reboot_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            journal_path = root / "journal" / "provision.jsonl"
            users_root = root / "users"
            users_root.mkdir(mode=0o700)
            keybag_root = users_root / "1000"
            keybag_root.mkdir(mode=0o700)
            operation_id = str(uuid.UUID(int=1))
            account_uuid = str(uuid.UUID(int=2))
            bag_uuid = str(uuid.UUID(int=3))
            first_boot = str(uuid.UUID(int=4))
            second_boot = str(uuid.UUID(int=5))
            request_digest = "a" * 64
            export_digest = "b" * 64

            history = provisioning.create(
                journal_path,
                operation_id=operation_id,
                account_uuid=account_uuid,
                linux_boot_uuid=first_boot,
                connection_generation=str(uuid.UUID(int=6)),
                preflight_sha256="9" * 64,
                session=7,
                request_sha256=request_digest,
                xart_ready=True,
                primary_identity_absent=True,
                inventory_stable=True,
            )
            with self.assertRaisesRegex(
                provisioning.AKSProvisioningError, "out of order"
            ):
                provisioning.append_checked(
                    journal_path,
                    operation_id,
                    "AKS_KEYBAG_COMMITTED",
                    {
                        "saved_keybag_sha256": "d" * 64,
                        "saved_keybag_length": 1,
                    },
                )
            self.assertEqual(provisioning.read(journal_path).phase, "create-intent")
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_CREATE_SUCCEEDED",
                {"session": 7, "live_handle": 42, "kek_length": 0},
            )
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_EXPORT_INTENT",
                {
                    "session": 7,
                    "live_handle": 42,
                    "request_sha256": export_digest,
                },
            )
            saved = bytearray(b"saved-keybag")
            saved_digest = hashlib.sha256(saved).hexdigest()
            saved_length = len(saved)
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_EXPORT_SUCCEEDED",
                {
                    "saved_keybag_sha256": saved_digest,
                    "saved_keybag_length": saved_length,
                },
            )
            rejected_root = root / "rejected-keybag"
            rejected_root.mkdir(mode=0o700)
            rejected = bytearray(b"wrong-digest")
            with self.assertRaisesRegex(
                provisioning.AKSProvisioningError, "differs"
            ):
                provisioning.SavedKeybagStore(rejected_root).commit(
                    rejected, operation_id, "f" * 64
                )
            self.assertEqual(rejected, bytearray(len(rejected)))
            self.assertFalse((rejected_root / "user.kb").exists())
            committed_digest, committed_length = provisioning.SavedKeybagStore(
                keybag_root
            ).commit(saved, operation_id, saved_digest)
            self.assertEqual(
                (committed_digest, committed_length),
                (saved_digest, saved_length),
            )
            self.assertEqual(saved, bytearray(len(saved)))
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_KEYBAG_COMMITTED",
                {
                    "saved_keybag_sha256": saved_digest,
                    "saved_keybag_length": saved_length,
                },
            )
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_LIVE_UUID_VERIFIED",
                {"bag_uuid": bag_uuid, "uuid_verified": True},
            )
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_MAPPING_COMMITTED",
                {"mapping_generation": "c" * 64, "bag_uuid": bag_uuid},
            )
            history = provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_REBOOT_VERIFIED",
                {
                    "linux_boot_uuid": second_boot,
                    "bag_uuid": bag_uuid,
                    "saved_keybag_sha256": saved_digest,
                    "keybag_loaded": True,
                    "uuid_verified": True,
                },
            )

            self.assertEqual(history.phase, "reboot-verified")
            self.assertEqual(history.bag_uuid, bag_uuid)
            self.assertEqual((keybag_root / "user.kb").read_bytes(), b"saved-keybag")
            self.assertEqual((keybag_root / "user.kb").stat().st_mode & 0o777, 0o600)

    def test_operation_owns_create_export_buffers_and_fresh_owner_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            users_root = root / "users"
            users_root.mkdir(mode=0o700)
            keybag_root = users_root / "1000"
            keybag_root.mkdir(mode=0o700)
            journal_path = root / "journal" / "provision.jsonl"
            operation_id = str(uuid.UUID(int=11))
            account_uuid = str(uuid.UUID(int=12))
            bag_uuid = str(uuid.UUID(int=13))
            generation = str(uuid.UUID(int=14))
            transport = FakeTransport(generation, bag_uuid)
            external_form = bytearray(b"a" * 16)
            mapping_path = root / "users.json"
            mapping_writer = t2_user_mapping_store.InitialUserMappingStore(
                path=mapping_path,
                operation_id=operation_id,
                linux_uid=1000,
                linux_account_generation="8" * 64,
                apple_uid=501,
                keybag_path=keybag_root / "user.kb",
            )

            with patch.object(
                t2_user_mapping,
                "KEYBAG_ROOT",
                PurePosixPath(str(users_root)),
            ):
                history = operation.run_to_mapping(
                    journal_path=journal_path,
                    operation_id=operation_id,
                    linux_boot_uuid=str(uuid.UUID(int=15)),
                    account_uuid=account_uuid,
                    session=7,
                    acm_external_form=external_form,
                    preflight=operation.PreflightAttestation(
                        connection_generation=generation,
                        evidence_sha256="9" * 64,
                        xart_ready=True,
                        primary_identity_absent=True,
                        inventory_stable=True,
                    ),
                    transport=transport,
                    keybag_store=provisioning.SavedKeybagStore(keybag_root),
                    mapping_writer=mapping_writer,
                )
            self.assertEqual(history.phase, "mapping-committed")
            self.assertEqual(external_form, bytearray(16))
            self.assertTrue(all(not any(buffer) for buffer in transport.buffers))
            with patch.object(
                t2_user_mapping,
                "KEYBAG_ROOT",
                PurePosixPath(str(users_root)),
            ):
                mapping = t2_user_mapping.parse(mapping_path.read_bytes()).mappings[0]
            self.assertFalse(mapping.enabled)
            self.assertEqual(mapping.bag_uuid, bag_uuid)
            with patch.object(
                t2_user_mapping,
                "KEYBAG_ROOT",
                PurePosixPath(str(users_root)),
            ):
                repeated_generation = mapping_writer.commit(
                    account_uuid=account_uuid,
                    bag_uuid=bag_uuid,
                    keybag_sha256=history.saved_keybag_sha256,
                )
            self.assertEqual(repeated_generation, history.mapping_generation)

            with patch.object(
                t2_user_mapping,
                "KEYBAG_ROOT",
                PurePosixPath(str(users_root)),
            ):
                history = operation.verify_after_owner_change(
                    journal_path=journal_path,
                    operation_id=operation_id,
                    linux_boot_uuid=str(uuid.UUID(int=15)),
                    load_and_copy_uuid=lambda: (bag_uuid, generation),
                    mapping_writer=mapping_writer,
                )
            self.assertEqual(history.phase, "mapping-enabled")
            self.assertEqual(history.reboot_linux_boot_uuid, str(uuid.UUID(int=15)))
            with patch.object(
                t2_user_mapping,
                "KEYBAG_ROOT",
                PurePosixPath(str(users_root)),
            ):
                enabled_mapping_set = t2_user_mapping.parse(mapping_path.read_bytes())
                enabled_mapping = enabled_mapping_set.mappings[0]
            self.assertTrue(enabled_mapping.enabled)
            self.assertEqual(
                enabled_mapping_set.generation,
                history.enabled_mapping_generation,
            )


if __name__ == "__main__":
    unittest.main()
