# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path, PurePosixPath
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_activation_bundle as bundle
import t2_user_mapping
import t2_user_mapping_store


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class ActivationBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.users = Path(self.temporary.name) / "users"
        self.users.mkdir(mode=0o700)
        self.user_root = self.users / "1000"
        self.user_root.mkdir(mode=0o700)
        self.identities = self.user_root / "identities"
        self.identities.mkdir(mode=0o700)
        self.operation_id = identifier(1)
        self.account_uuid = identifier(2)
        self.bag_uuid = identifier(3)
        self.store = bundle.ActivationBundleStore(
            root=self.identities,
            operation_id=self.operation_id,
            account_uuid=self.account_uuid,
            linux_uid=1000,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_stage_then_atomically_publish_complete_generation(self) -> None:
        secret = bytearray(range(1, 17))
        secret_digest = hashlib.sha256(secret).hexdigest()
        self.assertEqual(self.store.stage(secret), secret_digest)
        self.assertEqual(secret, bytearray(16))
        self.assertTrue(self.store.pending_secret_path.exists())
        self.assertFalse(self.store.final_directory.exists())

        recovered = None
        with self.store.staged_secret(secret_digest) as staged:
            recovered = staged
            self.assertEqual(staged, bytearray(range(1, 17)))
        self.assertEqual(recovered, bytearray(16))

        saved = bytearray(b"saved-keybag")
        saved_digest = hashlib.sha256(saved).hexdigest()
        committed = self.store.commit(
            saved,
            expected_keybag_sha256=saved_digest,
            activation_secret_sha256=secret_digest,
            bag_uuid=self.bag_uuid,
        )
        self.assertEqual(saved, bytearray(len(b"saved-keybag")))
        self.assertFalse(self.store.pending_directory.exists())
        self.assertEqual(committed.directory, self.identities / self.operation_id)
        self.assertEqual(committed.keybag_path.read_bytes(), b"saved-keybag")
        self.assertEqual(
            committed.activation_secret_path.read_bytes(), bytes(range(1, 17))
        )
        for path in (
            committed.keybag_path,
            committed.activation_secret_path,
            committed.manifest_path,
        ):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        manifest = json.loads(committed.manifest_path.read_bytes())
        self.assertEqual(manifest["phase"], "complete")
        self.assertEqual(manifest["activation_secret_sha256"], secret_digest)
        self.assertNotIn(bytes(range(1, 17)).hex(), committed.manifest_path.read_text())
        replay = bytearray(b"saved-keybag")
        reconciled = self.store.commit(
            replay,
            expected_keybag_sha256=saved_digest,
            activation_secret_sha256=secret_digest,
            bag_uuid=self.bag_uuid,
        )
        self.assertEqual(replay, bytearray(len(b"saved-keybag")))
        self.assertEqual(reconciled.manifest_sha256, committed.manifest_sha256)

    def test_mapping_commit_binds_published_bundle_and_stays_disabled(self) -> None:
        secret = bytearray(range(1, 17))
        secret_digest = self.store.stage(secret)
        saved = bytearray(b"saved-keybag")
        saved_digest = hashlib.sha256(saved).hexdigest()
        committed = self.store.commit(
            saved,
            expected_keybag_sha256=saved_digest,
            activation_secret_sha256=secret_digest,
            bag_uuid=self.bag_uuid,
        )
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=Path(self.temporary.name) / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="a" * 64,
            apple_uid=501,
            keybag_path=committed.keybag_path,
            bundle_generation=committed.generation,
            activation_secret_path=committed.activation_secret_path,
            activation_secret_sha256=committed.activation_secret_sha256,
        )
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            writer.commit(
                account_uuid=self.account_uuid,
                bag_uuid=self.bag_uuid,
                keybag_sha256=saved_digest,
            )
            parsed = t2_user_mapping.parse(writer.path.read_bytes())
        selected = parsed.mappings[0]
        self.assertEqual(parsed.schema_version, 2)
        self.assertFalse(selected.enabled)
        self.assertEqual(selected.bundle_generation, self.operation_id)
        self.assertEqual(selected.activation_secret_sha256, secret_digest)

    def test_mapping_commit_requires_exact_bundle_artifact_modes(self) -> None:
        secret = bytearray(range(1, 17))
        secret_digest = self.store.stage(secret)
        saved = bytearray(b"saved-keybag")
        saved_digest = hashlib.sha256(saved).hexdigest()
        committed = self.store.commit(
            saved,
            expected_keybag_sha256=saved_digest,
            activation_secret_sha256=secret_digest,
            bag_uuid=self.bag_uuid,
        )
        committed.activation_secret_path.chmod(0o400)
        writer = t2_user_mapping_store.InitialUserMappingStore(
            path=Path(self.temporary.name) / "users.json",
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="a" * 64,
            apple_uid=501,
            keybag_path=committed.keybag_path,
            bundle_generation=committed.generation,
            activation_secret_path=committed.activation_secret_path,
            activation_secret_sha256=committed.activation_secret_sha256,
        )
        with self.assertRaisesRegex(
            t2_user_mapping_store.UserMappingStoreError, "metadata"
        ):
            writer.commit(
                account_uuid=self.account_uuid,
                bag_uuid=self.bag_uuid,
                keybag_sha256=saved_digest,
            )

    def test_replacement_mapping_archives_old_authority_before_atomic_swap(self) -> None:
        old_keybag = self.user_root / "user.kb"
        old_keybag.write_bytes(b"old-keybag")
        old_keybag.chmod(0o600)
        mapping_path = Path(self.temporary.name) / "users.json"
        old_mapping = json.dumps(
            {
                "schema_version": 1,
                "mappings": [
                    {
                        "linux_uid": 1000,
                        "linux_account_generation": "a" * 64,
                        "apple_uid": 501,
                        "account_uuid": identifier(20),
                        "bag_uuid": identifier(21),
                        "keybag_path": str(old_keybag),
                        "keybag_sha256": hashlib.sha256(b"old-keybag").hexdigest(),
                        "unlock_mode": "password-on-demand",
                        "capabilities": ["enroll", "identity-management", "verify"],
                        "enabled": True,
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        mapping_path.write_bytes(old_mapping)
        mapping_path.chmod(0o600)
        archive_root = Path(self.temporary.name) / "replacement-archive"
        archive_root.mkdir(mode=0o700)

        secret_digest = self.store.stage(bytearray(range(1, 17)))
        saved_digest = hashlib.sha256(b"saved-keybag").hexdigest()
        committed = self.store.commit(
            bytearray(b"saved-keybag"),
            expected_keybag_sha256=saved_digest,
            activation_secret_sha256=secret_digest,
            bag_uuid=self.bag_uuid,
        )
        writer = t2_user_mapping_store.ReplacementUserMappingStore(
            path=mapping_path,
            operation_id=self.operation_id,
            linux_uid=1000,
            linux_account_generation="a" * 64,
            apple_uid=501,
            keybag_path=committed.keybag_path,
            bundle_generation=committed.generation,
            activation_secret_path=committed.activation_secret_path,
            activation_secret_sha256=committed.activation_secret_sha256,
            old_mapping_generation=hashlib.sha256(old_mapping).hexdigest(),
            old_account_uuid=identifier(20),
            old_bag_uuid=identifier(21),
            archive_root=archive_root,
        )
        with mock.patch.object(
            t2_user_mapping, "KEYBAG_ROOT", PurePosixPath(str(self.users))
        ):
            with mock.patch.object(
                t2_user_mapping_store.os,
                "replace",
                side_effect=OSError("synthetic crash boundary"),
            ):
                with self.assertRaisesRegex(
                    t2_user_mapping_store.UserMappingStoreError, "publication"
                ):
                    writer.commit(
                        account_uuid=self.account_uuid,
                        bag_uuid=self.bag_uuid,
                        keybag_sha256=saved_digest,
                    )
            self.assertEqual(mapping_path.read_bytes(), old_mapping)
            self.assertEqual(writer.archive_path.read_bytes(), old_mapping)
            generation = writer.commit(
                account_uuid=self.account_uuid,
                bag_uuid=self.bag_uuid,
                keybag_sha256=saved_digest,
            )
            self.assertEqual(
                writer.commit(
                    account_uuid=self.account_uuid,
                    bag_uuid=self.bag_uuid,
                    keybag_sha256=saved_digest,
                ),
                generation,
            )
            replacement = t2_user_mapping.parse(mapping_path.read_bytes())
        self.assertFalse(replacement.mappings[0].enabled)
        self.assertEqual(writer.archive_path.read_bytes(), old_mapping)

    def test_unsafe_or_interrupted_staging_fails_closed_and_wipes_input(self) -> None:
        unsafe = Path(self.temporary.name) / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaisesRegex(bundle.ActivationBundleError, "not private"):
            bundle.ActivationBundleStore(
                root=unsafe,
                operation_id=identifier(10),
                account_uuid=identifier(11),
                linux_uid=1000,
            )

        secret = bytearray(range(1, 17))
        digest = self.store.stage(secret)
        self.store.pending_secret_path.chmod(0o644)
        with self.assertRaisesRegex(bundle.ActivationBundleError, "metadata"):
            with self.store.staged_secret(digest):
                pass

        second_root = self.user_root / "second-identities"
        second_root.mkdir(mode=0o700)
        second_store = bundle.ActivationBundleStore(
            root=second_root,
            operation_id=identifier(20),
            account_uuid=identifier(21),
            linux_uid=1000,
        )
        secret = bytearray(range(1, 17))
        with mock.patch.object(bundle.os, "write", side_effect=OSError("short")):
            with self.assertRaises(bundle.ActivationBundleError):
                second_store.stage(secret)
        self.assertEqual(secret, bytearray(16))
        self.assertTrue(second_store.pending_directory.exists())
        self.assertFalse(second_store.final_directory.exists())

        third_root = self.user_root / "third-identities"
        third_root.mkdir(mode=0o700)
        third_store = bundle.ActivationBundleStore(
            root=third_root,
            operation_id=identifier(30),
            account_uuid=identifier(31),
            linux_uid=1000,
        )
        digest = third_store.stage(bytearray(range(1, 17)))
        partial_keybag = third_store.pending_directory / "user.kb"
        partial_keybag.write_bytes(b"partial")
        partial_keybag.chmod(0o600)
        partial_manifest = third_store.pending_directory / "manifest.json"
        partial_manifest.write_bytes(b"{")
        partial_manifest.chmod(0o600)
        saved = bytearray(b"saved-keybag")
        committed = third_store.commit(
            saved,
            expected_keybag_sha256=hashlib.sha256(b"saved-keybag").hexdigest(),
            activation_secret_sha256=digest,
            bag_uuid=identifier(32),
        )
        self.assertEqual(committed.keybag_path.read_bytes(), b"saved-keybag")
        self.assertFalse(third_store.pending_directory.exists())


if __name__ == "__main__":
    unittest.main()
