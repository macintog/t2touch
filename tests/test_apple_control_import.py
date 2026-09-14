#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_apple_control_import as control_import
import t2_catacomb_local
import t2_user_authority
import t2_user_mapping
from tests.test_catacomb_codec import (
    biolockout_fixture,
    fixture as user_fixture,
    master_fixture,
)


SAVED_KEYBAG = b"synthetic-saved-keybag"


def add_file(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    archive.addfile(info, io.BytesIO(data))


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o700
    archive.addfile(info)


def write_keybag_archive(
    path: Path,
    *,
    second_user: bytes = SAVED_KEYBAG,
    include_nested_payload: bool = True,
) -> None:
    mapping = (
        b"candidate-0001\t/private/example/user.kb\n"
        b"candidate-0002\t/Users/example/user.kb\n"
        b"candidate-0003\t/private/example/keybags\n"
    )
    with tarfile.open(path, "w:gz") as archive:
        add_file(archive, "state/path-map.txt", mapping)
        add_file(archive, "state/candidate-0001", SAVED_KEYBAG)
        add_file(archive, "state/candidate-0002", second_user)
        add_directory(archive, "state/candidate-0003")
        if include_nested_payload:
            add_file(archive, "state/candidate-0003/system.kb", b"other")
    path.chmod(0o600)


def write_catacomb_archive(path: Path) -> None:
    components = {
        "master.cat": master_fixture(),
        "user_000001f5.cat": user_fixture(),
        "biolockout.cat": biolockout_fixture(),
    }
    with tarfile.open(path, "w:gz") as archive:
        add_directory(archive, "Library/Catacomb")
        add_directory(archive, "Library/Catacomb/example")
        for name, data in components.items():
            info = tarfile.TarInfo(f"Library/Catacomb/example/{name}")
            info.size = len(data)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            archive.addfile(info, io.BytesIO(data))
    path.chmod(0o600)


class AppleControlImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.keybag_archive = self.root / "keybags.tar.gz"
        self.catacomb_archive = self.root / "catacomb.tar.gz"
        write_keybag_archive(self.keybag_archive)
        write_catacomb_archive(self.catacomb_archive)
        self.catacomb_archive.chmod(0o600)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_selects_one_unique_user_keybag_across_identical_views(self):
        selected = control_import.read_keybag_archive(self.keybag_archive)
        self.assertEqual(selected.saved_keybag, SAVED_KEYBAG)
        self.assertEqual(selected.source_view_count, 2)
        self.assertEqual(selected.mapped_candidate_count, 3)
        self.assertEqual(
            selected.saved_keybag_sha256,
            hashlib.sha256(SAVED_KEYBAG).hexdigest(),
        )
        selected.wipe()
        self.assertEqual(selected.saved_keybag, bytearray(len(SAVED_KEYBAG)))

    def test_rejects_distinct_user_views_and_incomplete_candidate_graph(self):
        write_keybag_archive(self.keybag_archive, second_user=b"different")
        with self.assertRaisesRegex(
            control_import.AppleControlImportError, "distinct"
        ):
            control_import.read_keybag_archive(self.keybag_archive)

        write_keybag_archive(self.keybag_archive, include_nested_payload=False)
        with self.assertRaisesRegex(
            control_import.AppleControlImportError, "do not correspond"
        ):
            control_import.read_keybag_archive(self.keybag_archive)

    def test_import_is_private_disabled_cross_bound_and_idempotent(self):
        keybag_root = PurePosixPath(str(self.state / "users"))
        with mock.patch.object(t2_user_mapping, "KEYBAG_ROOT", keybag_root):
            first_plan, first = control_import.import_control_archives(
                keybag_archive=self.keybag_archive,
                catacomb_archive=self.catacomb_archive,
                linux_uid=1000,
                linux_account_generation="a" * 64,
                apple_uid=501,
                state_root=self.state,
            )
            second_plan, second = control_import.import_control_archives(
                keybag_archive=self.keybag_archive,
                catacomb_archive=self.catacomb_archive,
                linux_uid=1000,
                linux_account_generation="a" * 64,
                apple_uid=501,
                state_root=self.state,
            )

        self.assertEqual(first_plan, second_plan)
        self.assertEqual(first, second)
        self.assertTrue(first["import_reconciled"])
        self.assertFalse(first["mapping_enabled"])
        self.assertTrue(first["identifiers_redacted"])
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn(first_plan.account_uuid, rendered)
        self.assertNotIn(first_plan.bag_uuid, rendered)
        self.assertNotIn(first_plan.keybag_sha256, rendered)

        keybag = self.state / "users/1000/user.kb"
        self.assertEqual(keybag.read_bytes(), SAVED_KEYBAG)
        self.assertEqual(keybag.stat().st_mode & 0o777, 0o600)
        with mock.patch.object(t2_user_mapping, "KEYBAG_ROOT", keybag_root):
            mappings = t2_user_mapping.parse(
                (self.state / "users.json").read_bytes()
            )
        self.assertEqual(len(mappings.mappings), 1)
        selected = mappings.mappings[0]
        self.assertFalse(selected.enabled)
        self.assertEqual(selected.account_uuid, first_plan.account_uuid)
        self.assertEqual(selected.bag_uuid, first_plan.bag_uuid)
        runtime = t2_user_authority._compatibility_runtime_mapping(selected)
        self.assertFalse(selected.enabled)
        self.assertTrue(runtime.enabled)
        self.assertEqual(runtime.capabilities, t2_user_mapping.CAPABILITIES)
        self.assertEqual(runtime.unlock_mode, "host-encrypted-credential")

        backups = list((self.state / "backups").glob("*.tar.gz"))
        self.assertEqual(len(backups), 1)
        host, components = t2_catacomb_local.read_backup_components(backups[0], 501)
        self.assertEqual(host["bag_uuid"], first_plan.bag_uuid)
        for name, data in components.items():
            self.assertEqual((self.state / "catacomb" / name).read_bytes(), data)
        provenance = json.loads(
            (self.state / "users/1000/apple-control-import.json").read_text()
        )
        self.assertEqual(provenance["origin"], control_import.ORIGIN)
        self.assertTrue(provenance["import_complete"])
        self.assertFalse(provenance["mapping_enabled"])
        self.assertFalse(provenance["sep_keybag_uuid_verified"])

    def test_existing_keybag_is_never_replaced_on_conflict(self):
        users_parent = self.state / "users"
        users_parent.mkdir(mode=0o700)
        users = users_parent / "1000"
        users.mkdir(mode=0o700)
        target = users / "user.kb"
        target.write_bytes(b"different")
        target.chmod(0o600)
        with (
            mock.patch.object(
                t2_user_mapping,
                "KEYBAG_ROOT",
                PurePosixPath(str(self.state / "users")),
            ),
            self.assertRaisesRegex(
                control_import.AppleControlImportError, "differs"
            ),
        ):
            control_import.import_control_archives(
                keybag_archive=self.keybag_archive,
                catacomb_archive=self.catacomb_archive,
                linux_uid=1000,
                linux_account_generation="a" * 64,
                apple_uid=501,
                state_root=self.state,
            )
        self.assertEqual(target.read_bytes(), b"different")


if __name__ == "__main__":
    unittest.main()
