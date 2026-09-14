# SPDX-License-Identifier: GPL-2.0-only
import io
import plistlib
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path

from src import t2_baseline
from src import t2_mutation_journal


def uid(value):
    return plistlib.UID(value)


IDENTITY_UUID = "00000000-0000-0000-0000-000000000010"
ACCOUNT_UUID = "00000000-0000-0000-0000-000000000011"
BAG_UUID = "00000000-0000-0000-0000-000000000012"
CATACOMB_UUID = "00000000-0000-0000-0000-000000000013"


def keyed(top, objects):
    return plistlib.dumps(
        {
            "$archiver": "NSKeyedArchiver",
            "$version": 100000,
            "$top": top,
            "$objects": objects,
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


def user_component():
    objects = [
        "$null",
        {"NS.objects": [uid(2)]},
        {
            "BKIdentityUserID": 501,
            "BKIdentityEntityNumber": 0,
            "BKIdentityUUID": uuid.UUID(IDENTITY_UUID).bytes,
        },
        {"NS.uuidbytes": uuid.UUID(ACCOUNT_UUID).bytes},
        {"NS.uuidbytes": uuid.UUID(BAG_UUID).bytes},
    ]
    return keyed(
        {
            "CatacombVersion": 0x30000,
            "CatacombUserID": 501,
            "CatacombIdentityList": uid(1),
            "CatacombUserUUID": uid(3),
            "CatacombUserKeybagUUID": uid(4),
        },
        objects,
    )


def write_archive(path, *, include_source_stat=True, header_uid=0):
    components = {
        "master.cat": keyed(
            {"CatacombVersion": 0x30000, "CatacombEnrollmentCount": 2},
            ["$null"],
        ),
        "user_000001f5.cat": user_component(),
        "biolockout.cat": keyed({"BioLockoutRecordVersion": 0x10000}, ["$null"]),
        "source-stat.txt": (
            b"-rw-r--r-- root:wheel 100 1 /Library/Catacomb/TEST/master.cat\n"
            b"-rw-r--r-- root:wheel 100 1 /Library/Catacomb/TEST/user_000001f5.cat\n"
            b"-rw-r--r-- root:wheel 100 1 /Library/Catacomb/TEST/biolockout.cat\n"
        ),
    }
    if not include_source_stat:
        components.pop("source-stat.txt")
    with tarfile.open(path, "w:gz") as archive:
        for name, data in components.items():
            info = tarfile.TarInfo(f"capture/{name}")
            info.size = len(data)
            info.mode = 0o644
            info.uid = header_uid
            info.gid = 0
            info.uname = "root" if header_uid == 0 else "user"
            info.gname = "wheel"
            archive.addfile(info, io.BytesIO(data))


def live_inventory(identity_uuid=IDENTITY_UUID):
    return {
        "schema_version": 1,
        "connection_generation": "00000000-0000-0000-0000-000000000020",
        "bridge_boot_uuid": None,
        "biometric_protocol_version": 2,
        "apple_uid": 501,
        "per_user_identity_records": [
            {"user_id": 501, "identity_uuid": identity_uuid}
        ],
        "global_identity_records": [],
        "maximum_capacity": 5,
        "configured_user_free_capacity": 2,
        "catacomb": {
            "uuid": CATACOMB_UUID,
            "present": True,
            "hash": "a" * 64,
            "global_state": "00" * 16,
        },
        "sks_lock_state_raw": 0,
        "double_collection_equal": True,
    }


class BaselineTests(unittest.TestCase):
    def test_archive_without_sidecar_uses_validated_tar_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw-export.tar.gz"
            write_archive(path, include_source_stat=False)
            host = t2_baseline.read_host_archive(path, 501)
            self.assertEqual(len(host["identity_records"]), 1)
            self.assertTrue(
                all(component["uid"] == 0 for component in host["host_components"])
            )

    def test_archive_without_sidecar_rejects_non_root_tar_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe-export.tar.gz"
            write_archive(path, include_source_stat=False, header_uid=501)
            with self.assertRaises(t2_baseline.BaselineError):
                t2_baseline.read_host_archive(path, 501)

    def test_archive_and_live_inventory_build_valid_journal_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            host = t2_baseline.read_host_archive(path, 501)
            baseline = t2_baseline.build_baseline(
                host=host,
                live=live_inventory(),
                caller_linux_uid=1000,
                target_linux_uid=1000,
                linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                mapping_generation="b" * 64,
                backup_reference="backup-1",
                password_fallback_verified=True,
            )
            t2_mutation_journal.validate_baseline(baseline)
            self.assertEqual(baseline["identity_records"][0]["uuid"], IDENTITY_UUID)

            credential_free = t2_baseline.build_baseline(
                host=host,
                live=live_inventory(),
                caller_linux_uid=1000,
                target_linux_uid=1000,
                linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                mapping_generation="b" * 64,
                backup_reference="backup-1",
                password_fallback_verified=False,
            )
            t2_mutation_journal.validate_baseline(credential_free)
            self.assertFalse(credential_free["password_fallback_verified"])

    def test_rejects_live_host_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            host = t2_baseline.read_host_archive(path, 501)
            with self.assertRaises(t2_baseline.BaselineError):
                t2_baseline.build_baseline(
                    host=host,
                    live=live_inventory("00000000-0000-0000-0000-000000000099"),
                    caller_linux_uid=1000,
                    target_linux_uid=1000,
                    linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                    mapping_generation="b" * 64,
                    backup_reference="backup-1",
                    password_fallback_verified=True,
                )

    def test_accepts_exact_absent_sep_first_enrollment_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            host = t2_baseline.read_host_archive(path, 501)
            live = live_inventory()
            live["per_user_identity_records"] = []
            live["catacomb"] = {
                "uuid": "00000000-0000-0000-0000-000000000000",
                "present": False,
                "hash": "0" * 64,
                "global_state": "ffffffff03000000",
                "user_states": [
                    {
                        "kind": "master",
                        "user_id": 0xFFFFFFFF,
                        "state": 3,
                        "needs_save": False,
                    }
                ],
            }
            result = t2_baseline.build_baseline(
                host=host,
                live=live,
                caller_linux_uid=1000,
                target_linux_uid=1000,
                linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                mapping_generation="b" * 64,
                backup_reference="backup-1",
                password_fallback_verified=True,
            )
            t2_mutation_journal.validate_baseline(result)
            self.assertEqual(
                result["sep_catacomb"],
                {"present": False, "uuid": None, "hash": None},
            )

            external_host = dict(host)
            external_host["identity_records"] = []
            external_live = live_inventory()
            external_live["per_user_identity_records"] = []
            external_live["global_identity_records"] = []
            external_live["catacomb"] = {
                "uuid": CATACOMB_UUID,
                "present": False,
                "hash": "0" * 64,
                "global_state": "00" * 16,
                "user_states": [
                    {
                        "kind": "master",
                        "user_id": 0xFFFFFFFF,
                        "state": 3,
                        "needs_save": False,
                    },
                    {
                        "kind": "user",
                        "user_id": 501,
                        "state": 3,
                        "needs_save": False,
                    },
                ],
            }
            external = t2_baseline.build_baseline(
                host=external_host,
                live=external_live,
                caller_linux_uid=1000,
                target_linux_uid=1000,
                linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                mapping_generation="b" * 64,
                backup_reference="backup-1",
                password_fallback_verified=True,
            )
            t2_mutation_journal.validate_baseline(external)
            self.assertEqual(external["capacity"]["used"], 0)
            self.assertFalse(external["sep_catacomb"]["present"])

    def test_rejects_wrong_archive_user(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            with self.assertRaises(t2_baseline.BaselineError):
                t2_baseline.read_host_archive(path, 502)

    def test_linux_native_empty_baseline_has_no_imported_state(self):
        live = live_inventory()
        live["per_user_identity_records"] = []
        live["catacomb"] = {
            "uuid": CATACOMB_UUID,
            "present": False,
            "hash": "0" * 64,
            "global_state": "00" * 16,
            "user_states": [
                {
                    "kind": "master",
                    "user_id": 0xFFFFFFFF,
                    "state": 1,
                    "needs_save": False,
                },
                {
                    "kind": "user",
                    "user_id": 501,
                    "state": 1,
                    "needs_save": False,
                },
            ],
        }
        baseline = t2_baseline.build_linux_native_empty_baseline(
            live=live,
            caller_linux_uid=1000,
            target_linux_uid=1000,
            linux_boot_uuid="00000000-0000-0000-0000-000000000021",
            mapping_generation="b" * 64,
            account_uuid=ACCOUNT_UUID,
            bag_uuid=BAG_UUID,
            password_fallback_verified=True,
        )
        t2_mutation_journal.validate_baseline(baseline)
        self.assertEqual(baseline["baseline_version"], 2)
        self.assertEqual(baseline["host_components"], [])
        self.assertEqual(baseline["backup_references"], [])


if __name__ == "__main__":
    unittest.main()
