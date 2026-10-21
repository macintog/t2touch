import copy
import hashlib
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_apple_control_discriminator as discriminator
import t2_catacomb_codec as codec
import t2_catacomb_local
import t2_identity_rename_journal as rename
from tests.test_catacomb_codec import fixture


class CompatibilityRenameTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        mutation_root = self.root / "mutations"
        mutation_root.mkdir(mode=0o700)
        self.operation = "00000000-0000-0000-0000-000000000010"
        (mutation_root / f"{self.operation}.jsonl").touch(mode=0o600)
        self.before = codec.decode_user_catacomb(fixture(), 501)
        self.original = {"master.cat": b"master", "biolockout.cat": b"lock",
                         "user_000001f5.cat": fixture()}
        self.components = dict(self.original)
        self.components["user_000001f5.cat"] = self.before.rename(
            self.before.identities[0].uuid, "finger-1"
        )
        self.provenance = {
            "apple_uid": 501, "linux_uid": 1000,
            "account_uuid": self.before.account_uuid,
            "bag_uuid": self.before.keybag_uuid,
            "catacomb_backup_sha256": "a" * 64,
            "catacomb_component_sha256": {
                name: hashlib.sha256(data).hexdigest()
                for name, data in self.original.items()
            },
        }
        self.baseline = {
            "apple_uid": 501, "caller_linux_uid": 1000, "target_linux_uid": 1000,
            "account_uuid": self.before.account_uuid, "bag_uuid": self.before.keybag_uuid,
            "host_components": [
                {"name": name, "sha256": digest}
                for name, digest in self.provenance["catacomb_component_sha256"].items()
            ],
            "backup_references": [{"reference": "a" * 64 + ".tar.gz", "sha256": "a" * 64}],
            "master_enrollment_count": 1, "mapping_generation": "b" * 64,
            "identity_records": [
                {"user_id": item.user_id, "uuid": item.uuid, "entity": item.entity}
                for item in self.before.identities
            ],
        }
        item = self.before.identities[0]
        self.history = SimpleNamespace(
            operation_id=self.operation, phase=rename.IdentityRenamePhase.RECONCILED,
            baseline=self.baseline, target_identity_uuid=item.uuid, target_entity=item.entity,
            previous_name_sha256=hashlib.sha256(item.name.encode()).hexdigest(),
            new_name_sha256=hashlib.sha256(b"finger-1").hexdigest(),
            persistence=SimpleNamespace(staged_files=((
                "user_000001f5.cat", hashlib.sha256(self.components["user_000001f5.cat"]).hexdigest()
            ),)),
        )

    def validate(self):
        # Journal parser/state-machine behavior is covered by rename journal tests.
        with (
            mock.patch.object(discriminator, "_private_bytes", return_value=b"journal\n"),
            mock.patch.object(discriminator.journal, "validate_records", return_value=[]),
            mock.patch.object(rename, "validate_history", return_value=self.history),
            mock.patch.object(t2_catacomb_local, "read_backup_components", return_value=(
                {"master_enrollment_count": 1}, self.original
            )),
            mock.patch.object(Path, "stat", return_value=SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=0
            )),
        ):
            return discriminator._read_completed_label_change(
                self.root, self.provenance, self.components
            )

    def test_accepts_completed_and_post_reboot_rename(self):
        for phase in (rename.IdentityRenamePhase.RECONCILED,
                      rename.IdentityRenamePhase.POST_REBOOT_VERIFIED):
            self.history.phase = phase
            self.assertEqual(self.validate(), "b" * 64)

    def test_rejects_unfinished_journal(self):
        self.history.phase = rename.IdentityRenamePhase.OUTCOME_UNKNOWN
        with self.assertRaises(discriminator.AppleControlDiscriminatorError):
            self.validate()

    def test_rejects_changed_archive_and_unrelated_components(self):
        for name in self.components:
            with self.subTest(name=name):
                original = self.components[name]
                self.components[name] = original + b"changed"
                with self.assertRaises(discriminator.AppleControlDiscriminatorError):
                    self.validate()
                self.components[name] = original

    def test_rejects_cross_account_and_backup_baselines(self):
        for key, value in (("caller_linux_uid", 1001), ("target_linux_uid", 1001),
                           ("apple_uid", 502), ("backup_references", []),
                           ("identity_records", [])):
            with self.subTest(key=key):
                saved = copy.deepcopy(self.baseline[key])
                self.baseline[key] = value
                with self.assertRaises(discriminator.AppleControlDiscriminatorError):
                    self.validate()
                self.baseline[key] = saved

    def test_rejects_wrong_name_proof_and_extra_journal(self):
        self.history.new_name_sha256 = "c" * 64
        with self.assertRaises(discriminator.AppleControlDiscriminatorError):
            self.validate()
        (self.root / "mutations" / "extra.jsonl").touch()
        with self.assertRaises(discriminator.AppleControlDiscriminatorError):
            self.validate()
