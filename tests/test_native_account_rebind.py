# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_linux_account as linux_account
import t2_native_account_rebind as rebind


class NativeAccountRebindTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name) / "state"
        self.user_root = self.state / "users" / "1000"
        self.user_root.mkdir(parents=True, mode=0o700)
        self.state.chmod(0o700)
        (self.state / "users").chmod(0o700)
        self.user_root.chmod(0o700)
        self.uid = 1000
        self.previous = "a" * 64
        self.current = "b" * 64
        self.mapping_generation = "c" * 64
        self.keybag = self.user_root / "user.kb"
        self.keybag.write_bytes(b"keybag")
        self.keybag.chmod(0o600)
        self.activation = self.state / "activation.secret"
        self.activation.write_bytes(b"activation")
        self.activation.chmod(0o600)
        self.authority = SimpleNamespace(
            origin="linux-native-e4",
            selected=SimpleNamespace(
                linux_uid=self.uid,
                linux_account_generation=self.previous,
                keybag_path="/var/lib/t2-touchid/users/1000/user.kb",
                keybag_sha256=hashlib.sha256(b"keybag").hexdigest(),
                activation_secret_path="/var/lib/t2-touchid/activation.secret",
                activation_secret_sha256=hashlib.sha256(b"activation").hexdigest(),
                activation_secret_length=len(b"activation"),
            ),
            mapping_set=SimpleNamespace(generation=self.mapping_generation),
        )
        self.owner = mock.patch.object(rebind, "ROOT_UID", os.geteuid())
        self.owner.start()

    def tearDown(self):
        self.owner.stop()
        self.temporary.cleanup()

    def loader(self, linux_uid, **arguments):
        self.assertEqual(linux_uid, self.uid)
        self.assertEqual(arguments["mapping_path"], self.state / "users.json")
        self.assertEqual(arguments["users_root"], self.state / "users")
        return self.authority

    def account(self, _linux_uid):
        return linux_account.AccountEvidence(self.uid, self.current)

    def publish(self):
        return rebind.publish(
            self.uid,
            acknowledge_complete_native_authority_migration=True,
            state_root=self.state,
            account_collector=self.account,
            authority_loader=self.loader,
        )

    def test_publish_preserves_authority_and_resolves_previous_generation(self):
        result = self.publish()
        self.assertEqual(
            result.redacted(),
            {
                "schema_version": 1,
                "state": "native-authority-rebound-to-current-account",
                "linux_uid": self.uid,
                "complete_authority_validated": True,
                "identifiers_redacted": True,
            },
        )
        path = self.user_root / rebind.MANIFEST_NAME
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            rebind.resolve(
                self.uid,
                self.current,
                state_root=self.state,
                authority_loader=self.loader,
            ),
            self.previous,
        )

    def test_rejects_wrong_current_generation_and_changed_authority(self):
        self.publish()
        with self.assertRaisesRegex(
            rebind.NativeAccountRebindError, "current account"
        ):
            rebind.resolve(
                self.uid,
                "d" * 64,
                state_root=self.state,
                authority_loader=self.loader,
            )
        changed = SimpleNamespace(
            **{
                **self.authority.__dict__,
                "mapping_set": SimpleNamespace(generation="e" * 64),
            }
        )
        with self.assertRaisesRegex(
            rebind.NativeAccountRebindError, "complete authority"
        ):
            rebind.resolve(
                self.uid,
                self.current,
                state_root=self.state,
                authority_loader=lambda *_args, **_kwargs: changed,
            )

    def test_invalid_or_public_manifest_fails_closed(self):
        path = self.user_root / rebind.MANIFEST_NAME
        path.write_text('{"schema_version":1,"schema_version":1}')
        path.chmod(0o600)
        with self.assertRaisesRegex(
            rebind.NativeAccountRebindError, "duplicate"
        ):
            rebind.resolve(
                self.uid,
                self.current,
                state_root=self.state,
                authority_loader=self.loader,
            )
        path.write_text(json.dumps({"schema_version": 1}))
        path.chmod(0o644)
        with self.assertRaisesRegex(
            rebind.NativeAccountRebindError, "private"
        ):
            rebind.resolve(
                self.uid,
                self.current,
                state_root=self.state,
                authority_loader=self.loader,
            )

    def test_acknowledgement_and_existing_binding_are_required(self):
        with self.assertRaisesRegex(
            rebind.NativeAccountRebindError, "acknowledgement"
        ):
            rebind.publish(
                self.uid,
                acknowledge_complete_native_authority_migration=False,
                state_root=self.state,
                account_collector=self.account,
                authority_loader=self.loader,
            )
        with self.assertRaisesRegex(
            rebind.NativeAccountRebindError, "already current"
        ):
            rebind.publish(
                self.uid,
                acknowledge_complete_native_authority_migration=True,
                state_root=self.state,
                account_collector=lambda _uid: linux_account.AccountEvidence(
                    self.uid, self.previous
                ),
                authority_loader=self.loader,
            )


if __name__ == "__main__":
    unittest.main()
