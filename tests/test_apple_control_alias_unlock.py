# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
import uuid

SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as unlock
import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal
import t2_user_readiness


def identifier(value: int) -> str:
    return str(uuid.UUID(int=value))


class FakeTransport:
    runtime_generation = identifier(40)

    def __init__(self, observations, status=0):
        self.observations = iter(observations)
        self.status = status
        self.calls = []
        self.password_seen = None

    def observe_alias(self, special_alias):
        self.calls.append(("observe", special_alias))
        value = next(self.observations)
        if isinstance(value, BaseException):
            raise value
        return value

    def unlock_alias(self, special_alias, password):
        self.calls.append(("unlock", special_alias))
        self.password_seen = bytes(password)
        if isinstance(self.status, BaseException):
            raise self.status
        return self.status


class AppleControlAliasUnlockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "unlock.jsonl"
        self.evidence = keybag_discriminator.OracleEvidence(
            identifier(1), "a" * 64, 1000, 501, identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb", "b" * 64,
        )
        self.proof = reconciliation.ReconciledAliasProof(
            identifier(30), identifier(31), identifier(32), "c" * 64
        )
        self.locked = t2_user_readiness.AliasEvidence(
            True, -501, self.evidence.bag_uuid, t2_user_readiness.DEVICE_LOCKED
        )
        self.ready = t2_user_readiness.AliasEvidence(
            True, -501, self.evidence.bag_uuid, 0
        )

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, transport, password=None):
        password = password or bytearray(b"test")
        try:
            result = unlock.run(
                journal_path=self.path,
                evidence=self.evidence,
                proof=self.proof,
                linux_boot_uuid=identifier(33),
                transport=transport,
                password=password,
                operation_id=identifier(34),
            )
            return result, password
        except BaseException as error:
            error.wiped_password = password
            raise

    def test_locked_alias_unlocks_once_and_is_read_back(self):
        transport = FakeTransport([self.locked, self.ready])

        result, password = self.invoke(transport)

        self.assertEqual(result.outcome, "unlocked")
        self.assertTrue(result.mutation_performed)
        self.assertFalse(result.reconciliation_required)
        self.assertEqual(transport.password_seen, b"test")
        self.assertEqual(password, bytearray(4))
        self.assertEqual(
            [record["milestone"] for record in t2_mutation_journal.read(self.path)],
            [
                "APPLE_CONTROL_ALIAS_UNLOCK_BASELINE",
                "APPLE_CONTROL_ALIAS_UNLOCK_PRESTATE",
                "APPLE_CONTROL_ALIAS_UNLOCK_INTENT",
                "APPLE_CONTROL_ALIAS_UNLOCK_OBSERVED",
                "APPLE_CONTROL_ALIAS_UNLOCK_COMPLETE",
            ],
        )
        self.assertEqual(
            [call[0] for call in transport.calls], ["observe", "unlock", "observe"]
        )
        proof = unlock.read_completed_unlock_proof(
            self.path, self.evidence, self.proof
        )
        self.assertEqual(proof.operation_id, identifier(34))
        self.assertEqual(proof.linux_boot_uuid, identifier(33))
        self.assertEqual(proof.runtime_generation, identifier(40))

    def test_readback_can_reconcile_raised_unlock_command(self):
        transport = FakeTransport(
            [self.locked, self.ready], RuntimeError("synthetic reply loss")
        )

        result, _password = self.invoke(transport)

        self.assertEqual(result.outcome, "unlocked")
        observed = t2_mutation_journal.read(self.path)[3]["evidence"]
        self.assertTrue(observed["command_raised"])
        self.assertIsNone(observed["command_status"])

    def test_still_locked_completes_as_rejected_without_retry(self):
        transport = FakeTransport([self.locked, self.locked], 7)

        result, _password = self.invoke(transport)

        self.assertEqual(result.outcome, "unlock-rejected")
        self.assertFalse(result.unlocked)
        self.assertTrue(self.path.exists())

    def test_failed_post_unlock_readback_is_unknown_and_wipes_password(self):
        transport = FakeTransport(
            [self.locked, RuntimeError("synthetic readback failure")]
        )

        with self.assertRaisesRegex(
            unlock.AppleControlAliasUnlockError, "do not retry"
        ) as raised:
            self.invoke(transport)

        self.assertEqual(raised.exception.wiped_password, bytearray(4))
        self.assertEqual(
            t2_mutation_journal.read(self.path)[-1]["milestone"],
            "APPLE_CONTROL_ALIAS_UNLOCK_UNKNOWN",
        )

    def test_same_boot_is_rejected_before_journal_or_transport(self):
        transport = FakeTransport([self.locked])
        password = bytearray(b"test")

        with self.assertRaisesRegex(
            unlock.AppleControlAliasUnlockError, "later boot"
        ):
            unlock.run(
                journal_path=self.path,
                evidence=self.evidence,
                proof=self.proof,
                linux_boot_uuid=self.proof.linux_boot_uuid,
                transport=transport,
                password=password,
                operation_id=identifier(34),
            )

        self.assertEqual(password, bytearray(4))
        self.assertEqual(transport.calls, [])
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
