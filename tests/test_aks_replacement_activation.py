# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import contextlib
import tempfile
import unittest
import uuid
from dataclasses import dataclass
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import t2_aks_replacement_activation_journal as activation_journal
import t2_aks_replacement_activation_operation as operation
import t2_user_readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


@dataclass(frozen=True)
class Policy:
    requirement_type: int
    satisfied: bool


class FakeTransport:
    def __init__(self, states: list[t2_user_readiness.AliasEvidence]) -> None:
        self.runtime_generation = identifier(90)
        self.states = states
        self.events: list[str] = []
        self.handle = 42
        self.login_credential: bytes | None = None

    def __enter__(self):
        self.events.append("open")
        return self

    def __exit__(self, *_: object) -> None:
        self.events.append("close")

    def load_keybag(self, _path: str) -> int:
        self.events.append("load")
        return self.handle

    def bag_uuid(self, _handle: int) -> str:
        self.events.append("uuid")
        return identifier(4)

    def bind_alias(self, _handle: int, _alias: int) -> int:
        self.events.append("bind")
        return 0

    def observe_alias(self, _alias: int) -> t2_user_readiness.AliasEvidence:
        self.events.append("observe")
        return self.states.pop(0)

    def resolve_alias_configuration(self, _alias: int) -> None:
        self.events.append("configure")

    def bind_loaded_identity_secret_to_acm_context(
        self, _identity: bytes, _authorization: bytes
    ) -> None:
        self.events.append("authorize")

    def unlock_alias_with_acm_context(
        self, _alias: int, login_credential: bytes
    ) -> int:
        self.events.append("unlock")
        self.login_credential = login_credential
        return 0

    def unload_keybag(self, _handle: int) -> int:
        self.events.append("unload")
        return 0


class FakeWriter:
    def __init__(self, root: Path) -> None:
        self.keybag_path = root / "user.kb"
        self.keybag_path.write_bytes(b"saved")
        self.enables = 0

    def enable_after_reboot(self, **_values: object) -> str:
        self.enables += 1
        return "e" * 64


class ReplacementActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.journal = self.root / "journal" / "activation.jsonl"
        self.writer = FakeWriter(self.root)
        self.operation_id = identifier(1)
        self.boot = identifier(12)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_torn_reply_keeps_unlock_intent_recoverable(self):
        self._append_crash_at_unlock_intent()
        before = activation_journal.read(self.journal)
        with self.journal.open("ab") as stream:
            stream.write(b'{"milestone":"REPLACEMENT_ALIAS_UNLOCK')
        recovered = activation_journal.read(self.journal)
        self.assertEqual(recovered.phase, before.phase)
        self.assertEqual(recovered.record_count, before.record_count + 1)
        self.assertEqual(activation_journal.read(self.journal), recovered)

    @staticmethod
    def alias(state: int, bag_uuid: str | None = None):
        return t2_user_readiness.AliasEvidence(
            True,
            -501,
            bag_uuid or identifier(4),
            state,
        )

    def create(self) -> None:
        operation.create(
            journal_path=self.journal,
            operation_id=self.operation_id,
            replacement_head_hash="a" * 64,
            replacement_initial_linux_boot_uuid=identifier(10),
            replacement_final_linux_boot_uuid=identifier(11),
            activation_linux_boot_uuid=self.boot,
            linux_account_generation="b" * 64,
            target_linux_uid=1000,
            apple_uid=501,
            account_uuid=identifier(3),
            bag_uuid=identifier(4),
            disabled_mapping_generation="c" * 64,
            keybag_sha256="d" * 64,
            activation_material_digest="f" * 64,
            bundle_manifest_sha256="1" * 64,
            initial_alias_state="alias-absent",
        )

    @contextlib.contextmanager
    def secret(self):
        value = bytearray(range(1, 17))
        try:
            yield value
        finally:
            value[:] = bytes(16)

    @contextlib.contextmanager
    def authorization(self, _uid: int, material: bytearray, binder):
        self.assertEqual(material, bytearray(range(1, 17)))
        binder(b"I" * 16, b"A" * 16)
        yield Policy(1, False), Policy(1, True), b"I" * 16

    def _append_crash_at_unlock_intent(self) -> None:
        self.create()
        records = [
            (
                "REPLACEMENT_ACTIVATION_ATTEMPT_STARTED",
                {
                    "attempt_number": 1,
                    "linux_boot_uuid": self.boot,
                    "runtime_generation": identifier(90),
                    "mutation_possible": False,
                },
            ),
            (
                "REPLACEMENT_KEYBAG_LOAD_INTENT",
                {
                    "attempt_number": 1,
                    "keybag_sha256": "d" * 64,
                    "mutation_possible": True,
                },
            ),
            (
                "REPLACEMENT_KEYBAG_LOADED",
                {
                    "attempt_number": 1,
                    "handle": 42,
                    "bag_uuid_matches": True,
                    "command_status": 0,
                },
            ),
            (
                "REPLACEMENT_ALIAS_BIND_INTENT",
                {
                    "attempt_number": 1,
                    "handle": 42,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            ),
            (
                "REPLACEMENT_ALIAS_BOUND",
                {
                    "attempt_number": 1,
                    "special_alias": -501,
                    "bag_uuid_matches": True,
                    "alias_state": "device-locked",
                    "command_status": 0,
                },
            ),
            (
                "REPLACEMENT_ALIAS_CONFIGURATION_INTENT",
                {
                    "attempt_number": 1,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            ),
            (
                "REPLACEMENT_ALIAS_CONFIGURATION_RESOLVED",
                {
                    "attempt_number": 1,
                    "special_alias": -501,
                    "command_status": 0,
                },
            ),
            (
                "REPLACEMENT_IDENTITY_AUTHORIZATION_INTENT",
                {
                    "attempt_number": 1,
                    "activation_material_digest": "f" * 64,
                    "mutation_possible": True,
                },
            ),
            (
                "REPLACEMENT_IDENTITY_AUTHORIZED",
                {
                    "attempt_number": 1,
                    "initial_requirement_type": 1,
                    "initial_policy_satisfied": False,
                    "final_policy_satisfied": True,
                    "command_status": 0,
                },
            ),
            (
                "REPLACEMENT_ALIAS_UNLOCK_INTENT",
                {
                    "attempt_number": 1,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            ),
        ]
        for milestone, evidence in records:
            activation_journal.append_checked(
                self.journal, self.operation_id, milestone, evidence
            )

    def test_full_activation_proves_fresh_owner_before_enable(self) -> None:
        self.create()
        active = FakeTransport(
            [
                self.alias(t2_user_readiness.DEVICE_LOCKED),
                self.alias(0),
            ]
        )
        independent = FakeTransport([self.alias(0)])
        transports = iter([active, independent])
        history = operation.run_attempt(
            journal_path=self.journal,
            linux_boot_uuid=self.boot,
            transport_factory=lambda: next(transports),
            authorization_factory=self.authorization,
            secret_reader=self.secret,
            mapping_writer=self.writer,
        )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(self.writer.enables, 1)
        self.assertEqual(active.events.count("authorize"), 1)
        self.assertLess(active.events.index("authorize"), active.events.index("unlock"))
        self.assertEqual(active.login_credential, b"I" * 16)
        self.assertEqual(independent.events, ["open", "observe", "close"])

    def test_different_boot_ready_recovery_does_not_redispatch(self) -> None:
        self._append_crash_at_unlock_intent()
        recovery = FakeTransport([self.alias(0)])
        history = operation.reconcile(
            journal_path=self.journal,
            linux_boot_uuid=identifier(13),
            transport_factory=lambda: recovery,
            authorization_factory=self.authorization,
            secret_reader=self.secret,
            mapping_writer=self.writer,
        )
        self.assertEqual(history.phase, "complete")
        self.assertEqual(self.writer.enables, 1)
        self.assertEqual(recovery.events, ["open", "observe", "close"])

    def test_different_boot_uuid_mismatch_quarantines(self) -> None:
        self._append_crash_at_unlock_intent()
        recovery = FakeTransport([self.alias(0, identifier(99))])
        with self.assertRaisesRegex(
            operation.AKSReplacementActivationOperationError, "quarantine"
        ):
            operation.reconcile(
                journal_path=self.journal,
                linux_boot_uuid=identifier(13),
                transport_factory=lambda: recovery,
                authorization_factory=self.authorization,
                secret_reader=self.secret,
                mapping_writer=self.writer,
            )
        self.assertEqual(
            activation_journal.read(self.journal).phase, "quarantined"
        )
        self.assertEqual(self.writer.enables, 0)


if __name__ == "__main__":
    unittest.main()
