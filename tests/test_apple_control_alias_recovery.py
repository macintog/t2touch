# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import copy
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import t2_apple_control_alias_recovery as recovery
import t2_apple_control_alias_discriminator as alias
import t2_apple_control_alias_unlock as unlock
import t2_apple_control_discriminator as keybag
import t2_compatibility_transition as transition
import t2_mutation_journal as journal
import t2_user_authority as authority
import t2_user_mapping as mapping
import t2_user_readiness as readiness
from tests.test_apple_control_alias_discriminator import AliasTransport, MatchedTransport, identifier


class RecoveryTransport(AliasTransport):
    def __init__(self, bag_uuid):
        super().__init__(bag_uuid)
        self.runtime_generation = identifier(24)
        self.ready = False
        self.loaded = False
        self.reject_unlock = False
        self.raise_unlock = False

    def observe_alias(self, special_alias):
        result = super().observe_alias(special_alias)
        if result.present and self.ready:
            return readiness.AliasEvidence(True, special_alias, self.bag_uuid_value, 0)
        return result

    def unlock_alias(self, special_alias, password):
        self.calls.append("unlock")
        if not self.loaded:
            raise RuntimeError("synthetic kernel rejected unlock without active handle")
        if self.raise_unlock:
            raise TimeoutError("synthetic unlock timeout")
        self.ready = not self.reject_unlock
        return 1 if self.reject_unlock else 0

    def load_keybag(self, path):
        handle = super().load_keybag(path)
        self.loaded = True
        return handle

    def unload_keybag(self, handle):
        status = super().unload_keybag(handle)
        self.loaded = False
        return status


class AliasRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.oracle = self.root / "oracle"
        self.oracle.mkdir(mode=0o700)
        (self.root / "users.json").write_text("{}")
        self.evidence = keybag.OracleEvidence(
            identifier(1), "a" * 64, 1000, 501, identifier(2),
            str(self.root / "user.kb"), "b" * 64,
        )
        (self.root / "user.kb").write_bytes(b"synthetic saved keybag")
        keybag_path = self.oracle / "apple-control-discriminator.jsonl"
        keybag.run(journal_path=keybag_path, evidence=self.evidence,
                   linux_boot_uuid=identifier(10), transport=MatchedTransport(),
                   operation_id=identifier(30))
        self.matched = alias.read_matched_keybag_proof(keybag_path, self.evidence)
        bind_path = self.oracle / "apple-control-alias-discriminator.jsonl"
        alias.run(journal_path=bind_path, evidence=self.evidence,
                  matched_proof=self.matched, linux_boot_uuid=identifier(11),
                  transport=AliasTransport(self.evidence.bag_uuid), operation_id=identifier(31))
        self.bound = alias.read_bound_alias_proof(bind_path, self.evidence, self.matched)
        self.failed_path = self.oracle / recovery.FAILED_JOURNAL
        absent = RecoveryTransport(self.evidence.bag_uuid)
        absent.runtime_generation = identifier(23)
        with self.assertRaises(unlock.AppleControlAliasUnlockError):
            unlock.run(journal_path=self.failed_path, evidence=self.evidence,
                       proof=self.bound, linux_boot_uuid=identifier(12),
                       transport=absent, password=bytearray(b"synthetic-password"),
                       operation_id=identifier(32))
        self.assertEqual(absent.calls, ["observe"])

    def invoke(self, transport=None, boot=None):
        transport = transport or RecoveryTransport(self.evidence.bag_uuid)
        password = bytearray(b"synthetic-password")
        try:
            return recovery.run(
                oracle=self.oracle, evidence=self.evidence, matched=self.matched,
                bound=self.bound, linux_boot_uuid=boot or identifier(13),
                transport=transport, password=password,
            )
        finally:
            self.assertEqual(password, bytearray(len(password)))

    def inspect(self):
        with mock.patch.object(transition, "_evidence", return_value=self.evidence):
            return transition.inspect(linux_uid=1000, linux_user="tester", state_root=self.root)

    def rewrite(self, path, records):
        path.unlink()
        for index, record in enumerate(records):
            journal.append(path, record["operation_id"], record["milestone"],
                           record["evidence"], exclusive=index == 0)

    def load_authority(self):
        disabled = mapping.UserMapping(
            1000, "c" * 64, 501, identifier(3), self.evidence.bag_uuid,
            self.evidence.keybag_path, self.evidence.keybag_sha256,
            "disabled", frozenset(), False,
        )
        # Only authority's root gate is substituted; journal ownership checks
        # still validate the actual test process owner and private files.
        with (
            mock.patch.object(authority, "os", SimpleNamespace(geteuid=lambda: 0, path=os.path)),
            mock.patch.object(keybag, "read_oracle_import", return_value=self.evidence),
            mock.patch.object(mapping, "load", return_value=mapping.UserMappingSet(
                self.evidence.mapping_generation, (disabled,)
            )),
        ):
            result = authority.load_compatibility(1000, state_root=self.root)
        self.assertFalse(disabled.enabled)
        return result

    def test_recovery_completes_authority_without_changing_original_state(self):
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        status = self.inspect()
        self.assertEqual(status.phase, transition.UNLOCK_RECOVERY_REQUIRED)
        self.assertIn("recover", status.next_command)
        transport = RecoveryTransport(self.evidence.bag_uuid)
        result = self.invoke(transport)
        self.assertTrue(result["recovery_complete"])
        self.assertEqual(transport.calls, [
            "observe", "load", "double-uuid", "bind", "observe",
            "observe", "unlock", "observe", "unload", "observe",
        ])
        self.assertEqual(self.inspect().phase, transition.COMPLETE)
        proof = recovery.read_completed_recovery(self.oracle, self.evidence, self.matched, self.bound)
        self.assertEqual(proof.unlocked.linux_boot_uuid, identifier(13))
        loaded = self.load_authority()
        self.assertTrue(loaded.selected.enabled)
        self.assertEqual(loaded.enrollment_journal, self.oracle / recovery.JOURNAL)
        self.assertEqual(loaded.mapping_set.generation, self.load_authority().mapping_set.generation)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        added = {p.name for p in self.root.rglob("*") if p.is_file() and p not in before}
        self.assertEqual(added, set(recovery.ARTIFACTS))
        for name in recovery.ARTIFACTS:
            self.assertNotIn(b"synthetic-password", (self.oracle / name).read_bytes())
        second = RecoveryTransport(self.evidence.bag_uuid)
        with self.assertRaisesRegex(recovery.AliasRecoveryError, "already exist"):
            self.invoke(second)
        self.assertEqual(second.calls, [])

    def test_same_boot_and_runtime_block_before_hardware(self):
        for boot, runtime in ((12, 24), (11, 24), (13, 23), (13, 21), (13, 20)):
            with self.subTest(boot=boot, runtime=runtime):
                transport = RecoveryTransport(self.evidence.bag_uuid)
                transport.runtime_generation = identifier(runtime)
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke(transport, identifier(boot))
                self.assertEqual(transport.calls, [])
                self.assertFalse((self.oracle / recovery.JOURNAL).exists())

    def test_completed_recovery_reader_requires_boot_and_runtime_after_matched(self):
        self.invoke()
        journal_path = self.oracle / recovery.JOURNAL
        original = journal.read(journal_path)
        for field, value in (("linux_boot_uuid", self.matched.linux_boot_uuid),
                             ("runtime_generation", self.matched.runtime_generation)):
            with self.subTest(field=field):
                records = copy.deepcopy(original)
                records[0]["evidence"][field] = value
                self.rewrite(journal_path, records)
                with self.assertRaises(recovery.AliasRecoveryError):
                    recovery.read_completed_recovery(
                        self.oracle, self.evidence, self.matched, self.bound
                    )
        self.rewrite(journal_path, original)

    def test_operation_id_collision_exhaustion_precedes_any_hardware(self):
        transport = RecoveryTransport(self.evidence.bag_uuid)
        with mock.patch.object(recovery.uuid, "uuid4", return_value=uuid.UUID(self.bound.operation_id)):
            with self.assertRaisesRegex(recovery.AliasRecoveryError, "operation IDs"):
                self.invoke(transport)
        self.assertEqual(transport.calls, [])
        self.assertFalse((self.oracle / recovery.JOURNAL).exists())

    def test_existing_alias_is_never_overwritten_or_unlocked(self):
        for matches in (True, False):
            with self.subTest(matches=matches):
                transport = RecoveryTransport(self.evidence.bag_uuid if matches else identifier(99))
                transport.bound = True
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke(transport)
                self.assertEqual(transport.calls, ["observe"])
                self.assertIsNone(self.inspect().next_command)
                for name in recovery.ARTIFACTS:
                    (self.oracle / name).unlink(missing_ok=True)

    def test_ambiguous_bind_unload_or_unlock_never_retries(self):
        for failure in ("fail_bind_readback", "fail_unload", "reject_unlock", "raise_unlock"):
            with self.subTest(failure=failure):
                transport = RecoveryTransport(self.evidence.bag_uuid)
                setattr(transport, failure, True)
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke(transport)
                self.assertLessEqual(transport.calls.count("bind"), 1)
                self.assertLessEqual(transport.calls.count("unload"), 1)
                self.assertLessEqual(transport.calls.count("unlock"), 1)
                with self.assertRaises(authority.UserAuthorityError):
                    self.load_authority()
                self.assertIsNone(self.inspect().next_command)
                for name in recovery.ARTIFACTS:
                    (self.oracle / name).unlink(missing_ok=True)

    def test_failed_prestate_proof_rejects_cross_user_mutation_and_extra_fields(self):
        original = journal.read(self.failed_path)
        changes = [
            (0, "linux_uid", 1001), (0, "bag_uuid", identifier(99)),
            (0, "reconciliation_operation_id", identifier(99)),
            (0, "mapping_generation", "f" * 64), (0, "mapping_enabled", 0),
            (1, "mutation_performed", True), (1, "mutation_performed", 0),
            (1, "stage", "unlock"), (1, "stage", "readback"),
            (1, "extra", False),
        ]
        for index, field, value in changes:
            with self.subTest(field=field, value=value):
                records = copy.deepcopy(original)
                records[index]["evidence"][field] = value
                self.rewrite(self.failed_path, records)
                transport = RecoveryTransport(self.evidence.bag_uuid)
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke(transport)
                self.assertEqual(transport.calls, [])
                self.assertIsNone(self.inspect().next_command)

    def test_partial_artifact_and_symlink_prevent_transport_open(self):
        for name in recovery.ARTIFACTS:
            path = self.oracle / name
            path.symlink_to(self.oracle / "missing")
            password = bytearray(b"test")
            with (
                mock.patch.object(transition, "_evidence", return_value=self.evidence),
                mock.patch.object(transition, "_boot_id", return_value=identifier(13)),
                mock.patch.object(transition.t2_aks_transport, "AKSActivationTransport") as hardware,
            ):
                with self.assertRaises(recovery.AliasRecoveryError):
                    transition.recover(linux_uid=1000, password=password, state_root=self.root)
                hardware.assert_not_called()
                self.assertEqual(password, bytearray(4))
            path.unlink()

    def test_completed_proof_requires_all_children_and_exact_recovery_links(self):
        self.invoke()
        path = self.oracle / recovery.JOURNAL
        original = journal.read(path)
        for field, value in (("failed_unlock_operation_id", identifier(99)),
                             ("recovery_bind_operation_id", identifier(99)),
                             ("linux_boot_uuid", identifier(99)),
                             ("runtime_generation", identifier(99)),
                             ("mapping_enabled", 0)):
            with self.subTest(field=field):
                records = copy.deepcopy(original)
                records[0]["evidence"][field] = value
                self.rewrite(path, records)
                with self.assertRaises(authority.UserAuthorityError):
                    self.load_authority()
        self.rewrite(path, original)
        (self.oracle / recovery.BIND_JOURNAL).unlink()
        with self.assertRaises(authority.UserAuthorityError):
            self.load_authority()

    def test_journal_failure_prevents_mutation_and_wipes_password(self):
        transport = RecoveryTransport(self.evidence.bag_uuid)
        with mock.patch.object(journal, "append", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(recovery.AliasRecoveryError):
                self.invoke(transport)
        self.assertEqual(transport.calls, [])

    def test_failed_unlock_with_intent_or_changed_operation_cannot_recover(self):
        original = journal.read(self.failed_path)
        variants = []
        changed = copy.deepcopy(original)
        changed[1]["operation_id"] = identifier(99)
        with mock.patch.object(recovery, "_read", return_value=changed):
            with self.assertRaises(recovery.AliasRecoveryError):
                self.invoke()
        changed = copy.deepcopy(original)
        changed.insert(1, {
            "operation_id": identifier(32),
            "milestone": "APPLE_CONTROL_ALIAS_UNLOCK_INTENT",
            "evidence": {"mutation_possible": True},
        })
        variants.append(changed)
        for records in variants:
            self.rewrite(self.failed_path, records)
            with self.assertRaises(recovery.AliasRecoveryError):
                self.invoke()
            self.assertFalse((self.oracle / recovery.JOURNAL).exists())

    def test_transition_success_uses_validated_recovery_and_wipes_input(self):
        transport = RecoveryTransport(self.evidence.bag_uuid)
        password = bytearray(b"synthetic-password")
        with (
            mock.patch.object(transition, "_evidence", return_value=self.evidence),
            mock.patch.object(transition, "_boot_id", return_value=identifier(13)),
            mock.patch.object(transition.t2_aks_transport, "AKSActivationTransport") as hardware,
        ):
            hardware.return_value.__enter__.return_value = transport
            self.assertTrue(transition.recover(
                linux_uid=1000, password=password, state_root=self.root,
            )["recovery_complete"])
        self.assertEqual(password, bytearray(len(password)))
        self.assertEqual(self.inspect().phase, transition.COMPLETE)


class CapacityFixRecoveryTests(unittest.TestCase):
    def setUp(self):
        AliasRecoveryTests.setUp(self)
        self.failed_recovery_operation = identifier(33)
        self.failed_recovery_bind = identifier(34)
        self.failed_recovery_unlock = identifier(35)
        failed = recovery.read_failed_prestate_proof(
            self.oracle, self.evidence, self.matched, self.bound
        )
        old_baseline = recovery._baseline(
            self.evidence,
            self.matched,
            self.bound,
            failed,
            identifier(13),
            identifier(24),
            self.failed_recovery_bind,
            self.failed_recovery_unlock,
        )
        old_baseline["operation_scope"] = (
            "absent-load-verify-bind-read-unload-read-unlock-read"
        )
        journal.append(
            self.oracle / recovery.JOURNAL,
            self.failed_recovery_operation,
            "APPLE_CONTROL_ALIAS_RECOVERY_BASELINE",
            old_baseline,
            exclusive=True,
        )
        old_transport = RecoveryTransport(self.evidence.bag_uuid)
        alias.run(
            journal_path=self.oracle / recovery.BIND_JOURNAL,
            evidence=self.evidence,
            matched_proof=self.matched,
            linux_boot_uuid=identifier(13),
            transport=old_transport,
            operation_id=self.failed_recovery_bind,
        )
        old_password = bytearray(b"synthetic-password")
        result = unlock.run(
            journal_path=self.oracle / recovery.UNLOCK_JOURNAL,
            evidence=self.evidence,
            proof=self.bound,
            linux_boot_uuid=identifier(13),
            transport=old_transport,
            password=old_password,
            operation_id=self.failed_recovery_unlock,
        )
        self.assertEqual(result.outcome, "unlock-rejected")
        self.assertEqual(old_password, bytearray(len(old_password)))
        journal.append(
            self.oracle / recovery.JOURNAL,
            self.failed_recovery_operation,
            "APPLE_CONTROL_ALIAS_RECOVERY_UNKNOWN",
            {
                "runtime_generation": identifier(24),
                "stage": "unlock",
                "retry_permitted": False,
            },
        )

    def capacity_transport(self):
        transport = RecoveryTransport(self.evidence.bag_uuid)
        transport.runtime_generation = identifier(25)
        return transport

    def invoke_capacity(self, transport=None, boot=None):
        transport = transport or self.capacity_transport()
        password = bytearray(b"synthetic-password")
        try:
            return recovery.run_capacity_fix(
                oracle=self.oracle,
                evidence=self.evidence,
                matched=self.matched,
                bound=self.bound,
                linux_boot_uuid=boot or identifier(14),
                transport=transport,
                password=password,
                predispatch_capacity_defect_acknowledged=True,
            )
        finally:
            self.assertEqual(password, bytearray(len(password)))

    def load_authority(self):
        return AliasRecoveryTests.load_authority(self)

    def inspect(self):
        return AliasRecoveryTests.inspect(self)

    def rewrite(self, path, records):
        return AliasRecoveryTests.rewrite(self, path, records)

    def test_exact_failed_chain_continues_in_handle_lifecycle_and_enables_authority(self):
        failed = recovery.read_failed_recovery_for_capacity_fix(
            self.oracle, self.evidence, self.matched, self.bound
        )
        self.assertEqual(failed.operation_id, self.failed_recovery_operation)
        status = self.inspect()
        self.assertEqual(status.phase, transition.UNLOCK_RECOVERY_REQUIRED)
        self.assertIn("recover-capacity-fix", status.next_command)
        transport = self.capacity_transport()
        result = self.invoke_capacity(transport)
        self.assertTrue(result["capacity_fix_recovery_complete"])
        self.assertEqual(
            transport.calls,
            [
                "observe", "load", "double-uuid", "bind", "observe",
                "observe", "unlock", "observe", "unload", "observe",
            ],
        )
        proof = recovery.read_completed_capacity_fix(
            self.oracle, self.evidence, self.matched, self.bound
        )
        self.assertEqual(proof.failed_recovery_operation_id, failed.operation_id)
        self.assertEqual(self.inspect().phase, transition.COMPLETE)
        loaded = self.load_authority()
        self.assertTrue(loaded.selected.enabled)
        self.assertEqual(
            loaded.enrollment_journal, self.oracle / recovery.CAPACITY_JOURNAL
        )
        replay = self.capacity_transport()
        with self.assertRaisesRegex(recovery.AliasRecoveryError, "already exist"):
            self.invoke_capacity(replay)
        self.assertEqual(replay.calls, [])

    def test_status_withholds_capacity_fix_on_failed_recovery_boot(self):
        with (
            mock.patch.object(transition, "_evidence", return_value=self.evidence),
            mock.patch.object(transition, "_boot_id", return_value=identifier(13)),
        ):
            status = transition.inspect(
                linux_uid=1000, linux_user="tester", state_root=self.root
            )
        self.assertEqual(status.phase, transition.UNLOCK_RECOVERY_REQUIRED)
        self.assertIsNone(status.next_command)
        self.assertIn("reboot", status.detail)

    def test_failed_chain_rejects_mutations_extras_and_cross_links(self):
        cases = [
            (recovery.JOURNAL, 0, "failed_recovery_unlock_operation_id", identifier(99)),
            (recovery.JOURNAL, 1, "stage", "bind"),
            (recovery.JOURNAL, 1, "extra", False),
            (recovery.BIND_JOURNAL, 9, "outcome", "precondition-already-bound"),
            (recovery.UNLOCK_JOURNAL, 1, "unlock_actionable", False),
            (recovery.UNLOCK_JOURNAL, 3, "command_raised", False),
            (recovery.UNLOCK_JOURNAL, 3, "command_status", 0),
            (recovery.UNLOCK_JOURNAL, 3, "unlocked", True),
            (recovery.UNLOCK_JOURNAL, 4, "outcome", "unlocked"),
        ]
        originals = {
            name: journal.read(self.oracle / name)
            for name in (recovery.JOURNAL, recovery.BIND_JOURNAL, recovery.UNLOCK_JOURNAL)
        }
        for name, index, field, value in cases:
            with self.subTest(name=name, field=field):
                records = copy.deepcopy(originals[name])
                records[index]["evidence"][field] = value
                self.rewrite(self.oracle / name, records)
                transport = self.capacity_transport()
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke_capacity(transport)
                self.assertEqual(transport.calls, [])
                self.rewrite(self.oracle / name, originals[name])

    def test_alias_present_same_boot_and_prior_runtime_refuse_without_dispatch(self):
        for boot, runtime in ((13, 25), (10, 25), (11, 25), (12, 25), (14, 24),
                              (14, 23), (14, 21), (14, 20)):
            with self.subTest(boot=boot, runtime=runtime):
                transport = self.capacity_transport()
                transport.runtime_generation = identifier(runtime)
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke_capacity(transport, identifier(boot))
                self.assertEqual(transport.calls, [])
                self.assertFalse((self.oracle / recovery.CAPACITY_JOURNAL).exists())
        transport = self.capacity_transport()
        transport.bound = True
        with self.assertRaises(recovery.AliasRecoveryError):
            self.invoke_capacity(transport)
        self.assertEqual(transport.calls, ["observe"])
        self.assertNotIn("unlock", transport.calls)

    def test_capacity_artifact_or_symlink_refuses_before_transport_open(self):
        for name in recovery.CAPACITY_ARTIFACTS:
            path = self.oracle / name
            path.symlink_to(self.oracle / "missing")
            password = bytearray(b"test")
            with (
                mock.patch.object(transition, "_evidence", return_value=self.evidence),
                mock.patch.object(transition, "_boot_id", return_value=identifier(14)),
                mock.patch.object(
                    transition.t2_aks_transport, "AKSActivationTransport"
                ) as hardware,
            ):
                with self.assertRaises(recovery.AliasRecoveryError):
                    transition.recover_capacity_fix(
                        linux_uid=1000, password=password,
                        predispatch_capacity_defect_acknowledged=True,
                        state_root=self.root,
                    )
                hardware.assert_not_called()
                self.assertEqual(password, bytearray(4))
            path.unlink()

    def test_capacity_fix_requires_predispatch_ack_before_hardware(self):
        transport = self.capacity_transport()
        password = bytearray(b"test")
        with self.assertRaisesRegex(recovery.AliasRecoveryError, "acknowledgement"):
            recovery.run_capacity_fix(
                oracle=self.oracle,
                evidence=self.evidence,
                matched=self.matched,
                bound=self.bound,
                linux_boot_uuid=identifier(14),
                transport=transport,
                password=password,
                predispatch_capacity_defect_acknowledged=False,
            )
        self.assertEqual(transport.calls, [])
        self.assertEqual(password, bytearray(4))

    def test_same_boot_refuses_before_transport_open(self):
        password = bytearray(b"test")
        with (
            mock.patch.object(transition, "_evidence", return_value=self.evidence),
            mock.patch.object(transition, "_boot_id", return_value=identifier(13)),
            mock.patch.object(
                transition.t2_aks_transport, "AKSActivationTransport"
            ) as hardware,
        ):
            with self.assertRaisesRegex(recovery.AliasRecoveryError, "fresh later boot"):
                transition.recover_capacity_fix(
                    linux_uid=1000, password=password,
                    predispatch_capacity_defect_acknowledged=True,
                    state_root=self.root,
                )
            hardware.assert_not_called()
        self.assertEqual(password, bytearray(4))

    def test_capacity_fix_failures_are_terminal_and_never_redispatch(self):
        for failure in ("fail_bind_readback", "reject_unlock", "raise_unlock", "fail_unload"):
            with self.subTest(failure=failure):
                transport = self.capacity_transport()
                setattr(transport, failure, True)
                with self.assertRaises(recovery.AliasRecoveryError):
                    self.invoke_capacity(transport)
                self.assertLessEqual(transport.calls.count("bind"), 1)
                self.assertLessEqual(transport.calls.count("unlock"), 1)
                self.assertLessEqual(transport.calls.count("unload"), 1)
                parent = journal.read(self.oracle / recovery.CAPACITY_JOURNAL)
                self.assertEqual(
                    parent[-1]["milestone"],
                    "APPLE_CONTROL_ALIAS_CAPACITY_FIX_UNKNOWN",
                )
                self.assertFalse(parent[-1]["evidence"]["retry_permitted"])
                self.assertIsNone(self.inspect().next_command)
                for name in recovery.CAPACITY_ARTIFACTS:
                    (self.oracle / name).unlink(missing_ok=True)


class RecoveryCommandTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "src/t2-touchid-migrate-compatibility.py"
        spec = importlib.util.spec_from_file_location("compatibility_cli", path)
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)

    def arguments(self, acknowledge=True):
        args = ["recover", "--linux-user", "tester", "--password-prompt",
                "--acknowledge-research-mac-and-macos-recovery"]
        if acknowledge:
            args.append("--acknowledge-one-shot-alias-recovery")
        return self.cli._build_parser().parse_args(args)

    def test_acknowledgement_precedes_password_and_transport(self):
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli.getpass, "getpass") as prompt,
            mock.patch.object(transition, "recover") as run,
        ):
            with self.assertRaises(self.cli.CommandError):
                self.cli._dispatch(self.arguments(False))
            prompt.assert_not_called()
            run.assert_not_called()

    def test_research_mac_and_macos_recovery_ack_precedes_password(self):
        arguments = self.arguments()
        arguments.acknowledge_research_mac_and_macos_recovery = False
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli.getpass, "getpass") as prompt,
            mock.patch.object(transition, "recover") as run,
        ):
            with self.assertRaisesRegex(self.cli.CommandError, "research Mac"):
                self.cli._dispatch(arguments)
            prompt.assert_not_called()
            run.assert_not_called()

    def test_prompt_password_is_not_printed_and_buffer_is_wiped(self):
        output = io.StringIO()
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(self.cli.getpass, "getpass", return_value="synthetic-password"),
            mock.patch.object(transition, "recover", return_value={"recovery_complete": True}) as run,
            mock.patch.object(self.cli.sys, "stdout", output),
        ):
            self.assertEqual(self.cli._dispatch(self.arguments()), 0)
        self.assertNotIn("synthetic-password", output.getvalue())
        self.assertEqual(run.call_args.kwargs["password"], bytearray(18))

    def test_nonterminal_prompt_refuses_without_reading_password(self):
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli.sys.stdin, "isatty", return_value=False),
            mock.patch.object(self.cli.getpass, "getpass") as prompt,
        ):
            with self.assertRaisesRegex(self.cli.CommandError, "requires a terminal"):
                self.cli._dispatch(self.arguments())
            prompt.assert_not_called()

    def test_capacity_fix_requires_both_acks_and_wipes_prompt_password(self):
        parser = self.cli._build_parser()
        base = [
            "recover-capacity-fix", "--linux-user", "tester", "--password-prompt",
        ]
        for missing in ("capacity", "predispatch", "research"):
            args = list(base)
            if missing != "capacity":
                args.append("--acknowledge-one-shot-capacity-fix")
            if missing != "research":
                args.append("--acknowledge-research-mac-and-macos-recovery")
            if missing != "predispatch":
                args.append("--acknowledge-known-predispatch-capacity-defect")
            with (
                self.subTest(missing=missing),
                mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
                mock.patch.object(self.cli.getpass, "getpass") as prompt,
                mock.patch.object(transition, "recover_capacity_fix") as run,
            ):
                with self.assertRaises(self.cli.CommandError):
                    self.cli._dispatch(parser.parse_args(args))
                prompt.assert_not_called()
                run.assert_not_called()
        args = parser.parse_args(base + [
            "--acknowledge-one-shot-capacity-fix",
            "--acknowledge-known-predispatch-capacity-defect",
            "--acknowledge-research-mac-and-macos-recovery",
        ])
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(self.cli.getpass, "getpass", return_value="synthetic-password"),
            mock.patch.object(
                transition, "recover_capacity_fix",
                return_value={"capacity_fix_recovery_complete": True},
            ) as run,
            mock.patch.object(self.cli.sys, "stdout", io.StringIO()),
        ):
            self.assertEqual(self.cli._dispatch(args), 0)
        self.assertEqual(run.call_args.kwargs["password"], bytearray(18))

    def test_capacity_fix_accepts_hidden_stdin_and_wipes_it(self):
        args = self.cli._build_parser().parse_args([
            "recover-capacity-fix", "--linux-user", "tester", "--password-stdin",
            "--acknowledge-one-shot-capacity-fix",
            "--acknowledge-known-predispatch-capacity-defect",
            "--acknowledge-research-mac-and-macos-recovery",
        ])
        supplied = bytearray(b"synthetic-password")
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli, "_password_from_stdin", return_value=supplied),
            mock.patch.object(
                transition, "recover_capacity_fix",
                return_value={"capacity_fix_recovery_complete": True},
            ) as run,
            mock.patch.object(self.cli.sys, "stdout", io.StringIO()),
        ):
            self.assertEqual(self.cli._dispatch(args), 0)
        self.assertIs(run.call_args.kwargs["password"], supplied)
        self.assertEqual(supplied, bytearray(len(supplied)))

    def test_capacity_fix_prompt_mismatch_stops_before_transition(self):
        args = self.cli._build_parser().parse_args([
            "recover-capacity-fix", "--linux-user", "tester", "--password-prompt",
            "--acknowledge-one-shot-capacity-fix",
            "--acknowledge-known-predispatch-capacity-defect",
            "--acknowledge-research-mac-and-macos-recovery",
        ])
        with (
            mock.patch.object(self.cli, "_account", return_value=SimpleNamespace(pw_uid=1000)),
            mock.patch.object(self.cli.sys.stdin, "isatty", return_value=True),
            mock.patch.object(
                self.cli.getpass, "getpass", side_effect=["first", "second"]
            ),
            mock.patch.object(transition, "recover_capacity_fix") as run,
        ):
            with self.assertRaisesRegex(self.cli.CommandError, "did not match"):
                self.cli._dispatch(args)
        run.assert_not_called()
