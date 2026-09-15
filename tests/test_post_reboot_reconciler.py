# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import errno
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_enrollment_journal as enrollment_journal
import t2_catacomb_codec as catacomb_codec
import t2_identity_delete_journal as delete_journal
import t2_identity_rename_journal as rename_journal
import t2_linux_account as linux_account
import t2_post_reboot_reconciler as reconciler
import t2_post_reboot_diagnostic as post_reboot_diagnostic
import t2_native_post_reboot_reconciler as native_reconciler
import t2_user_mapping as mapping
import t2_user_readiness as readiness
import t2_user_reconciliation_live as live_reconciliation
from tests.test_catacomb_codec import fixture


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class Live:
    def __init__(self, selected, material):
        self.selected = selected
        self.material = material
        self.runtime_generation = material.connection_generation
        self.entered = False
        self.exited = False
        self.collect_count = 0

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.exited = True
        return False

    def collect(self, selected, generation, keybag_sha256):
        self.collect_count += 1
        if (
            selected != self.selected
            or generation != self.selected.linux_account_generation
            or keybag_sha256 != self.selected.keybag_sha256
        ):
            raise AssertionError("wrong live binding")
        return (
            readiness.PersistentEvidence(
                generation,
                keybag_sha256,
                selected.apple_uid,
                selected.account_uuid,
                selected.bag_uuid,
                True,
            ),
            readiness.AliasEvidence(
                True,
                selected.special_bag_alias,
                selected.bag_uuid,
                0,
                selected.account_uuid,
            ),
        )

    def revalidate_runtime_keybag(self, selected, positive_handle):
        return selected == self.selected and positive_handle == 42

    def prepare_post_reboot_material(self, selected, _baseline):
        if selected != self.selected:
            raise AssertionError("wrong material mapping")
        return self.material


class PostRebootReconcilerTests(unittest.TestCase):
    def test_child_failure_reason_accepts_only_exact_public_messages(self):
        message = b"t2-touchid-manage: restored master Catacomb does not advertise the selected user"
        self.assertEqual(post_reboot_diagnostic.child_failure_reason(message + b"\n"),
                         "restore-user-not-advertised")
        self.assertEqual(
            post_reboot_diagnostic.child_failure_reason(
                b"t2-touchid-manage: live T2 authority belongs to another installation\n"
            ),
            "foreign-live-authority",
        )
        for private in (b"private payload", message + b" private identifier", b"x" * 513,
                        "private payload", None):
            self.assertIsNone(post_reboot_diagnostic.child_failure_reason(private))
        with self.assertRaises(ValueError):
            post_reboot_diagnostic.staged("external-deletion-reconciliation",
                                          RuntimeError(), reason="private identifier")

    def test_external_reconciliation_skips_only_empty_initial_state(self):
        mapping_set = SimpleNamespace(
            mappings=(SimpleNamespace(enabled=True, linux_uid=1000),)
        )
        for retained in (None, "manifest", "dangling-manifest", "mutation", "catacomb", "journal"):
            with self.subTest(retained=retained), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                users = root / "users"
                user = users / "1000"
                mutations = root / "mutations"
                catacomb = root / "catacomb"
                for directory in (user, mutations, catacomb):
                    directory.mkdir(parents=True)
                if retained == "manifest":
                    (user / "authority.json").write_text("invalid")
                elif retained == "dangling-manifest":
                    (user / "authority.json").symlink_to(user / "absent")
                elif retained == "mutation":
                    (mutations / "retained.jsonl").touch()
                elif retained == "catacomb":
                    (catacomb / "prepare").mkdir()
                elif retained == "journal":
                    (user / "retained.jsonl").touch()
                runner = mock.Mock(return_value=SimpleNamespace(returncode=17))
                with (
                    mock.patch.object(native_reconciler.t2_user_mapping, "load", return_value=mapping_set),
                    mock.patch.object(native_reconciler.t2_user_authority, "USERS_ROOT", users),
                    mock.patch.object(native_reconciler, "MUTATION_ROOT", mutations),
                    mock.patch.object(native_reconciler, "CATACOMB_ROOT", catacomb),
                ):
                    if retained is None:
                        result = native_reconciler.reconcile_external_deletion_if_needed(runner=runner)
                        self.assertEqual(result.state, "no-pending-mutation")
                        self.assertFalse(result.journal_updated)
                        runner.assert_not_called()
                    else:
                        with self.assertRaises(post_reboot_diagnostic.PostRebootStageError) as caught:
                            native_reconciler.reconcile_external_deletion_if_needed(runner=runner)
                        failure = caught.exception.redacted()
                        self.assertEqual(failure["stage"], "external-deletion-reconciliation")
                        self.assertEqual(failure["child_exit_status"], 17)
                        runner.assert_called_once()

    def test_failure_diagnostic_is_bounded_and_redacted(self):
        private = OSError(errno.EIO, "/private/identifier/payload")
        failure = post_reboot_diagnostic.staged(
            "inventory-collection", private
        ).redacted()

        self.assertEqual(failure["stage"], "inventory-collection")
        self.assertEqual(failure["exception_class"], "OSError")
        self.assertEqual(failure["errno"], errno.EIO)
        self.assertIsNone(failure["child_exit_status"])
        encoded = json.dumps(failure, sort_keys=True)
        self.assertNotIn("/private/identifier/payload", encoded)
        self.assertNotIn("payload", encoded)

    def setUp(self):
        self.mapping = mapping.UserMapping(
            1000,
            "a" * 64,
            501,
            identifier(1),
            identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb",
            "b" * 64,
            "host-encrypted-credential",
            frozenset({"enroll", "identity-management", "verify"}),
            True,
        )
        self.mapping_set = mapping.UserMappingSet(
            "d" * 64, (self.mapping,)
        )
        self.protected_mapping_set = mapping.UserMappingSet(
            "c" * 64,
            (
                mapping.UserMapping(
                    self.mapping.linux_uid,
                    self.mapping.linux_account_generation,
                    self.mapping.apple_uid,
                    self.mapping.account_uuid,
                    self.mapping.bag_uuid,
                    self.mapping.keybag_path,
                    self.mapping.keybag_sha256,
                    self.mapping.unlock_mode,
                    self.mapping.capabilities,
                    False,
                ),
            ),
        )
        self.baseline = {
            "caller_linux_uid": 1000,
            "target_linux_uid": 1000,
            "apple_uid": 501,
            "account_uuid": identifier(1),
            "bag_uuid": identifier(2),
            "mapping_generation": "d" * 64,
        }
        self.history = SimpleNamespace(
            operation_id=identifier(20),
            phase=enrollment_journal.EnrollmentPhase.RECONCILED,
            record_count=10,
            head_hash="e" * 64,
            baseline=self.baseline,
            terminal_identity_uuid=identifier(21),
        )
        self.path = Path("/var/lib/t2-touchid/mutations") / (
            f"{self.history.operation_id}.jsonl"
        )
        self.local = catacomb_codec.decode_user_catacomb(fixture(), 501)
        self.material = live_reconciliation.PostRebootMaterial(
            {"host": True},
            {"live": True},
            self.local,
            501,
            identifier(30),
        )
        self.live = Live(self.mapping, self.material)
        self.account = linux_account.AccountEvidence(1000, "a" * 64)
        self.authority = reconciler.t2_user_authority.RuntimeUserAuthority(
            self.mapping_set,
            self.mapping,
            readiness.PersistentEvidence(
                "a" * 64,
                "b" * 64,
                501,
                identifier(1),
                identifier(2),
                True,
            ),
            Path("/var/lib/t2-touchid/oracle/proof.jsonl"),
            "macos-control-oracle-v1",
        )

        self.candidate = reconciler.PendingMutation(
            "enroll", "enroll", self.path, self.history
        )

    def common_patches(self, candidate=None):
        return (
            mock.patch.object(reconciler, "ROOT_UID", os.geteuid()),
            mock.patch.object(
                reconciler,
                "_pending_candidate",
                return_value=candidate or self.candidate,
            ),
            mock.patch.object(
                reconciler.t2_user_mapping_admin,
                "_open_parent",
                return_value=(10, "users.json"),
            ),
            mock.patch.object(
                reconciler.t2_user_mapping_admin,
                "_open_lock",
                return_value=11,
            ),
            mock.patch.object(
                reconciler.t2_user_mapping_admin,
                "_load_optional",
                return_value=self.protected_mapping_set,
            ),
            mock.patch.object(reconciler, "_unchanged_history"),
            mock.patch.object(reconciler.os, "close"),
        )

    def test_no_pending_enrollment_is_a_read_only_noop(self):
        with mock.patch.object(reconciler, "ROOT_UID", os.geteuid()), mock.patch.object(
            reconciler, "_pending_candidate", return_value=None
        ), mock.patch.object(
            reconciler.t2_user_mapping_admin, "_open_parent"
        ) as open_parent:
            result = reconciler.run()
        self.assertEqual(result.state, "no-pending-mutation")
        self.assertFalse(result.journal_updated)
        open_parent.assert_not_called()

    def test_stable_fresh_boot_appends_only_e4(self):
        verified = SimpleNamespace(
            phase=enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )
        append = mock.Mock(return_value=verified)
        patches = self.common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], mock.patch.object(
            reconciler.t2_enrollment_reconciliation,
            "append_post_reboot_verified",
            append,
        ):
            result = reconciler.run(
                live_factory=lambda: self.live,
                account_collector=lambda _uid: self.account,
                keybag_reader=lambda _path: "b" * 64,
                runtime_state=lambda _alias: (1, 42),
                authority_loader=lambda _uid: self.authority,
                boot_reader=lambda: identifier(40),
            )
        self.assertEqual(result.state, "enroll-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        self.assertEqual(self.live.collect_count, 2)
        self.assertTrue(self.live.exited)
        arguments = append.call_args.kwargs
        self.assertIs(arguments["host"], self.material.host)
        self.assertIs(arguments["live"], self.material.live)
        self.assertTrue(arguments["keybag_runtime_revalidated"])

    def test_mapping_drift_fails_before_live_collection_or_append(self):
        self.history.baseline["mapping_generation"] = "f" * 64
        append = mock.Mock()
        patches = self.common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], mock.patch.object(
            reconciler.t2_enrollment_reconciliation,
            "append_post_reboot_verified",
            append,
        ):
            with self.assertRaisesRegex(
                reconciler.PostRebootReconcilerError,
                "another protected mapping",
            ):
                reconciler.run(
                    live_factory=lambda: self.live,
                    account_collector=lambda _uid: self.account,
                    keybag_reader=lambda _path: "b" * 64,
                    runtime_state=lambda _alias: (1, 42),
                    authority_loader=lambda _uid: self.authority,
                    boot_reader=lambda: identifier(40),
                )
        self.assertEqual(self.live.collect_count, 0)
        append.assert_not_called()

    def test_invalid_runtime_handle_fails_before_live_collection(self):
        patches = self.common_patches()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
        ):
            with self.assertRaisesRegex(
                reconciler.PostRebootReconcilerError,
                "runtime keybag state",
            ):
                reconciler.run(
                    live_factory=lambda: self.live,
                    account_collector=lambda _uid: self.account,
                    keybag_reader=lambda _path: "b" * 64,
                    runtime_state=lambda _alias: (2, 42),
                    authority_loader=lambda _uid: self.authority,
                    boot_reader=lambda: identifier(40),
                )
        self.assertEqual(self.live.collect_count, 0)

    def test_native_authority_is_not_misreported_as_automatic_verification(self):
        native = reconciler.t2_user_authority.RuntimeUserAuthority(
            self.mapping_set,
            self.mapping,
            self.authority.persistent,
            self.authority.enrollment_journal,
            "linux-native-e4",
        )
        patches = self.common_patches()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
        ):
            with self.assertRaisesRegex(
                reconciler.PostRebootReconcilerError,
                "requires compatibility authority",
            ):
                reconciler.run(
                    live_factory=lambda: self.live,
                    account_collector=lambda _uid: self.account,
                    keybag_reader=lambda _path: "b" * 64,
                    runtime_state=lambda _alias: (1, 42),
                    authority_loader=lambda _uid: native,
                    boot_reader=lambda: identifier(40),
                )
        self.assertEqual(self.live.collect_count, 0)

    def test_candidate_scan_requires_one_blocking_reconciled_enrollment(self):
        self.history.baseline["baseline_version"] = 2
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"{self.history.operation_id}.jsonl"
            path.touch()
            entry = SimpleNamespace(blocks_new_mutation=True)
            with mock.patch.object(reconciler, "MUTATION_ROOT", root), mock.patch.object(
                reconciler.t2_mutation_registry,
                "scan",
                return_value=(entry,),
            ), mock.patch.object(
                reconciler.t2_mutation_journal,
                "read",
                return_value=[{"evidence": {"operation_kind": "enroll"}}],
            ), mock.patch.object(
                reconciler.t2_enrollment_journal,
                "validate_history",
                return_value=self.history,
            ):
                candidate = reconciler._pending_candidate()
                self.assertEqual(candidate.kind, "enroll")
                self.assertEqual(candidate.capability, "enroll")
                self.assertEqual(candidate.path, path)
                self.assertIs(candidate.history, self.history)

                addition = SimpleNamespace(
                    **{
                        **self.history.__dict__,
                        "baseline": {
                            **self.history.baseline,
                            "baseline_version": 1,
                        },
                    }
                )
                with mock.patch.object(
                    reconciler.t2_enrollment_journal,
                    "validate_history",
                    return_value=addition,
                ):
                    self.assertIsNone(reconciler._pending_candidate())

                with mock.patch.object(
                    reconciler.t2_mutation_registry,
                    "scan",
                    return_value=(entry, entry),
                ):
                    with self.assertRaisesRegex(
                        reconciler.PostRebootReconcilerError,
                        "another biometric mutation",
                    ):
                        reconciler._pending_candidate()

    def test_stable_rename_appends_only_rename_post_reboot_proof(self):
        history = SimpleNamespace(
            operation_id=identifier(50),
            phase=rename_journal.IdentityRenamePhase.RECONCILED,
            record_count=12,
            head_hash="f" * 64,
            baseline=dict(self.baseline),
        )
        path = Path("/var/lib/t2-touchid/mutations") / (
            f"{history.operation_id}.jsonl"
        )
        candidate = reconciler.PendingMutation(
            "rename", "identity-management", path, history
        )
        verified = SimpleNamespace(
            phase=rename_journal.IdentityRenamePhase.POST_REBOOT_VERIFIED
        )
        rename_append = mock.Mock(return_value=verified)
        enrollment_append = mock.Mock()
        patches = self.common_patches(candidate)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            mock.patch.object(
                reconciler.t2_identity_rename_reconciliation,
                "append_post_reboot_verified",
                rename_append,
            ),
            mock.patch.object(
                reconciler.t2_enrollment_reconciliation,
                "append_post_reboot_verified",
                enrollment_append,
            ),
        ):
            result = reconciler.run(
                live_factory=lambda: self.live,
                account_collector=lambda _uid: self.account,
                keybag_reader=lambda _path: "b" * 64,
                runtime_state=lambda _alias: (1, 42),
                authority_loader=lambda _uid: self.authority,
                boot_reader=lambda: identifier(40),
            )
        self.assertEqual(result.state, "rename-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        enrollment_append.assert_not_called()
        self.assertIs(rename_append.call_args.kwargs["local"], self.local)
        self.assertIs(rename_append.call_args.kwargs["host"], self.material.host)
        self.assertIs(rename_append.call_args.kwargs["live"], self.material.live)

    def test_candidate_scan_selects_one_reconciled_rename(self):
        history = SimpleNamespace(
            operation_id=identifier(60),
            phase=rename_journal.IdentityRenamePhase.RECONCILED,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"{history.operation_id}.jsonl"
            path.touch()
            entry = SimpleNamespace(blocks_new_mutation=True)
            with (
                mock.patch.object(reconciler, "MUTATION_ROOT", root),
                mock.patch.object(
                    reconciler.t2_mutation_registry,
                    "scan",
                    return_value=(entry,),
                ),
                mock.patch.object(
                    reconciler.t2_mutation_journal,
                    "read",
                    return_value=[{"evidence": {"operation_kind": "rename"}}],
                ),
                mock.patch.object(
                    reconciler.t2_identity_rename_journal,
                    "validate_history",
                    return_value=history,
                ),
            ):
                candidate = reconciler._pending_candidate()
        self.assertEqual(candidate.kind, "rename")
        self.assertEqual(candidate.capability, "identity-management")
        self.assertEqual(candidate.path, path)
        self.assertIs(candidate.history, history)

    def test_stable_delete_appends_only_delete_post_reboot_proof(self):
        history = SimpleNamespace(
            operation_id=identifier(70),
            phase=delete_journal.IdentityDeletePhase.RECONCILED,
            record_count=14,
            head_hash="9" * 64,
            baseline=dict(self.baseline),
        )
        path = Path("/var/lib/t2-touchid/mutations") / (
            f"{history.operation_id}.jsonl"
        )
        candidate = reconciler.PendingMutation(
            "delete-one", "identity-management", path, history
        )
        verified = SimpleNamespace(
            phase=delete_journal.IdentityDeletePhase.POST_REBOOT_VERIFIED
        )
        delete_append = mock.Mock(return_value=verified)
        enrollment_append = mock.Mock()
        rename_append = mock.Mock()
        patches = self.common_patches(candidate)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            mock.patch.object(
                reconciler.t2_identity_delete_reconciliation,
                "append_post_reboot_verified",
                delete_append,
            ),
            mock.patch.object(
                reconciler.t2_enrollment_reconciliation,
                "append_post_reboot_verified",
                enrollment_append,
            ),
            mock.patch.object(
                reconciler.t2_identity_rename_reconciliation,
                "append_post_reboot_verified",
                rename_append,
            ),
        ):
            result = reconciler.run(
                live_factory=lambda: self.live,
                account_collector=lambda _uid: self.account,
                keybag_reader=lambda _path: "b" * 64,
                runtime_state=lambda _alias: (1, 42),
                authority_loader=lambda _uid: self.authority,
                boot_reader=lambda: identifier(40),
            )
        self.assertEqual(result.state, "delete-one-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        enrollment_append.assert_not_called()
        rename_append.assert_not_called()
        self.assertIs(delete_append.call_args.kwargs["local"], self.local)
        self.assertIs(delete_append.call_args.kwargs["host"], self.material.host)
        self.assertIs(delete_append.call_args.kwargs["live"], self.material.live)

    def test_candidate_scan_leaves_reconciled_delete_complete(self):
        history = SimpleNamespace(
            operation_id=identifier(80),
            phase=delete_journal.IdentityDeletePhase.RECONCILED,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"{history.operation_id}.jsonl"
            path.touch()
            entry = SimpleNamespace(blocks_new_mutation=True)
            with (
                mock.patch.object(reconciler, "MUTATION_ROOT", root),
                mock.patch.object(
                    reconciler.t2_mutation_registry,
                    "scan",
                    return_value=(entry,),
                ),
                mock.patch.object(
                    reconciler.t2_mutation_journal,
                    "read",
                    return_value=[
                        {"evidence": {"operation_kind": "delete-one"}}
                    ],
                ),
                mock.patch.object(
                    reconciler.t2_identity_delete_journal,
                    "validate_history",
                    return_value=history,
                ),
            ):
                candidate = reconciler._pending_candidate()
        self.assertIsNone(candidate)

    def test_service_is_read_only_ordered_and_installed(self):
        root = Path(__file__).parents[1]
        unit = (
            root / "systemd/system/t2-touchid-post-reboot.service"
        ).read_text(encoding="utf-8")
        fprintd = (root / "systemd/system/fprintd.service").read_text(
            encoding="utf-8"
        )
        install = (root / "install.sh").read_text(encoding="utf-8")
        uninstall = (root / "uninstall.sh").read_text(encoding="utf-8")
        for required in (
            "Before=fprintd.service",
            "EnvironmentFile=/etc/t2-touchid.conf",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_IPC_LOCK CAP_SYS_ADMIN",
            "DevicePolicy=closed",
            "DeviceAllow=/dev/t2-aks rw",
            "DeviceAllow=/dev/t2-acm rw",
            "ReadWritePaths=/run/t2-touchid /var/lib/t2-touchid",
        ):
            self.assertIn(required, unit)
        self.assertIn("Requires=t2-biometric-ready.service", unit)
        self.assertNotIn(
            "Requires=t2-keybag-load.service t2-credential-unlock.service", unit
        )
        self.assertNotIn("LoadCredential", unit)
        self.assertNotIn("t2-fprint-enrollment-worker", unit)
        self.assertIn(
            "Requires=t2-native-first-run.service t2-biometric-ready.service t2-touchid-post-reboot.service",
            fprintd,
        )
        first_run = (
            root / "systemd/system/t2-native-first-run.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Before=t2-biometric-ready.service "
            "t2-touchid-post-reboot.service fprintd.service",
            first_run,
        )
        self.assertIn("DeviceAllow=/dev/t2-aks rw", first_run)
        self.assertIn("DeviceAllow=/dev/t2-acm rw", first_run)
        self.assertIn("t2-touchid-post-reboot.py", install)
        self.assertIn("t2-native-first-run.service.d", install)
        self.assertIn("t2-touchid-post-reboot", uninstall)
        self.assertIn("t2-native-first-run", uninstall)

    def test_native_dispatch_routes_each_pending_proof_to_its_owner(self):
        bound_history = SimpleNamespace(
            baseline={"caller_linux_uid": 1000, "target_linux_uid": 1000}
        )
        enrollment = mock.Mock(
            return_value={
                "schema_version": 1,
                "enrollment_post_reboot_verified": True,
                "runtime_authority_published": True,
                "fingerprint_mutation_performed": False,
                "identifiers_redacted": True,
            }
        )
        with mock.patch.object(native_reconciler, "ROOT_UID", os.geteuid()):
            result = native_reconciler.run(
                candidate_loader=lambda: SimpleNamespace(
                    kind="enroll", history=bound_history
                ),
                enrollment_verifier=enrollment,
            )
        self.assertEqual(result.state, "enroll-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        enrollment.assert_called_once_with(1000)

        publication = mock.Mock(
            return_value={
                "schema_version": 1,
                "enrollment_post_reboot_verified": True,
                "runtime_authority_published": True,
                "fingerprint_mutation_performed": False,
                "identifiers_redacted": True,
            }
        )
        publication_history = SimpleNamespace(
            operation_id=identifier(70),
            baseline={"caller_linux_uid": 1000, "target_linux_uid": 1000},
        )
        with mock.patch.object(native_reconciler, "ROOT_UID", os.geteuid()):
            result = native_reconciler.run(
                candidate_loader=lambda: SimpleNamespace(
                    kind="enroll-publication", history=publication_history
                ),
                enrollment_verifier=enrollment,
                publication_recoverer=publication,
            )
        self.assertEqual(result.state, "enroll-authority-published")
        self.assertFalse(result.journal_updated)
        publication.assert_called_once_with(1000, identifier(70))
        enrollment.assert_called_once_with(1000)

        for kind, command, field in (
            ("rename", "verify-post-reboot", "post_reboot_verified"),
            (
                "delete-one",
                "verify-delete-post-reboot",
                "delete_post_reboot_verified",
            ),
        ):
            runner = mock.Mock(
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        {
                            "schema_version": 1,
                            field: True,
                            "identifiers_redacted": True,
                        }
                    ).encode(),
                )
            )
            with mock.patch.object(native_reconciler, "ROOT_UID", os.geteuid()):
                result = native_reconciler.run(
                    candidate_loader=lambda kind=kind: SimpleNamespace(
                        kind=kind, history=bound_history
                    ),
                    management_runner=runner,
                )
            self.assertEqual(result.state, f"{kind}-post-reboot-verified")
            self.assertTrue(result.journal_updated)
            self.assertEqual(runner.call_args.args[0][-1], command)
            self.assertEqual(runner.call_args.kwargs["env"]["SUDO_UID"], "1000")

        external_runner = mock.Mock(
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "schema_version": 1,
                        "external_deletion_reconciled": True,
                        "sep_mutation_performed": False,
                        "identifiers_redacted": True,
                    }
                ).encode(),
            )
        )
        mapping = SimpleNamespace(
            mappings=(SimpleNamespace(enabled=True, linux_uid=1000),)
        )
        with (
            mock.patch.object(native_reconciler.t2_user_mapping, "load", return_value=mapping),
            mock.patch.object(native_reconciler.os.path, "lexists", return_value=True),
        ):
            result = native_reconciler.reconcile_external_deletion_if_needed(
                runner=external_runner
            )
        self.assertEqual(result.state, "external-deletion-reconciled")
        self.assertTrue(result.journal_updated)
        self.assertEqual(
            external_runner.call_args.args[0][-1],
            "reconcile-external-deletion-if-needed",
        )
        self.assertEqual(
            external_runner.call_args.kwargs["env"]["SUDO_UID"], "1000"
        )


if __name__ == "__main__":
    unittest.main()
