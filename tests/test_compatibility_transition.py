#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as alias_unlock
import t2_apple_control_discriminator as keybag_discriminator
import t2_compatibility_transition as transition


class InspectPhaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory()
        self.addCleanup(self._root.cleanup)
        self.state_root = Path(self._root.name)

    def _inspect(self) -> transition.TransitionStatus:
        return transition.inspect(
            linux_uid=1000, linux_user="tester", state_root=self.state_root
        )

    def _write_mapping(self) -> None:
        (self.state_root / "users.json").write_text("{}", encoding="utf-8")

    def test_needs_import_when_no_mapping(self) -> None:
        (self.state_root / "user.kb").write_bytes(b"legacy")
        status = self._inspect()
        self.assertEqual(status.phase, transition.NEED_IMPORT)
        self.assertTrue(status.legacy_keybag_present)
        self.assertIn("migrate-compatibility import", status.next_command)

    def test_import_invalid_when_evidence_unreadable(self) -> None:
        self._write_mapping()
        failure = keybag_discriminator.AppleControlDiscriminatorError("no mapping")
        with mock.patch.object(transition, "_evidence", side_effect=failure):
            status = self._inspect()
        self.assertEqual(status.phase, transition.IMPORT_INVALID)
        self.assertIn("no mapping", status.detail)

    def test_needs_discriminate_when_matched_proof_missing(self) -> None:
        self._write_mapping()
        failure = alias_discriminator.AppleControlAliasDiscriminatorError("none")
        with (
            mock.patch.object(transition, "_evidence", return_value="evidence"),
            mock.patch.object(
                transition.alias_discriminator,
                "read_matched_keybag_proof",
                side_effect=failure,
            ),
        ):
            status = self._inspect()
        self.assertEqual(status.phase, transition.NEED_DISCRIMINATE)
        self.assertIn("discriminate", status.next_command)

    def test_needs_bind_when_bind_proof_missing(self) -> None:
        self._write_mapping()
        failure = reconciliation.AppleControlAliasReconciliationError("none")
        with (
            mock.patch.object(transition, "_evidence", return_value="evidence"),
            mock.patch.object(
                transition.alias_discriminator,
                "read_matched_keybag_proof",
                return_value="matched",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_ambiguous_bind_proof",
                side_effect=failure,
            ),
        ):
            status = self._inspect()
        self.assertEqual(status.phase, transition.NEED_BIND)
        self.assertIn("bind", status.next_command)

    def test_needs_reconcile_when_reconciled_proof_missing(self) -> None:
        self._write_mapping()
        failure = reconciliation.AppleControlAliasReconciliationError("none")
        with (
            mock.patch.object(transition, "_evidence", return_value="evidence"),
            mock.patch.object(
                transition.alias_discriminator,
                "read_matched_keybag_proof",
                return_value="matched",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_ambiguous_bind_proof",
                return_value="bind",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_reconciled_alias_proof",
                side_effect=failure,
            ),
        ):
            status = self._inspect()
        self.assertEqual(status.phase, transition.NEED_RECONCILE)
        self.assertIn("reconcile", status.next_command)

    def test_needs_unlock_when_unlock_proof_missing(self) -> None:
        self._write_mapping()
        failure = alias_unlock.AppleControlAliasUnlockError("none")
        with (
            mock.patch.object(transition, "_evidence", return_value="evidence"),
            mock.patch.object(
                transition.alias_discriminator,
                "read_matched_keybag_proof",
                return_value="matched",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_ambiguous_bind_proof",
                return_value="bind",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_reconciled_alias_proof",
                return_value="reconciled",
            ),
            mock.patch.object(
                transition.alias_unlock,
                "read_completed_unlock_proof",
                side_effect=failure,
            ),
        ):
            status = self._inspect()
        self.assertEqual(status.phase, transition.UNLOCK_RECOVERY_REQUIRED)
        self.assertIsNone(status.next_command)
        self.assertIn("active keybag handle", status.detail)

    def test_complete_when_chain_satisfied(self) -> None:
        self._write_mapping()
        with (
            mock.patch.object(transition, "_evidence", return_value="evidence"),
            mock.patch.object(
                transition.alias_discriminator,
                "read_matched_keybag_proof",
                return_value="matched",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_ambiguous_bind_proof",
                return_value="bind",
            ),
            mock.patch.object(
                transition.reconciliation,
                "read_reconciled_alias_proof",
                return_value="reconciled",
            ),
            mock.patch.object(
                transition.alias_unlock,
                "read_completed_unlock_proof",
                return_value="unlocked",
            ),
        ):
            status = self._inspect()
        self.assertEqual(status.phase, transition.COMPLETE)
        self.assertIsNone(status.next_command)

    def test_existing_invalid_unlock_journal_requires_recovery_without_retry(self):
        self._write_mapping()
        oracle = self.state_root / "oracle"
        oracle.mkdir()
        path = oracle / "apple-control-alias-unlock.jsonl"
        with (
            mock.patch.object(transition, "_evidence", return_value="evidence"),
            mock.patch.object(alias_discriminator, "read_matched_keybag_proof", return_value="matched"),
            mock.patch.object(reconciliation, "read_ambiguous_bind_proof", return_value="bind"),
            mock.patch.object(reconciliation, "read_reconciled_alias_proof", return_value="reconciled"),
            mock.patch.object(transition.t2_aks_transport, "AKSActivationTransport") as hardware,
        ):
            for dangling in (False, True):
                with self.subTest(dangling=dangling):
                    if dangling:
                        path.symlink_to(oracle / "missing")
                    else:
                        path.write_text("incomplete journal\n")
                    status = self._inspect()
                    self.assertEqual(status.phase, transition.UNLOCK_RECOVERY_REQUIRED)
                    self.assertIsNone(status.next_command)
                    self.assertIn("preserve the journal", status.detail)
                    path.unlink()
            hardware.assert_not_called()


class ImportStateTests(unittest.TestCase):
    def test_import_passes_account_generation(self) -> None:
        account = SimpleNamespace(generation="generation-digest")
        plan = SimpleNamespace()
        summary = {"import_complete": True}
        with (
            mock.patch.object(
                transition.t2_linux_account, "collect", return_value=account
            ) as collect,
            mock.patch.object(
                transition.t2_apple_control_import,
                "import_control_archives",
                return_value=(plan, summary),
            ) as import_control,
        ):
            result = transition.import_state(
                keybag_archive=Path("/tmp/keybags.tar.gz"),
                catacomb_archive=Path("/tmp/catacomb.tar.gz"),
                linux_uid=1000,
                apple_uid=501,
            )
        self.assertEqual(result, summary)
        collect.assert_called_once_with(1000)
        self.assertEqual(
            import_control.call_args.kwargs["linux_account_generation"],
            "generation-digest",
        )
        self.assertEqual(import_control.call_args.kwargs["apple_uid"], 501)


if __name__ == "__main__":
    unittest.main()
