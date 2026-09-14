#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free contracts for Linux-native identity management."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "t2_touchid_manage_native", ROOT / "src/t2-touchid-manage.py"
)
assert spec is not None and spec.loader is not None
MANAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MANAGE)


class NativeIdentityManagementTests(unittest.TestCase):
    def test_unverified_addition_rollback_deletes_only_terminal_delta_and_closes(self):
        target = "00000000-0000-0000-0000-000000000007"
        enrollment_path = Path("pending-enrollment.jsonl")
        enrollment = SimpleNamespace(
            operation_id="00000000-0000-0000-0000-000000000001",
            phase=MANAGE.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid=target,
            baseline={"identity_records": []},
        )
        deletion = SimpleNamespace()
        closed = SimpleNamespace(
            phase=MANAGE.t2_enrollment_journal.EnrollmentPhase.ADDITION_ROLLED_BACK
        )
        with (
            patch.object(
                MANAGE,
                "_pending_unverified_addition",
                return_value=(enrollment_path, enrollment),
            ),
            patch.object(
                MANAGE,
                "_rollback_delete_for",
                side_effect=[None, deletion],
            ),
            patch.object(
                MANAGE,
                "run_delete",
                return_value={"delete_succeeded": True},
            ) as run_delete,
            patch.object(
                MANAGE,
                "_close_unverified_addition_rollback",
                return_value=closed,
            ) as close,
        ):
            result = MANAGE.run_unverified_addition_rollback({})
        run_delete.assert_called_once_with(
            {},
            target_identity_uuid=target,
            rollback_enrollment=(enrollment_path, enrollment),
        )
        close.assert_called_once_with(enrollment_path, enrollment, deletion)
        self.assertTrue(result["unverified_addition_rolled_back"])
        self.assertEqual(result["identity_count"], 0)

    def test_delete_recovery_resumes_after_observation_stopped_before_persistence(self):
        baseline_generation = "00000000-0000-0000-0000-000000000001"
        recovery_generation = "00000000-0000-0000-0000-000000000002"
        history = SimpleNamespace(
            operation_id="operation",
            phase=(
                MANAGE.t2_identity_delete_journal.IdentityDeletePhase.SEP_DELETED
            ),
            recovery_action="no-local-transaction",
            persistence=SimpleNamespace(
                phase=(
                    MANAGE.t2_enrollment_persistence_journal.PersistencePhase.NOT_STARTED
                )
            ),
            persistence_connection_generation=recovery_generation,
            baseline={"connection_generation": baseline_generation},
        )
        transitioned = SimpleNamespace(
            **{
                **history.__dict__,
                "phase": (
                    MANAGE.t2_identity_delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN
                ),
            }
        )
        with patch.object(
            MANAGE.t2_identity_delete_journal,
            "append_checked",
            return_value=transitioned,
        ) as append:
            normalized, retrying = MANAGE._normalize_delete_recovery_resume(
                Path("journal"), history
            )
        self.assertIs(normalized, transitioned)
        self.assertTrue(retrying)
        self.assertEqual(append.call_args.args[2], "DELETE_OUTCOME_UNKNOWN")
        self.assertEqual(
            append.call_args.args[3],
            {
                "connection_generation": recovery_generation,
                "stage": "persistence",
                "reason": "process-interrupted",
                "mutation_possible": True,
            },
        )

    def test_operation_lock_owns_missing_private_runtime_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "run" / "t2-touchid"
            runtime.parent.mkdir()
            lock = runtime / "operation.lock"

            class RootOwnedRuntime:
                def mkdir(self, *args, **kwargs):
                    return runtime.mkdir(*args, **kwargs)

                def stat(self, *args, **kwargs):
                    info = runtime.stat(*args, **kwargs)
                    return SimpleNamespace(
                        st_mode=info.st_mode,
                        st_uid=0,
                        st_gid=0,
                    )

            with (
                patch.object(MANAGE, "RUN_ROOT", RootOwnedRuntime()),
                patch.object(MANAGE, "OPERATION_LOCK", lock),
                patch.object(
                    MANAGE.os,
                    "fstat",
                    return_value=SimpleNamespace(
                        st_mode=0o100600,
                        st_uid=0,
                        st_nlink=1,
                    ),
                ),
                MANAGE.operation_lock(),
            ):
                self.assertTrue(lock.is_file())
                self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)

    def test_delete_recovery_binds_native_mapping_without_legacy_keybag_state(self):
        native_generation = "a" * 64
        history = SimpleNamespace(
            phase=MANAGE.t2_identity_delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
            baseline={
                "apple_uid": 501,
                "mapping_generation": native_generation,
            }
        )
        authority = SimpleNamespace(
            origin="linux-native-e4",
            selected=SimpleNamespace(apple_uid=501),
            mapping_set=SimpleNamespace(generation=native_generation),
        )
        with (
            patch.object(
                MANAGE,
                "delete_journals",
                return_value=[(Path("journal"), history)],
            ),
            patch.object(
                MANAGE.t2_user_authority,
                "load",
                return_value=authority,
            ),
            patch.object(
                MANAGE.t2_catacomb_store,
                "CatacombStore",
                side_effect=RuntimeError("native mapping guard passed"),
            ),
            patch.object(MANAGE, "keybag_runtime") as legacy_keybag,
        ):
            with self.assertRaisesRegex(RuntimeError, "native mapping guard passed"):
                MANAGE.run_delete_recovery(
                    {
                        "linux_uid": 1000,
                        "apple_uid": 501,
                        "mapping_generation": "b" * 64,
                        "special_bag": -501,
                        "authority_mode": "linux-native",
                    }
                )
        legacy_keybag.assert_not_called()

    def test_delete_preflight_uses_native_inventory_without_legacy_keybag_state(self):
        local = SimpleNamespace(identities=(object(), object()))
        plan = SimpleNamespace(name="Linux second finger")
        native = MagicMock()
        native.__enter__.return_value = (
            object(), object(), {}, local, object(), {}
        )
        native.__exit__.return_value = False
        with (
            patch.object(
                MANAGE.t2_mutation_registry,
                "blocks_new_mutation",
                return_value=False,
            ),
            patch.object(MANAGE.os.path, "lexists", return_value=False),
            patch.object(MANAGE, "_native_management_lease", return_value=native),
            patch.object(MANAGE, "keybag_runtime") as legacy_keybag,
            patch.object(MANAGE.t2_identity_delete, "plan", return_value=plan),
        ):
            result = MANAGE.run_delete_preflight(
                {"linux_uid": 1000, "authority_mode": "linux-native"}, slot=2
            )
        legacy_keybag.assert_not_called()
        self.assertTrue(result["delete_preflight_succeeded"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["slot"], 2)
        self.assertEqual(result["name"], "Linux second finger")
        self.assertEqual(result["identity_count_before"], 2)
        self.assertEqual(result["identity_count_after"], 1)

    def test_delete_post_reboot_verification_uses_native_mapping(self):
        mapping_generation = "a" * 64
        history = SimpleNamespace(
            phase=MANAGE.t2_identity_delete_journal.IdentityDeletePhase.RECONCILED,
            operation_id="operation",
            baseline={"apple_uid": 501, "mapping_generation": mapping_generation},
        )
        authority = SimpleNamespace(
            selected=SimpleNamespace(apple_uid=501),
            mapping_set=SimpleNamespace(generation=mapping_generation),
        )
        local = SimpleNamespace(identities=(object(),))
        native = MagicMock()
        native.__enter__.return_value = (
            authority, object(), {}, local, object(), {}
        )
        native.__exit__.return_value = False
        completed = SimpleNamespace(
            phase=(
                MANAGE.t2_identity_delete_journal.IdentityDeletePhase.POST_REBOOT_VERIFIED
            )
        )
        with (
            patch.object(MANAGE, "BOOT_ID", SimpleNamespace(
                read_text=lambda **_: "11111111-1111-4111-8111-111111111111\n"
            )),
            patch.object(MANAGE, "delete_journals", return_value=[(Path("journal"), history)]),
            patch.object(MANAGE, "_native_management_lease", return_value=native),
            patch.object(MANAGE, "keybag_runtime") as legacy_keybag,
            patch.object(
                MANAGE.t2_identity_delete_reconciliation,
                "append_post_reboot_verified",
                return_value=completed,
            ) as append,
        ):
            result = MANAGE.run_delete_post_reboot_verification(
                {"linux_uid": 1000, "authority_mode": "linux-native"}
            )
        legacy_keybag.assert_not_called()
        self.assertTrue(result["delete_post_reboot_verified"])
        self.assertEqual(result["identity_count"], 1)
        self.assertEqual(
            append.call_args.kwargs["mapping_generation"], mapping_generation
        )


if __name__ == "__main__":
    unittest.main()
