# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_native_enroll_cli", SOURCE / "t2-native-enroll.py"
)
assert SPEC is not None and SPEC.loader is not None
native_enroll = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native_enroll)


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class NativeEnrollmentAuthorityTests(unittest.TestCase):
    def test_native_addition_uses_high_water_candidate_from_exact_inventory(self) -> None:
        selected = SimpleNamespace(apple_uid=501)
        store = mock.Mock()
        store.read_committed_components.return_value = {
            "user_000001f5.cat": b"user"
        }
        projected = SimpleNamespace(
            complete=True,
            finger_names=("finger-1", "finger-2"),
        )
        with (
            mock.patch.object(
                native_enroll.t2_catacomb_store,
                "CatacombStore",
                return_value=store,
            ),
            mock.patch.object(
                native_enroll.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=mock.sentinel.local,
            ),
            mock.patch.object(
                native_enroll.t2_identity_inventory,
                "summarize",
                return_value={"inventory": "exact"},
            ),
            mock.patch.object(
                native_enroll.t2_fprint_projection,
                "project",
                return_value=projected,
            ),
            mock.patch.object(
                native_enroll.t2_fprint_sequence,
                "candidate",
                return_value="finger-4",
            ) as candidate,
        ):
            result = native_enroll._candidate_native_identity_name(
                selected, mock.sentinel.authority, {"live": "exact"}
            )

        self.assertEqual(result, "finger-4")
        candidate.assert_called_once_with(501, ("finger-1", "finger-2"))

    def test_active_outcome_unknown_reconciles_no_change_without_replay(self) -> None:
        """A mid-capture protocol failure must not permanently block inventory."""

        journal = Path("/var/lib/t2-touchid/mutations") / f"{identifier(58)}.jsonl"
        history = SimpleNamespace(
            operation_id=identifier(58),
            baseline={"bound": "baseline"},
        )
        reconciled = SimpleNamespace(
            phase=native_enroll.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid=None,
        )
        mapping_set = SimpleNamespace(generation="a" * 64)
        selected = SimpleNamespace(apple_uid=501)
        lease = SimpleNamespace()
        lease_context = mock.MagicMock()
        lease_context.__enter__.return_value = lease
        inhibitor = mock.MagicMock()
        inhibitor.__enter__.return_value = inhibitor
        inhibitor.poll.return_value = None
        live = {"per_user_identity_records": [{"identity_uuid": identifier(1)}]}
        host = {"bound": "host"}
        with (
            mock.patch.object(
                native_enroll,
                "_pending_outcome_unknown_reconciliation",
                return_value=(journal, history),
            ),
            mock.patch.object(native_enroll, "_require_private_runtime_root"),
            mock.patch.object(native_enroll.os, "open", return_value=90),
            mock.patch.object(
                native_enroll.os,
                "fstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_uid=0,
                ),
            ),
            mock.patch.object(native_enroll.os, "close"),
            mock.patch.object(native_enroll.fcntl, "flock"),
            mock.patch.object(
                native_enroll, "_sleep_inhibitor", return_value=inhibitor
            ),
            mock.patch.object(native_enroll, "_discover_port", return_value=49152),
            mock.patch.object(
                native_enroll.t2_catacomb_store,
                "CatacombStore",
                return_value=mock.sentinel.store,
            ),
            mock.patch.object(
                native_enroll.t2_bridge_connection.BridgeConnectionLease,
                "connect",
                return_value=lease_context,
            ),
            mock.patch.object(
                native_enroll.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value=live,
            ),
            mock.patch.object(
                native_enroll,
                "_discard_cancelled_biolockout_prepare",
                return_value=False,
            ),
            mock.patch.object(
                native_enroll.t2_enrollment_finalizer,
                "read_local_host_snapshot",
                return_value=host,
            ),
            mock.patch.object(
                native_enroll.t2_enrollment_reconciliation,
                "append_reconciled",
                return_value=reconciled,
            ) as append,
            mock.patch.object(native_enroll, "_run", autospec=True) as enroll,
        ):
            result = native_enroll._run_outcome_unknown_reconciliation(
                configuration={"host": "127.0.0.1", "interface": "t2bridge0"},
                mapping_set=mapping_set,
                selected=selected,
            )

        self.assertTrue(result["outcome_unknown_reconciled"])
        self.assertFalse(result["fingerprint_mutation_performed"])
        append.assert_called_once_with(
            journal,
            history.operation_id,
            host=host,
            live=live,
            mapping_generation=mapping_set.generation,
        )
        enroll.assert_not_called()

    def test_cancel_save_ambiguity_discards_only_empty_prepare_before_readback(
        self,
    ) -> None:
        """A cancelled capture cannot strand an empty local transaction."""

        persistence = SimpleNamespace(
            phase=(
                native_enroll.t2_enrollment_persistence_journal.PersistencePhase.OUTCOME_UNKNOWN
            ),
            outcome_unknown_stage="complete",
            outcome_unknown_host_commit_possible=False,
            batch_index=0,
            component_index=0,
            staged_files=(),
            batches=((('biolockout.cat', 'a' * 64),),),
        )
        history = SimpleNamespace(
            phase=native_enroll.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN,
            terminal_identity_uuid=None,
            terminal_status=66,
            persistence=persistence,
        )
        store = SimpleNamespace(discard_empty_prepare=mock.Mock())
        with mock.patch.object(
            native_enroll.os.path,
            "lexists",
            side_effect=lambda path: Path(path).name == "prepare",
        ):
            discarded = native_enroll._discard_cancelled_biolockout_prepare(
                store, history
            )

        self.assertTrue(discarded)
        store.discard_empty_prepare.assert_called_once_with()

    def test_exact_interrupted_authority_temp_is_resumed(self) -> None:
        """Only byte-identical publication state may cross the atomic rename."""

        authority_module = native_enroll.t2_user_authority
        operation_id = identifier(59)
        linux_uid = 1000
        source = Path("/var/lib/t2-touchid/mutations") / f"{operation_id}.jsonl"
        users_root = Path("/var/lib/t2-touchid/users")
        user_root = users_root / str(linux_uid)
        copied = user_root / f"{operation_id}.jsonl"
        temporary = user_root / f".authority.{operation_id}.tmp"
        selected = SimpleNamespace()
        mapping_set = SimpleNamespace(
            generation="a" * 64,
            resolve=mock.Mock(return_value=selected),
        )
        history = SimpleNamespace(
            operation_id=operation_id,
            head_hash="b" * 64,
            reconciled_snapshot_sha256="c" * 64,
        )
        authority = SimpleNamespace(enrollment_journal=copied)
        manifest = {
            "schema_version": 1,
            "linux_uid": linux_uid,
            "mapping_generation": mapping_set.generation,
            "enrollment_operation_id": operation_id,
            "enrollment_head_hash": history.head_hash,
            "reconciliation_snapshot_sha256": (
                history.reconciled_snapshot_sha256
            ),
            "enrollment_journal": copied.name,
        }
        encoded = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        journal_bytes = b"validated immutable E4 journal\n"

        def private_bytes(path: Path, _maximum: int) -> bytes:
            return encoded if path == temporary else journal_bytes

        write = mock.Mock()
        with (
            mock.patch.object(authority_module.os, "geteuid", return_value=0),
            mock.patch.object(
                authority_module.t2_user_mapping,
                "load",
                return_value=mapping_set,
            ),
            mock.patch.object(
                authority_module.t2_enrollment_journal,
                "read",
                return_value=history,
            ),
            mock.patch.object(authority_module, "_bound_history"),
            mock.patch.object(authority_module, "_private_directory"),
            mock.patch.object(
                authority_module,
                "_read_private_bytes",
                side_effect=private_bytes,
            ),
            mock.patch.object(authority_module, "_write_exclusive", write),
            mock.patch.object(authority_module.os.path, "lexists", return_value=True),
            mock.patch.object(authority_module.os, "replace") as replace,
            mock.patch.object(authority_module.os, "open", return_value=92),
            mock.patch.object(authority_module.os, "fsync"),
            mock.patch.object(authority_module.os, "close"),
            mock.patch.object(authority_module, "load", return_value=authority),
        ):
            observed = authority_module.publish(
                linux_uid,
                source,
                mapping_path=Path("/var/lib/t2-touchid/users.json"),
                users_root=users_root,
            )

        self.assertIs(observed, authority)
        write.assert_not_called()
        replace.assert_called_once_with(temporary, user_root / "authority.json")

    def test_interrupted_e4_publication_recovers_without_hardware(self) -> None:
        """A committed E4 is host-published without re-running its verifier."""

        operation_id = identifier(60)
        journal = Path("/var/lib/t2-touchid/mutations") / f"{operation_id}.jsonl"
        mapping_set = SimpleNamespace(generation="a" * 64)
        selected = SimpleNamespace(linux_uid=1000)
        history = SimpleNamespace(operation_id=operation_id)
        authority = SimpleNamespace(
            mapping_set=mapping_set,
            selected=selected,
            enrollment_journal=journal,
        )
        activation = mock.Mock()
        bridge = mock.Mock()
        with (
            mock.patch.object(native_enroll, "_require_private_runtime_root"),
            mock.patch.object(native_enroll.os, "open", return_value=91),
            mock.patch.object(
                native_enroll.os,
                "fstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_uid=0,
                ),
            ),
            mock.patch.object(native_enroll.os, "close"),
            mock.patch.object(native_enroll.fcntl, "flock"),
            mock.patch.object(
                native_enroll,
                "_pending_authority_publication_journal",
                return_value=(journal, history),
            ) as selector,
            mock.patch.object(
                native_enroll.t2_user_authority,
                "load",
                side_effect=native_enroll.t2_user_authority.UserAuthorityError(
                    "fault-injected missing publication"
                ),
            ) as load,
            mock.patch.object(native_enroll.os.path, "lexists", return_value=False),
            mock.patch.object(
                native_enroll.t2_user_authority,
                "publish",
                return_value=authority,
            ) as publish,
            mock.patch.object(
                native_enroll,
                "_activate_for_post_reboot_verification",
                activation,
            ),
            mock.patch.object(
                native_enroll.t2_bridge_connection.BridgeConnectionLease,
                "connect",
                bridge,
            ),
        ):
            result = native_enroll._run_post_reboot_publication_recovery(
                mapping_set=mapping_set,
                selected=selected,
                expected_operation_id=operation_id,
            )

        self.assertTrue(result["authority_publication_recovered"])
        self.assertTrue(result["runtime_authority_published"])
        self.assertFalse(result["fingerprint_mutation_performed"])
        selector.assert_called_once_with(
            mapping_set, selected, expected_operation_id=operation_id
        )
        load.assert_called_once_with(selected.linux_uid)
        publish.assert_called_once_with(selected.linux_uid, journal)
        activation.assert_not_called()
        bridge.assert_not_called()

    def test_first_enrollment_seeds_rolling_biolockout(self) -> None:
        """Protect the first E4 identity from lacking match restore state."""

        payload = b"HRLB" + b"a" * 20
        result = SimpleNamespace(persistence_ready=True)
        catacomb_store = mock.Mock()
        catacomb_store.read_committed_components.return_value = {
            "biolockout.cat": b"committed-component"
        }
        rolling_store = mock.Mock()
        rolling_store.current.return_value = None
        with (
            mock.patch.object(
                native_enroll.t2_catacomb_store,
                "CatacombStore",
                return_value=catacomb_store,
            ),
            mock.patch.object(
                native_enroll.t2_catacomb_codec,
                "decode_biolockout_catacomb",
                return_value=SimpleNamespace(secure_data=payload),
            ),
            mock.patch.object(
                native_enroll.t2_biolockout_store,
                "BioLockoutStore",
                return_value=rolling_store,
            ),
            mock.patch.object(native_enroll, "_emit") as emit,
        ):
            observed = native_enroll._synchronize_persisted_biolockout(
                result, 501
            )

        self.assertIs(observed, result)
        rolling_store.commit.assert_called_once_with(payload)
        emit.assert_called_once_with("rolling-biolockout-synchronized")

    def test_additional_recovery_selects_pending_journal_beside_e4_authority(self) -> None:
        """Protect one-to-two recovery from rejecting the existing E4 journal."""

        boot_id = identifier(40)
        mapping_generation = "a" * 64
        selected = SimpleNamespace(
            linux_uid=1000,
            apple_uid=501,
            account_uuid=identifier(41),
            bag_uuid=identifier(42),
        )
        mappings = SimpleNamespace(generation=mapping_generation)
        authority = SimpleNamespace(
            phase=native_enroll.t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )
        pending = SimpleNamespace(
            phase=native_enroll.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN,
            outcome_unknown_stage="terminal",
            baseline={
                "baseline_version": 1,
                "linux_boot_uuid": boot_id,
                "caller_linux_uid": selected.linux_uid,
                "target_linux_uid": selected.linux_uid,
                "apple_uid": selected.apple_uid,
                "account_uuid": selected.account_uuid,
                "bag_uuid": selected.bag_uuid,
                "mapping_generation": mapping_generation,
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mutations"
            root.mkdir()
            authority_path = root / "authority.jsonl"
            pending_path = root / "pending.jsonl"
            delete_path = root / "delete.jsonl"
            authority_path.touch()
            pending_path.touch()
            delete_path.touch()
            boot_path = Path(directory) / "boot_id"
            boot_path.write_text(boot_id, encoding="ascii")
            histories = {
                authority_path: authority,
                pending_path: pending,
            }
            raw_histories = {
                authority_path: [{"evidence": {"operation_kind": "enroll"}}],
                pending_path: [{"evidence": {"operation_kind": "enroll"}}],
                delete_path: [{"evidence": {"operation_kind": "delete-one"}}],
            }
            with (
                mock.patch.object(native_enroll, "CATACOMB_ROOT", root),
                mock.patch.object(native_enroll, "MUTATION_ROOT", root),
                mock.patch.object(native_enroll, "BOOT_ID", boot_path),
                mock.patch.object(native_enroll, "_private"),
                mock.patch.object(native_enroll.t2_mutation_registry, "scan"),
                mock.patch.object(
                    native_enroll.t2_enrollment_journal,
                    "validate_history",
                    side_effect=lambda records: (
                        authority
                        if records is raw_histories[authority_path]
                        else pending
                    ),
                ),
                mock.patch.object(
                    native_enroll.t2_mutation_journal,
                    "read",
                    side_effect=lambda path: raw_histories[path],
                ),
            ):
                observed_path, observed_history = (
                    native_enroll._pending_observed_identity_recovery(
                        mappings, selected
                    )
                )

        self.assertEqual(observed_path, pending_path)
        self.assertIs(observed_history, pending)

    def test_add_finger_preflight_needs_no_input_descriptors(self) -> None:
        """Protect the live no-touch gate from normal ceremony FD admission."""

        mapping_set = mock.Mock()
        selected = mock.Mock(linux_uid=1000)
        authority = mock.Mock()
        result = {
            "additional_enrollment_preflight_ready": True,
            "fingerprint_mutation_performed": False,
            "journal_created": False,
            "identifiers_redacted": True,
        }
        with (
            mock.patch.object(
                sys, "argv", ["t2-native-enroll", "--preflight-add-finger"]
            ),
            mock.patch.object(native_enroll.os, "geteuid", return_value=0),
            mock.patch.object(native_enroll, "_configuration", return_value={
                "linux_uid": 1000,
                "apple_uid": 501,
            }),
            mock.patch.object(
                native_enroll,
                "_load_provisioned_authority",
                return_value=(mapping_set, selected, mock.Mock()),
            ),
            mock.patch.object(
                native_enroll.t2_user_authority,
                "load",
                return_value=authority,
            ),
            mock.patch.object(
                native_enroll,
                "_run_add_finger_preflight",
                return_value=result,
            ) as preflight,
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(native_enroll.main(), 0)

        preflight.assert_called_once_with(
            configuration={"linux_uid": 1000, "apple_uid": 501},
            mapping_set=mapping_set,
            selected=selected,
            existing_authority=authority,
        )
        output.assert_called_once()

    def test_capture_loop_has_no_keyboard_acknowledgement(self) -> None:
        cancellation = native_enroll.Event()
        transition = native_enroll.t2_enrollment_protocol.EnrollmentTransition(
            native_enroll.t2_enrollment_protocol.EnrollmentAction.RETRY_SCAN,
            native_enroll.t2_enrollment_protocol.EnrollmentState.ACTIVE,
        )
        with mock.patch.object(native_enroll, "_emit") as emit:
            native_enroll._arm_enrollment(cancellation)
            native_enroll._feedback(transition)
        self.assertEqual(
            emit.call_args_list,
            [
                mock.call("enrollment-armed"),
                mock.call("enrollment-feedback", action="retry-scan"),
            ],
        )

    def test_completed_replacement_activation_is_enrollment_authority(self) -> None:
        """Protect the D179 schema-2 handoff that legacy-only admission rejected."""

        linux_uid = 1000
        apple_uid = 501
        operation_id = identifier(1)
        old_account = identifier(2)
        old_bag = identifier(3)
        new_account = identifier(4)
        new_bag = identifier(5)
        old_mapping_generation = "a" * 64
        disabled_mapping_generation = "b" * 64
        enabled_mapping_generation = "c" * 64
        account_generation = "d" * 64
        keybag = b"replacement-keybag"
        keybag_digest = hashlib.sha256(keybag).hexdigest()
        activation_digest = "e" * 64
        manifest_digest = "f" * 64
        replacement_head = "1" * 64
        initial_boot = identifier(6)
        final_boot = identifier(7)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keybag_path = root / "user.kb"
            secret_path = root / "activation.secret"
            keybag_path.write_bytes(keybag)
            selected = native_enroll.t2_user_mapping.UserMapping(
                linux_uid=linux_uid,
                linux_account_generation=account_generation,
                apple_uid=apple_uid,
                account_uuid=new_account,
                bag_uuid=new_bag,
                keybag_path=str(keybag_path),
                keybag_sha256=keybag_digest,
                unlock_mode="password-on-demand",
                capabilities=native_enroll.t2_user_mapping.CAPABILITIES,
                enabled=True,
                bundle_generation=operation_id,
                activation_secret_path=str(secret_path),
                activation_secret_sha256=activation_digest,
                activation_secret_length=16,
            )
            mappings = native_enroll.t2_user_mapping.UserMappingSet(
                enabled_mapping_generation,
                (selected,),
                native_enroll.t2_user_mapping.SCHEMA_VERSION,
            )
            provisioning = SimpleNamespace(
                phase="mapping-enabled",
                record_count=9,
                reboot_linux_boot_uuid=identifier(8),
                enabled_mapping_generation=old_mapping_generation,
                account_uuid=old_account,
                bag_uuid=old_bag,
            )
            replacement = SimpleNamespace(
                phase="complete",
                operation_id=operation_id,
                activation_material_digest=activation_digest,
                saved_keybag_digest=keybag_digest,
                saved_keybag_length=len(keybag),
                bundle_generation=operation_id,
                mapping_generation=disabled_mapping_generation,
                live_bag_uuid=new_bag,
                old_mapping_generation=old_mapping_generation,
                old_account_uuid=old_account,
                old_bag_uuid=old_bag,
                new_account_uuid=new_account,
                reconciliation_linux_boot_uuid=final_boot,
                initial_linux_boot_uuid=initial_boot,
                head_hash=replacement_head,
            )
            baseline = {
                "replacement_head_hash": replacement_head,
                "replacement_initial_linux_boot_uuid": initial_boot,
                "replacement_final_linux_boot_uuid": final_boot,
                "linux_account_generation": account_generation,
                "target_linux_uid": linux_uid,
                "apple_uid": apple_uid,
                "account_uuid": new_account,
                "bag_uuid": new_bag,
                "disabled_mapping_generation": disabled_mapping_generation,
                "keybag_sha256": keybag_digest,
                "activation_material_digest": activation_digest,
                "bundle_manifest_sha256": manifest_digest,
                "special_alias": -apple_uid,
            }
            activation = SimpleNamespace(
                phase="complete",
                operation_id=operation_id,
                enabled_mapping_generation=enabled_mapping_generation,
                baseline=baseline,
            )
            bundle = SimpleNamespace(
                generation=operation_id,
                keybag_path=keybag_path,
                keybag_sha256=keybag_digest,
                activation_secret_path=secret_path,
                activation_secret_sha256=activation_digest,
                manifest_sha256=manifest_digest,
            )
            store = mock.Mock()
            store.published.return_value = bundle
            with (
                mock.patch.object(
                    native_enroll.t2_user_mapping, "load", return_value=mappings
                ),
                mock.patch.object(
                    native_enroll.t2_linux_account,
                    "collect",
                    return_value=native_enroll.t2_linux_account.AccountEvidence(
                        linux_uid, account_generation
                    ),
                ),
                mock.patch.object(
                    native_enroll.t2_aks_provisioning,
                    "read",
                    return_value=provisioning,
                ),
                mock.patch.object(
                    native_enroll.t2_aks_replacement_journal,
                    "read",
                    return_value=replacement,
                ),
                mock.patch.object(
                    native_enroll.t2_aks_replacement_activation_journal,
                    "read",
                    return_value=activation,
                ),
                mock.patch.object(
                    native_enroll.t2_activation_bundle,
                    "ActivationBundleStore",
                    return_value=store,
                ),
                mock.patch.object(
                    native_enroll,
                    "_private",
                    return_value=SimpleNamespace(st_size=len(keybag)),
                ),
            ):
                observed = native_enroll._load_provisioned_authority(
                    linux_uid, apple_uid
                )

        self.assertIs(observed[0], mappings)
        self.assertIs(observed[1], selected)
        self.assertIs(observed[2], activation)
        store.published.assert_called_once_with(
            expected_keybag_sha256=keybag_digest,
            activation_secret_sha256=activation_digest,
            bag_uuid=new_bag,
            expected_keybag_length=len(keybag),
        )

    def test_terminal_identity_recovery_persists_without_recapture(self) -> None:
        """Protect D196's stable-readback recovery from enrollment replay."""

        identity_uuid = identifier(20)
        generation = identifier(21)
        operation_id = identifier(22)
        mapping_generation = "a" * 64
        selected = SimpleNamespace(apple_uid=501)
        mappings = SimpleNamespace(generation=mapping_generation)
        history = SimpleNamespace(
            operation_id=operation_id,
            baseline={"marker": True, "identity_records": []},
        )
        recovery = SimpleNamespace(
            identity_uuid=identity_uuid,
            evidence={"identity_uuid": identity_uuid},
        )
        recovered = SimpleNamespace(
            phase=native_enroll.t2_enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY,
            terminal_identity_uuid=identity_uuid,
            persistence_connection_generation=generation,
        )
        final_history = SimpleNamespace(
            phase=native_enroll.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid=identity_uuid,
        )
        attestation = SimpleNamespace(
            persistence_ready=True, reconciliation_complete=True
        )
        lease = mock.MagicMock(connection_generation=generation)
        connection = mock.MagicMock()
        connection.__enter__.return_value = lease
        inhibitor = mock.MagicMock()
        inhibitor.poll.return_value = None
        inhibition = mock.MagicMock()
        inhibition.__enter__.return_value = inhibitor
        finalizer = mock.Mock(return_value=attestation)

        with (
            mock.patch.object(
                native_enroll,
                "_pending_observed_identity_recovery",
                return_value=(Path("/private/enrollment.jsonl"), history),
            ),
            mock.patch.object(native_enroll, "_require_private_runtime_root"),
            mock.patch.object(native_enroll.os, "open", return_value=9),
            mock.patch.object(
                native_enroll.os,
                "fstat",
                return_value=SimpleNamespace(st_mode=0o100600, st_uid=0),
            ),
            mock.patch.object(native_enroll.os, "close"),
            mock.patch.object(native_enroll.fcntl, "flock"),
            mock.patch.object(native_enroll, "_sleep_inhibitor", return_value=inhibition),
            mock.patch.object(native_enroll, "_discover_port", return_value=55555),
            mock.patch.object(
                native_enroll.t2_catacomb_store, "CatacombStore", return_value=mock.Mock()
            ),
            mock.patch.object(
                native_enroll.t2_bridge_connection.BridgeConnectionLease,
                "connect",
                return_value=connection,
            ),
            mock.patch.object(
                native_enroll.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value={"stable": True},
            ),
            mock.patch.object(
                native_enroll.t2_enrollment_finalizer,
                "read_local_host_snapshot",
                return_value={"host": True},
            ),
            mock.patch.object(
                native_enroll.t2_fprint_sequence,
                "candidate",
                return_value="finger-1",
            ),
            mock.patch.object(
                native_enroll.t2_enrollment_reconciliation,
                "classify_observed_identity_recovery",
                return_value=recovery,
            ) as classify,
            mock.patch.object(
                native_enroll.t2_enrollment_journal,
                "append_checked",
                return_value=recovered,
            ) as append,
            mock.patch.object(
                native_enroll.t2_enrollment_finalizer,
                "BuiltinEnrollmentFinalizer",
                return_value=finalizer,
            ) as finalizer_factory,
            mock.patch.object(
                native_enroll.t2_enrollment_journal,
                "read",
                return_value=final_history,
            ),
            mock.patch.object(native_enroll, "_run") as capture,
            mock.patch.object(native_enroll, "_synchronize_persisted_biolockout") as synchronize,
        ):
            result = native_enroll._run_observed_identity_recovery(
                configuration={"host": "host", "interface": "if0"},
                mapping_set=mappings,
                selected=selected,
                identity_name=None,
            )

        self.assertTrue(result["enrollment_succeeded"])
        synchronize.assert_called_once()
        self.assertTrue(synchronize.call_args.args[0].persistence_ready)
        self.assertEqual(synchronize.call_args.args[1], 501)
        self.assertFalse(result["fingerprint_mutation_performed"])
        capture.assert_not_called()
        classify.assert_called_once()
        append.assert_called_once_with(
            Path("/private/enrollment.jsonl"),
            operation_id,
            "E2_RECOVERY_IDENTITY_READBACK_OBSERVED",
            recovery.evidence,
        )
        finalizer.assert_called_once()
        self.assertEqual(
            finalizer_factory.call_args.kwargs["identity_name"], "finger-1"
        )

    def test_post_reboot_schema_two_uses_creation_secret_activation(self) -> None:
        """Protect D199 from routing replacement authority through schema 1."""

        transport = mock.Mock()
        acm_device = mock.Mock()
        mappings = SimpleNamespace(
            schema_version=native_enroll.t2_user_mapping.SCHEMA_VERSION
        )
        selected = mock.Mock()
        password = bytearray(b"unused-password")
        with (
            mock.patch.object(
                native_enroll, "_activate_replacement_for_verification"
            ) as replacement,
            mock.patch.object(native_enroll, "_activate_for_operation") as legacy,
        ):
            native_enroll._activate_for_post_reboot_verification(
                transport=transport,
                acm_device=acm_device,
                mapping_set=mappings,
                selected=selected,
                password=password,
                linux_boot_uuid=identifier(30),
            )

        replacement.assert_called_once_with(
            transport=transport,
            acm_device=acm_device,
            mapping_set=mappings,
            selected=selected,
            linux_boot_uuid=identifier(30),
        )
        legacy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
