# SPDX-License-Identifier: GPL-2.0-only

import copy
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_mutation_journal
import t2_native_state_recovery as recovery


USER = 501
MAPPING = "a" * 64
BOOT = str(uuid.UUID(int=1))
CONNECTION = str(uuid.UUID(int=2))
IDENTITY = str(uuid.UUID(int=3))


def retained_inventory():
    return {
        "double_collection_equal": True,
        "apple_uid": USER,
        "biometric_protocol_version": 2,
        "connection_generation": CONNECTION,
        "bridge_boot_uuid": None,
        "per_user_identity_records": [],
        "global_identity_records": [],
        "catacomb": {
            "present": False,
            "uuid": str(uuid.UUID(int=0)),
            "hash": "0" * 64,
            "user_states": [
                {
                    "kind": "master",
                    "user_id": 0xFFFFFFFF,
                    "state": 3,
                    "needs_save": False,
                }
            ],
        },
    }


def authority():
    user = SimpleNamespace(
        secure_data=b"LTFC-user",
        identities=(SimpleNamespace(user_id=USER, uuid=IDENTITY, entity=1),),
    )
    components = {
        "master.cat": b"master",
        "biolockout.cat": b"bio",
        "user_000001f5.cat": b"user",
    }
    return user, components


class FakeLease:
    def __init__(self, *, client_version=0, reject=None, reject_at=None):
        self.client_version = client_version
        self.connection_generation = CONNECTION
        self.commands = []
        self.payloads = []
        self.reject = reject
        self.reject_at = reject_at

    def biometric_command(self, command, **kwargs):
        self.commands.append(command)
        self.payloads.append(kwargs.get("data"))
        if command == self.reject and (
            self.reject_at is None
            or self.commands.count(command) == self.reject_at
        ):
            return [5, b""], []
        return [0, b""], []

    def select_client_version(self):
        self.client_version = 2
        return 2

    def invalidate(self):
        pass


class NativeStateRecoveryTests(unittest.TestCase):
    def create(self, root):
        user, components = authority()
        path = root / f"{uuid.UUID(int=4)}.jsonl"
        history = recovery.create_journal(
            path,
            str(uuid.UUID(int=4)),
            apple_user_id=USER,
            mapping_generation=MAPPING,
            linux_boot_uuid=BOOT,
            live=retained_inventory(),
            components=components,
            user=user,
        )
        return path, history, user, components

    def advance_to_reprepared_rejection(
        self, path, *, secure_hash="c" * 64, intermediate_hash="d" * 64
    ):
        evidence = {
            "PREPARE_MASTER_INTENT": {
                "command": 0x31, "component": "master", "retry_permitted": False
            },
            "PREPARE_MASTER_ACCEPTED": {
                "reply_received": True, "retry_permitted": False
            },
            "PREPARE_USER_INTENT": {
                "command": 0x31,
                "component": "selected-user",
                "retry_permitted": False,
            },
            "PREPARE_USER_ACCEPTED": {
                "reply_received": True, "retry_permitted": False
            },
            "CLIENT_VERSION_SELECTED": {"client_version": 2},
            "MISSING_COMPONENTS_POST_STATE_REJECTED": {
                "stable_surface_rejected": True, "retry_permitted": False
            },
            "LOADED_EMPTY_USER_RECONCILED": {
                "master_state": 3,
                "user_state": 7,
                "identity_count": 0,
                "group_state_count": 0,
            },
            "REMOVE_EMPTY_USER_INTENT": {
                "command": 0x48,
                "component": "selected-user",
                "retry_permitted": False,
            },
            "REMOVE_EMPTY_USER_ACCEPTED": {
                "reply_received": True, "retry_permitted": False
            },
            "REMOVED_USER_RECONCILED": {
                "master_state": 7, "identity_count": 0, "group_state_count": 0
            },
            "MASTER_EXPORT_PREPARE_INTENT": {
                "component": "master",
                "descriptor_sha256": "b" * 64,
                "retry_permitted": False,
            },
            "MASTER_EXPORT_PREPARED": {
                "component": "master", "expected_length": 24
            },
            "MASTER_EXPORT_COMPLETE_INTENT": {
                "component": "master", "retry_permitted": False
            },
            "MASTER_EXPORT_CAPTURED": {
                "component": "master",
                "secure_data_sha256": secure_hash,
                "encoded_sha256": intermediate_hash,
                "encoded_enrollment_count": 0,
            },
            "MASTER_EXPORT_CONFIRM_INTENT": {
                "component": "master", "retry_permitted": False
            },
            "MASTER_EXPORT_CONFIRMED": {"component": "master", "status": 0},
            "MASTER_SETTLED": {
                "master_state": 3, "identity_count": 0, "group_state_count": 0
            },
            "REPREPARE_MASTER_INTENT": {
                "command": 0x31, "component": "master", "retry_permitted": False
            },
            "REPREPARE_MASTER_ACCEPTED": {
                "reply_received": True, "retry_permitted": False
            },
            "REPREPARE_USER_INTENT": {
                "command": 0x31,
                "component": "selected-user",
                "retry_permitted": False,
            },
            "REPREPARE_USER_ACCEPTED": {
                "reply_received": True, "retry_permitted": False
            },
            "RECLIENT_VERSION_SELECTED": {"client_version": 2},
            "REPREPARED_COMPONENTS_POST_STATE_REJECTED": {
                "stable_surface_rejected": True, "retry_permitted": False
            },
        }
        history = recovery.validate_history(t2_mutation_journal.read(path))
        for milestone in recovery.COLD_RESCUE_MILESTONES[1:24]:
            history = recovery._append(
                path, history.operation_id, milestone, evidence[milestone]
            )
        return history

    def advance_to_canonical_user_rejection(self, path):
        history = self.advance_to_reprepared_rejection(path)
        evidence = {
            "COLD_RESTART_PREPARED": {
                "source_linux_boot_uuid": BOOT,
                "intermediate_master_sha256": "1" * 64,
                "candidate_master_sha256": "2" * 64,
                "identity_count": 1,
            },
            "COLD_SURFACE_RECONCILED": {
                "different_linux_boot": True,
                "master_state": 1,
                "user_state": None,
                "identity_count": 0,
                "group_state_count": 0,
            },
            "RETAINED_MASTER_LOAD_INTENT": {
                "command": 0x40,
                "component": "master",
                "secure_data_sha256": "3" * 64,
                "identity_count": 1,
                "retry_permitted": False,
            },
            "RETAINED_MASTER_LOAD_ACCEPTED": {
                "reply_received": True,
                "retry_permitted": False,
            },
            "COLD_MASTER_RECONCILED": {
                "master_state": 3,
                "user_state": None,
                "identity_count": 0,
                "group_state_count": 0,
            },
            "SAVED_USER_LOAD_INTENT": {
                "command": 0x40,
                "component": "selected-user",
                "secure_data_sha256": "4" * 64,
                "identity_count": 1,
                "retry_permitted": False,
            },
            "SAVED_USER_LOAD_REPLY_REJECTED": {
                "reply_received": True,
                "retry_permitted": False,
            },
            "CANONICAL_RESTART_PREPARED": {
                "source_linux_boot_uuid": BOOT,
                "master_sha256": "5" * 64,
                "master_secure_data_sha256": "6" * 64,
                "user_secure_data_sha256": "7" * 64,
                "identity_count": 1,
            },
            "CANONICAL_COLD_SURFACE_RECONCILED": {
                "different_linux_boot": True,
                "master_state": 1,
                "user_state": None,
                "identity_count": 0,
                "group_state_count": 0,
            },
            "CANONICAL_MASTER_LOAD_INTENT": {
                "command": 0x40,
                "component": "master",
                "secure_data_sha256": "6" * 64,
                "identity_count": 1,
                "retry_permitted": False,
            },
            "CANONICAL_MASTER_LOAD_REPLY_REJECTED": {
                "reply_received": True,
                "retry_permitted": False,
            },
            "CANONICAL_MASTER_REPLY_RECONCILED": {
                "master_state": 3,
                "user_state": None,
                "identity_count": 0,
                "group_state_count": 0,
                "nonzero_reply": True,
                "load_replayed": False,
            },
            "CANONICAL_USER_LOAD_INTENT": {
                "command": 0x40,
                "component": "selected-user",
                "secure_data_sha256": "7" * 64,
                "identity_count": 1,
                "retry_permitted": False,
            },
            "CANONICAL_USER_LOAD_REPLY_REJECTED": {
                "reply_received": True,
                "retry_permitted": False,
            },
        }
        for milestone in recovery.EMPTY_REPROVISION_MILESTONES[24:38]:
            history = recovery._append(
                path, history.operation_id, milestone, evidence[milestone]
            )
        return history

    def test_retained_inventory_is_exact(self):
        live = retained_inventory()
        self.assertTrue(recovery.is_retained_master_inventory(live, USER))
        for key, value in (
            ("double_collection_equal", False),
            ("apple_uid", USER + 1),
            ("per_user_identity_records", [{"unexpected": True}]),
        ):
            changed = copy.deepcopy(live)
            changed[key] = value
            self.assertFalse(recovery.is_retained_master_inventory(changed, USER))
        changed = copy.deepcopy(live)
        changed["catacomb"]["user_states"][0]["state"] = 1
        self.assertFalse(recovery.is_retained_master_inventory(changed, USER))

    def test_rejected_canonical_user_reprovisions_empty_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _history, user, components = self.create(root)
            history = self.advance_to_canonical_user_rejection(path)
            self.assertTrue(history.blocked)
            self.assertTrue(
                recovery.empty_reprovision_is_resumable(
                    t2_mutation_journal.read(path)
                )
            )
            master_only = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 3),),
                "group_state_count": 0,
            }
            ready = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            lease = FakeLease(client_version=2)
            with patch.object(
                recovery.t2_compatibility_user_rebind,
                "read_stable_surface",
                return_value=master_only,
            ):
                history = recovery.reconcile_incompatible_user_surface(
                    lease, apple_user_id=USER, journal_path=path
                )
            preclient = FakeLease(client_version=0)
            with (
                patch.object(
                    recovery.t2_bridge_inventory,
                    "attest_preclient_protocol",
                ),
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    return_value=ready,
                ),
            ):
                history = recovery.prepare_empty_reprovision(
                    preclient, apple_user_id=USER, journal_path=path
                )
            self.assertEqual(preclient.commands, [0x31, 0x31])
            self.assertEqual(history.milestone, "EMPTY_REPROVISION_READY")

            from tests.test_catacomb_codec import fixture

            source_user = recovery.t2_catacomb_codec.decode_user_catacomb(
                fixture(), USER
            )
            empty_user = recovery.t2_catacomb_codec.decode_user_catacomb(
                source_user.clear_after_stable_sep_empty(
                    sep_empty_attested=True
                ),
                USER,
            )
            empty_master = recovery.t2_catacomb_codec.encode_initial_master_catacomb(
                secure_data=b"LTFC" + b"m" * 28,
                enrollment_count=0,
                current_time=3.0,
            )
            empty_components = dict(
                components,
                **{
                    "master.cat": empty_master,
                    "user_000001f5.cat": empty_user.replace_secure_data(
                        b"LTFC" + b"u" * 28
                    ),
                },
            )
            live = retained_inventory()
            live["catacomb"]["user_states"].append(
                {
                    "kind": "user",
                    "user_id": USER,
                    "state": 3,
                    "needs_save": False,
                }
            )
            with patch.object(
                recovery.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value=live,
            ):
                history = recovery.reconcile_empty_catacombs(
                    lease,
                    apple_user_id=USER,
                    components=empty_components,
                    journal_path=path,
                )
            record = SimpleNamespace(payload=b"encrypted-biolockout")
            biolockout_store = SimpleNamespace(current=lambda: record)
            with patch.object(
                recovery.t2_native_state_restore, "_load_biolockout"
            ) as load:
                history = recovery.restore_empty_reprovision_biolockout(
                    lease,
                    apple_user_id=USER,
                    store=biolockout_store,
                    journal_path=path,
                )
            load.assert_called_once()
            self.assertTrue(history.complete)
            self.assertEqual(history.milestone, "EMPTY_REPROVISION_COMPLETE")

    def test_full_sequence_is_journaled_before_each_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, history, user, components = self.create(root)
            lease = FakeLease()
            prepared = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 5),
                ),
                "group_state_count": 0,
            }
            loaded = {
                "per_user_identity_count": 1,
                "global_identity_count": 1,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            with (
                patch.object(
                    recovery.t2_bridge_inventory,
                    "attest_preclient_protocol",
                ),
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    side_effect=(prepared, prepared, loaded),
                ),
                patch.object(
                    recovery.t2_native_state_restore,
                    "_identities",
                    return_value={(USER, IDENTITY)},
                ),
                patch.object(
                    recovery.t2_native_state_restore,
                    "_load_biolockout",
                ) as load_biolockout,
            ):
                history = recovery.prepare_missing_components(
                    lease, apple_user_id=USER, journal_path=path
                )
                self.assertEqual(history.milestone, "MISSING_COMPONENTS_RECONCILED")
                history = recovery.restore_saved_user(
                    lease, apple_user_id=USER, user=user, journal_path=path
                )
                self.assertEqual(history.milestone, "SAVED_USER_RECONCILED")
                history = recovery.begin_catacomb_persistence(
                    path, required=True
                )
                self.assertEqual(history.milestone, "CATACOMB_PERSISTENCE_INTENT")
                history = recovery.reconcile_catacomb_persistence(
                    path,
                    persisted=True,
                    components=components,
                    user=user,
                )
                store = SimpleNamespace(
                    current=lambda: SimpleNamespace(payload=b"HRLB-current")
                )
                history = recovery.restore_biolockout(
                    lease,
                    apple_user_id=USER,
                    store=store,
                    journal_path=path,
                )
            self.assertTrue(history.complete)
            self.assertEqual(lease.commands, [0x31, 0x31, 0x40])
            load_biolockout.assert_called_once()
            self.assertEqual(
                [record["milestone"] for record in t2_mutation_journal.read(path)],
                list(recovery.SUCCESS_MILESTONES),
            )

    def test_rejected_prepare_is_terminal_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _history, _user, _components = self.create(Path(directory))
            lease = FakeLease(reject=0x31)
            with patch.object(
                recovery.t2_bridge_inventory, "attest_preclient_protocol"
            ):
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError, "rejected"
                ):
                    recovery.prepare_missing_components(
                        lease, apple_user_id=USER, journal_path=path
                    )
            history = recovery.validate_history(
                t2_mutation_journal.read(path)
            )
            self.assertTrue(history.blocked)
            self.assertEqual(history.milestone, "PREPARE_MASTER_REPLY_REJECTED")
            self.assertEqual(lease.commands, [0x31])

    def test_rejected_saved_user_load_is_terminal_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _history, user, _components = self.create(Path(directory))
            lease = FakeLease(reject=0x40)
            prepared = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 1),
                ),
                "group_state_count": 0,
            }
            with (
                patch.object(
                    recovery.t2_bridge_inventory,
                    "attest_preclient_protocol",
                ),
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    return_value=prepared,
                ),
            ):
                recovery.prepare_missing_components(
                    lease, apple_user_id=USER, journal_path=path
                )
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError, "rejected"
                ):
                    recovery.restore_saved_user(
                        lease,
                        apple_user_id=USER,
                        user=user,
                        journal_path=path,
                    )
            history = recovery.validate_history(
                t2_mutation_journal.read(path)
            )
            self.assertTrue(history.blocked)
            self.assertEqual(
                history.milestone, "SAVED_USER_LOAD_REPLY_REJECTED"
            )
            self.assertEqual(lease.commands.count(0x40), 1)

    def test_saved_authority_change_blocks_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            path, history, user, components = self.create(Path(directory))
            changed = dict(components)
            changed["user_000001f5.cat"] = b"changed"
            with self.assertRaisesRegex(
                recovery.NativeStateRecoveryError, "authority changed"
            ):
                recovery.require_authority_unchanged(
                    history,
                    apple_user_id=USER,
                    mapping_generation=MAPPING,
                    components=changed,
                    user=user,
                )

    def test_loaded_empty_result_runs_guarded_rescue_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _history, user, _components = self.create(root)
            loaded_empty = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            removed = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 7),),
                "group_state_count": 0,
            }
            settled = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 3),),
                "group_state_count": 0,
            }
            prepared = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 5),
                ),
                "group_state_count": 0,
            }
            restored = {
                "per_user_identity_count": 1,
                "global_identity_count": 1,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            initial = FakeLease()
            with (
                patch.object(
                    recovery.t2_bridge_inventory, "attest_preclient_protocol"
                ),
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    return_value=loaded_empty,
                ),
            ):
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError, "unexpected state"
                ):
                    recovery.prepare_missing_components(
                        initial, apple_user_id=USER, journal_path=path
                    )
            history = recovery.validate_history(
                t2_mutation_journal.read(path)
            )
            self.assertFalse(history.blocked)
            self.assertEqual(
                history.milestone, "MISSING_COMPONENTS_POST_STATE_REJECTED"
            )

            selected = FakeLease(client_version=2)
            artifact_root = root / "artifacts"
            artifact_root.mkdir(mode=0o700)
            transport = SimpleNamespace(
                prepare=lambda _descriptor: (0, 11),
                complete=lambda _descriptor: (0, bytearray(b"master-live")),
                confirm=lambda _descriptor: None,
            )
            master = SimpleNamespace(
                encode=lambda **_kwargs: b"encoded-intermediate-master"
            )
            with (
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    side_effect=(
                        loaded_empty,
                        loaded_empty,
                        removed,
                        removed,
                        settled,
                    ),
                ),
                patch.object(
                    recovery.t2_catacomb_bridge,
                    "CatacombBridgeTransport",
                    return_value=transport,
                ),
                patch.object(
                    recovery.t2_catacomb_codec,
                    "decode_master_catacomb",
                    return_value=master,
                ),
            ):
                recovery.reconcile_loaded_empty_user(
                    selected, apple_user_id=USER, journal_path=path
                )
                recovery.remove_loaded_empty_user(
                    selected, apple_user_id=USER, journal_path=path
                )
                history = recovery.settle_removed_master(
                    selected,
                    apple_user_id=USER,
                    master_archive=b"saved-master",
                    artifact_path=artifact_root / "intermediate-master.cat",
                    journal_path=path,
                )
            self.assertEqual(history.milestone, "MASTER_SETTLED")
            self.assertEqual(selected.commands, [0x48])

            recreated = FakeLease()
            with (
                patch.object(
                    recovery.t2_bridge_inventory, "attest_preclient_protocol"
                ),
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    side_effect=(prepared, prepared, restored),
                ),
                patch.object(
                    recovery.t2_native_state_restore,
                    "_identities",
                    return_value={(USER, IDENTITY)},
                ),
            ):
                history = recovery.reprepare_missing_components(
                    recreated, apple_user_id=USER, journal_path=path
                )
                history = recovery.restore_saved_user(
                    recreated,
                    apple_user_id=USER,
                    user=user,
                    journal_path=path,
                )
            self.assertEqual(history.milestone, "SAVED_USER_RECONCILED")
            self.assertEqual(recreated.commands, [0x31, 0x31, 0x40])
            self.assertEqual(
                [
                    record["milestone"]
                    for record in t2_mutation_journal.read(path)
                ],
                list(
                    recovery.RESCUE_MILESTONES[
                        : recovery.RESCUE_MILESTONES.index(
                            "SAVED_USER_RECONCILED"
                        ) + 1
                    ]
                ),
            )

    def test_loaded_empty_reconciliation_refuses_nonempty_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _history, _user, _components = self.create(Path(directory))
            initial = FakeLease()
            loaded_empty = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            with (
                patch.object(
                    recovery.t2_bridge_inventory, "attest_preclient_protocol"
                ),
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    return_value=loaded_empty,
                ),
            ):
                with self.assertRaises(recovery.NativeStateRecoveryError):
                    recovery.prepare_missing_components(
                        initial, apple_user_id=USER, journal_path=path
                    )
            changed = dict(loaded_empty, per_user_identity_count=1)
            lease = FakeLease(client_version=2)
            with patch.object(
                recovery.t2_compatibility_user_rebind,
                "read_stable_surface",
                return_value=changed,
            ):
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError, "exact loaded-empty"
                ):
                    recovery.reconcile_loaded_empty_user(
                        lease, apple_user_id=USER, journal_path=path
                    )
            self.assertNotIn(0x48, lease.commands)

    def test_repeated_loaded_result_prepares_and_restores_on_cold_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user, components = authority()
            retained_secure = b"LTFC" + b"r" * 16
            canonical_secure = b"LTFC" + b"c" * 16
            intermediate = recovery.t2_catacomb_codec.encode_initial_master_catacomb(
                secure_data=retained_secure,
                enrollment_count=0,
                current_time=1.0,
            )
            canonical = recovery.t2_catacomb_codec.encode_initial_master_catacomb(
                secure_data=canonical_secure,
                enrollment_count=1,
                current_time=2.0,
            )
            components["master.cat"] = canonical
            path = root / f"{uuid.UUID(int=4)}.jsonl"
            recovery.create_journal(
                path,
                str(uuid.UUID(int=4)),
                apple_user_id=USER,
                mapping_generation=MAPPING,
                linux_boot_uuid=BOOT,
                live=retained_inventory(),
                components=components,
                user=user,
            )
            artifact_root = root / "artifacts"
            artifact_root.mkdir(mode=0o700)
            intermediate_path = artifact_root / "intermediate-master.cat"
            intermediate_path.write_bytes(intermediate)
            intermediate_path.chmod(0o600)
            history = self.advance_to_reprepared_rejection(
                path,
                secure_hash=recovery._sha256(retained_secure),
                intermediate_hash=recovery._sha256(intermediate),
            )
            self.assertFalse(history.blocked)
            terminal = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            candidate_path = artifact_root / "cold-retained-master.cat"
            with patch.object(
                recovery.t2_compatibility_user_rebind,
                "read_stable_surface",
                return_value=terminal,
            ):
                history = recovery.prepare_cold_restart(
                    FakeLease(client_version=2),
                    apple_user_id=USER,
                    linux_boot_uuid=BOOT,
                    master_archive=canonical,
                    user=user,
                    intermediate_path=intermediate_path,
                    candidate_path=candidate_path,
                    journal_path=path,
                )
            self.assertEqual(history.milestone, "COLD_RESTART_PREPARED")
            candidate = recovery.t2_catacomb_codec.decode_master_catacomb(
                candidate_path.read_bytes()
            )
            self.assertEqual(candidate.secure_data, retained_secure)
            self.assertEqual(candidate.enrollment_count, 1)
            with self.assertRaisesRegex(
                recovery.NativeStateRecoveryError, "different Linux boot"
            ):
                recovery.reconcile_cold_surface(
                    FakeLease(client_version=2),
                    apple_user_id=USER,
                    linux_boot_uuid=BOOT,
                    journal_path=path,
                )

            cold = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 1),),
                "group_state_count": 0,
            }
            after_master = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 3),),
                "group_state_count": 0,
            }
            restored = {
                "per_user_identity_count": 1,
                "global_identity_count": 1,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            next_boot = str(uuid.UUID(int=90))
            lease = FakeLease(client_version=2)
            with (
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    side_effect=(cold, after_master, after_master, restored),
                ),
                patch.object(
                    recovery.t2_native_state_restore,
                    "_identities",
                    return_value={(USER, IDENTITY)},
                ),
            ):
                history = recovery.reconcile_cold_surface(
                    lease,
                    apple_user_id=USER,
                    linux_boot_uuid=next_boot,
                    journal_path=path,
                )
                history = recovery.load_canonical_master(
                    lease,
                    apple_user_id=USER,
                    master_archive=canonical,
                    user=user,
                    journal_path=path,
                )
                history = recovery.reconcile_canonical_master(
                    lease,
                    apple_user_id=USER,
                    journal_path=path,
                )
                history = recovery.load_canonical_user(
                    lease,
                    apple_user_id=USER,
                    user=user,
                    journal_path=path,
                )
                history = recovery.reconcile_saved_user(
                    lease,
                    apple_user_id=USER,
                    user=user,
                    journal_path=path,
                )
            self.assertEqual(history.milestone, "SAVED_USER_RECONCILED")
            self.assertEqual(lease.commands, [0x40, 0x40])
            self.assertEqual(lease.payloads, [canonical_secure, user.secure_data])

    def test_rejected_derived_user_redirects_to_canonical_cold_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            user, components = authority()
            retained_secure = b"LTFC" + b"r" * 16
            canonical_secure = b"LTFC" + b"c" * 16
            intermediate = recovery.t2_catacomb_codec.encode_initial_master_catacomb(
                secure_data=retained_secure,
                enrollment_count=0,
                current_time=1.0,
            )
            canonical = recovery.t2_catacomb_codec.encode_initial_master_catacomb(
                secure_data=canonical_secure,
                enrollment_count=1,
                current_time=2.0,
            )
            components["master.cat"] = canonical
            path = root / f"{uuid.UUID(int=4)}.jsonl"
            recovery.create_journal(
                path,
                str(uuid.UUID(int=4)),
                apple_user_id=USER,
                mapping_generation=MAPPING,
                linux_boot_uuid=BOOT,
                live=retained_inventory(),
                components=components,
                user=user,
            )
            artifact_root = root / "artifacts"
            artifact_root.mkdir(mode=0o700)
            intermediate_path = artifact_root / "intermediate-master.cat"
            intermediate_path.write_bytes(intermediate)
            intermediate_path.chmod(0o600)
            self.advance_to_reprepared_rejection(
                path,
                secure_hash=recovery._sha256(retained_secure),
                intermediate_hash=recovery._sha256(intermediate),
            )
            terminal = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            candidate_path = artifact_root / "cold-retained-master.cat"
            with patch.object(
                recovery.t2_compatibility_user_rebind,
                "read_stable_surface",
                return_value=terminal,
            ):
                recovery.prepare_cold_restart(
                    FakeLease(client_version=2),
                    apple_user_id=USER,
                    linux_boot_uuid=BOOT,
                    master_archive=canonical,
                    user=user,
                    intermediate_path=intermediate_path,
                    candidate_path=candidate_path,
                    journal_path=path,
                )

            cold = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 1),),
                "group_state_count": 0,
            }
            after_master = {
                "per_user_identity_count": 0,
                "global_identity_count": 0,
                "user_states": (("master", 0xFFFFFFFF, 3),),
                "group_state_count": 0,
            }
            first_cold_boot = str(uuid.UUID(int=90))
            derived = FakeLease(client_version=2, reject=0x40, reject_at=2)
            with patch.object(
                recovery.t2_compatibility_user_rebind,
                "read_stable_surface",
                side_effect=(cold, after_master, after_master),
            ):
                recovery.reconcile_cold_surface(
                    derived,
                    apple_user_id=USER,
                    linux_boot_uuid=first_cold_boot,
                    journal_path=path,
                )
                recovery.load_retained_master(
                    derived,
                    apple_user_id=USER,
                    candidate_path=candidate_path,
                    journal_path=path,
                )
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError, "rejected"
                ):
                    recovery.restore_saved_user(
                        derived,
                        apple_user_id=USER,
                        user=user,
                        journal_path=path,
                    )
            records = t2_mutation_journal.read(path)
            self.assertTrue(recovery.validate_history(records).blocked)
            self.assertTrue(recovery.canonical_restart_is_resumable(records))
            with patch.object(
                recovery.t2_compatibility_user_rebind,
                "read_stable_surface",
                return_value=after_master,
            ):
                history = recovery.prepare_canonical_restart(
                    derived,
                    apple_user_id=USER,
                    linux_boot_uuid=first_cold_boot,
                    master_archive=canonical,
                    user=user,
                    journal_path=path,
                )
            self.assertEqual(history.milestone, "CANONICAL_RESTART_PREPARED")
            self.assertFalse(history.blocked)
            with self.assertRaisesRegex(
                recovery.NativeStateRecoveryError, "different Linux boot"
            ):
                recovery.reconcile_canonical_cold_surface(
                    derived,
                    apple_user_id=USER,
                    linux_boot_uuid=first_cold_boot,
                    journal_path=path,
                )

            restored = {
                "per_user_identity_count": 1,
                "global_identity_count": 1,
                "user_states": (
                    ("master", 0xFFFFFFFF, 3),
                    ("user", USER, 7),
                ),
                "group_state_count": 0,
            }
            canonical_lease = FakeLease(
                client_version=2, reject=0x40, reject_at=1
            )
            changed_canonical = (
                recovery.t2_catacomb_codec.encode_initial_master_catacomb(
                    secure_data=b"LTFC" + b"d" * 16,
                    enrollment_count=1,
                    current_time=3.0,
                )
            )
            with (
                patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    side_effect=(cold, after_master, after_master, restored),
                ),
                patch.object(
                    recovery.t2_native_state_restore,
                    "_identities",
                    return_value={(USER, IDENTITY)},
                ),
            ):
                recovery.reconcile_canonical_cold_surface(
                    canonical_lease,
                    apple_user_id=USER,
                    linux_boot_uuid=str(uuid.UUID(int=91)),
                    journal_path=path,
                )
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError,
                    "differs from the recovery journal",
                ):
                    recovery.load_canonical_master(
                        canonical_lease,
                        apple_user_id=USER,
                        master_archive=changed_canonical,
                        user=user,
                        journal_path=path,
                    )
                self.assertEqual(canonical_lease.commands, [])
                with self.assertRaisesRegex(
                    recovery.NativeStateRecoveryError, "rejected"
                ):
                    recovery.load_canonical_master(
                        canonical_lease,
                        apple_user_id=USER,
                        master_archive=canonical,
                        user=user,
                        journal_path=path,
                    )
                records = t2_mutation_journal.read(path)
                self.assertTrue(recovery.validate_history(records).blocked)
                self.assertTrue(
                    recovery.canonical_master_reply_is_resumable(records)
                )
                rejected_copy = root / "rejected-master-copy.jsonl"
                rejected_copy.write_bytes(path.read_bytes())
                rejected_copy.chmod(0o600)
                with patch.object(
                    recovery.t2_compatibility_user_rebind,
                    "read_stable_surface",
                    return_value=cold,
                ):
                    with self.assertRaisesRegex(
                        recovery.NativeStateRecoveryError,
                        "exact loaded surface",
                    ):
                        recovery.reconcile_canonical_master_reply(
                            canonical_lease,
                            apple_user_id=USER,
                            journal_path=rejected_copy,
                        )
                self.assertEqual(canonical_lease.commands, [0x40])
                recovery.reconcile_canonical_master_reply(
                    canonical_lease,
                    apple_user_id=USER,
                    journal_path=path,
                )
                recovery.load_canonical_user(
                    canonical_lease,
                    apple_user_id=USER,
                    user=user,
                    journal_path=path,
                )
                history = recovery.reconcile_saved_user(
                    canonical_lease,
                    apple_user_id=USER,
                    user=user,
                    journal_path=path,
                )
            self.assertEqual(history.milestone, "SAVED_USER_RECONCILED")
            self.assertEqual(
                canonical_lease.payloads,
                [canonical_secure, user.secure_data],
            )


if __name__ == "__main__":
    unittest.main()
