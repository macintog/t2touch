# SPDX-License-Identifier: GPL-2.0-only

import copy
import struct
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_native_state_restore as restore


USER = 501


def states(master: int, user: int) -> bytes:
    return struct.pack("<IIII", 0xFFFFFFFF, master, USER, user)


def master_state(state: int) -> bytes:
    return struct.pack("<II", 0xFFFFFFFF, state)


class FakeLease:
    def __init__(self, *, state_reads=None, identity_reads=None):
        self.commands = []
        self.state_reads = iter(
            state_reads or (master_state(1), states(3, 1), states(3, 3))
        )
        self.identity_reads = iter(
            identity_reads
            or (b"", struct.pack("<I", USER) + uuid.UUID(int=1).bytes)
        )
        self.invalidated = False

    def biometric_command(self, command, *, version, value, data, output_capacity):
        self.commands.append(command)
        if command == 0x3C:
            return [0, next(self.state_reads)], []
        if command == 0x50:
            return [0, b""], []
        if command == 0x42:
            return [0, next(self.identity_reads)], []
        return [0, b""], []

    def invalidate(self):
        self.invalidated = True


class NativeStateRestoreTests(unittest.TestCase):
    def test_cold_inventory_requires_exact_unloaded_master_only_state(self):
        cold = {
            "double_collection_equal": True,
            "apple_uid": USER,
            "biometric_protocol_version": 2,
            "per_user_identity_records": [],
            "global_identity_records": [],
            "catacomb": {
                "present": False,
                "uuid": str(uuid.UUID(int=0)),
                "hash": "0" * 64,
                "user_states": [{"kind": "master", "user_id": 0xFFFFFFFF,
                                 "state": 1, "needs_save": False}],
            },
        }
        self.assertTrue(restore.is_cold_unloaded_inventory(cold, USER))
        master_loaded = copy.deepcopy(cold)
        master_loaded["catacomb"]["user_states"][0]["state"] = 3
        self.assertFalse(restore.is_cold_unloaded_inventory(master_loaded, USER))
        changes = (
            ("double_collection_equal", False),
            ("apple_uid", USER + 1),
            ("biometric_protocol_version", 1),
            ("per_user_identity_records", [object()]),
            ("global_identity_records", [object()]),
        )
        for field, value in changes:
            with self.subTest(field=field):
                changed = copy.deepcopy(cold)
                changed[field] = value
                self.assertFalse(restore.is_cold_unloaded_inventory(changed, USER))
        for state in (0, 3, 7, 9, True):
            with self.subTest(master_state=state):
                changed = copy.deepcopy(cold)
                changed["catacomb"]["user_states"][0]["state"] = state
                self.assertFalse(restore.is_cold_unloaded_inventory(changed, USER))
        for field, value in (("present", True), ("uuid", str(uuid.UUID(int=1))),
                             ("hash", "a" * 64), ("user_states", [])):
            with self.subTest(catacomb_field=field):
                changed = copy.deepcopy(cold)
                changed["catacomb"][field] = value
                self.assertFalse(restore.is_cold_unloaded_inventory(changed, USER))
        loaded_empty = copy.deepcopy(cold)
        loaded_empty["catacomb"]["user_states"] = [
            {"kind": "master", "user_id": 0xFFFFFFFF, "state": 3, "needs_save": False},
            {"kind": "user", "user_id": USER, "state": 3, "needs_save": False},
        ]
        self.assertFalse(restore.is_cold_unloaded_inventory(loaded_empty, USER))

    def test_master_then_user_then_biolockout_restore_order(self):
        lease = FakeLease()
        catacomb = SimpleNamespace(
            read_committed_components=lambda: {
                "master.cat": b"master",
                "user_000001f5.cat": b"user",
                "biolockout.cat": b"bio",
            }
        )
        biolockout = SimpleNamespace(
            current=lambda: SimpleNamespace(payload=b"HRLB-current")
        )
        with (
            patch.object(
                restore.t2_catacomb_codec,
                "decode_master_catacomb",
                return_value=SimpleNamespace(secure_data=b"LTFC-master"),
            ),
            patch.object(
                restore.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=SimpleNamespace(
                    secure_data=b"LTFC-user",
                    identities=(
                        SimpleNamespace(user_id=USER, uuid=str(uuid.UUID(int=1))),
                    ),
                ),
            ),
        ):
            count = restore.restore_for_enrollment(
                lease,
                apple_user_id=USER,
                catacomb_store=catacomb,
                biolockout_store=biolockout,
            )
        self.assertEqual(count, 1)
        self.assertEqual(
            lease.commands,
            [0x3C, 0x50, 0x42, 0x40, 0x3C, 0x40, 0x3C, 0x50, 0x42, 0x4B],
        )
        self.assertFalse(lease.invalidated)

    def test_sep_ahead_biolockout_is_exported_appended_and_reloaded(self):
        identity = struct.pack("<I", USER) + uuid.UUID(int=1).bytes

        class SepAheadLease(FakeLease):
            def __init__(self):
                super().__init__(
                    state_reads=(states(3, 3), states(3, 3)),
                    identity_reads=(identity, identity),
                )
                self.load_count = 0

            def biometric_command(
                self, command, *, version, value, data, output_capacity
            ):
                if command == 0x4B:
                    self.commands.append(command)
                    self.load_count += 1
                    return ([-5], []) if self.load_count == 1 else ([0, b""], [])
                if command == 0x4A:
                    self.commands.append(command)
                    return [0, b"HRLB-sep-ahead"], []
                return super().biometric_command(
                    command,
                    version=version,
                    value=value,
                    data=data,
                    output_capacity=output_capacity,
                )

        lease = SepAheadLease()
        catacomb = SimpleNamespace(
            read_committed_components=lambda: {
                "master.cat": b"master",
                "user_000001f5.cat": b"user",
            }
        )
        committed = []
        current = SimpleNamespace(payload=b"HRLB-host-head")
        biolockout = SimpleNamespace(
            current=lambda: current,
            commit=lambda payload: (
                committed.append(payload)
                or SimpleNamespace(payload=payload)
            ),
        )
        with (
            patch.object(
                restore.t2_catacomb_codec,
                "decode_master_catacomb",
                return_value=SimpleNamespace(secure_data=b"LTFC-master"),
            ),
            patch.object(
                restore.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=SimpleNamespace(
                    secure_data=b"LTFC-user",
                    identities=(
                        SimpleNamespace(
                            user_id=USER, uuid=str(uuid.UUID(int=1))
                        ),
                    ),
                ),
            ),
        ):
            count = restore.restore_for_enrollment(
                lease,
                apple_user_id=USER,
                catacomb_store=catacomb,
                biolockout_store=biolockout,
            )
        self.assertEqual(count, 1)
        self.assertEqual(committed, [b"HRLB-sep-ahead"])
        self.assertEqual(lease.commands[-3:], [0x4B, 0x4A, 0x4B])
        self.assertFalse(lease.invalidated)

    def test_missing_user_after_master_load_dispatches_saved_user(self):
        identity = struct.pack("<I", USER) + uuid.UUID(int=1).bytes
        lease = FakeLease(
            state_reads=(master_state(1), master_state(3), states(3, 3)),
            identity_reads=(b"", identity),
        )
        catacomb = SimpleNamespace(read_committed_components=lambda: {
            "master.cat": b"master", "user_000001f5.cat": b"user",
        })
        biolockout = SimpleNamespace(
            current=lambda: SimpleNamespace(payload=b"HRLB-current")
        )
        with (
            patch.object(restore.t2_catacomb_codec, "decode_master_catacomb",
                         return_value=SimpleNamespace(secure_data=b"LTFC-master")),
            patch.object(restore.t2_catacomb_codec, "decode_user_catacomb",
                         return_value=SimpleNamespace(secure_data=b"LTFC-user", identities=(
                             SimpleNamespace(user_id=USER, uuid=str(uuid.UUID(int=1))),))),
        ):
            count = restore.restore_for_enrollment(
                lease,
                apple_user_id=USER,
                catacomb_store=catacomb,
                biolockout_store=biolockout,
            )
        self.assertEqual(count, 1)
        self.assertEqual(lease.commands.count(0x40), 2)
        self.assertFalse(lease.invalidated)

    def test_live_identity_allows_secure_dirty_user_for_following_enrollment(self):
        identity = struct.pack("<I", USER) + uuid.UUID(int=1).bytes
        lease = FakeLease(
            state_reads=(states(3, 7), states(3, 7)),
            identity_reads=(identity, identity),
        )
        catacomb = SimpleNamespace(
            read_committed_components=lambda: {
                "master.cat": b"master",
                "user_000001f5.cat": b"user",
                "biolockout.cat": b"bio",
            }
        )
        biolockout = SimpleNamespace(
            current=lambda: SimpleNamespace(payload=b"HRLB-current")
        )
        with (
            patch.object(
                restore.t2_catacomb_codec,
                "decode_master_catacomb",
                return_value=SimpleNamespace(secure_data=b"LTFC-master"),
            ),
            patch.object(
                restore.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=SimpleNamespace(
                    secure_data=b"LTFC-user",
                    identities=(
                        SimpleNamespace(user_id=USER, uuid=str(uuid.UUID(int=1))),
                    ),
                ),
            ),
        ):
            count = restore.restore_for_enrollment(
                lease,
                apple_user_id=USER,
                catacomb_store=catacomb,
                biolockout_store=biolockout,
            )
        self.assertEqual(count, 1)
        self.assertEqual(
            lease.commands,
            [0x3C, 0x50, 0x42, 0x3C, 0x50, 0x42, 0x4B],
        )
        self.assertFalse(lease.invalidated)

    def test_empty_inventory_with_loaded_state_requires_cold_bridgeos_restart(self):
        lease = FakeLease(
            state_reads=(states(3, 7),),
            identity_reads=(b"",),
        )
        catacomb = SimpleNamespace(
            read_committed_components=lambda: {
                "master.cat": b"master",
                "user_000001f5.cat": b"user",
                "biolockout.cat": b"bio",
            }
        )
        biolockout = SimpleNamespace(current=lambda: None)
        with (
            patch.object(
                restore.t2_catacomb_codec,
                "decode_master_catacomb",
                return_value=SimpleNamespace(secure_data=b"LTFC-master"),
            ),
            patch.object(
                restore.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=SimpleNamespace(
                    secure_data=b"LTFC-user",
                    identities=(
                        SimpleNamespace(user_id=USER, uuid=str(uuid.UUID(int=1))),
                    ),
                ),
            ),
        ):
            with self.assertRaisesRegex(
                restore.NativeStateRestoreError, "cold bridgeOS restart required"
            ):
                restore.restore_for_enrollment(
                    lease,
                    apple_user_id=USER,
                    catacomb_store=catacomb,
                    biolockout_store=biolockout,
                )
        self.assertEqual(lease.commands, [0x3C, 0x50, 0x42])
        self.assertTrue(lease.invalidated)

        reconciled = FakeLease(
            state_reads=(states(3, 7), states(3, 7)),
            identity_reads=(b"", b""),
        )
        biolockout = SimpleNamespace(
            current=lambda: SimpleNamespace(payload=b"HRLB-current")
        )
        with (
            patch.object(
                restore.t2_catacomb_codec,
                "decode_master_catacomb",
                return_value=SimpleNamespace(secure_data=b"LTFC-master"),
            ),
            patch.object(
                restore.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=SimpleNamespace(
                    secure_data=b"LTFC-user", identities=()
                ),
            ),
        ):
            count = restore.restore_for_enrollment(
                reconciled,
                apple_user_id=USER,
                catacomb_store=catacomb,
                biolockout_store=biolockout,
            )
        self.assertEqual(count, 0)
        self.assertNotIn(0x40, reconciled.commands)
        self.assertFalse(reconciled.invalidated)


if __name__ == "__main__":
    unittest.main()
