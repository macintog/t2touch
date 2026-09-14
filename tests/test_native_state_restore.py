# SPDX-License-Identifier: GPL-2.0-only

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
