# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_catacomb_codec as codec
import t2_fprint_match_gate as match_gate
import t2_fprint_match_selection as match_selection
import t2_fprint_projection as projection
import t2_fprint_sequence as sequence
import t2_identity_delete as identity_delete
import t2_identity_inventory as identity_inventory
from tests.test_catacomb_codec import fixture
from tests.test_identity_inventory import live_for


def user_record(identity: codec.Identity) -> bytes:
    return struct.pack("<I", identity.user_id) + uuid.UUID(identity.uuid).bytes


def global_record(record: bytes) -> bytes:
    return record + struct.pack("<I", 1) + uuid.UUID(int=0).bytes


def named_local(*, replacement: bool = False) -> codec.UserCatacomb:
    original = codec.decode_user_catacomb(fixture(), 501)
    first = codec.decode_user_catacomb(
        original.rename(original.identities[0].uuid, "finger-1"), 501
    )
    second = codec.decode_user_catacomb(
        first.add(
            identity_uuid=str(uuid.UUID(int=2)),
            entity=1,
            name="finger-2",
        ),
        501,
    )
    if not replacement:
        return second
    removed = identity_delete.plan_named(
        second, live_for(second), finger_name="finger-1"
    )
    survivor = codec.decode_user_catacomb(removed.archive, 501)
    return codec.decode_user_catacomb(
        survivor.add(
            identity_uuid=str(uuid.UUID(int=3)),
            entity=2,
            name="finger-3",
        ),
        501,
    )


class NeutralIdentityContractTests(unittest.TestCase):
    def assert_round_trip(self, local: codec.UserCatacomb, handle: str, expected: uuid.UUID):
        live = live_for(local)
        listed = projection.project(identity_inventory.summarize(local, live))
        self.assertIn(handle, listed.finger_names)
        records = tuple(user_record(identity) for identity in local.identities)
        selected = match_selection.select(local, records, handle)
        self.assertEqual(selected.identity_record[4:20], expected.bytes)
        deletion = identity_delete.plan_named(local, live, finger_name=handle)
        self.assertEqual(deletion.identity_uuid, str(expected))
        components = {"master.cat": b"master", "user.cat": b"user"}
        globals_ = tuple(global_record(record) for record in records)
        gate = match_gate.prepare_all(
            local, components, records, globals_, records, globals_
        )
        event = expected.bytes + b"\0" * (0xC70 - 16)
        self.assertEqual(match_gate.resolve_all_match_event(gate, event), handle)

    def test_uuid_binding_survives_earlier_delete_and_replacement(self):
        before = named_local()
        self.assert_round_trip(before, "finger-2", uuid.UUID(int=2))
        after = named_local(replacement=True)
        self.assertEqual(
            projection.project(
                identity_inventory.summarize(after, live_for(after))
            ).finger_names,
            ("finger-2", "finger-3"),
        )
        self.assert_round_trip(after, "finger-2", uuid.UUID(int=2))
        self.assert_round_trip(after, "finger-3", uuid.UUID(int=3))

    @unittest.skipUnless(os.geteuid() == 0, "requires private root sequence state")
    def test_lowest_vacant_slot_is_reused_without_moving_survivors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(
                sequence.reconcile(
                    501,
                    ("finger-1", "finger-2", "finger-3"),
                    root=root,
                ),
                3,
            )
            self.assertEqual(
                sequence.candidate(501, ("finger-1", "finger-2"), root=root),
                "finger-3",
            )
            self.assertEqual(
                sequence.candidate(501, ("finger-2", "finger-3"), root=root),
                "finger-1",
            )


if __name__ == "__main__":
    unittest.main()
