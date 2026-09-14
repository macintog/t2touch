# SPDX-License-Identifier: GPL-2.0-only

import json
import hashlib
import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_compatibility_user_rebind as rebind
import t2_catacomb_codec
import t2_mutation_journal


APPLE_UID = 501
BOOT_ID = str(uuid.UUID(int=51))
GENERATION = str(uuid.UUID(int=52))
AUTHORITY_GENERATION = "a" * 64


def surface(*, identities: bool, states: tuple[tuple[int, int], ...]) -> dict[int, list[object]]:
    identity = struct.pack("<I", APPLE_UID) + uuid.UUID(int=53).bytes
    global_record = identity + struct.pack("<I", 1) + uuid.UUID(int=54).bytes
    return {
        0x42: [0, identity if identities else b""],
        0x51: [0, global_record if identities else b""],
        0x3C: [0, b"".join(struct.pack("<II", *record) for record in states)],
        0x50: [0, b""],
    }


class FakeLease:
    def __init__(self, surfaces: list[dict[int, list[object]]], journal: Path) -> None:
        self.connection_generation = GENERATION
        self.peer_boot_uuid = None
        self.client_version = 0
        self.surfaces = surfaces
        self.surface_index = 0
        self.seen: list[int] = []
        self.invalidated = False
        self.journal = journal

    def biometric_command(self, command: int, **_kwargs):
        self.seen.append(command)
        if command == 0x01:
            return [0, struct.pack("<I", 2)], []
        if command == 0x48:
            records = t2_mutation_journal.read(self.journal)
            if [record["milestone"] for record in records] != [
                "BASELINE_RECONCILED",
                "REMOVE_USER_INTENT",
            ]:
                raise AssertionError("remove-user dispatch was not journaled first")
            return [0, b""], []
        if command == 0x40:
            records = t2_mutation_journal.read(self.journal)
            if records[-1]["milestone"] != "SAVED_USER_RELOAD_INTENT":
                raise AssertionError("saved-user load was not journaled first")
            return [0, b""], []
        if command == 0x3D:
            records = t2_mutation_journal.read(self.journal)
            if records[-1]["milestone"] != "MASTER_EXPORT_PREPARE_INTENT":
                raise AssertionError("master prepare was not journaled first")
            return [0, struct.pack("<I", len(b"LTFC" + b"m" * 16))], []
        if command == 0x3E:
            records = t2_mutation_journal.read(self.journal)
            if records[-1]["milestone"] != "MASTER_EXPORT_COMPLETE_INTENT":
                raise AssertionError("master complete was not journaled first")
            return [0, b"LTFC" + b"m" * 16], []
        if command == 0x3F:
            records = t2_mutation_journal.read(self.journal)
            if records[-1]["milestone"] != "MASTER_EXPORT_CONFIRM_INTENT":
                raise AssertionError("master confirm was not journaled first")
            return [0, b""], []
        if command == 0x31:
            records = t2_mutation_journal.read(self.journal)
            if records[-1]["milestone"] not in {
                "MISSING_USER_PREPARE_INTENT",
                "MISSING_MASTER_PREPARE_INTENT",
                "MISSING_USER_REPREPARE_INTENT",
            }:
                raise AssertionError("missing-user preparation was not journaled first")
            return [0, b""], []
        reply = self.surfaces[self.surface_index][command]
        if command == 0x50:
            self.surface_index += 1
        return reply, []

    def invalidate(self) -> None:
        self.invalidated = True

    def select_client_version(self) -> int:
        if self.client_version != 0:
            raise AssertionError("client version was selected twice")
        self.client_version = 2
        return self.client_version


class CompatibilityUserRebindTests(unittest.TestCase):
    def test_retained_master_seed_is_exactly_bound_and_offline(self):
        identity_uuid = str(uuid.UUID(int=53))
        canonical_master = t2_catacomb_codec.encode_initial_master_catacomb(
            secure_data=b"LTFC" + b"c" * 16,
            enrollment_count=1,
            current_time=1.0,
        )
        canonical = rebind.CanonicalAuthority(
            frozenset({(APPLE_UID, identity_uuid)}),
            1,
            ("b" * 64,) * 3,
            b"LTFC-saved-user",
            canonical_master,
        )
        retained = t2_catacomb_codec.decode_master_catacomb(
            canonical_master
        ).encode(
            secure_data=b"LTFC" + b"r" * 16,
            enrollment_count=0,
        )
        milestones = [
            "BASELINE_RECONCILED",
            "REMOVE_USER_INTENT",
            "REMOVE_USER_ACCEPTED",
            "POST_STATE_OBSERVED",
            "USER_LOAD_INTENT",
            "USER_LOAD_REPLY_REJECTED",
            "MASTER_EXPORT_PREPARE_INTENT",
            "MASTER_EXPORT_PREPARED",
            "MASTER_EXPORT_COMPLETE_INTENT",
            "MASTER_EXPORT_CAPTURED",
            "MASTER_EXPORT_CONFIRM_INTENT",
            "MASTER_EXPORT_CONFIRMED",
            "MASTER_SETTLED",
            "SAVED_USER_RELOAD_INTENT",
            "SAVED_USER_RELOAD_REPLY_REJECTED",
            "MISSING_USER_PREPARE_INTENT",
            "MISSING_USER_PREPARE_ACCEPTED",
            "MISSING_USER_PREPARE_POST_STATE_REJECTED",
            "MISSING_MASTER_PREPARE_INTENT",
            "MISSING_MASTER_PREPARE_ACCEPTED",
            "MISSING_USER_REPREPARE_INTENT",
            "MISSING_USER_REPREPARE_ACCEPTED",
            "BRIDGE_CLIENT_VERSION_SELECTED",
            "MISSING_COMPONENT_SEQUENCE_OBSERVED",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "operation.jsonl"
            artifact = root / "intermediate-master-after-remove.cat"
            artifact.write_bytes(retained)
            artifact.chmod(0o600)
            operation_id = str(uuid.UUID(int=55))
            head = None
            for milestone in milestones:
                evidence = {"fixture": True}
                if milestone == "BASELINE_RECONCILED":
                    evidence = {
                        "operation_kind": "compatibility-empty-user-rebind",
                        "linux_boot_uuid": BOOT_ID,
                        "authority_generation": AUTHORITY_GENERATION,
                        "canonical_identity_count": 1,
                        "canonical_master_enrollment_count": 1,
                        "canonical_component_hashes": ["b" * 64] * 3,
                    }
                elif milestone == "MASTER_EXPORT_CAPTURED":
                    evidence = {
                        "secure_data_sha256": hashlib.sha256(
                            b"LTFC" + b"r" * 16
                        ).hexdigest(),
                        "encoded_sha256": hashlib.sha256(retained).hexdigest(),
                        "encoded_enrollment_count": 0,
                    }
                elif milestone == "MISSING_COMPONENT_SEQUENCE_OBSERVED":
                    evidence = {
                        "user_states": [
                            ["master", 0xFFFFFFFF, 3],
                            ["user", APPLE_UID, 7],
                        ],
                        "per_user_identity_count": 0,
                        "global_identity_count": 0,
                        "group_state_count": 0,
                        "saved_user_load_permitted": False,
                        "retry_permitted": False,
                    }
                head = rebind._append(
                    journal, operation_id, milestone, evidence, head
                )

            current_boot = str(uuid.UUID(int=56))
            seed = rebind.build_retained_master_seed(
                canonical,
                authority_generation=AUTHORITY_GENERATION,
                current_linux_boot_uuid=current_boot,
                source_journal_path=journal,
            )
            decoded = t2_catacomb_codec.decode_master_catacomb(
                seed.candidate_archive
            )
            self.assertEqual(decoded.enrollment_count, 1)
            self.assertEqual(decoded.secure_data, b"LTFC" + b"r" * 16)
            self.assertEqual(seed.source_record_count, 24)
            self.assertEqual(seed.current_linux_boot_uuid, current_boot)
            self.assertFalse(hasattr(seed, "lease"))

            plan = rebind.plan_retained_master_restore(
                canonical,
                seed,
                {
                    "per_user_identity_count": 0,
                    "global_identity_count": 0,
                    "user_states": (("master", 0xFFFFFFFF, 1),),
                    "group_state_count": 0,
                },
            )
            self.assertEqual(plan.master_secure_data, b"LTFC" + b"r" * 16)
            self.assertEqual(plan.user_secure_data, canonical.user_secure_data)
            self.assertEqual(plan.expected_identity_count, 1)
            self.assertFalse(hasattr(plan, "lease"))

            with self.assertRaisesRegex(
                rebind.CompatibilityUserRebindError, "cold and loadable"
            ):
                rebind.plan_retained_master_restore(
                    canonical,
                    seed,
                    {
                        "per_user_identity_count": 0,
                        "global_identity_count": 0,
                        "user_states": (("master", 0xFFFFFFFF, 3),),
                        "group_state_count": 0,
                    },
                )

            with self.assertRaisesRegex(
                rebind.CompatibilityUserRebindError, "different Linux boot"
            ):
                rebind.build_retained_master_seed(
                    canonical,
                    authority_generation=AUTHORITY_GENERATION,
                    current_linux_boot_uuid=BOOT_ID,
                    source_journal_path=journal,
                )

    def test_live_identity_refuses_and_empty_loaded_user_dispatches_once_after_intent(self):
        identity_uuid = str(uuid.UUID(int=53))
        master_archive = t2_catacomb_codec.encode_initial_master_catacomb(
            secure_data=b"LTFC" + b"c" * 16,
            enrollment_count=1,
            current_time=1.0,
        )
        canonical = rebind.CanonicalAuthority(
            frozenset({(APPLE_UID, identity_uuid)}),
            1,
            ("b" * 64,) * 3,
            b"LTFC-saved-user",
            master_archive,
        )
        # Either loaded component may carry the save-dirty bit.  The live
        # reference state after the cold power cycle was master=7, user=3.
        loaded = ((0xFFFFFFFF, 7), (APPLE_UID, 3))
        after = ((0xFFFFFFFF, 7),)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe_journal = root / "unsafe" / "operation.jsonl"
            unsafe = FakeLease(
                [surface(identities=True, states=loaded)] * 2,
                unsafe_journal,
            )
            with self.assertRaisesRegex(rebind.CompatibilityUserRebindError, "exact"):
                rebind.reset_empty_loaded_user_once(
                    unsafe,
                    apple_user_id=APPLE_UID,
                    canonical=canonical,
                    authority_generation=AUTHORITY_GENERATION,
                    linux_boot_uuid=BOOT_ID,
                    journal_path=unsafe_journal,
                )
            self.assertNotIn(0x48, unsafe.seen)
            self.assertFalse(unsafe_journal.exists())

            journal = root / "safe" / "operation.jsonl"
            safe = FakeLease(
                [
                    surface(identities=False, states=loaded),
                    surface(identities=False, states=loaded),
                    surface(identities=False, states=after),
                    surface(identities=False, states=after),
                ],
                journal,
            )
            result = rebind.reset_empty_loaded_user_once(
                safe,
                apple_user_id=APPLE_UID,
                canonical=canonical,
                authority_generation=AUTHORITY_GENERATION,
                linux_boot_uuid=BOOT_ID,
                journal_path=journal,
            )
            self.assertEqual(safe.seen.count(0x48), 1)
            self.assertFalse(result["restoration_attempted"])
            self.assertEqual(result["user_states"], (("master", 0xFFFFFFFF, 7),))
            records = t2_mutation_journal.read(journal)
            self.assertEqual(records[-1]["milestone"], "POST_STATE_OBSERVED")
            self.assertNotIn(str(uuid.UUID(int=53)), json.dumps(records))

            operation_id = records[0]["operation_id"]
            head = rebind._append(
                journal,
                operation_id,
                "USER_LOAD_INTENT",
                {"fixture": "definite-rejection"},
                records[-1],
            )
            rebind._append(
                journal,
                operation_id,
                "USER_LOAD_REPLY_REJECTED",
                {"reply_received": True, "retry_permitted": False},
                head,
            )

            settled = ((0xFFFFFFFF, 3),)
            settle_lease = FakeLease(
                [
                    surface(identities=False, states=after),
                    surface(identities=False, states=after),
                    surface(identities=False, states=settled),
                    surface(identities=False, states=settled),
                ],
                journal,
            )
            settle_result = rebind.settle_removed_master_once(
                settle_lease,
                apple_user_id=APPLE_UID,
                canonical=canonical,
                authority_generation=AUTHORITY_GENERATION,
                linux_boot_uuid=BOOT_ID,
                journal_path=journal,
            )
            self.assertTrue(settle_result["saved_user_load_permitted"])
            self.assertEqual(settle_lease.seen.count(0x3D), 1)
            self.assertEqual(settle_lease.seen.count(0x3E), 1)
            self.assertEqual(settle_lease.seen.count(0x3F), 1)

            records = t2_mutation_journal.read(journal)
            head = rebind._append(
                journal,
                operation_id,
                "SAVED_USER_RELOAD_INTENT",
                {"fixture": "definite-rejection-after-master-settlement"},
                records[-1],
            )
            rebind._append(
                journal,
                operation_id,
                "SAVED_USER_RELOAD_REPLY_REJECTED",
                {"reply_received": True, "retry_permitted": False},
                head,
            )

            prepared = ((0xFFFFFFFF, 3), (APPLE_UID, 5))
            prepare_lease = FakeLease(
                [
                    surface(identities=False, states=settled),
                    surface(identities=False, states=settled),
                    surface(identities=False, states=settled),
                    surface(identities=False, states=settled),
                ],
                journal,
            )
            with self.assertRaisesRegex(
                rebind.CompatibilityUserRebindError, "unexpected state"
            ):
                rebind.prepare_missing_user_once(
                    prepare_lease,
                    apple_user_id=APPLE_UID,
                    canonical=canonical,
                    authority_generation=AUTHORITY_GENERATION,
                    linux_boot_uuid=BOOT_ID,
                    journal_path=journal,
                )
            self.assertEqual(prepare_lease.seen.count(0x31), 1)

            sequence_lease = FakeLease(
                [
                    surface(identities=False, states=prepared),
                    surface(identities=False, states=prepared),
                ],
                journal,
            )
            sequence_result = rebind.prepare_missing_components_once(
                sequence_lease,
                apple_user_id=APPLE_UID,
                canonical=canonical,
                authority_generation=AUTHORITY_GENERATION,
                linux_boot_uuid=BOOT_ID,
                journal_path=journal,
                preflight_surface={
                    "per_user_identity_count": 0,
                    "global_identity_count": 0,
                    "user_states": (("master", 0xFFFFFFFF, 3),),
                    "group_state_count": 0,
                },
            )
            self.assertEqual(sequence_lease.seen[:3], [0x01, 0x31, 0x31])
            self.assertEqual(sequence_lease.client_version, 2)
            self.assertTrue(sequence_result["saved_user_load_permitted"])

            restored = ((0xFFFFFFFF, 7), (APPLE_UID, 3))
            restore_lease = FakeLease(
                [
                    surface(identities=False, states=prepared),
                    surface(identities=False, states=prepared),
                    surface(identities=True, states=restored),
                    surface(identities=True, states=restored),
                ],
                journal,
            )
            live = {
                "per_user_identity_records": [
                    {"user_id": APPLE_UID, "identity_uuid": identity_uuid}
                ]
            }
            with mock.patch.object(
                rebind.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value=live,
            ):
                restore_result = rebind.restore_saved_user_once(
                    restore_lease,
                    apple_user_id=APPLE_UID,
                    canonical=canonical,
                    authority_generation=AUTHORITY_GENERATION,
                    linux_boot_uuid=BOOT_ID,
                    journal_path=journal,
                )
            self.assertEqual(restore_lease.seen.count(0x40), 1)
            self.assertTrue(restore_result["master_persistence_required"])
            records = t2_mutation_journal.read(journal)
            self.assertEqual(
                records[-1]["milestone"], "SAVED_USER_RELOAD_RECONCILED"
            )
            self.assertNotIn(identity_uuid, json.dumps(records))


if __name__ == "__main__":
    unittest.main()
