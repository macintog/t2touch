# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_catacomb_protocol as protocol
import t2_identity_delete as delete
import t2_identity_delete_journal as journal
import t2_identity_delete_persistence as persistence
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import fixture, master_fixture
from tests.test_mutation_journal import baseline


def delete_baseline():
    value = baseline()
    value["identity_records"].append(
        {"user_id": value["apple_uid"], "uuid": str(uuid.UUID(int=2)), "entity": 1}
    )
    value["capacity"]["used"] = 2
    return value


def live_for(local):
    records = [
        {"user_id": identity.user_id, "identity_uuid": identity.uuid}
        for identity in local.identities
    ]
    return {
        "double_collection_equal": True,
        "apple_uid": 501,
        "biometric_protocol_version": 2,
        "catacomb": {"present": True},
        "per_user_identity_records": records,
        "global_identity_records": [
            {
                **record,
                "group_type": 1,
                "group_uuid": str(uuid.UUID(int=0)),
            }
            for record in records
        ],
    }


class FakeTransport:
    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.blobs = []
        self.calls = []

    def prepare(self, descriptor):
        self.calls.append("prepare")
        if self.fail_at == "prepare":
            raise OSError("synthetic private error")
        return 0, 32

    def complete(self, descriptor):
        self.calls.append("complete")
        if self.fail_at == "complete":
            raise OSError("synthetic private error")
        blob = bytearray(b"LTFC" + b"z" * 28)
        self.blobs.append(blob)
        return 0, blob

    def confirm(self, descriptor):
        self.calls.append("confirm")
        if self.fail_at == "confirm":
            raise OSError("synthetic private error")
        return 0


class FakeStore:
    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.staged = {}
        self.committed = {}

    def begin_stage(self, expected_names):
        if self.fail_at == "begin":
            raise OSError("synthetic private error")
        self.expected_names = expected_names

    def stage_component(self, name, data, expected_names):
        if self.fail_at == "stage":
            raise OSError("synthetic private error")
        self.staged[name] = bytes(data)
        return hashlib.sha256(data).hexdigest()

    def cross_commit_boundary(self, expected):
        if self.fail_at == "commit":
            raise OSError("synthetic private error")
        self.committed = dict(self.staged)


class IdentityDeletePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "delete.jsonl"
        one = codec.decode_user_catacomb(fixture(), 501)
        self.local = codec.decode_user_catacomb(
            one.add(identity_uuid=str(uuid.UUID(int=2)), entity=1, name="Finger 2"),
            501,
        )
        self.plan = delete.plan(self.local, live_for(self.local), slot=2)
        self.master = codec.decode_master_catacomb(master_fixture())
        self.value = delete_baseline()
        self.value["identity_records"] = [
            {"user_id": item.user_id, "uuid": item.uuid, "entity": item.entity}
            for item in self.local.identities
        ]
        self.operation_id, _record = mutation.create(
            self.path, "delete-one", self.value
        )
        target_name_hash = hashlib.sha256(self.plan.name.encode()).hexdigest()
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "user_id": 501,
                "identity_uuid": self.plan.identity_uuid,
                "entity": self.plan.entity,
                "target_name_sha256": target_name_hash,
                "request_sha256": hashlib.sha256(self.plan.request).hexdigest(),
                "request_length": 20,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "mapping_generation": self.value["mapping_generation"],
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_DISPATCH_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.plan.identity_uuid,
                "request_sha256": hashlib.sha256(self.plan.request).hexdigest(),
                "command": 0x0D,
                "protocol_version": 0,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_COMMAND_OBSERVED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.plan.identity_uuid,
                "status": 0,
                "output_length": 0,
                "service_event_count": 0,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_SEP_ABSENCE_OBSERVED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.plan.identity_uuid,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "stable_double_read": True,
                "per_user_global_equal": True,
                "target_absent": True,
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def execute(
        self,
        transport=None,
        store=None,
        readback=None,
        generation=None,
        master_only=False,
    ):
        generation = generation or self.value["connection_generation"]
        return persistence.run(
            self.path,
            self.operation_id,
            plan=self.plan,
            master=self.master,
            transport=transport or FakeTransport(),
            store=store or FakeStore(),
            mapping_generation=self.value["mapping_generation"],
            readback=readback
            or (lambda: persistence.DeleteReadbackAttestation(
                connection_generation=generation,
                snapshot_sha256="8" * 64,
                identity_count=1,
            )),
            master_only=master_only,
        )

    def test_forward_transaction_persists_survivors_and_wipes_blob(self):
        transport = FakeTransport()
        store = FakeStore()
        result = self.execute(transport=transport, store=store)
        self.assertEqual(result.phase, journal.IdentityDeletePhase.RECONCILED)
        self.assertEqual(
            transport.calls,
            ["prepare", "complete", "confirm", "prepare", "complete", "confirm"],
        )
        self.assertEqual(len(transport.blobs), 2)
        self.assertTrue(
            all(bytes(blob) == bytes(len(blob)) for blob in transport.blobs)
        )
        decoded = codec.decode_user_catacomb(
            store.committed["user_000001f5.cat"], 501
        )
        self.assertEqual(decoded.identities, (self.local.identities[0],))
        self.assertEqual(decoded.secure_data, b"LTFC" + b"z" * 28)
        decoded_master = codec.decode_master_catacomb(
            store.committed["master.cat"]
        )
        self.assertEqual(decoded_master.enrollment_count, 1)
        self.assertEqual(decoded_master.secure_data, b"LTFC" + b"z" * 28)

    def test_forward_recovery_uses_its_fresh_connection_generation(self):
        generation = str(uuid.UUID(int=9301))
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_INTENT",
            {
                "action": "prepare-discarded",
                "linux_boot_uuid": self.value["linux_boot_uuid"],
                "mapping_generation": self.value["mapping_generation"],
                "host_commit_possible": False,
                "mutation_possible": True,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_SEP_ABSENCE_OBSERVED",
            {
                "connection_generation": generation,
                "identity_uuid": self.plan.identity_uuid,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "mapping_generation": self.value["mapping_generation"],
                "target_absent": True,
                "local_archive_state": "baseline",
                "host_archive_state": "baseline",
                "sep_user_needs_save": True,
                "sep_master_needs_save": True,
                "stable_double_read": True,
                "recovery_action": "prepare-discarded",
            },
        )
        result = self.execute(generation=generation)
        self.assertEqual(result.phase, journal.IdentityDeletePhase.RECONCILED)
        self.assertEqual(result.reconciled_connection_generation, generation)

    def test_forward_recovery_host_stage_failure_freezes_on_fresh_generation(self):
        generation = str(uuid.UUID(int=9302))
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_INTENT",
            {
                "action": "prepare-discarded",
                "linux_boot_uuid": self.value["linux_boot_uuid"],
                "mapping_generation": self.value["mapping_generation"],
                "host_commit_possible": False,
                "mutation_possible": True,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_SEP_ABSENCE_OBSERVED",
            {
                "connection_generation": generation,
                "identity_uuid": self.plan.identity_uuid,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "mapping_generation": self.value["mapping_generation"],
                "target_absent": True,
                "local_archive_state": "baseline",
                "host_archive_state": "baseline",
                "sep_user_needs_save": True,
                "sep_master_needs_save": True,
                "stable_double_read": True,
                "recovery_action": "prepare-discarded",
            },
        )
        with self.assertRaises(persistence.IdentityDeletePersistenceError):
            self.execute(store=FakeStore("begin"), generation=generation)
        history = journal.read(self.path)
        self.assertEqual(history.phase, journal.IdentityDeletePhase.OUTCOME_UNKNOWN)
        self.assertEqual(history.outcome_unknown_stage, "persistence")
        retried = journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_INTENT",
            {
                "action": "prepare-discarded",
                "linux_boot_uuid": str(uuid.UUID(int=9303)),
                "mapping_generation": self.value["mapping_generation"],
                "host_commit_possible": False,
                "mutation_possible": True,
            },
        )
        self.assertEqual(
            retried.recovery_linux_boot_uuid, str(uuid.UUID(int=9303))
        )

    def test_legacy_user_commit_can_roll_forward_only_dirty_master(self):
        user_name = "user_000001f5.cat"
        descriptor = protocol.CatacombComponent.user(501).descriptor
        descriptor_hash = hashlib.sha256(descriptor).hexdigest()
        reference = {
            "connection_generation": self.value["connection_generation"],
            "batch_index": 0,
            "component_index": 0,
            "name": user_name,
            "descriptor_sha256": descriptor_hash,
        }
        secure_hash = "a" * 64
        user_hash = "b" * 64
        journal.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_PERSISTENCE_PLAN",
            {
                "connection_generation": self.value["connection_generation"],
                "batches": [[{"name": user_name, "descriptor_sha256": descriptor_hash}]],
            },
        )
        journal.append_checked(self.path, self.operation_id, "CATACOMB_PREPARE_INTENT", reference)
        journal.append_checked(self.path, self.operation_id, "CATACOMB_PREPARED", {**reference, "status": 0, "expected_blob_length": 32})
        journal.append_checked(self.path, self.operation_id, "CATACOMB_COMPLETE_INTENT", reference)
        journal.append_checked(self.path, self.operation_id, "CATACOMB_SECURE_BLOB_CAPTURED", {**reference, "status": 0, "blob_length": 32, "secure_blob_sha256": secure_hash})
        journal.append_checked(self.path, self.operation_id, "CATACOMB_HOST_STAGED", {**reference, "secure_blob_sha256": secure_hash, "final_file_sha256": user_hash})
        staged_snapshot = hashlib.sha256(
            mutation.canonical([{"name": user_name, "final_file_sha256": user_hash}])
        ).hexdigest()
        batch = {
            "connection_generation": self.value["connection_generation"],
            "batch_index": 0,
            "staged_snapshot_sha256": staged_snapshot,
        }
        journal.append_checked(self.path, self.operation_id, "CATACOMB_HOST_BATCH_COMMIT_INTENT", batch)
        journal.append_checked(self.path, self.operation_id, "CATACOMB_HOST_BATCH_COMMITTED", batch)
        journal.append_checked(self.path, self.operation_id, "CATACOMB_FINAL_CONFIRM_INTENT", reference)
        journal.append_checked(self.path, self.operation_id, "CATACOMB_FINAL_CONFIRMED", {**reference, "status": 0})
        journal.append_checked(self.path, self.operation_id, "CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN", {**reference, "stage": "readback", "reason": "readback-error", "sep_mutation_possible": True, "host_commit_possible": True})
        generation = str(uuid.UUID(int=9304))
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_INTENT",
            {
                "action": "no-local-transaction",
                "linux_boot_uuid": self.value["linux_boot_uuid"],
                "mapping_generation": self.value["mapping_generation"],
                "host_commit_possible": True,
                "mutation_possible": True,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_RECOVERY_MASTER_SAVE_REQUIRED",
            {
                "connection_generation": generation,
                "identity_uuid": self.plan.identity_uuid,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "mapping_generation": self.value["mapping_generation"],
                "committed_user_sha256": user_hash,
                "target_absent": True,
                "local_live_equal": True,
                "sep_user_clean": True,
                "sep_master_needs_save": True,
                "stable_double_read": True,
                "recovery_action": "no-local-transaction",
            },
        )
        store = FakeStore()
        result = self.execute(
            store=store,
            generation=generation,
            master_only=True,
        )
        self.assertEqual(result.phase, journal.IdentityDeletePhase.RECONCILED)
        self.assertEqual(result.recovery_user_file_sha256, user_hash)
        self.assertEqual(set(store.committed), {"master.cat"})
        self.assertEqual(
            codec.decode_master_catacomb(store.committed["master.cat"]).enrollment_count,
            1,
        )

    def test_every_post_sep_failure_freezes_without_claiming_rollback(self):
        cases = (
            (None, "begin", None),
            ("prepare", None, None),
            ("complete", None, None),
            (None, "stage", None),
            (None, "commit", None),
            ("confirm", None, None),
            (None, None, lambda: None),
        )
        for index, (transport_failure, store_failure, readback) in enumerate(cases):
            with self.subTest(index=index):
                if index:
                    self.tearDown()
                    self.setUp()
                with self.assertRaises(persistence.IdentityDeletePersistenceError):
                    self.execute(
                        transport=FakeTransport(transport_failure),
                        store=FakeStore(store_failure),
                        readback=readback,
                    )
                self.assertEqual(
                    journal.read(self.path).phase,
                    journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
                )


if __name__ == "__main__":
    unittest.main()
