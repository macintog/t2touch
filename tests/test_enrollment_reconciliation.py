import copy
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_journal as enrollment_journal
import t2_enrollment_reconciliation as reconciliation
import t2_mutation_journal as mutation_journal
from tests.test_mutation_journal import baseline


def _component_ref(batch_index, component_index, name, descriptor_sha256):
    return {
        "connection_generation": baseline()["connection_generation"],
        "batch_index": batch_index,
        "component_index": component_index,
        "name": name,
        "descriptor_sha256": descriptor_sha256,
    }


def append_persistence(
    path, operation_id, reconciliation_snapshot_sha256, *, include_biolockout=False
):
    """Append the smallest complete persistence transcript used by this suite."""
    descriptors = {
        "user_000001f5.cat": "1" * 64,
        "master.cat": "2" * 64,
        "biolockout.cat": "3" * 64,
    }
    batches = [("user_000001f5.cat", "master.cat")]
    if include_biolockout:
        batches.append(("biolockout.cat",))
    enrollment_journal.append_checked(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_PLAN",
        {
            "connection_generation": baseline()["connection_generation"],
            "batches": [
                [
                    {"name": name, "descriptor_sha256": descriptors[name]}
                    for name in names
                ]
                for names in batches
            ],
        },
    )
    for batch_index, names in enumerate(batches):
        staged = []
        final_reference = None
        for component_index, name in enumerate(names):
            reference = _component_ref(
                batch_index, component_index, name, descriptors[name]
            )
            blob_sha256 = str(4 + batch_index * 2 + component_index) * 64
            file_sha256 = str(7 + batch_index + component_index) * 64
            enrollment_journal.append_checked(
                path, operation_id, "CATACOMB_PREPARE_INTENT", reference
            )
            enrollment_journal.append_checked(
                path,
                operation_id,
                "CATACOMB_PREPARED",
                {**reference, "status": 0, "expected_blob_length": 32},
            )
            enrollment_journal.append_checked(
                path, operation_id, "CATACOMB_COMPLETE_INTENT", reference
            )
            enrollment_journal.append_checked(
                path,
                operation_id,
                "CATACOMB_SECURE_BLOB_CAPTURED",
                {
                    **reference,
                    "status": 0,
                    "blob_length": 32,
                    "secure_blob_sha256": blob_sha256,
                },
            )
            enrollment_journal.append_checked(
                path,
                operation_id,
                "CATACOMB_HOST_STAGED",
                {
                    **reference,
                    "secure_blob_sha256": blob_sha256,
                    "final_file_sha256": file_sha256,
                },
            )
            staged.append({"name": name, "final_file_sha256": file_sha256})
            final_reference = reference
            if component_index + 1 < len(names):
                enrollment_journal.append_checked(
                    path, operation_id, "CATACOMB_CONFIRM_INTENT", reference
                )
                enrollment_journal.append_checked(
                    path,
                    operation_id,
                    "CATACOMB_CONFIRMED",
                    {**reference, "status": 0},
                )
        staged_sha256 = hashlib.sha256(
            mutation_journal.canonical(staged)
        ).hexdigest()
        batch = {
            "connection_generation": baseline()["connection_generation"],
            "batch_index": batch_index,
            "staged_snapshot_sha256": staged_sha256,
        }
        enrollment_journal.append_checked(
            path, operation_id, "CATACOMB_HOST_BATCH_COMMIT_INTENT", batch
        )
        enrollment_journal.append_checked(
            path, operation_id, "CATACOMB_HOST_BATCH_COMMITTED", batch
        )
        enrollment_journal.append_checked(
            path,
            operation_id,
            "CATACOMB_FINAL_CONFIRM_INTENT",
            final_reference,
        )
        enrollment_journal.append_checked(
            path,
            operation_id,
            "CATACOMB_FINAL_CONFIRMED",
            {**final_reference, "status": 0},
        )
    return enrollment_journal.append_checked(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_ATTESTED",
        {
            "connection_generation": baseline()["connection_generation"],
            "batch_count": len(batches),
            "reconciliation_snapshot_sha256": reconciliation_snapshot_sha256,
            "sep_host_generation_equal": True,
            "independent_archive_readback": True,
        },
    )


class EnrollmentReconciliationTests(unittest.TestCase):
    def create_unknown(self, directory: str) -> tuple[Path, str]:
        value = baseline()
        path = Path(directory) / "operation.jsonl"
        operation_id, _record = mutation_journal.create(path, "enroll", value)
        enrollment_journal.append_checked(
            path,
            operation_id,
            "ENROLL_START_INTENT",
            {
                "apple_uid": value["apple_uid"],
                "protocol_version": value["protocol_version"],
                "connection_generation": value["connection_generation"],
                "request_length": 68,
                "request_sha256": "a" * 64,
            },
        )
        enrollment_journal.append_checked(
            path,
            operation_id,
            "ENROLL_OUTCOME_UNKNOWN",
            {
                "connection_generation": value["connection_generation"],
                "stage": "start",
                "reason": "transport-error",
                "mutation_possible": True,
            },
        )
        return path, operation_id

    def create_terminal(
        self, directory: str, *, identity: bool
    ) -> tuple[Path, str, str | None]:
        value = baseline()
        path = Path(directory) / "operation.jsonl"
        operation_id, _record = mutation_journal.create(path, "enroll", value)
        enrollment_journal.append_checked(
            path,
            operation_id,
            "ENROLL_START_INTENT",
            {
                "apple_uid": 501,
                "protocol_version": 2,
                "connection_generation": value["connection_generation"],
                "request_length": 68,
                "request_sha256": "a" * 64,
            },
        )
        enrollment_journal.append_checked(
            path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
        )
        identity_uuid = str(uuid.UUID(int=8)) if identity else None
        if identity:
            enrollment_journal.append_checked(
                path,
                operation_id,
                "E2_TERMINAL_IDENTITY_OBSERVED",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 1,
                    "envelope_type": enrollment_journal.SERVICE_ENROLLMENT_RESULT,
                    "event_version": 2,
                    "user_id": 501,
                    "identity_uuid": identity_uuid,
                },
            )
        else:
            enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_TERMINAL_FAILURE_OBSERVED",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 1,
                    "envelope_type": enrollment_journal.SERVICE_STATUS,
                    "status": 67,
                },
            )
        return path, operation_id, identity_uuid

    def snapshots(self, *, success: bool) -> tuple[dict, dict]:
        value = baseline()
        identities = copy.deepcopy(value["identity_records"])
        if success:
            identities.append(
                {
                    "user_id": 501,
                    "uuid": str(uuid.UUID(int=8)),
                    "entity": 1,
                }
            )
        components = copy.deepcopy(value["host_components"])
        if success:
            for component in components:
                if component["name"] == "master.cat":
                    component["sha256"] = "1" * 64
                elif component["name"] == "user_000001f5.cat":
                    component["sha256"] = "2" * 64
                elif component["name"] == "biolockout.cat":
                    component["sha256"] = "4" * 64
        host = {
            "account_uuid": value["account_uuid"],
            "bag_uuid": value["bag_uuid"],
            "identity_records": identities,
            "host_components": components,
            "master_enrollment_count": value["master_enrollment_count"]
            + int(success),
        }
        per_user = [
            {"user_id": item["user_id"], "identity_uuid": item["uuid"]}
            for item in identities
        ]
        live = {
            "double_collection_equal": True,
            "connection_generation": value["connection_generation"],
            "apple_uid": 501,
            "biometric_protocol_version": 2,
            "per_user_identity_records": per_user,
            "global_identity_records": [
                {**item, "group_type": 1, "group_uuid": str(uuid.UUID(int=0))}
                for item in per_user
            ],
            "maximum_capacity": value["capacity"]["maximum"],
            "configured_user_free_capacity": value["capacity"]["maximum"]
            - len(per_user),
            "catacomb": {
                "present": True,
                "uuid": value["sep_catacomb"]["uuid"],
                "hash": "3" * 64 if success else value["sep_catacomb"]["hash"],
            },
        }
        return host, live

    def snapshot_digest(self, host, live):
        identity_records = sorted(
            (record["user_id"], record["identity_uuid"])
            for record in live["per_user_identity_records"]
        )
        components = {
            component["name"]: component for component in host["host_components"]
        }
        model = {
            "account_uuid": host["account_uuid"],
            "bag_uuid": host["bag_uuid"],
            "identity_records": identity_records,
            "catacomb": {
                "uuid": live["catacomb"]["uuid"],
                "hash": live["catacomb"]["hash"],
            },
            "host_components": [components[name] for name in sorted(components)],
            "master_enrollment_count": host["master_enrollment_count"],
            "mapping_generation": baseline()["mapping_generation"],
        }
        return hashlib.sha256(mutation_journal.canonical(model)).hexdigest()

    def persist(self, path, operation_id, host, live):
        return append_persistence(
            path,
            operation_id,
            self.snapshot_digest(host, live),
            include_biolockout=True,
        )

    def test_terminal_identity_reconciles_only_after_durable_state_advances(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, operation_id, host, live)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)

    def test_terminal_unknown_recovers_only_one_fresh_builtin_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            value = baseline()
            path = Path(directory) / "operation.jsonl"
            operation_id, _record = mutation_journal.create(path, "enroll", value)
            enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_START_INTENT",
                {
                    "apple_uid": value["apple_uid"],
                    "protocol_version": value["protocol_version"],
                    "connection_generation": value["connection_generation"],
                    "request_length": 68,
                    "request_sha256": "a" * 64,
                },
            )
            enrollment_journal.append_checked(
                path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
            )
            history = enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_OUTCOME_UNKNOWN",
                {
                    "connection_generation": value["connection_generation"],
                    "stage": "terminal",
                    "reason": "protocol-error",
                    "mutation_possible": True,
                },
            )
            host, live = self.snapshots(success=False)
            new_identity = {
                "user_id": value["apple_uid"],
                "identity_uuid": str(uuid.UUID(int=8)),
            }
            live["connection_generation"] = str(uuid.UUID(int=99))
            live["per_user_identity_records"].append(new_identity)
            live["global_identity_records"].append(
                {
                    **new_identity,
                    "group_type": 1,
                    "group_uuid": str(uuid.UUID(int=0)),
                }
            )
            live["configured_user_free_capacity"] -= 1
            live["catacomb"]["hash"] = "3" * 64
            recovery = reconciliation.classify_observed_identity_recovery(
                history,
                host=host,
                live=live,
                mapping_generation=value["mapping_generation"],
            )
            self.assertEqual(recovery.identity_uuid, new_identity["identity_uuid"])
            self.assertTrue(recovery.evidence["single_identity_added"])

            unsafe = copy.deepcopy(live)
            unsafe["global_identity_records"] = unsafe[
                "global_identity_records"
            ][:-1]
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError,
                "exactly one built-in SEP addition",
            ):
                reconciliation.classify_observed_identity_recovery(
                    history,
                    host=host,
                    live=unsafe,
                    mapping_generation=value["mapping_generation"],
                )

    def test_terminal_witness_rolls_to_fresh_generation_before_persistence(self):
        value = baseline()
        fresh_generation = str(uuid.UUID(int=99))
        new_identity = {
            "user_id": value["apple_uid"],
            "identity_uuid": str(uuid.UUID(int=8)),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "operation.jsonl"
            operation_id, _record = mutation_journal.create(
                path, "enroll", value
            )
            enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_START_INTENT",
                {
                    "apple_uid": value["apple_uid"],
                    "protocol_version": value["protocol_version"],
                    "connection_generation": value["connection_generation"],
                    "request_length": 68,
                    "request_sha256": "a" * 64,
                },
            )
            enrollment_journal.append_checked(
                path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
            )
            history = enrollment_journal.append_checked(
                path,
                operation_id,
                "E2_TERMINAL_RESULT_WITNESSED",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 1,
                    "envelope_type": enrollment_journal.SERVICE_ENROLLMENT_RESULT,
                    "event_version": 1,
                    "payload_length": 36,
                    "event_sha256": "b" * 64,
                    "embedded_user_matches": False,
                },
            )
            host, live = self.snapshots(success=False)
            live["connection_generation"] = fresh_generation
            live["per_user_identity_records"].append(new_identity)
            live["global_identity_records"].append(
                {
                    **new_identity,
                    "group_type": 1,
                    "group_uuid": str(uuid.UUID(int=0)),
                }
            )
            live["configured_user_free_capacity"] -= 1
            live["catacomb"]["hash"] = "3" * 64
            recovery = reconciliation.classify_terminal_result_witness(
                history,
                host=host,
                live=live,
                mapping_generation=value["mapping_generation"],
                require_fresh_generation=True,
            )
            recovered = enrollment_journal.append_checked(
                path,
                operation_id,
                "E2_WITNESS_IDENTITY_READBACK_OBSERVED",
                recovery.evidence,
            )

        self.assertEqual(
            recovered.phase, enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY
        )
        self.assertEqual(
            recovered.persistence_connection_generation, fresh_generation
        )

    def test_first_identity_recovery_accepts_only_zero_to_new_catacomb(self):
        """Protect D196's observed bootstrap Catacomb UUID transition."""

        value = baseline()
        value.update(
            {
                "baseline_version": 2,
                "identity_records": [],
                "capacity": {"used": 0, "maximum": 5},
                "sep_catacomb": {
                    "present": False,
                    "uuid": str(uuid.UUID(int=0)),
                    "hash": None,
                },
                "host_components": [],
                "master_enrollment_count": 0,
                "backup_references": [],
            }
        )
        identity_uuid = str(uuid.UUID(int=8))
        new_catacomb_uuid = str(uuid.UUID(int=9))
        recovery_generation = str(uuid.UUID(int=99))
        host_before = {
            "account_uuid": value["account_uuid"],
            "bag_uuid": value["bag_uuid"],
            "identity_records": [],
            "host_components": [],
            "master_enrollment_count": 0,
        }
        live = {
            "double_collection_equal": True,
            "connection_generation": recovery_generation,
            "apple_uid": value["apple_uid"],
            "biometric_protocol_version": 2,
            "per_user_identity_records": [
                {"user_id": value["apple_uid"], "identity_uuid": identity_uuid}
            ],
            "global_identity_records": [
                {
                    "user_id": value["apple_uid"],
                    "identity_uuid": identity_uuid,
                    "group_type": 1,
                    "group_uuid": str(uuid.UUID(int=0)),
                }
            ],
            "maximum_capacity": 5,
            "configured_user_free_capacity": 4,
            "catacomb": {
                "present": True,
                "uuid": new_catacomb_uuid,
                "hash": "3" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "operation.jsonl"
            operation_id, _record = mutation_journal.create(path, "enroll", value)
            enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_START_INTENT",
                {
                    "apple_uid": value["apple_uid"],
                    "protocol_version": 2,
                    "connection_generation": value["connection_generation"],
                    "request_length": 68,
                    "request_sha256": "a" * 64,
                },
            )
            enrollment_journal.append_checked(
                path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
            )
            history = enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_OUTCOME_UNKNOWN",
                {
                    "connection_generation": value["connection_generation"],
                    "stage": "terminal",
                    "reason": "protocol-error",
                    "mutation_possible": True,
                },
            )
            recovery = reconciliation.classify_observed_identity_recovery(
                history,
                host=host_before,
                live=live,
                mapping_generation=value["mapping_generation"],
            )

        self.assertEqual(recovery.identity_uuid, identity_uuid)
        unsafe = copy.deepcopy(live)
        unsafe["catacomb"]["uuid"] = value["sep_catacomb"]["uuid"]
        with self.assertRaisesRegex(
            reconciliation.EnrollmentReconciliationError, "new SEP Catacomb"
        ):
            reconciliation.classify_observed_identity_recovery(
                history,
                host=host_before,
                live=unsafe,
                mapping_generation=value["mapping_generation"],
            )

        host_after = {
            "account_uuid": value["account_uuid"],
            "bag_uuid": value["bag_uuid"],
            "identity_records": [
                {"user_id": value["apple_uid"], "uuid": identity_uuid, "entity": 0}
            ],
            "host_components": [
                {"name": "biolockout.cat", "sha256": "4" * 64, "mode": 0o600, "uid": 0, "gid": 0},
                {"name": "master.cat", "sha256": "1" * 64, "mode": 0o600, "uid": 0, "gid": 0},
                {"name": "user_000001f5.cat", "sha256": "2" * 64, "mode": 0o600, "uid": 0, "gid": 0},
            ],
            "master_enrollment_count": 1,
        }
        snapshot_sha256 = self.snapshot_digest(host_after, live)
        persisted_history = SimpleNamespace(
            phase=enrollment_journal.EnrollmentPhase.PERSISTENCE_READY,
            baseline=value,
            terminal_identity_uuid=identity_uuid,
            persistence_connection_generation=recovery_generation,
            persistence=SimpleNamespace(
                phase=reconciliation.persistence_journal.PersistencePhase.COMPLETE,
                reconciliation_snapshot_sha256=snapshot_sha256,
            ),
        )
        plan = reconciliation.classify(
            persisted_history,
            host=host_after,
            live=live,
            mapping_generation=value["mapping_generation"],
        )
        self.assertEqual(plan.evidence["identity_uuid"], identity_uuid)

    def test_e4_requires_new_boot_and_exact_e3_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, operation_id, host, live)
            reconciled = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            evidence = {
                "linux_boot_uuid": str(uuid.UUID(int=20)),
                "connection_generation": str(uuid.UUID(int=21)),
                "bridge_boot_uuid": None,
                "protocol_version": 2,
                "mapping_generation": baseline()["mapping_generation"],
                "account_uuid": baseline()["account_uuid"],
                "bag_uuid": baseline()["bag_uuid"],
                "identity_uuid": identity_uuid,
                "snapshot_sha256": reconciled.reconciled_snapshot_sha256,
                "double_collection_equal": True,
                "host_sep_identity_equal": True,
                "bindings_preserved": True,
                "keybag_runtime_revalidated": True,
            }
            with self.assertRaisesRegex(
                enrollment_journal.EnrollmentJournalError, "boot"
            ):
                enrollment_journal.append_checked(
                    path,
                    operation_id,
                    "E4_POST_REBOOT_VERIFIED",
                    {
                        **evidence,
                        "linux_boot_uuid": baseline()["linux_boot_uuid"],
                    },
                )
            with self.assertRaisesRegex(
                enrollment_journal.EnrollmentJournalError, "differs"
            ):
                enrollment_journal.append_checked(
                    path,
                    operation_id,
                    "E4_POST_REBOOT_VERIFIED",
                    {**evidence, "snapshot_sha256": "f" * 64},
                )
            result = enrollment_journal.append_checked(
                path, operation_id, "E4_POST_REBOOT_VERIFIED", evidence
            )
        self.assertEqual(
            result.phase, enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )

    def test_live_e4_classifier_recomputes_exact_e3_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, operation_id, host, live)
            reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            live["connection_generation"] = str(uuid.UUID(int=21))
            result = reconciliation.append_post_reboot_verified(
                path,
                operation_id,
                host=host,
                live=live,
                linux_boot_uuid=str(uuid.UUID(int=20)),
                mapping_generation=baseline()["mapping_generation"],
                keybag_runtime_revalidated=True,
            )
        self.assertEqual(
            result.phase, enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )

    def test_live_e4_runtime_accepts_same_boot_with_fresh_connection(self):
        """Catch accidental restoration of a reboot gate in first enrollment."""

        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, operation_id, host, live)
            reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            live["connection_generation"] = str(uuid.UUID(int=21))
            result = reconciliation.append_runtime_verified(
                path,
                operation_id,
                host=host,
                live=live,
                linux_boot_uuid=baseline()["linux_boot_uuid"],
                mapping_generation=baseline()["mapping_generation"],
                keybag_runtime_revalidated=True,
            )
        self.assertEqual(
            result.phase, enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )

    def test_live_e4_classifier_rejects_same_boot_or_snapshot_drift(self):
        for drift in ("same-boot", "component"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                path, operation_id, _identity_uuid = self.create_terminal(
                    directory, identity=True
                )
                host, live = self.snapshots(success=True)
                self.persist(path, operation_id, host, live)
                reconciliation.append_reconciled(
                    path,
                    operation_id,
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )
                live["connection_generation"] = str(uuid.UUID(int=21))
                boot = str(uuid.UUID(int=20))
                if drift == "same-boot":
                    boot = baseline()["linux_boot_uuid"]
                else:
                    host["host_components"][0]["sha256"] = "e" * 64
                with self.assertRaises(
                    reconciliation.EnrollmentReconciliationError
                ):
                    reconciliation.classify_post_reboot(
                        enrollment_journal.read(path),
                        host=host,
                        live=live,
                        linux_boot_uuid=boot,
                        mapping_generation=baseline()["mapping_generation"],
                        keybag_runtime_revalidated=True,
                    )

    def test_identity_reconciliation_requires_completed_persistence_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "not ready"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_e3_readback_must_match_journaled_persistence_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            append_persistence(
                path, operation_id, "f" * 64, include_biolockout=True
            )
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "snapshot"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_generic_failure_reconciles_only_when_every_snapshot_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=False
            )
            host, live = self.snapshots(success=False)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)

    def test_unknown_outcome_reconciles_unchanged_state_on_fresh_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create_unknown(directory)
            host, live = self.snapshots(success=False)
            live["connection_generation"] = str(uuid.UUID(int=99))
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            records = mutation_journal.read(path)
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)
        self.assertEqual(
            records[-1]["milestone"], "E3_RECOVERY_NO_CHANGE_RECONCILED"
        )

    def test_unknown_outcome_recovery_rejects_old_generation_or_new_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create_unknown(directory)
            host, live = self.snapshots(success=False)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "stale"
            ):
                reconciliation.append_reconciled(
                    path,
                    operation_id,
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )
            host, live = self.snapshots(success=True)
            live["connection_generation"] = str(uuid.UUID(int=99))
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "automatic recovery"
            ):
                reconciliation.append_reconciled(
                    path,
                    operation_id,
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_failure_with_new_identity_is_promoted_before_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=False
            )
            host, live = self.snapshots(success=True)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            records = mutation_journal.read(path)
        self.assertEqual(
            result.phase, enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY
        )
        self.assertEqual(records[-1]["milestone"], "E2_IDENTITY_READBACK_OBSERVED")

    def test_host_sep_divergence_and_mapping_change_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, _operation_id, host, live)
            host["identity_records"] = host["identity_records"][:-1]
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "diverge"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )
            host, live = self.snapshots(success=True)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "mapping"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation="f" * 64,
                )

    def test_existing_identity_and_component_metadata_must_be_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, _operation_id, host, live)
            host["identity_records"][0]["entity"] = 4
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "entity"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

            host, live = self.snapshots(success=True)
            host["host_components"][0]["mode"] = 0o600
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "metadata"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

            host, live = self.snapshots(success=True)
            live["catacomb"]["uuid"] = str(uuid.UUID(int=9))
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "Catacomb UUID"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_identity_event_without_changed_persistence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, _operation_id, host, live)
            before = baseline()
            for component in host["host_components"]:
                component["sha256"] = next(
                    item["sha256"]
                    for item in before["host_components"]
                    if item["name"] == component["name"]
                )
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "durable"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )


if __name__ == "__main__":
    unittest.main()
