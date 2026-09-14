# SPDX-License-Identifier: GPL-2.0-only
"""Forward-only paired Catacomb persistence after SEP identity deletion."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

import t2_catacomb_codec
import t2_catacomb_protocol
import t2_identity_delete
import t2_identity_delete_journal as delete_journal
import t2_mutation_journal


class IdentityDeletePersistenceError(RuntimeError):
    pass


class DeletePersistenceTransport(Protocol):
    def prepare(self, descriptor: bytes) -> tuple[int, int]: ...
    def complete(self, descriptor: bytes) -> tuple[int, bytearray]: ...
    def confirm(self, descriptor: bytes) -> int: ...


class DeletePersistenceStore(Protocol):
    def begin_stage(self, expected_names: set[str]) -> None: ...
    def stage_component(self, name: str, data: bytearray, expected_names: set[str]) -> str: ...
    def cross_commit_boundary(self, expected: dict[str, str]) -> None: ...


Readback = Callable[[], object]


@dataclass(frozen=True)
class DeleteReadbackAttestation:
    connection_generation: str
    snapshot_sha256: str
    identity_count: int


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\x00" * len(value)


def _append(path, operation_id, milestone, evidence):
    return delete_journal.append_checked(path, operation_id, milestone, evidence)


def _freeze(
    path: Path,
    operation_id: str,
    generation: str,
    reference: dict[str, object] | None,
    *,
    stage: str,
    reason: str,
    host_commit_possible: bool,
    cause: BaseException | None = None,
) -> None:
    try:
        if reference is None:
            _append(
                path,
                operation_id,
                "DELETE_OUTCOME_UNKNOWN",
                {
                    "connection_generation": generation,
                    "stage": "persistence",
                    "reason": reason,
                    "mutation_possible": True,
                },
            )
        else:
            _append(
                path,
                operation_id,
                "CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN",
                {
                    **reference,
                    "stage": stage,
                    "reason": reason,
                    "sep_mutation_possible": True,
                    "host_commit_possible": host_commit_possible,
                },
            )
    except BaseException:
        pass
    error = IdentityDeletePersistenceError(
        f"identity deletion persistence stopped at {stage}; recovery is required"
    )
    if cause is None:
        raise error
    raise error from cause


def run(
    path: Path,
    operation_id: str,
    *,
    plan: t2_identity_delete.IdentityDeletePlan,
    master: t2_catacomb_codec.MasterCatacomb,
    transport: DeletePersistenceTransport,
    store: DeletePersistenceStore,
    mapping_generation: str,
    readback: Readback,
    master_only: bool = False,
) -> delete_journal.IdentityDeleteHistory:
    history = delete_journal.read(path)
    if (
        history.operation_id != operation_id
        or history.phase is not delete_journal.IdentityDeletePhase.SEP_DELETED
        or history.target_identity_uuid != plan.identity_uuid
        or history.survivor_snapshot_sha256 != plan.survivor_snapshot_sha256
        or history.baseline["apple_uid"] != plan.apple_user_id
        or history.baseline["mapping_generation"] != mapping_generation
        or not isinstance(master, t2_catacomb_codec.MasterCatacomb)
        or master.enrollment_count != history.baseline["master_enrollment_count"]
        or master.enrollment_count < 1
        or (master_only and history.recovery_user_file_sha256 is None)
        or (not master_only and history.recovery_user_file_sha256 is not None)
    ):
        raise IdentityDeletePersistenceError(
            "delete persistence plan differs from journal"
        )

    generation = history.persistence_connection_generation
    user_name = f'user_{plan.apple_user_id:08x}.cat'
    user_component = t2_catacomb_protocol.CatacombComponent.user(
        plan.apple_user_id
    )
    master_component = t2_catacomb_protocol.CatacombComponent.master()
    components = (
        (("master.cat", master_component.descriptor),)
        if master_only
        else (
            (user_name, user_component.descriptor),
            ("master.cat", master_component.descriptor),
        )
    )
    references = [
        {
            "connection_generation": generation,
            "batch_index": 0,
            "component_index": index,
            "name": name,
            "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
        }
        for index, (name, descriptor) in enumerate(components)
    ]
    _append(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_PLAN",
        {
            "connection_generation": generation,
            "batches": [[
                {
                    "name": reference["name"],
                    "descriptor_sha256": reference["descriptor_sha256"],
                }
                for reference in references
            ]],
        },
    )
    expected_names = {name for name, _descriptor in components}
    try:
        store.begin_stage(expected_names)
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            generation,
            None,
            stage="host-stage",
            reason="host-store-error",
            host_commit_possible=False,
            cause=error,
        )

    staged: dict[str, str] = {}
    master_time = time.time() - 978307200.0
    if master_time <= master.current_time:
        _freeze(
            path,
            operation_id,
            generation,
            None,
            stage="encode",
            reason="codec-error",
            host_commit_possible=False,
        )
    for index, ((name, descriptor), reference) in enumerate(
        zip(components, references)
    ):
        _append(path, operation_id, "CATACOMB_PREPARE_INTENT", reference)
        try:
            status, expected_length = transport.prepare(descriptor)
        except BaseException as error:
            _freeze(path, operation_id, generation, reference, stage="prepare", reason="transport-error", host_commit_possible=False, cause=error)
        if type(status) is not int or status != 0 or type(expected_length) is not int or not 0 < expected_length <= 1024 * 1024:
            _freeze(path, operation_id, generation, reference, stage="prepare", reason="transport-error", host_commit_possible=False)
        _append(path, operation_id, "CATACOMB_PREPARED", {**reference, "status": 0, "expected_blob_length": expected_length})
        _append(path, operation_id, "CATACOMB_COMPLETE_INTENT", reference)
        secure_blob = None
        encoded = None
        try:
            try:
                status, secure_blob = transport.complete(descriptor)
            except BaseException as error:
                _freeze(path, operation_id, generation, reference, stage="complete", reason="transport-error", host_commit_possible=False, cause=error)
            if type(status) is not int or status != 0 or not isinstance(secure_blob, bytearray) or len(secure_blob) != expected_length:
                _freeze(path, operation_id, generation, reference, stage="complete", reason="transport-error", host_commit_possible=False)
            blob_hash = hashlib.sha256(secure_blob).hexdigest()
            _append(path, operation_id, "CATACOMB_SECURE_BLOB_CAPTURED", {**reference, "status": 0, "blob_length": len(secure_blob), "secure_blob_sha256": blob_hash})
            try:
                if name == user_name:
                    encoded = t2_identity_delete.bind_secure_blob(plan, secure_blob)
                elif name == "master.cat":
                    encoded = bytearray(
                        master.encode(
                            secure_data=bytes(secure_blob),
                            enrollment_count=master.enrollment_count - 1,
                            current_time=master_time,
                        )
                    )
                else:
                    raise IdentityDeletePersistenceError(
                        "delete persistence component is invalid"
                    )
            except (t2_identity_delete.IdentityDeleteError, t2_catacomb_codec.CatacombCodecError) as error:
                _freeze(path, operation_id, generation, reference, stage="encode", reason="codec-error", host_commit_possible=False, cause=error)
            try:
                file_hash = store.stage_component(name, encoded, expected_names)
            except BaseException as error:
                _freeze(path, operation_id, generation, reference, stage="host-stage", reason="host-store-error", host_commit_possible=False, cause=error)
            if file_hash != hashlib.sha256(encoded).hexdigest():
                _freeze(path, operation_id, generation, reference, stage="host-stage", reason="host-store-error", host_commit_possible=False)
            staged[name] = file_hash
            _append(path, operation_id, "CATACOMB_HOST_STAGED", {**reference, "secure_blob_sha256": blob_hash, "final_file_sha256": file_hash})
        finally:
            _wipe(encoded)
            _wipe(secure_blob)
        if index + 1 < len(components):
            _append(path, operation_id, "CATACOMB_CONFIRM_INTENT", reference)
            try:
                status = transport.confirm(descriptor)
            except BaseException as error:
                _freeze(path, operation_id, generation, reference, stage="early-confirm", reason="transport-error", host_commit_possible=False, cause=error)
            if type(status) is not int or status != 0:
                _freeze(path, operation_id, generation, reference, stage="early-confirm", reason="transport-error", host_commit_possible=False)
            _append(path, operation_id, "CATACOMB_CONFIRMED", {**reference, "status": 0})

    staged_snapshot = hashlib.sha256(
        t2_mutation_journal.canonical(
            [
                {"name": name, "final_file_sha256": staged[name]}
                for name, _descriptor in components
            ]
        )
    ).hexdigest()
    batch = {"connection_generation": generation, "batch_index": 0, "staged_snapshot_sha256": staged_snapshot}
    final_reference = references[-1]
    _append(path, operation_id, "CATACOMB_HOST_BATCH_COMMIT_INTENT", batch)
    try:
        store.cross_commit_boundary(staged)
    except BaseException as error:
        _freeze(path, operation_id, generation, final_reference, stage="host-commit", reason="host-store-error", host_commit_possible=True, cause=error)
    _append(path, operation_id, "CATACOMB_HOST_BATCH_COMMITTED", batch)
    _append(path, operation_id, "CATACOMB_FINAL_CONFIRM_INTENT", final_reference)
    try:
        status = transport.confirm(components[-1][1])
    except BaseException as error:
        _freeze(path, operation_id, generation, final_reference, stage="final-confirm", reason="transport-error", host_commit_possible=True, cause=error)
    if type(status) is not int or status != 0:
        _freeze(path, operation_id, generation, final_reference, stage="final-confirm", reason="transport-error", host_commit_possible=True)
    _append(path, operation_id, "CATACOMB_FINAL_CONFIRMED", {**final_reference, "status": 0})
    try:
        attestation = readback()
    except BaseException as error:
        _freeze(path, operation_id, generation, final_reference, stage="readback", reason="readback-error", host_commit_possible=True, cause=error)
    if (
        not isinstance(attestation, DeleteReadbackAttestation)
        or attestation.connection_generation != generation
        or attestation.identity_count != len(history.baseline["identity_records"]) - 1
    ):
        _freeze(path, operation_id, generation, final_reference, stage="readback", reason="readback-error", host_commit_possible=True)
    try:
        t2_mutation_journal.require_sha256(attestation.snapshot_sha256, "delete snapshot")
    except t2_mutation_journal.JournalError as error:
        _freeze(path, operation_id, generation, final_reference, stage="readback", reason="readback-error", host_commit_possible=True, cause=error)
    _append(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_ATTESTED",
        {
            "connection_generation": generation,
            "batch_count": 1,
            "reconciliation_snapshot_sha256": attestation.snapshot_sha256,
            "sep_host_generation_equal": True,
            "independent_archive_readback": True,
        },
    )
    return _append(
        path,
        operation_id,
        "DELETE_RECONCILED",
        {
            "connection_generation": generation,
            "identity_uuid": plan.identity_uuid,
            "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
            "snapshot_sha256": attestation.snapshot_sha256,
            "mapping_generation": mapping_generation,
            "identity_count": attestation.identity_count,
            "target_absent": True,
            "local_live_equal": True,
            "host_reconciled": True,
            "sep_clean": True,
        },
    )
