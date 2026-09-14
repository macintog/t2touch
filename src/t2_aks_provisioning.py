# SPDX-License-Identifier: GPL-2.0-only
"""Durable primitives for one non-retryable AKS create/export transaction.

There is deliberately no transport or CLI here.  The endpoint operations stay
disabled until a broker composes these primitives with exact preflight and
post-reboot reconciliation.
"""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import t2_mutation_journal as journal


MAX_SAVED_KEYBAG_BYTES = 1024 * 1024


class AKSProvisioningError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class ProvisioningHistory:
    operation_id: str
    phase: str
    account_uuid: str
    initial_linux_boot_uuid: str
    connection_generation: str
    preflight_sha256: str
    session: int
    live_handle: int | None
    bag_uuid: str | None
    saved_keybag_sha256: str | None
    saved_keybag_length: int | None
    mapping_generation: str | None
    reboot_linux_boot_uuid: str | None
    enabled_mapping_generation: str | None
    record_count: int
    head_hash: str


def _exact(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AKSProvisioningError(f"{name} evidence has an invalid schema")
    return value


def _uuid(value: Any, name: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise AKSProvisioningError(f"{name} is not a UUID") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AKSProvisioningError(f"{name} is not a canonical nonzero UUID")
    return value


def _sha256(value: Any, name: str) -> str:
    try:
        journal.require_sha256(value, name)
    except journal.JournalError as error:
        raise AKSProvisioningError(str(error)) from error
    if value.lower() != value:
        raise AKSProvisioningError(f"{name} is not lowercase")
    return value


def _uint(value: Any, name: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AKSProvisioningError(f"{name} is not a bounded integer")
    return value


def validate_history(records: list[dict[str, Any]]) -> ProvisioningHistory:
    if not records:
        raise AKSProvisioningError("AKS provisioning journal is empty")
    operation_id = records[0].get("operation_id")
    _uuid(operation_id, "operation ID")
    phase = "new"
    account_uuid = ""
    initial_linux_boot_uuid = ""
    connection_generation = ""
    preflight_sha256 = ""
    session = 0
    live_handle = None
    bag_uuid = None
    saved_digest = None
    saved_length = None
    mapping_generation = None
    reboot_linux_boot_uuid = None
    enabled_mapping_generation = None

    for record in records:
        if record.get("operation_id") != operation_id:
            raise AKSProvisioningError("operation ID changed in provisioning journal")
        milestone = record.get("milestone")
        evidence = record.get("evidence")
        if milestone == "AKS_CREATE_INTENT":
            if phase != "new":
                raise AKSProvisioningError("create intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "account_uuid",
                    "linux_boot_uuid",
                    "connection_generation",
                    "preflight_sha256",
                    "session",
                    "request_sha256",
                    "xart_ready",
                    "primary_identity_absent",
                    "inventory_stable",
                },
                milestone,
            )
            account_uuid = _uuid(evidence["account_uuid"], "account UUID")
            initial_linux_boot_uuid = _uuid(
                evidence["linux_boot_uuid"], "initial Linux boot UUID"
            )
            connection_generation = _uuid(
                evidence["connection_generation"], "connection generation"
            )
            preflight_sha256 = _sha256(
                evidence["preflight_sha256"], "preflight digest"
            )
            session = _uint(evidence["session"], "session", (1 << 64) - 1)
            if session == 0:
                raise AKSProvisioningError("session is zero")
            _sha256(evidence["request_sha256"], "create request digest")
            if any(
                evidence[field] is not True
                for field in (
                    "xart_ready",
                    "primary_identity_absent",
                    "inventory_stable",
                )
            ):
                raise AKSProvisioningError("create preflight is incomplete")
            phase = "create-intent"
        elif milestone == "AKS_CREATE_SUCCEEDED":
            if phase != "create-intent":
                raise AKSProvisioningError("create result is out of order")
            evidence = _exact(
                evidence,
                {"session", "live_handle", "kek_length"},
                milestone,
            )
            if evidence["session"] != session:
                raise AKSProvisioningError("create session changed")
            live_handle = _uint(
                evidence["live_handle"], "live handle", (1 << 31) - 1
            )
            if live_handle == 0:
                raise AKSProvisioningError("live handle is zero")
            _uint(evidence["kek_length"], "KEK length", MAX_SAVED_KEYBAG_BYTES)
            phase = "create-succeeded"
        elif milestone == "AKS_EXPORT_INTENT":
            if phase != "create-succeeded":
                raise AKSProvisioningError("export intent is out of order")
            evidence = _exact(
                evidence, {"session", "live_handle", "request_sha256"}, milestone
            )
            if evidence["session"] != session or evidence["live_handle"] != live_handle:
                raise AKSProvisioningError("export is not bound to create")
            _sha256(evidence["request_sha256"], "export request digest")
            phase = "export-intent"
        elif milestone == "AKS_EXPORT_SUCCEEDED":
            if phase != "export-intent":
                raise AKSProvisioningError("export result is out of order")
            evidence = _exact(
                evidence, {"saved_keybag_sha256", "saved_keybag_length"}, milestone
            )
            saved_digest = _sha256(
                evidence["saved_keybag_sha256"], "saved keybag digest"
            )
            saved_length = _uint(
                evidence["saved_keybag_length"],
                "saved keybag length",
                MAX_SAVED_KEYBAG_BYTES,
            )
            if saved_length == 0:
                raise AKSProvisioningError("saved keybag is empty")
            phase = "export-succeeded"
        elif milestone == "AKS_KEYBAG_COMMITTED":
            if phase != "export-succeeded":
                raise AKSProvisioningError("keybag commit is out of order")
            evidence = _exact(
                evidence, {"saved_keybag_sha256", "saved_keybag_length"}, milestone
            )
            if (
                evidence["saved_keybag_sha256"] != saved_digest
                or evidence["saved_keybag_length"] != saved_length
            ):
                raise AKSProvisioningError("committed keybag differs from export")
            phase = "keybag-committed"
        elif milestone == "AKS_LIVE_UUID_VERIFIED":
            if phase != "keybag-committed":
                raise AKSProvisioningError("live UUID verification is out of order")
            evidence = _exact(evidence, {"bag_uuid", "uuid_verified"}, milestone)
            bag_uuid = _uuid(evidence["bag_uuid"], "bag UUID")
            if evidence["uuid_verified"] is not True:
                raise AKSProvisioningError("live bag UUID is not verified")
            phase = "live-uuid-verified"
        elif milestone == "AKS_MAPPING_COMMITTED":
            if phase != "live-uuid-verified":
                raise AKSProvisioningError("mapping commit is out of order")
            evidence = _exact(
                evidence, {"mapping_generation", "bag_uuid"}, milestone
            )
            mapping_generation = _sha256(
                evidence["mapping_generation"], "mapping generation"
            )
            if evidence["bag_uuid"] != bag_uuid:
                raise AKSProvisioningError("mapping bag UUID differs from live bag")
            phase = "mapping-committed"
        elif milestone in {
            "AKS_RUNTIME_VERIFIED",
            "AKS_REBOOT_VERIFIED",
            "AKS_REBOOT_REVERIFIED",
        }:
            expected_phase = (
                "mapping-committed"
                if milestone in {"AKS_RUNTIME_VERIFIED", "AKS_REBOOT_VERIFIED"}
                else "reboot-verified"
            )
            if phase != expected_phase:
                raise AKSProvisioningError("runtime verification is out of order")
            fields = {
                "linux_boot_uuid",
                "bag_uuid",
                "saved_keybag_sha256",
                "keybag_loaded",
                "uuid_verified",
            }
            if milestone == "AKS_RUNTIME_VERIFIED":
                fields |= {"connection_generation", "fresh_owner"}
            evidence = _exact(evidence, fields, milestone)
            reboot_uuid = _uuid(evidence["linux_boot_uuid"], "reboot Linux UUID")
            if (
                milestone != "AKS_RUNTIME_VERIFIED"
                and reboot_uuid == initial_linux_boot_uuid
            ):
                raise AKSProvisioningError("keybag verification reused the creation boot")
            if (
                milestone == "AKS_REBOOT_REVERIFIED"
                and reboot_uuid == reboot_linux_boot_uuid
            ):
                raise AKSProvisioningError("keybag reverification reused its prior boot")
            if (
                evidence["bag_uuid"] != bag_uuid
                or evidence["saved_keybag_sha256"] != saved_digest
                or evidence["keybag_loaded"] is not True
                or evidence["uuid_verified"] is not True
            ):
                raise AKSProvisioningError("reloaded keybag identity is not verified")
            if milestone == "AKS_RUNTIME_VERIFIED":
                _uuid(
                    evidence["connection_generation"],
                    "runtime connection generation",
                )
                if evidence["fresh_owner"] is not True:
                    raise AKSProvisioningError(
                        "runtime keybag verification did not use a fresh owner"
                    )
            reboot_linux_boot_uuid = reboot_uuid
            phase = "reboot-verified"
        elif milestone == "AKS_MAPPING_ENABLED":
            if phase != "reboot-verified":
                raise AKSProvisioningError("mapping enable is out of order")
            evidence = _exact(
                evidence,
                {
                    "disabled_mapping_generation",
                    "enabled_mapping_generation",
                    "bag_uuid",
                    "linux_boot_uuid",
                },
                milestone,
            )
            if (
                evidence["disabled_mapping_generation"] != mapping_generation
                or evidence["bag_uuid"] != bag_uuid
                or evidence["linux_boot_uuid"] != reboot_linux_boot_uuid
            ):
                raise AKSProvisioningError("enabled mapping differs from provisioning")
            enabled_mapping_generation = _sha256(
                evidence["enabled_mapping_generation"],
                "enabled mapping generation",
            )
            if enabled_mapping_generation == mapping_generation:
                raise AKSProvisioningError("mapping enable did not change generation")
            phase = "mapping-enabled"
        elif milestone == "AKS_OUTCOME_UNKNOWN":
            if phase not in {"create-intent", "export-intent"}:
                raise AKSProvisioningError("ambiguous outcome marker is out of order")
            evidence = _exact(evidence, {"stage", "mutation_possible"}, milestone)
            if evidence["stage"] not in {"create", "export"} or evidence[
                "mutation_possible"
            ] is not True:
                raise AKSProvisioningError("ambiguous outcome evidence is invalid")
            if evidence["stage"] != phase.removesuffix("-intent"):
                raise AKSProvisioningError("ambiguous outcome stage differs from intent")
            phase = "outcome-unknown"
        else:
            raise AKSProvisioningError(f"unsupported milestone {milestone!r}")

    head_hash = _sha256(records[-1].get("record_hash"), "journal head hash")
    return ProvisioningHistory(
        operation_id,
        phase,
        account_uuid,
        initial_linux_boot_uuid,
        connection_generation,
        preflight_sha256,
        session,
        live_handle,
        bag_uuid,
        saved_digest,
        saved_length,
        mapping_generation,
        reboot_linux_boot_uuid,
        enabled_mapping_generation,
        len(records),
        head_hash,
    )


def create(
    path: Path,
    *,
    operation_id: str,
    account_uuid: str,
    linux_boot_uuid: str,
    connection_generation: str,
    preflight_sha256: str,
    session: int,
    request_sha256: str,
    xart_ready: bool,
    primary_identity_absent: bool,
    inventory_stable: bool,
) -> ProvisioningHistory:
    _uuid(operation_id, "operation ID")
    evidence = {
        "account_uuid": account_uuid,
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": connection_generation,
        "preflight_sha256": preflight_sha256,
        "session": session,
        "request_sha256": request_sha256,
        "xart_ready": xart_ready,
        "primary_identity_absent": primary_identity_absent,
        "inventory_stable": inventory_stable,
    }
    unsigned = {
        "format_version": journal.FORMAT_VERSION,
        "operation_id": operation_id,
        "sequence": 0,
        "previous_hash": None,
        "milestone": "AKS_CREATE_INTENT",
        "evidence": evidence,
    }
    validate_history([{**unsigned, "record_hash": journal.record_hash(unsigned)}])
    journal.append(
        path,
        operation_id,
        "AKS_CREATE_INTENT",
        evidence,
        exclusive=True,
    )
    return read(path)


def read(path: Path) -> ProvisioningHistory:
    try:
        return validate_history(journal.read(path))
    except journal.JournalError as error:
        raise AKSProvisioningError(str(error)) from error


def append_checked(
    path: Path, operation_id: str, milestone: str, evidence: dict[str, Any]
) -> ProvisioningHistory:
    try:
        records = journal.read(path)
    except journal.JournalError as error:
        raise AKSProvisioningError(str(error)) from error
    history = validate_history(records)
    if history.operation_id != operation_id:
        raise AKSProvisioningError("operation ID differs from provisioning journal")
    unsigned = {
        "format_version": journal.FORMAT_VERSION,
        "operation_id": operation_id,
        "sequence": history.record_count,
        "previous_hash": history.head_hash,
        "milestone": milestone,
        "evidence": evidence,
    }
    validate_history(
        records + [{**unsigned, "record_hash": journal.record_hash(unsigned)}]
    )
    try:
        journal.append(
            path,
            operation_id,
            milestone,
            evidence,
            expected_record_count=history.record_count,
            expected_previous_hash=history.head_hash,
        )
    except journal.JournalError as error:
        raise AKSProvisioningError(str(error)) from error
    return read(path)


class SavedKeybagStore:
    """Atomically create one private saved-keybag file without replacement."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        info = directory.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise AKSProvisioningError("keybag directory is not private and caller-owned")

    def commit(
        self, saved_keybag: bytearray, operation_id: str, expected_sha256: str
    ) -> tuple[str, int]:
        if not isinstance(saved_keybag, bytearray):
            raise AKSProvisioningError("saved keybag buffer is invalid")
        try:
            _uuid(operation_id, "operation ID")
            expected_sha256 = _sha256(
                expected_sha256, "expected saved keybag digest"
            )
            if not 0 < len(saved_keybag) <= MAX_SAVED_KEYBAG_BYTES:
                raise AKSProvisioningError("saved keybag buffer is invalid")
            destination = self.directory / "user.kb"
            temporary = self.directory / f".user.kb.{operation_id}.tmp"
            if os.path.lexists(destination) or os.path.lexists(temporary):
                raise AKSProvisioningError(
                    "keybag destination or transaction file exists"
                )
            digest = hashlib.sha256(saved_keybag).hexdigest()
            if digest != expected_sha256:
                raise AKSProvisioningError(
                    "saved keybag differs from journaled export"
                )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            committed = False
            try:
                offset = 0
                while offset < len(saved_keybag):
                    written = os.write(descriptor, saved_keybag[offset:])
                    if written <= 0:
                        raise AKSProvisioningError(
                            "saved keybag write made no progress"
                        )
                    offset += written
                os.fsync(descriptor)
                length = len(saved_keybag)
                os.close(descriptor)
                descriptor = -1
                os.rename(temporary, destination)
                directory_fd = os.open(
                    self.directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                committed = True
                return digest, length
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                if not committed and os.path.lexists(temporary):
                    temporary.unlink()
        finally:
            saved_keybag[:] = b"\0" * len(saved_keybag)
