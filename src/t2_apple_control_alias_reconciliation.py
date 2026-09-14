# SPDX-License-Identifier: GPL-2.0-only
"""Read-only reconciliation after an ambiguous Apple-control alias bind."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import t2_aks_state
import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal as journal


SECOND_MILESTONES = (
    "APPLE_CONTROL_ALIAS_BASELINE",
    "APPLE_CONTROL_ALIAS_PRESTATE_OBSERVED",
    "APPLE_CONTROL_ALIAS_KEYBAG_LOAD_INTENT",
    "APPLE_CONTROL_ALIAS_HANDLE_OBSERVED",
    "APPLE_CONTROL_ALIAS_BIND_INTENT",
    "APPLE_CONTROL_ALIAS_KEYBAG_UNLOAD_INTENT",
    "APPLE_CONTROL_ALIAS_HANDLE_RELEASED",
    "APPLE_CONTROL_ALIAS_OUTCOME_UNKNOWN",
)


class AppleControlAliasReconciliationError(RuntimeError):
    pass


class AliasReconciliationTransport(Protocol):
    runtime_generation: str

    def observe_alias_uuid(self, special_alias: int) -> str | None: ...
    def read_alias_state_blob(self, special_alias: int) -> bytearray: ...


@dataclass(frozen=True, repr=False)
class AmbiguousBindProof:
    operation_id: str
    linux_boot_uuid: str
    runtime_generation: str


@dataclass(frozen=True, repr=False)
class ReconciledAliasProof:
    operation_id: str
    linux_boot_uuid: str
    runtime_generation: str
    state_blob_sha256: str


@dataclass(frozen=True)
class AliasReconciliationResult:
    outcome: str
    alias_present: bool
    bag_uuid_matched: bool
    state_captured: bool
    state_decoded: bool
    uuid_stable: bool
    reconciliation_required: bool

    def public_summary(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "alias_present": self.alias_present,
            "bag_uuid_matched": self.bag_uuid_matched,
            "state_captured": self.state_captured,
            "state_decoded": self.state_decoded,
            "uuid_stable": self.uuid_stable,
            "reconciliation_required": self.reconciliation_required,
            "mutation_performed": False,
            "mapping_enabled": False,
            "identifiers_redacted": True,
        }


def _uuid(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError) as error:
        raise AppleControlAliasReconciliationError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AppleControlAliasReconciliationError(f"{label} is invalid")
    return str(parsed)


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AppleControlAliasReconciliationError(f"{label} is invalid")
    return value


def _baseline_matches(
    baseline: dict[str, Any],
    evidence: keybag_discriminator.OracleEvidence,
    matched_proof: alias_discriminator.MatchedKeybagProof,
) -> bool:
    return (
        baseline["operation_kind"] == "apple-control-alias-discriminator"
        and baseline["origin"] == keybag_discriminator.ORIGIN
        and baseline["import_operation_id"] == evidence.import_operation_id
        and baseline["matched_keybag_operation_id"] == matched_proof.operation_id
        and baseline["mapping_generation"] == evidence.mapping_generation
        and baseline["linux_uid"] == evidence.linux_uid
        and baseline["apple_uid"] == evidence.apple_uid
        and baseline["bag_uuid"] == evidence.bag_uuid
        and baseline["keybag_sha256"] == evidence.keybag_sha256
        and baseline["special_alias"] == -evidence.apple_uid
        and baseline["mapping_enabled"] is False
        and baseline["operation_scope"]
        == "observe-load-verify-bind-read-unload-read"
    )


def read_ambiguous_bind_proof(
    oracle_root: Path,
    evidence: keybag_discriminator.OracleEvidence,
    matched_proof: alias_discriminator.MatchedKeybagProof,
) -> AmbiguousBindProof:
    """Validate both immutable journals through clean handle release."""
    first_path = oracle_root / "apple-control-alias-discriminator.jsonl"
    second_path = oracle_root / "apple-control-alias-discriminator-2.jsonl"
    try:
        first = journal.read(first_path)
        second = journal.read(second_path)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasReconciliationError(
            "alias bind journals are unavailable"
        ) from error
    if [record.get("milestone") for record in first] != [
        "APPLE_CONTROL_ALIAS_BASELINE",
        "APPLE_CONTROL_ALIAS_OUTCOME_UNKNOWN",
    ] or tuple(record.get("milestone") for record in second) != SECOND_MILESTONES:
        raise AppleControlAliasReconciliationError(
            "alias bind journals do not reach the required boundary"
        )
    first_operation = _uuid(first[0].get("operation_id"), "first alias operation ID")
    operation_id = _uuid(second[0].get("operation_id"), "bind operation ID")
    if (
        any(record.get("operation_id") != first_operation for record in first)
        or any(record.get("operation_id") != operation_id for record in second)
    ):
        raise AppleControlAliasReconciliationError("alias operation ID changed")
    baseline_keys = {
        "operation_kind", "origin", "import_operation_id",
        "matched_keybag_operation_id", "mapping_generation",
        "linux_boot_uuid", "runtime_generation", "linux_uid", "apple_uid",
        "bag_uuid", "keybag_sha256", "special_alias", "mapping_enabled",
        "operation_scope", "reconciled_prestate_operation_id",
    }
    first_baseline = first[0].get("evidence")
    first_keys = baseline_keys - {"reconciled_prestate_operation_id"}
    if (
        isinstance(first_baseline, dict)
        and "reconciled_prestate_operation_id" in first_baseline
    ):
        first_keys.add("reconciled_prestate_operation_id")
    first_baseline = _exact(first_baseline, first_keys, "first alias baseline")
    first_runtime = _uuid(
        first_baseline["runtime_generation"], "first alias runtime generation"
    )
    _uuid(first_baseline["linux_boot_uuid"], "first alias Linux boot UUID")
    if (
        not _baseline_matches(first_baseline, evidence, matched_proof)
        or first_baseline.get("reconciled_prestate_operation_id") is not None
        or first[1].get("evidence") != {
            "runtime_generation": first_runtime,
            "stage": "pre-state",
            "handle_released": False,
            "retry_before_reboot_permitted": False,
        }
    ):
        raise AppleControlAliasReconciliationError(
            "first alias pre-state failure is inconsistent"
        )
    baseline = _exact(second[0].get("evidence"), baseline_keys, "bind baseline")
    boot = _uuid(baseline["linux_boot_uuid"], "bind Linux boot UUID")
    runtime = _uuid(baseline["runtime_generation"], "bind runtime generation")
    handle_evidence = _exact(
        second[3].get("evidence"),
        {"runtime_generation", "handle", "double_read_equal", "bag_uuid_matches"},
        "loaded handle evidence",
    )
    handle = handle_evidence["handle"]
    if (
        not _baseline_matches(baseline, evidence, matched_proof)
        or baseline["reconciled_prestate_operation_id"] != first_operation
        or type(handle) is not int
        or not 1 <= handle <= 0x7FFFFFFF
        or second[1].get("evidence") != {
            "runtime_generation": runtime,
            "alias_absent": True,
            "bag_uuid_matches": False,
            "state_observed": False,
        }
        or second[2].get("evidence") != {
            "runtime_generation": runtime,
            "keybag_sha256": evidence.keybag_sha256,
            "mutation_possible": True,
        }
        or handle_evidence != {
            "runtime_generation": runtime,
            "handle": handle,
            "double_read_equal": True,
            "bag_uuid_matches": True,
        }
        or second[4].get("evidence") != {
            "runtime_generation": runtime,
            "handle": handle,
            "special_alias": -evidence.apple_uid,
            "mutation_possible": True,
        }
        or second[5].get("evidence") != {
            "runtime_generation": runtime,
            "handle": handle,
            "mutation_possible": True,
        }
        or second[6].get("evidence")
        != {"runtime_generation": runtime, "command_status": 0}
        or second[7].get("evidence") != {
            "runtime_generation": runtime,
            "stage": "bind",
            "handle_released": True,
            "retry_before_reboot_permitted": False,
        }
    ):
        raise AppleControlAliasReconciliationError(
            "ambiguous bind proof is incomplete or inconsistent"
        )
    return AmbiguousBindProof(operation_id, boot, runtime)


def require_later_boot(proof: AmbiguousBindProof, linux_boot_uuid: str) -> str:
    current = _uuid(linux_boot_uuid, "Linux boot UUID")
    if current == proof.linux_boot_uuid:
        raise AppleControlAliasReconciliationError(
            "alias reconciliation requires a later boot"
        )
    return current


def _read_private_state(path: Path) -> tuple[str, int, t2_aks_state.KeybagState]:
    descriptor = -1
    blob = bytearray()
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or not 0 < info.st_size <= t2_aks_state.MAX_DER_BYTES
        ):
            raise AppleControlAliasReconciliationError(
                "captured alias state is unsafe"
            )
        while len(blob) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(blob))
            if not chunk:
                raise AppleControlAliasReconciliationError(
                    "captured alias state is truncated"
                )
            blob.extend(chunk)
        after = os.fstat(descriptor)
        unchanged = all(
            getattr(after, field) == getattr(info, field)
            for field in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid",
                "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns",
            )
        )
        if os.read(descriptor, 1) or not unchanged:
            raise AppleControlAliasReconciliationError(
                "captured alias state changed during validation"
            )
        digest = hashlib.sha256(blob).hexdigest()
        try:
            decoded = t2_aks_state.decode(bytes(blob))
        except t2_aks_state.AKSStateError as error:
            raise AppleControlAliasReconciliationError(
                "captured alias state does not decode"
            ) from error
        return digest, len(blob), decoded
    except OSError as error:
        raise AppleControlAliasReconciliationError(
            "captured alias state is unavailable"
        ) from error
    finally:
        blob[:] = b"\0" * len(blob)
        if descriptor >= 0:
            os.close(descriptor)


def read_reconciled_alias_proof(
    oracle_root: Path,
    evidence: keybag_discriminator.OracleEvidence,
    bind_proof: AmbiguousBindProof,
) -> ReconciledAliasProof:
    """Validate the immutable read-only journal and its private state capture."""
    journal_path = oracle_root / "apple-control-alias-reconciliation.jsonl"
    capture_path = oracle_root / "apple-control-alias-state.der"
    try:
        records = journal.read(journal_path)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasReconciliationError(
            "alias reconciliation proof is unavailable"
        ) from error
    milestones = (
        "APPLE_CONTROL_ALIAS_RECONCILE_BASELINE",
        "APPLE_CONTROL_ALIAS_UUID_OBSERVED",
        "APPLE_CONTROL_ALIAS_STATE_CAPTURED",
        "APPLE_CONTROL_ALIAS_UUID_RECONFIRMED",
        "APPLE_CONTROL_ALIAS_RECONCILE_COMPLETE",
    )
    if tuple(record.get("milestone") for record in records) != milestones:
        raise AppleControlAliasReconciliationError(
            "alias reconciliation proof is incomplete"
        )
    operation_id = _uuid(
        records[0].get("operation_id"), "reconciliation operation ID"
    )
    if any(record.get("operation_id") != operation_id for record in records):
        raise AppleControlAliasReconciliationError(
            "alias reconciliation operation ID changed"
        )
    baseline = _exact(
        records[0].get("evidence"),
        {
            "operation_kind", "origin", "ambiguous_bind_operation_id",
            "mapping_generation", "linux_boot_uuid", "runtime_generation",
            "linux_uid", "apple_uid", "bag_uuid", "special_alias",
            "mapping_enabled", "operation_scope", "mutation_performed",
        },
        "alias reconciliation baseline",
    )
    boot = _uuid(
        baseline["linux_boot_uuid"], "reconciliation Linux boot UUID"
    )
    runtime = _uuid(
        baseline["runtime_generation"], "reconciliation runtime generation"
    )
    observed = _exact(
        records[1].get("evidence"),
        {
            "runtime_generation", "alias_present", "bag_uuid_matches",
            "double_read_equal",
        },
        "alias UUID observation",
    )
    captured = _exact(
        records[2].get("evidence"),
        {
            "runtime_generation", "state_blob_sha256", "state_blob_length",
            "state_decoded", "state_handle_matches",
        },
        "alias state capture",
    )
    reconfirmed = _exact(
        records[3].get("evidence"),
        {"runtime_generation", "bag_uuid_matches", "double_read_equal"},
        "alias UUID reconfirmation",
    )
    complete = _exact(
        records[4].get("evidence"),
        {
            "runtime_generation", "outcome", "alias_present",
            "bag_uuid_matches", "state_captured", "state_decoded",
            "uuid_stable", "mutation_performed", "mapping_promoted",
        },
        "alias reconciliation completion",
    )
    journal_decoded = captured["state_decoded"]
    if type(journal_decoded) is not bool:
        raise AppleControlAliasReconciliationError(
            "alias state decode evidence is invalid"
        )
    expected_outcome = (
        "bound-and-reconciled" if journal_decoded else "bound-state-captured"
    )
    digest, length, decoded = _read_private_state(capture_path)
    if (
        baseline != {
            "operation_kind": "apple-control-alias-readback",
            "origin": keybag_discriminator.ORIGIN,
            "ambiguous_bind_operation_id": bind_proof.operation_id,
            "mapping_generation": evidence.mapping_generation,
            "linux_boot_uuid": boot,
            "runtime_generation": runtime,
            "linux_uid": evidence.linux_uid,
            "apple_uid": evidence.apple_uid,
            "bag_uuid": evidence.bag_uuid,
            "special_alias": -evidence.apple_uid,
            "mapping_enabled": False,
            "operation_scope": "double-uuid-state-capture-double-uuid",
            "mutation_performed": False,
        }
        or boot == bind_proof.linux_boot_uuid
        or runtime == bind_proof.runtime_generation
        or observed != {
            "runtime_generation": runtime,
            "alias_present": True,
            "bag_uuid_matches": True,
            "double_read_equal": True,
        }
        or captured != {
            "runtime_generation": runtime,
            "state_blob_sha256": digest,
            "state_blob_length": length,
            "state_decoded": journal_decoded,
            "state_handle_matches": journal_decoded,
        }
        or decoded.handle != -evidence.apple_uid
        or reconfirmed != {
            "runtime_generation": runtime,
            "bag_uuid_matches": True,
            "double_read_equal": True,
        }
        or complete != {
            "runtime_generation": runtime,
            "outcome": expected_outcome,
            "alias_present": True,
            "bag_uuid_matches": True,
            "state_captured": True,
            "state_decoded": journal_decoded,
            "uuid_stable": True,
            "mutation_performed": False,
            "mapping_promoted": False,
        }
    ):
        raise AppleControlAliasReconciliationError(
            "alias reconciliation proof is inconsistent"
        )
    return ReconciledAliasProof(operation_id, boot, runtime, digest)


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, Any],
    *,
    exclusive: bool = False,
) -> None:
    try:
        journal.append(path, operation_id, milestone, evidence, exclusive=exclusive)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasReconciliationError(
            "alias reconciliation journal cannot advance"
        ) from error


def _store_private(path: Path, blob: bytearray) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o077
    ):
        raise AppleControlAliasReconciliationError(
            "state capture directory is unsafe"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        written = 0
        while written < len(blob):
            count = os.write(descriptor, blob[written:])
            if count <= 0:
                raise OSError("state capture write made no progress")
            written += count
        os.fsync(descriptor)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return hashlib.sha256(blob).hexdigest()
    except OSError as error:
        raise AppleControlAliasReconciliationError(
            "state capture cannot be committed safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def run(
    *,
    journal_path: Path,
    capture_path: Path,
    evidence: keybag_discriminator.OracleEvidence,
    bind_proof: AmbiguousBindProof,
    linux_boot_uuid: str,
    transport: AliasReconciliationTransport,
    operation_id: str | None = None,
) -> AliasReconciliationResult:
    current_boot = require_later_boot(bind_proof, linux_boot_uuid)
    runtime = _uuid(transport.runtime_generation, "AKS runtime generation")
    if runtime == bind_proof.runtime_generation:
        raise AppleControlAliasReconciliationError(
            "AKS runtime generation did not change"
        )
    operation_id = _uuid(
        operation_id or str(uuid.uuid4()), "reconciliation operation ID"
    )
    special_alias = -evidence.apple_uid
    _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_RECONCILE_BASELINE", {
        "operation_kind": "apple-control-alias-readback",
        "origin": keybag_discriminator.ORIGIN,
        "ambiguous_bind_operation_id": bind_proof.operation_id,
        "mapping_generation": evidence.mapping_generation,
        "linux_boot_uuid": current_boot,
        "runtime_generation": runtime,
        "linux_uid": evidence.linux_uid,
        "apple_uid": evidence.apple_uid,
        "bag_uuid": evidence.bag_uuid,
        "special_alias": special_alias,
        "mapping_enabled": False,
        "operation_scope": "double-uuid-state-capture-double-uuid",
        "mutation_performed": False,
    }, exclusive=True)
    stage = "uuid"
    try:
        first = transport.observe_alias_uuid(special_alias)
        present = first is not None
        matched = first == evidence.bag_uuid
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_UUID_OBSERVED", {
            "runtime_generation": runtime,
            "alias_present": present,
            "bag_uuid_matches": matched,
            "double_read_equal": True,
        })
        if not present or not matched:
            outcome = "alias-absent" if not present else "binding-mismatch"
            _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_RECONCILE_COMPLETE", {
                "runtime_generation": runtime,
                "outcome": outcome,
                "alias_present": present,
                "bag_uuid_matches": matched,
                "state_captured": False,
                "state_decoded": False,
                "uuid_stable": True,
                "mutation_performed": False,
                "mapping_promoted": False,
            })
            return AliasReconciliationResult(
                outcome, present, matched, False, False, True, False
            )

        stage = "state"
        blob = transport.read_alias_state_blob(special_alias)
        if not isinstance(blob, bytearray) or not blob:
            raise AppleControlAliasReconciliationError(
                "state transport returned invalid storage"
            )
        try:
            digest = _store_private(capture_path, blob)
            decoded = True
            handle_matches = False
            try:
                state = t2_aks_state.decode(bytes(blob))
                handle_matches = state.handle == special_alias
                if not handle_matches:
                    decoded = False
            except t2_aks_state.AKSStateError:
                decoded = False
            _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_STATE_CAPTURED", {
                "runtime_generation": runtime,
                "state_blob_sha256": digest,
                "state_blob_length": len(blob),
                "state_decoded": decoded,
                "state_handle_matches": handle_matches,
            })
        finally:
            blob[:] = b"\0" * len(blob)

        stage = "uuid-recheck"
        second = transport.observe_alias_uuid(special_alias)
        stable = second == evidence.bag_uuid
        if not stable:
            raise AppleControlAliasReconciliationError(
                "alias UUID changed across state capture"
            )
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_UUID_RECONFIRMED", {
            "runtime_generation": runtime,
            "bag_uuid_matches": True,
            "double_read_equal": True,
        })
        outcome = "bound-and-reconciled" if decoded else "bound-state-captured"
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_RECONCILE_COMPLETE", {
            "runtime_generation": runtime,
            "outcome": outcome,
            "alias_present": True,
            "bag_uuid_matches": True,
            "state_captured": True,
            "state_decoded": decoded,
            "uuid_stable": True,
            "mutation_performed": False,
            "mapping_promoted": False,
        })
        return AliasReconciliationResult(
            outcome, True, True, True, decoded, True, not decoded
        )
    except BaseException as error:
        try:
            _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_RECONCILE_UNKNOWN", {
                "runtime_generation": runtime,
                "stage": stage,
                "mutation_performed": False,
                "retry_before_reboot_permitted": False,
            })
        except BaseException:
            pass
        raise AppleControlAliasReconciliationError(
            "Apple-control alias reconciliation is unknown; do not retry before reboot"
        ) from error
