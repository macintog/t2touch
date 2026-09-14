# SPDX-License-Identifier: GPL-2.0-only
"""One-shot password-unlock discriminator for the reconciled Apple alias."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal as journal
import t2_user_readiness


class AppleControlAliasUnlockError(RuntimeError):
    pass


class AliasUnlockTransport(Protocol):
    runtime_generation: str

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence: ...
    def unlock_alias(self, special_alias: int, password: memoryview) -> int: ...


@dataclass(frozen=True)
class AliasUnlockResult:
    outcome: str
    alias_present: bool
    bag_uuid_matched: bool
    unlocked: bool
    mutation_performed: bool
    reconciliation_required: bool

    def public_summary(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "alias_present": self.alias_present,
            "bag_uuid_matched": self.bag_uuid_matched,
            "unlocked": self.unlocked,
            "mutation_performed": self.mutation_performed,
            "reconciliation_required": self.reconciliation_required,
            "mapping_enabled": False,
            "identifiers_redacted": True,
        }


@dataclass(frozen=True)
class AliasUnlockProof:
    operation_id: str
    linux_boot_uuid: str
    runtime_generation: str


def _uuid(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError) as error:
        raise AppleControlAliasUnlockError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AppleControlAliasUnlockError(f"{label} is invalid")
    return str(parsed)


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AppleControlAliasUnlockError(f"{label} is invalid")
    return value


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
    *,
    exclusive: bool = False,
) -> None:
    try:
        journal.append(path, operation_id, milestone, evidence, exclusive=exclusive)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasUnlockError(
            "alias unlock journal cannot advance"
        ) from error


def _observe(
    transport: AliasUnlockTransport,
    special_alias: int,
    bag_uuid: str,
) -> t2_user_readiness.AliasEvidence:
    value = transport.observe_alias(special_alias)
    if not isinstance(value, t2_user_readiness.AliasEvidence):
        raise AppleControlAliasUnlockError("alias observation has the wrong type")
    if (
        not value.present
        or value.special_alias != special_alias
        or value.bag_uuid != bag_uuid
        or type(value.lock_state) is not int
    ):
        raise AppleControlAliasUnlockError("alias observation does not match proof")
    if value.lock_state & ~t2_user_readiness.KNOWN_LOCK_STATE_BITS:
        raise AppleControlAliasUnlockError("alias state contains unknown lock bits")
    if value.lock_state & t2_user_readiness.CATACOMB_CORRUPTED:
        raise AppleControlAliasUnlockError("alias state reports Catacomb corruption")
    return value


def _ready(lock_state: int) -> bool:
    blocked = (
        t2_user_readiness.DEVICE_LOCKED
        | t2_user_readiness.BEFORE_FIRST_UNLOCK
        | t2_user_readiness.PASSCODE_LOCKOUT
        | t2_user_readiness.BIO_LOCKOUT
        | t2_user_readiness.IDENTIFICATION_LOCKOUT
    )
    return not lock_state & blocked


def require_later_boot(
    proof: reconciliation.ReconciledAliasProof,
    linux_boot_uuid: str,
) -> str:
    boot = _uuid(linux_boot_uuid, "Linux boot UUID")
    if boot == proof.linux_boot_uuid:
        raise AppleControlAliasUnlockError(
            "alias unlock requires a later boot; no more SEP work is permitted now"
        )
    return boot


def read_completed_unlock_proof(
    path: Path,
    evidence: keybag_discriminator.OracleEvidence,
    proof: reconciliation.ReconciledAliasProof,
) -> AliasUnlockProof:
    """Validate the immutable successful compatibility unlock journal."""

    try:
        records = journal.read(path)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasUnlockError(
            "alias unlock proof is unavailable"
        ) from error
    milestones = tuple(record.get("milestone") for record in records)
    if milestones not in {
        (
            "APPLE_CONTROL_ALIAS_UNLOCK_BASELINE",
            "APPLE_CONTROL_ALIAS_UNLOCK_COMPLETE",
        ),
        (
            "APPLE_CONTROL_ALIAS_UNLOCK_BASELINE",
            "APPLE_CONTROL_ALIAS_UNLOCK_PRESTATE",
            "APPLE_CONTROL_ALIAS_UNLOCK_INTENT",
            "APPLE_CONTROL_ALIAS_UNLOCK_OBSERVED",
            "APPLE_CONTROL_ALIAS_UNLOCK_COMPLETE",
        ),
    }:
        raise AppleControlAliasUnlockError("alias unlock proof is incomplete")
    operation_id = _uuid(records[0].get("operation_id"), "unlock operation ID")
    if any(record.get("operation_id") != operation_id for record in records):
        raise AppleControlAliasUnlockError("alias unlock operation ID changed")
    baseline = _exact(
        records[0].get("evidence"),
        {
            "operation_kind", "origin", "reconciliation_operation_id",
            "mapping_generation", "linux_boot_uuid", "runtime_generation",
            "linux_uid", "apple_uid", "bag_uuid", "special_alias",
            "mapping_enabled", "operation_scope",
        },
        "alias unlock baseline",
    )
    boot = _uuid(baseline["linux_boot_uuid"], "unlock Linux boot UUID")
    runtime = _uuid(baseline["runtime_generation"], "unlock runtime generation")
    if (
        baseline
        != {
            "operation_kind": "apple-control-alias-unlock-discriminator",
            "origin": keybag_discriminator.ORIGIN,
            "reconciliation_operation_id": proof.operation_id,
            "mapping_generation": evidence.mapping_generation,
            "linux_boot_uuid": boot,
            "runtime_generation": runtime,
            "linux_uid": evidence.linux_uid,
            "apple_uid": evidence.apple_uid,
            "bag_uuid": evidence.bag_uuid,
            "special_alias": -evidence.apple_uid,
            "mapping_enabled": False,
            "operation_scope": "observe-unlock-observe",
        }
        or boot == proof.linux_boot_uuid
        or runtime == proof.runtime_generation
    ):
        raise AppleControlAliasUnlockError("alias unlock baseline is inconsistent")
    complete = records[-1].get("evidence")
    if len(records) == 2:
        if complete != {
            "runtime_generation": runtime,
            "outcome": "already-unlocked",
            "alias_present": True,
            "bag_uuid_matches": True,
            "unlocked": True,
            "mutation_performed": False,
            "mapping_promoted": False,
        }:
            raise AppleControlAliasUnlockError("alias ready proof is inconsistent")
    else:
        if records[1].get("evidence") != {
            "runtime_generation": runtime,
            "alias_present": True,
            "bag_uuid_matches": True,
            "unlock_actionable": True,
        } or records[2].get("evidence") != {
            "runtime_generation": runtime,
            "special_alias": -evidence.apple_uid,
            "mutation_possible": True,
        }:
            raise AppleControlAliasUnlockError("alias unlock intent is inconsistent")
        observed = _exact(
            records[3].get("evidence"),
            {
                "runtime_generation", "alias_present", "bag_uuid_matches",
                "unlocked", "command_status", "command_raised",
            },
            "alias unlock observation",
        )
        status = observed["command_status"]
        raised = observed["command_raised"]
        if (
            observed["runtime_generation"] != runtime
            or observed["alias_present"] is not True
            or observed["bag_uuid_matches"] is not True
            or observed["unlocked"] is not True
            or type(raised) is not bool
            or (raised and status is not None)
            or (
                not raised
                and (type(status) is not int or not -(1 << 31) <= status < (1 << 32))
            )
            or complete
            != {
                "runtime_generation": runtime,
                "outcome": "unlocked",
                "alias_present": True,
                "bag_uuid_matches": True,
                "unlocked": True,
                "mutation_performed": True,
                "mapping_promoted": False,
            }
        ):
            raise AppleControlAliasUnlockError(
                "alias unlock completion is inconsistent"
            )
    return AliasUnlockProof(operation_id, boot, runtime)


def run(
    *,
    journal_path: Path,
    evidence: keybag_discriminator.OracleEvidence,
    proof: reconciliation.ReconciledAliasProof,
    linux_boot_uuid: str,
    transport: AliasUnlockTransport,
    password: bytearray,
    operation_id: str | None = None,
) -> AliasUnlockResult:
    if not isinstance(password, bytearray) or not 1 <= len(password) <= 1024:
        raise AppleControlAliasUnlockError(
            "alias unlock password must use bounded wipeable storage"
        )
    try:
        boot = require_later_boot(proof, linux_boot_uuid)
        runtime = _uuid(transport.runtime_generation, "AKS runtime generation")
        if runtime == proof.runtime_generation:
            raise AppleControlAliasUnlockError(
                "alias unlock requires a later boot and runtime generation"
            )
        operation_id = _uuid(
            operation_id or str(uuid.uuid4()), "alias unlock operation ID"
        )
        special_alias = -evidence.apple_uid
        _append(
            journal_path,
            operation_id,
            "APPLE_CONTROL_ALIAS_UNLOCK_BASELINE",
            {
                "operation_kind": "apple-control-alias-unlock-discriminator",
                "origin": keybag_discriminator.ORIGIN,
                "reconciliation_operation_id": proof.operation_id,
                "mapping_generation": evidence.mapping_generation,
                "linux_boot_uuid": boot,
                "runtime_generation": runtime,
                "linux_uid": evidence.linux_uid,
                "apple_uid": evidence.apple_uid,
                "bag_uuid": evidence.bag_uuid,
                "special_alias": special_alias,
                "mapping_enabled": False,
                "operation_scope": "observe-unlock-observe",
            },
            exclusive=True,
        )
        stage = "pre-state"
        try:
            before = _observe(transport, special_alias, evidence.bag_uuid)
            if _ready(before.lock_state):
                _append(
                    journal_path,
                    operation_id,
                    "APPLE_CONTROL_ALIAS_UNLOCK_COMPLETE",
                    {
                        "runtime_generation": runtime,
                        "outcome": "already-unlocked",
                        "alias_present": True,
                        "bag_uuid_matches": True,
                        "unlocked": True,
                        "mutation_performed": False,
                        "mapping_promoted": False,
                    },
                )
                return AliasUnlockResult(
                    "already-unlocked", True, True, True, False, False
                )
            actionable = before.lock_state & (
                t2_user_readiness.DEVICE_LOCKED
                | t2_user_readiness.BEFORE_FIRST_UNLOCK
            )
            lockout = before.lock_state & (
                t2_user_readiness.PASSCODE_LOCKOUT
                | t2_user_readiness.BIO_LOCKOUT
                | t2_user_readiness.IDENTIFICATION_LOCKOUT
            )
            if not actionable or lockout:
                raise AppleControlAliasUnlockError(
                    "alias pre-state is not safely password-actionable"
                )
            _append(
                journal_path,
                operation_id,
                "APPLE_CONTROL_ALIAS_UNLOCK_PRESTATE",
                {
                    "runtime_generation": runtime,
                    "alias_present": True,
                    "bag_uuid_matches": True,
                    "unlock_actionable": True,
                },
            )
            _append(
                journal_path,
                operation_id,
                "APPLE_CONTROL_ALIAS_UNLOCK_INTENT",
                {
                    "runtime_generation": runtime,
                    "special_alias": special_alias,
                    "mutation_possible": True,
                },
            )
            stage = "unlock"
            status: int | None = None
            raised = False
            try:
                status = transport.unlock_alias(special_alias, memoryview(password))
                if type(status) is not int or not -(1 << 31) <= status < (1 << 32):
                    raise AppleControlAliasUnlockError(
                        "alias unlock returned an invalid status"
                    )
            except BaseException:
                raised = True
                status = None
            stage = "readback"
            after = _observe(transport, special_alias, evidence.bag_uuid)
            unlocked = _ready(after.lock_state)
            outcome = "unlocked" if unlocked else "unlock-rejected"
            _append(
                journal_path,
                operation_id,
                "APPLE_CONTROL_ALIAS_UNLOCK_OBSERVED",
                {
                    "runtime_generation": runtime,
                    "alias_present": True,
                    "bag_uuid_matches": True,
                    "unlocked": unlocked,
                    "command_status": status,
                    "command_raised": raised,
                },
            )
            _append(
                journal_path,
                operation_id,
                "APPLE_CONTROL_ALIAS_UNLOCK_COMPLETE",
                {
                    "runtime_generation": runtime,
                    "outcome": outcome,
                    "alias_present": True,
                    "bag_uuid_matches": True,
                    "unlocked": unlocked,
                    "mutation_performed": True,
                    "mapping_promoted": False,
                },
            )
            return AliasUnlockResult(outcome, True, True, unlocked, True, False)
        except BaseException as error:
            try:
                _append(
                    journal_path,
                    operation_id,
                    "APPLE_CONTROL_ALIAS_UNLOCK_UNKNOWN",
                    {
                        "runtime_generation": runtime,
                        "stage": stage,
                        "mutation_performed": stage != "pre-state",
                        "retry_before_reboot_permitted": False,
                    },
                )
            except BaseException:
                pass
            raise AppleControlAliasUnlockError(
                "Apple-control alias unlock is unknown; do not retry before reboot"
            ) from error
    finally:
        password[:] = b"\0" * len(password)
