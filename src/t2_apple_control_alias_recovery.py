# SPDX-License-Identifier: GPL-2.0-only
"""One audited recovery of a pre-state-only compatibility unlock failure.

Reuses the imported keybag and existing bind/unlock operations in one session.
No reset, erase, provisioning, Catacomb write, or fingerprint mutation is used.
The original journals remain immutable; recovery has three exclusive journals.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import t2_apple_control_alias_discriminator as alias
import t2_apple_control_alias_unlock as unlock
import t2_apple_control_discriminator as keybag
import t2_mutation_journal as journal


JOURNAL = "apple-control-alias-recovery.jsonl"
BIND_JOURNAL = "apple-control-alias-recovery-bind.jsonl"
UNLOCK_JOURNAL = "apple-control-alias-recovery-unlock.jsonl"
FAILED_JOURNAL = "apple-control-alias-unlock.jsonl"
ARTIFACTS = (JOURNAL, BIND_JOURNAL, UNLOCK_JOURNAL)
CAPACITY_JOURNAL = "apple-control-alias-capacity-fix.jsonl"
CAPACITY_BIND_JOURNAL = "apple-control-alias-capacity-fix-bind.jsonl"
CAPACITY_UNLOCK_JOURNAL = "apple-control-alias-capacity-fix-unlock.jsonl"
CAPACITY_ARTIFACTS = (
    CAPACITY_JOURNAL,
    CAPACITY_BIND_JOURNAL,
    CAPACITY_UNLOCK_JOURNAL,
)


class AliasRecoveryError(RuntimeError):
    pass


class RecoveryTransport(alias.AliasDiscriminatorTransport, unlock.AliasUnlockTransport, Protocol):
    pass


@dataclass(frozen=True, repr=False)
class FailedPrestateProof:
    operation_id: str
    linux_boot_uuid: str
    runtime_generation: str


@dataclass(frozen=True, repr=False)
class RecoveryProof:
    operation_id: str
    failed_unlock_operation_id: str
    bind_operation_id: str
    unlocked: unlock.AliasUnlockProof


@dataclass(frozen=True, repr=False)
class FailedRecoveryProof:
    operation_id: str
    bind_operation_id: str
    unlock_operation_id: str
    linux_boot_uuid: str
    runtime_generation: str


@dataclass(frozen=True, repr=False)
class CapacityFixProof:
    operation_id: str
    failed_recovery_operation_id: str
    bind_operation_id: str
    unlocked: unlock.AliasUnlockProof


def _uuid(value: object) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise AliasRecoveryError("recovery proof contains an invalid identifier") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AliasRecoveryError("recovery proof contains an invalid identifier")
    return str(parsed)


def _read(path: Path) -> list[dict]:
    try:
        return journal.read(path)
    except (OSError, journal.JournalError) as error:
        raise AliasRecoveryError("recovery prerequisite journal is unavailable or invalid") from error


def _equal(actual: object, expected: object) -> bool:
    # JSON equality also distinguishes booleans from integer lookalikes.
    return journal.canonical(actual) == journal.canonical(expected)


def read_failed_prestate_proof(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
) -> FailedPrestateProof:
    records = _read(oracle / FAILED_JOURNAL)
    if [r.get("milestone") for r in records] != [
        "APPLE_CONTROL_ALIAS_UNLOCK_BASELINE", "APPLE_CONTROL_ALIAS_UNLOCK_UNKNOWN",
    ]:
        raise AliasRecoveryError("unlock failure is not an exact pre-state-only failure")
    operation = _uuid(records[0].get("operation_id"))
    baseline = records[0].get("evidence", {})
    boot = _uuid(baseline.get("linux_boot_uuid"))
    runtime = _uuid(baseline.get("runtime_generation"))
    import_operation = _uuid(evidence.import_operation_id)
    if (
        records[1].get("operation_id") != operation
        or len({operation, bound.operation_id, matched.operation_id, import_operation}) != 4
        or boot == bound.linux_boot_uuid
        or runtime == bound.runtime_generation
        or not _equal(baseline, {
            "operation_kind": "apple-control-alias-unlock-discriminator",
            "origin": keybag.ORIGIN,
            "reconciliation_operation_id": bound.operation_id,
            "mapping_generation": evidence.mapping_generation,
            "linux_boot_uuid": boot, "runtime_generation": runtime,
            "linux_uid": evidence.linux_uid, "apple_uid": evidence.apple_uid,
            "bag_uuid": evidence.bag_uuid, "special_alias": -evidence.apple_uid,
            "mapping_enabled": False, "operation_scope": "observe-unlock-observe",
        })
        or not _equal(records[1].get("evidence"), {
            "runtime_generation": runtime, "stage": "pre-state",
            "mutation_performed": False, "retry_before_reboot_permitted": False,
        })
    ):
        raise AliasRecoveryError("failed unlock proof does not match clean-bind authority")
    return FailedPrestateProof(operation, boot, runtime)


def require_later_boot(
    failed: FailedPrestateProof, matched: alias.MatchedKeybagProof,
    bound: alias.BoundAliasProof, boot: str,
) -> str:
    boot = _uuid(boot)
    if boot in (failed.linux_boot_uuid, bound.linux_boot_uuid, matched.linux_boot_uuid):
        raise AliasRecoveryError("alias recovery requires a later boot than the failed unlock")
    return boot


def prepare(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
    boot: str,
) -> FailedPrestateProof:
    failed = read_failed_prestate_proof(oracle, evidence, matched, bound)
    require_later_boot(failed, matched, bound, boot)
    if any(os.path.lexists(oracle / name) for name in ARTIFACTS):
        raise AliasRecoveryError("alias recovery artifacts already exist; preserve them; do not retry")
    return failed


def _baseline(evidence, matched, bound, failed, boot, runtime, bind_id, unlock_id):
    return {
        "operation_kind": "apple-control-alias-prestate-recovery",
        "origin": keybag.ORIGIN,
        "import_operation_id": evidence.import_operation_id,
        "mapping_generation": evidence.mapping_generation,
        "matched_keybag_operation_id": matched.operation_id,
        "original_bind_operation_id": bound.operation_id,
        "failed_unlock_operation_id": failed.operation_id,
        "recovery_bind_operation_id": bind_id,
        "recovery_unlock_operation_id": unlock_id,
        "linux_boot_uuid": boot, "runtime_generation": runtime,
        "linux_uid": evidence.linux_uid, "apple_uid": evidence.apple_uid,
        "bag_uuid": evidence.bag_uuid, "keybag_sha256": evidence.keybag_sha256,
        "mapping_enabled": False,
        "operation_scope": "absent-load-verify-bind-read-unlock-read-unload-read",
    }


def _legacy_failed_baseline(
    evidence, matched, bound, failed, boot, runtime, bind_id, unlock_id,
):
    baseline = _baseline(
        evidence, matched, bound, failed, boot, runtime, bind_id, unlock_id
    )
    baseline["operation_scope"] = (
        "absent-load-verify-bind-read-unload-read-unlock-read"
    )
    return baseline


def _complete(runtime: str) -> dict:
    return {"runtime_generation": runtime, "outcome": "recovered-and-unlocked",
            "mapping_promoted": False}


def _operation_ids(reserved: set[str]) -> tuple[str, str, str]:
    generated: list[str] = []
    for _attempt in range(48):
        candidate = str(uuid.uuid4())
        if candidate not in reserved and candidate not in generated:
            generated.append(candidate)
            if len(generated) == 3:
                return generated[0], generated[1], generated[2]
    raise AliasRecoveryError("could not allocate distinct recovery operation IDs")


def read_completed_recovery(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
) -> RecoveryProof:
    failed = read_failed_prestate_proof(oracle, evidence, matched, bound)
    records = _read(oracle / JOURNAL)
    if [r.get("milestone") for r in records] != [
        "APPLE_CONTROL_ALIAS_RECOVERY_BASELINE", "APPLE_CONTROL_ALIAS_RECOVERY_COMPLETE",
    ]:
        raise AliasRecoveryError("alias recovery did not complete")
    operation = _uuid(records[0].get("operation_id"))
    try:
        rebound = alias.read_bound_alias_proof(oracle / BIND_JOURNAL, evidence, matched)
        # The original bind is still the unlock authority. The recovery envelope
        # additionally requires the new bind and unlock to share a boot/runtime.
        unlocked = unlock.read_completed_unlock_proof(oracle / UNLOCK_JOURNAL, evidence, bound)
    except (alias.AppleControlAliasDiscriminatorError, unlock.AppleControlAliasUnlockError) as error:
        raise AliasRecoveryError("alias recovery child proofs are invalid") from error
    boot, runtime = rebound.linux_boot_uuid, rebound.runtime_generation
    require_later_boot(failed, matched, bound, boot)
    operations = (operation, rebound.operation_id, unlocked.operation_id,
                  failed.operation_id, bound.operation_id, matched.operation_id)
    if (
        len(set(operations)) != len(operations)
        or records[1].get("operation_id") != operation
        or runtime in (failed.runtime_generation, bound.runtime_generation)
        or runtime == matched.runtime_generation
        or boot == matched.linux_boot_uuid
        or (unlocked.linux_boot_uuid, unlocked.runtime_generation) != (boot, runtime)
        or not _equal(records[0].get("evidence"), _baseline(
            evidence, matched, bound, failed, boot, runtime,
            rebound.operation_id, unlocked.operation_id,
        ))
        or not _equal(records[1].get("evidence"), _complete(runtime))
    ):
        raise AliasRecoveryError("alias recovery proof bindings are inconsistent")
    return RecoveryProof(operation, failed.operation_id, rebound.operation_id, unlocked)


def read_failed_recovery_for_capacity_fix(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
) -> FailedRecoveryProof:
    """Validate the exact unload-before-unlock/capacity failure generation."""
    failed = read_failed_prestate_proof(oracle, evidence, matched, bound)
    parent = _read(oracle / JOURNAL)
    if [record.get("milestone") for record in parent] != [
        "APPLE_CONTROL_ALIAS_RECOVERY_BASELINE",
        "APPLE_CONTROL_ALIAS_RECOVERY_UNKNOWN",
    ]:
        raise AliasRecoveryError("prior recovery parent is not the exact failed generation")
    operation = _uuid(parent[0].get("operation_id"))
    baseline = parent[0].get("evidence", {})
    boot = _uuid(baseline.get("linux_boot_uuid"))
    runtime = _uuid(baseline.get("runtime_generation"))
    try:
        rebound = alias.read_bound_alias_proof(oracle / BIND_JOURNAL, evidence, matched)
    except alias.AppleControlAliasDiscriminatorError as error:
        raise AliasRecoveryError("prior recovery bind proof is invalid") from error

    unlock_records = _read(oracle / UNLOCK_JOURNAL)
    if [record.get("milestone") for record in unlock_records] != [
        "APPLE_CONTROL_ALIAS_UNLOCK_BASELINE",
        "APPLE_CONTROL_ALIAS_UNLOCK_PRESTATE",
        "APPLE_CONTROL_ALIAS_UNLOCK_INTENT",
        "APPLE_CONTROL_ALIAS_UNLOCK_OBSERVED",
        "APPLE_CONTROL_ALIAS_UNLOCK_COMPLETE",
    ]:
        raise AliasRecoveryError("prior recovery unlock is not the exact rejected generation")
    unlock_operation = _uuid(unlock_records[0].get("operation_id"))
    unlock_baseline = {
        "operation_kind": "apple-control-alias-unlock-discriminator",
        "origin": keybag.ORIGIN,
        "reconciliation_operation_id": bound.operation_id,
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
    expected_unlock = (
        unlock_baseline,
        {
            "runtime_generation": runtime,
            "alias_present": True,
            "bag_uuid_matches": True,
            "unlock_actionable": True,
        },
        {
            "runtime_generation": runtime,
            "special_alias": -evidence.apple_uid,
            "mutation_possible": True,
        },
        {
            "runtime_generation": runtime,
            "alias_present": True,
            "bag_uuid_matches": True,
            "unlocked": False,
            "command_status": None,
            "command_raised": True,
        },
        {
            "runtime_generation": runtime,
            "outcome": "unlock-rejected",
            "alias_present": True,
            "bag_uuid_matches": True,
            "unlocked": False,
            "mutation_performed": True,
            "mapping_promoted": False,
        },
    )
    operations = (
        operation, rebound.operation_id, unlock_operation, failed.operation_id,
        bound.operation_id, matched.operation_id, _uuid(evidence.import_operation_id),
    )
    if (
        any(record.get("operation_id") != operation for record in parent)
        or any(record.get("operation_id") != unlock_operation for record in unlock_records)
        or len(set(operations)) != len(operations)
        or (rebound.linux_boot_uuid, rebound.runtime_generation) != (boot, runtime)
        or boot in (failed.linux_boot_uuid, bound.linux_boot_uuid, matched.linux_boot_uuid)
        or runtime in (
            failed.runtime_generation, bound.runtime_generation, matched.runtime_generation,
        )
        or not _equal(baseline, _legacy_failed_baseline(
            evidence, matched, bound, failed, boot, runtime,
            rebound.operation_id, unlock_operation,
        ))
        or not _equal(parent[1].get("evidence"), {
            "runtime_generation": runtime,
            "stage": "unlock",
            "retry_permitted": False,
        })
        or any(
            not _equal(record.get("evidence"), expected)
            for record, expected in zip(unlock_records, expected_unlock, strict=True)
        )
    ):
        raise AliasRecoveryError("prior failed recovery proof bindings are inconsistent")
    return FailedRecoveryProof(
        operation, rebound.operation_id, unlock_operation, boot, runtime
    )


def _capacity_prerequisites(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
) -> tuple[FailedPrestateProof, FailedRecoveryProof]:
    failed_unlock = read_failed_prestate_proof(oracle, evidence, matched, bound)
    failed_recovery = read_failed_recovery_for_capacity_fix(
        oracle, evidence, matched, bound
    )
    return failed_unlock, failed_recovery


def prepare_capacity_fix(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof, boot: str,
) -> tuple[FailedPrestateProof, FailedRecoveryProof]:
    failed_unlock, failed_recovery = _capacity_prerequisites(
        oracle, evidence, matched, bound
    )
    current_boot = _uuid(boot)
    prior_boots = {
        matched.linux_boot_uuid,
        bound.linux_boot_uuid,
        failed_unlock.linux_boot_uuid,
        failed_recovery.linux_boot_uuid,
    }
    if current_boot in prior_boots:
        raise AliasRecoveryError("capacity-fix recovery requires a fresh later boot")
    if any(os.path.lexists(oracle / name) for name in CAPACITY_ARTIFACTS):
        raise AliasRecoveryError(
            "capacity-fix recovery artifacts already exist; preserve them; do not retry"
        )
    return failed_unlock, failed_recovery


def _capacity_baseline(
    evidence, matched, bound, failed_unlock, failed_recovery,
    boot, runtime, bind_id, unlock_id,
):
    return {
        "operation_kind": "apple-control-alias-capacity-fix-recovery",
        "origin": keybag.ORIGIN,
        "import_operation_id": evidence.import_operation_id,
        "mapping_generation": evidence.mapping_generation,
        "matched_keybag_operation_id": matched.operation_id,
        "original_bind_operation_id": bound.operation_id,
        "original_failed_unlock_operation_id": failed_unlock.operation_id,
        "failed_recovery_operation_id": failed_recovery.operation_id,
        "failed_recovery_bind_operation_id": failed_recovery.bind_operation_id,
        "failed_recovery_unlock_operation_id": failed_recovery.unlock_operation_id,
        "capacity_fix_bind_operation_id": bind_id,
        "capacity_fix_unlock_operation_id": unlock_id,
        "linux_boot_uuid": boot,
        "runtime_generation": runtime,
        "linux_uid": evidence.linux_uid,
        "apple_uid": evidence.apple_uid,
        "bag_uuid": evidence.bag_uuid,
        "keybag_sha256": evidence.keybag_sha256,
        "mapping_enabled": False,
        "predispatch_capacity_defect_acknowledged": True,
        "operation_scope": "absent-load-verify-bind-read-unlock-read-unload-read",
    }


def read_completed_capacity_fix(
    oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
) -> CapacityFixProof:
    failed_unlock, failed_recovery = _capacity_prerequisites(
        oracle, evidence, matched, bound
    )
    records = _read(oracle / CAPACITY_JOURNAL)
    if [record.get("milestone") for record in records] != [
        "APPLE_CONTROL_ALIAS_CAPACITY_FIX_BASELINE",
        "APPLE_CONTROL_ALIAS_CAPACITY_FIX_COMPLETE",
    ]:
        raise AliasRecoveryError("capacity-fix recovery did not complete")
    operation = _uuid(records[0].get("operation_id"))
    try:
        rebound = alias.read_bound_alias_proof(
            oracle / CAPACITY_BIND_JOURNAL, evidence, matched
        )
        unlocked = unlock.read_completed_unlock_proof(
            oracle / CAPACITY_UNLOCK_JOURNAL, evidence, bound
        )
    except (alias.AppleControlAliasDiscriminatorError, unlock.AppleControlAliasUnlockError) as error:
        raise AliasRecoveryError("capacity-fix recovery child proofs are invalid") from error
    boot, runtime = rebound.linux_boot_uuid, rebound.runtime_generation
    operations = (
        operation, rebound.operation_id, unlocked.operation_id,
        failed_recovery.operation_id, failed_recovery.bind_operation_id,
        failed_recovery.unlock_operation_id, failed_unlock.operation_id,
        bound.operation_id, matched.operation_id, _uuid(evidence.import_operation_id),
    )
    if (
        any(record.get("operation_id") != operation for record in records)
        or len(set(operations)) != len(operations)
        or boot in {
            matched.linux_boot_uuid, bound.linux_boot_uuid,
            failed_unlock.linux_boot_uuid, failed_recovery.linux_boot_uuid,
        }
        or runtime in {
            matched.runtime_generation, bound.runtime_generation,
            failed_unlock.runtime_generation, failed_recovery.runtime_generation,
        }
        or (unlocked.linux_boot_uuid, unlocked.runtime_generation) != (boot, runtime)
        or not _equal(records[0].get("evidence"), _capacity_baseline(
            evidence, matched, bound, failed_unlock, failed_recovery,
            boot, runtime, rebound.operation_id, unlocked.operation_id,
        ))
        or not _equal(records[1].get("evidence"), {
            "runtime_generation": runtime,
            "outcome": "capacity-fixed-and-unlocked",
            "mapping_promoted": False,
        })
    ):
        raise AliasRecoveryError("capacity-fix recovery proof bindings are inconsistent")
    return CapacityFixProof(
        operation, failed_recovery.operation_id, rebound.operation_id, unlocked
    )


def run_capacity_fix(
    *, oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
    linux_boot_uuid: str, transport: RecoveryTransport, password: bytearray,
    predispatch_capacity_defect_acknowledged: bool,
) -> dict[str, object]:
    if not isinstance(password, bytearray):
        raise AliasRecoveryError("capacity-fix recovery requires wipeable password storage")
    try:
        if predispatch_capacity_defect_acknowledged is not True:
            raise AliasRecoveryError(
                "capacity-fix recovery requires acknowledgement that the prior "
                "installed client used the known pre-dispatch 4-byte response defect"
            )
        if not 1 <= len(password) <= 1023 or b"\0" in password:
            raise AliasRecoveryError("capacity-fix recovery password input is invalid")
        failed_unlock, failed_recovery = prepare_capacity_fix(
            oracle, evidence, matched, bound, linux_boot_uuid
        )
        runtime = _uuid(transport.runtime_generation)
        if runtime in {
            matched.runtime_generation,
            bound.runtime_generation,
            failed_unlock.runtime_generation,
            failed_recovery.runtime_generation,
        }:
            raise AliasRecoveryError(
                "capacity-fix recovery requires a fresh runtime generation"
            )
        reserved = {
            _uuid(evidence.import_operation_id),
            matched.operation_id,
            bound.operation_id,
            failed_unlock.operation_id,
            failed_recovery.operation_id,
            failed_recovery.bind_operation_id,
            failed_recovery.unlock_operation_id,
        }
        operation, bind_id, unlock_id = _operation_ids(reserved)
        path = oracle / CAPACITY_JOURNAL
        journal.append(
            path,
            operation,
            "APPLE_CONTROL_ALIAS_CAPACITY_FIX_BASELINE",
            _capacity_baseline(
                evidence, matched, bound, failed_unlock, failed_recovery,
                linux_boot_uuid, runtime, bind_id, unlock_id,
            ),
            exclusive=True,
        )
        stage = "bind"
        try:
            result: unlock.AliasUnlockResult | None = None

            def unlock_bound_alias() -> None:
                nonlocal result, stage
                stage = "unlock"
                result = unlock.run(
                    journal_path=oracle / CAPACITY_UNLOCK_JOURNAL,
                    evidence=evidence,
                    proof=bound,
                    linux_boot_uuid=linux_boot_uuid,
                    transport=transport,
                    password=password,
                    operation_id=unlock_id,
                )
                if not result.unlocked:
                    raise AliasRecoveryError(
                        "capacity-fix recovery unlock was rejected; do not retry"
                    )

            rebound = alias.run(
                journal_path=oracle / CAPACITY_BIND_JOURNAL,
                evidence=evidence,
                matched_proof=matched,
                linux_boot_uuid=linux_boot_uuid,
                transport=transport,
                operation_id=bind_id,
                while_bound=unlock_bound_alias,
            )
            if rebound.outcome != "bound-and-persisted":
                raise AliasRecoveryError(
                    "capacity-fix recovery requires an absent alias; no unlock was dispatched"
                )
            alias.read_bound_alias_proof(
                oracle / CAPACITY_BIND_JOURNAL, evidence, matched
            )
            if result is None:
                raise AliasRecoveryError("capacity-fix recovery unlock did not run")
            stage = "completion"
            journal.append(
                path,
                operation,
                "APPLE_CONTROL_ALIAS_CAPACITY_FIX_COMPLETE",
                {
                    "runtime_generation": runtime,
                    "outcome": "capacity-fixed-and-unlocked",
                    "mapping_promoted": False,
                },
            )
            read_completed_capacity_fix(oracle, evidence, matched, bound)
            return {**result.public_summary(), "capacity_fix_recovery_complete": True}
        except BaseException as error:
            try:
                journal.append(
                    path,
                    operation,
                    "APPLE_CONTROL_ALIAS_CAPACITY_FIX_UNKNOWN",
                    {
                        "runtime_generation": runtime,
                        "stage": stage,
                        "retry_permitted": False,
                    },
                )
            except (OSError, journal.JournalError):
                pass
            raise AliasRecoveryError(
                f"capacity-fix recovery stopped at {stage}; preserve journals and do not retry"
            ) from error
    except (OSError, journal.JournalError) as error:
        raise AliasRecoveryError(
            "capacity-fix recovery journal cannot advance safely"
        ) from error
    finally:
        password[:] = b"\0" * len(password)


def run(
    *, oracle: Path, evidence: keybag.OracleEvidence,
    matched: alias.MatchedKeybagProof, bound: alias.BoundAliasProof,
    linux_boot_uuid: str, transport: RecoveryTransport, password: bytearray,
) -> dict[str, object]:
    if not isinstance(password, bytearray):
        raise AliasRecoveryError("recovery requires wipeable password storage")
    try:
        if not 1 <= len(password) <= 1023 or b"\0" in password:
            raise AliasRecoveryError("recovery password input is invalid")
        failed = prepare(oracle, evidence, matched, bound, linux_boot_uuid)
        alias.require_later_boot(matched, linux_boot_uuid)
        runtime = _uuid(transport.runtime_generation)
        if runtime in (failed.runtime_generation, bound.runtime_generation, matched.runtime_generation):
            raise AliasRecoveryError("alias recovery requires a fresh runtime generation")
        reserved = {
            _uuid(evidence.import_operation_id),
            matched.operation_id,
            bound.operation_id,
            failed.operation_id,
        }
        operation, bind_id, unlock_id = _operation_ids(reserved)
        path = oracle / JOURNAL
        journal.append(path, operation, "APPLE_CONTROL_ALIAS_RECOVERY_BASELINE", _baseline(
            evidence, matched, bound, failed, linux_boot_uuid, runtime, bind_id, unlock_id,
        ), exclusive=True)
        stage = "bind"
        try:
            result: unlock.AliasUnlockResult | None = None

            def unlock_bound_alias() -> None:
                nonlocal result, stage
                stage = "unlock"
                result = unlock.run(
                    journal_path=oracle / UNLOCK_JOURNAL,
                    evidence=evidence,
                    proof=bound,
                    linux_boot_uuid=linux_boot_uuid,
                    transport=transport,
                    password=password,
                    operation_id=unlock_id,
                )
                if not result.unlocked:
                    raise AliasRecoveryError("recovery unlock was rejected; do not retry")

            rebound = alias.run(
                journal_path=oracle / BIND_JOURNAL, evidence=evidence, matched_proof=matched,
                linux_boot_uuid=linux_boot_uuid, transport=transport, operation_id=bind_id,
                while_bound=unlock_bound_alias,
            )
            if rebound.outcome != "bound-and-persisted":
                raise AliasRecoveryError("recovery requires an absent alias; no unlock was dispatched")
            alias.read_bound_alias_proof(oracle / BIND_JOURNAL, evidence, matched)
            if result is None:
                raise AliasRecoveryError("recovery unlock did not run")
            stage = "completion"
            journal.append(path, operation, "APPLE_CONTROL_ALIAS_RECOVERY_COMPLETE", _complete(runtime))
            read_completed_recovery(oracle, evidence, matched, bound)
            return {**result.public_summary(), "recovery_complete": True}
        except BaseException as error:
            try:
                journal.append(path, operation, "APPLE_CONTROL_ALIAS_RECOVERY_UNKNOWN", {
                    "runtime_generation": runtime, "stage": stage,
                    "retry_permitted": False,
                })
            except (OSError, journal.JournalError):
                pass
            raise AliasRecoveryError(
                f"alias recovery stopped at {stage}; preserve journals and do not retry"
            ) from error
    except (OSError, journal.JournalError) as error:
        raise AliasRecoveryError("alias recovery journal cannot advance safely") from error
    finally:
        password[:] = b"\0" * len(password)
