# SPDX-License-Identifier: GPL-2.0-only
"""One-shot Apple-control alias-binding discriminator.

This compatibility-oracle stage proves an absent derived alias, loads the
previously matched saved keybag, binds the alias once, reads it back, unloads
the positive handle once, and proves the alias persists.  It has no unlock,
mapping-promotion, service, PAM, or biometric operation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal as journal
import t2_user_readiness


MATCHED_MILESTONES = (
    "APPLE_CONTROL_DISCRIMINATOR_BASELINE",
    "APPLE_CONTROL_KEYBAG_LOAD_INTENT",
    "APPLE_CONTROL_KEYBAG_HANDLE_OBSERVED",
    "APPLE_CONTROL_KEYBAG_UUID_OBSERVED",
    "APPLE_CONTROL_KEYBAG_UNLOAD_INTENT",
    "APPLE_CONTROL_KEYBAG_HANDLE_RELEASED",
    "APPLE_CONTROL_DISCRIMINATOR_COMPLETE",
)


class AppleControlAliasDiscriminatorError(RuntimeError):
    pass


class AliasDiscriminatorTransport(Protocol):
    runtime_generation: str

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence: ...
    def load_keybag(self, keybag_path: str) -> int: ...
    def bag_uuid(self, handle: int) -> str: ...
    def bind_alias(self, handle: int, special_alias: int) -> int: ...
    def unload_keybag(self, handle: int) -> int: ...


@dataclass(frozen=True, repr=False)
class MatchedKeybagProof:
    operation_id: str
    linux_boot_uuid: str
    runtime_generation: str


@dataclass(frozen=True, repr=False)
class AliasJournalPlan:
    path: Path
    reconciled_prestate_operation_id: str | None


@dataclass(frozen=True)
class AliasDiscriminatorResult:
    outcome: str
    alias_absent_before: bool
    alias_bound: bool
    alias_persisted: bool
    handle_released: bool
    reconciliation_required: bool

    def public_summary(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "alias_absent_before": self.alias_absent_before,
            "alias_bound": self.alias_bound,
            "alias_persisted": self.alias_persisted,
            "handle_released": self.handle_released,
            "reconciliation_required": self.reconciliation_required,
            "mapping_enabled": False,
            "live_operation_scope": "observe-load-verify-bind-read-unload-read",
            "identifiers_redacted": True,
        }


def _uuid(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError) as error:
        raise AppleControlAliasDiscriminatorError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AppleControlAliasDiscriminatorError(f"{label} is invalid")
    return str(parsed)


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AppleControlAliasDiscriminatorError(f"{label} is invalid")
    return value


def read_matched_keybag_proof(
    path: Path,
    evidence: keybag_discriminator.OracleEvidence,
) -> MatchedKeybagProof:
    """Validate the complete earlier keybag discriminator before advancing."""
    try:
        records = journal.read(path)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasDiscriminatorError(
            "matched keybag discriminator proof is unavailable"
        ) from error
    if tuple(record.get("milestone") for record in records) != MATCHED_MILESTONES:
        raise AppleControlAliasDiscriminatorError(
            "keybag discriminator did not complete the matched path"
        )
    operation_id = _uuid(records[0].get("operation_id"), "keybag operation ID")
    baseline = _exact(
        records[0].get("evidence"),
        {
            "operation_kind", "origin", "import_operation_id",
            "mapping_generation", "linux_boot_uuid", "runtime_generation",
            "linux_uid", "apple_uid", "bag_uuid", "keybag_sha256",
            "operation_scope", "mapping_enabled",
        },
        "keybag discriminator baseline",
    )
    runtime = _uuid(baseline["runtime_generation"], "prior runtime generation")
    prior_boot = _uuid(baseline["linux_boot_uuid"], "prior Linux boot UUID")
    if (
        baseline["operation_kind"] != "apple-control-uuid-discriminator"
        or baseline["origin"] != keybag_discriminator.ORIGIN
        or baseline["import_operation_id"] != evidence.import_operation_id
        or baseline["mapping_generation"] != evidence.mapping_generation
        or baseline["linux_uid"] != evidence.linux_uid
        or baseline["apple_uid"] != evidence.apple_uid
        or baseline["bag_uuid"] != evidence.bag_uuid
        or baseline["keybag_sha256"] != evidence.keybag_sha256
        or baseline["operation_scope"] != "load-double-uuid-unload"
        or baseline["mapping_enabled"] is not False
    ):
        raise AppleControlAliasDiscriminatorError(
            "keybag discriminator proof does not match the protected import"
        )
    load = _exact(
        records[1].get("evidence"),
        {"runtime_generation", "keybag_sha256", "mutation_possible"},
        "keybag load intent",
    )
    handle_record = _exact(
        records[2].get("evidence"),
        {"runtime_generation", "handle"},
        "keybag handle evidence",
    )
    observed = _exact(
        records[3].get("evidence"),
        {"runtime_generation", "handle", "double_read_equal", "bag_uuid_matches"},
        "keybag UUID evidence",
    )
    unload = _exact(
        records[4].get("evidence"),
        {"runtime_generation", "handle", "mutation_possible"},
        "keybag unload intent",
    )
    released = _exact(
        records[5].get("evidence"),
        {"runtime_generation", "command_status"},
        "keybag release evidence",
    )
    complete = _exact(
        records[6].get("evidence"),
        {"runtime_generation", "outcome", "bag_uuid_matches", "mapping_promoted"},
        "keybag completion evidence",
    )
    handle = handle_record["handle"]
    if (
        any(record.get("operation_id") != operation_id for record in records)
        or type(handle) is not int
        or not 1 <= handle <= 0x7FFFFFFF
        or load != {
            "runtime_generation": runtime,
            "keybag_sha256": evidence.keybag_sha256,
            "mutation_possible": True,
        }
        or handle_record["runtime_generation"] != runtime
        or observed != {
            "runtime_generation": runtime,
            "handle": handle,
            "double_read_equal": True,
            "bag_uuid_matches": True,
        }
        or unload != {
            "runtime_generation": runtime,
            "handle": handle,
            "mutation_possible": True,
        }
        or released != {"runtime_generation": runtime, "command_status": 0}
        or complete != {
            "runtime_generation": runtime,
            "outcome": "matched",
            "bag_uuid_matches": True,
            "mapping_promoted": False,
        }
    ):
        raise AppleControlAliasDiscriminatorError(
            "keybag discriminator proof is incomplete or inconsistent"
        )
    return MatchedKeybagProof(operation_id, prior_boot, runtime)


def require_later_boot(proof: MatchedKeybagProof, linux_boot_uuid: str) -> str:
    current = _uuid(linux_boot_uuid, "Linux boot UUID")
    if current == proof.linux_boot_uuid:
        raise AppleControlAliasDiscriminatorError(
            "alias binding requires a later boot; no more SEP work is permitted now"
        )
    return current


def select_alias_journal(
    oracle_root: Path,
    evidence: keybag_discriminator.OracleEvidence,
    matched_proof: MatchedKeybagProof,
    linux_boot_uuid: str,
) -> AliasJournalPlan:
    """Select the first journal, or one audited retry after a pre-state fault."""
    current_boot = require_later_boot(matched_proof, linux_boot_uuid)
    first = oracle_root / "apple-control-alias-discriminator.jsonl"
    second = oracle_root / "apple-control-alias-discriminator-2.jsonl"
    if second.exists():
        raise AppleControlAliasDiscriminatorError(
            "alias discriminator recovery journal already exists"
        )
    if not first.exists():
        return AliasJournalPlan(first, None)
    try:
        records = journal.read(first)
    except (OSError, journal.JournalError) as error:
        raise AppleControlAliasDiscriminatorError(
            "prior alias discriminator journal is invalid"
        ) from error
    if [record.get("milestone") for record in records] != [
        "APPLE_CONTROL_ALIAS_BASELINE",
        "APPLE_CONTROL_ALIAS_OUTCOME_UNKNOWN",
    ]:
        raise AppleControlAliasDiscriminatorError(
            "prior alias discriminator is not a recoverable pre-state failure"
        )
    operation_id = _uuid(records[0].get("operation_id"), "prior alias operation ID")
    if records[1].get("operation_id") != operation_id:
        raise AppleControlAliasDiscriminatorError(
            "prior alias discriminator operation changed"
        )
    baseline = records[0].get("evidence")
    baseline_keys = {
        "operation_kind", "origin", "import_operation_id",
        "matched_keybag_operation_id", "mapping_generation",
        "linux_boot_uuid", "runtime_generation", "linux_uid", "apple_uid",
        "bag_uuid", "keybag_sha256", "special_alias", "mapping_enabled",
        "operation_scope",
    }
    if isinstance(baseline, dict) and "reconciled_prestate_operation_id" in baseline:
        baseline_keys.add("reconciled_prestate_operation_id")
    baseline = _exact(baseline, baseline_keys, "prior alias baseline")
    prior_boot = _uuid(baseline["linux_boot_uuid"], "prior alias Linux boot UUID")
    prior_runtime = _uuid(
        baseline["runtime_generation"], "prior alias runtime generation"
    )
    if (
        prior_boot == current_boot
        or baseline["operation_kind"] != "apple-control-alias-discriminator"
        or baseline["origin"] != keybag_discriminator.ORIGIN
        or baseline["import_operation_id"] != evidence.import_operation_id
        or baseline["matched_keybag_operation_id"] != matched_proof.operation_id
        or baseline["mapping_generation"] != evidence.mapping_generation
        or baseline["linux_uid"] != evidence.linux_uid
        or baseline["apple_uid"] != evidence.apple_uid
        or baseline["bag_uuid"] != evidence.bag_uuid
        or baseline["keybag_sha256"] != evidence.keybag_sha256
        or baseline["special_alias"] != -evidence.apple_uid
        or baseline["mapping_enabled"] is not False
        or baseline["operation_scope"]
        != "observe-load-verify-bind-read-unload-read"
        or baseline.get("reconciled_prestate_operation_id") is not None
    ):
        raise AppleControlAliasDiscriminatorError(
            "prior alias pre-state failure does not match current authority"
        )
    unknown = _exact(
        records[1].get("evidence"),
        {
            "runtime_generation", "stage", "handle_released",
            "retry_before_reboot_permitted",
        },
        "prior alias unknown outcome",
    )
    if unknown != {
        "runtime_generation": prior_runtime,
        "stage": "pre-state",
        "handle_released": False,
        "retry_before_reboot_permitted": False,
    }:
        raise AppleControlAliasDiscriminatorError(
            "prior alias failure crossed the mutation boundary"
        )
    return AliasJournalPlan(second, operation_id)


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
        raise AppleControlAliasDiscriminatorError(
            "alias discriminator journal cannot advance safely"
        ) from error


def _unknown(
    path: Path,
    operation_id: str,
    runtime: str,
    stage: str,
    *,
    handle_released: bool,
) -> None:
    try:
        _append(path, operation_id, "APPLE_CONTROL_ALIAS_OUTCOME_UNKNOWN", {
            "runtime_generation": runtime,
            "stage": stage,
            "handle_released": handle_released,
            "retry_before_reboot_permitted": False,
        })
    except BaseException:
        pass


def _observe(
    transport: AliasDiscriminatorTransport,
    special_alias: int,
) -> t2_user_readiness.AliasEvidence:
    value = transport.observe_alias(special_alias)
    if not isinstance(value, t2_user_readiness.AliasEvidence):
        raise AppleControlAliasDiscriminatorError(
            "alias observation returned the wrong type"
        )
    if value.present is False:
        if any(
            item is not None
            for item in (value.special_alias, value.bag_uuid, value.lock_state)
        ):
            raise AppleControlAliasDiscriminatorError(
                "absent alias observation is contradictory"
            )
        return value
    if (
        value.present is not True
        or value.special_alias != special_alias
        or _uuid(value.bag_uuid, "observed alias bag UUID") != value.bag_uuid
        or type(value.lock_state) is not int
        or not 0 <= value.lock_state <= 0xFFFF
    ):
        raise AppleControlAliasDiscriminatorError("alias observation is invalid")
    return value


def _matching_alias(
    observed: t2_user_readiness.AliasEvidence,
    bag_uuid: str,
) -> bool:
    return observed.present and observed.bag_uuid == bag_uuid


def run(
    *,
    journal_path: Path,
    evidence: keybag_discriminator.OracleEvidence,
    matched_proof: MatchedKeybagProof,
    linux_boot_uuid: str,
    transport: AliasDiscriminatorTransport,
    operation_id: str | None = None,
    reconciled_prestate_operation_id: str | None = None,
) -> AliasDiscriminatorResult:
    """Run the one allowed alias bind and its read-back sequence."""
    current_boot = require_later_boot(matched_proof, linux_boot_uuid)
    runtime = _uuid(transport.runtime_generation, "AKS runtime generation")
    if runtime == matched_proof.runtime_generation:
        raise AppleControlAliasDiscriminatorError(
            "AKS runtime generation did not change across the required reboot"
        )
    operation_id = _uuid(
        operation_id or str(uuid.uuid4()), "alias discriminator operation ID"
    )
    if reconciled_prestate_operation_id is not None:
        reconciled_prestate_operation_id = _uuid(
            reconciled_prestate_operation_id,
            "reconciled pre-state operation ID",
        )
    special_alias = -evidence.apple_uid
    _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_BASELINE", {
        "operation_kind": "apple-control-alias-discriminator",
        "origin": keybag_discriminator.ORIGIN,
        "import_operation_id": evidence.import_operation_id,
        "matched_keybag_operation_id": matched_proof.operation_id,
        "mapping_generation": evidence.mapping_generation,
        "linux_boot_uuid": current_boot,
        "runtime_generation": runtime,
        "linux_uid": evidence.linux_uid,
        "apple_uid": evidence.apple_uid,
        "bag_uuid": evidence.bag_uuid,
        "keybag_sha256": evidence.keybag_sha256,
        "special_alias": special_alias,
        "mapping_enabled": False,
        "operation_scope": "observe-load-verify-bind-read-unload-read",
        "reconciled_prestate_operation_id": reconciled_prestate_operation_id,
    }, exclusive=True)

    handle: int | None = None
    unload_attempted = False
    handle_released = False
    stage = "pre-state"
    try:
        before = _observe(transport, special_alias)
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_PRESTATE_OBSERVED", {
            "runtime_generation": runtime,
            "alias_absent": not before.present,
            "bag_uuid_matches": _matching_alias(before, evidence.bag_uuid),
            "state_observed": before.lock_state is not None,
        })
        if before.present:
            outcome = (
                "precondition-already-bound"
                if _matching_alias(before, evidence.bag_uuid)
                else "precondition-binding-mismatch"
            )
            _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_COMPLETE", {
                "runtime_generation": runtime,
                "outcome": outcome,
                "alias_bound_by_operation": False,
                "alias_persisted": False,
                "handle_released": False,
                "mapping_promoted": False,
            })
            return AliasDiscriminatorResult(
                outcome, False, False, False, False, False
            )

        stage = "load"
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_KEYBAG_LOAD_INTENT", {
            "runtime_generation": runtime,
            "keybag_sha256": evidence.keybag_sha256,
            "mutation_possible": True,
        })
        handle = transport.load_keybag(evidence.keybag_path)
        if type(handle) is not int or not 1 <= handle <= 0x7FFFFFFF:
            raise AppleControlAliasDiscriminatorError(
                "transport returned an invalid handle"
            )
        observed_uuid = _uuid(transport.bag_uuid(handle), "loaded keybag UUID")
        if observed_uuid != evidence.bag_uuid:
            raise AppleControlAliasDiscriminatorError(
                "loaded keybag no longer matches the protected oracle"
            )
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_HANDLE_OBSERVED", {
            "runtime_generation": runtime,
            "handle": handle,
            "double_read_equal": True,
            "bag_uuid_matches": True,
        })

        stage = "bind"
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_BIND_INTENT", {
            "runtime_generation": runtime,
            "handle": handle,
            "special_alias": special_alias,
            "mutation_possible": True,
        })
        bind_status: int | None = None
        bind_raised = False
        try:
            bind_status = transport.bind_alias(handle, special_alias)
            if type(bind_status) is not int or not -(1 << 31) <= bind_status < (1 << 32):
                raise AppleControlAliasDiscriminatorError(
                    "alias-bind returned an invalid status"
                )
        except BaseException:
            bind_raised = True
        after_bind = _observe(transport, special_alias)
        if not _matching_alias(after_bind, evidence.bag_uuid):
            raise AppleControlAliasDiscriminatorError(
                "alias bind was not reconciled by exact read-back"
            )
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_BOUND_OBSERVED", {
            "runtime_generation": runtime,
            "bag_uuid_matches": True,
            "state_observed": True,
            "command_status": bind_status,
            "command_raised": bind_raised,
        })

        stage = "unload"
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_KEYBAG_UNLOAD_INTENT", {
            "runtime_generation": runtime,
            "handle": handle,
            "mutation_possible": True,
        })
        unload_attempted = True
        status = transport.unload_keybag(handle)
        if type(status) is not int or status != 0:
            raise AppleControlAliasDiscriminatorError(
                "positive keybag handle release is ambiguous"
            )
        handle = None
        handle_released = True
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_HANDLE_RELEASED", {
            "runtime_generation": runtime,
            "command_status": 0,
        })

        stage = "persistence"
        after_unload = _observe(transport, special_alias)
        if not _matching_alias(after_unload, evidence.bag_uuid):
            raise AppleControlAliasDiscriminatorError(
                "alias did not persist after positive-handle unload"
            )
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_PERSISTED", {
            "runtime_generation": runtime,
            "bag_uuid_matches": True,
            "state_observed": True,
        })
        _append(journal_path, operation_id, "APPLE_CONTROL_ALIAS_COMPLETE", {
            "runtime_generation": runtime,
            "outcome": "bound-and-persisted",
            "alias_bound_by_operation": True,
            "alias_persisted": True,
            "handle_released": True,
            "mapping_promoted": False,
        })
        return AliasDiscriminatorResult(
            "bound-and-persisted", True, True, True, True, False
        )
    except BaseException as error:
        if handle is not None and not unload_attempted:
            try:
                _append(
                    journal_path,
                    operation_id,
                    "APPLE_CONTROL_ALIAS_KEYBAG_UNLOAD_INTENT",
                    {
                        "runtime_generation": runtime,
                        "handle": handle,
                        "mutation_possible": True,
                    },
                )
            except BaseException:
                pass
            unload_attempted = True
            try:
                status = transport.unload_keybag(handle)
                if type(status) is int and status == 0:
                    handle = None
                    handle_released = True
                    _append(
                        journal_path,
                        operation_id,
                        "APPLE_CONTROL_ALIAS_HANDLE_RELEASED",
                        {"runtime_generation": runtime, "command_status": 0},
                    )
            except BaseException:
                pass
        _unknown(
            journal_path,
            operation_id,
            runtime,
            stage,
            handle_released=handle_released,
        )
        raise AppleControlAliasDiscriminatorError(
            "Apple-control alias outcome is unknown; do not retry before reboot"
        ) from error
