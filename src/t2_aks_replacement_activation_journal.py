# SPDX-License-Identifier: GPL-2.0-only
"""Crash-complete journal for fresh-owner replacement activation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import t2_mutation_journal as journal


class AKSReplacementActivationJournalError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class AKSReplacementActivationHistory:
    operation_id: str
    phase: str
    baseline: dict[str, Any]
    attempt_number: int
    attempt_linux_boot_uuid: str | None
    attempt_runtime_generation: str | None
    temporary_handle: int | None
    enabled_mapping_generation: str | None
    record_count: int
    head_hash: str


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AKSReplacementActivationJournalError(
            f"{label} evidence has an invalid schema"
        )
    return value


def _uuid(value: Any, label: str) -> str:
    try:
        journal.require_uuid(value, label)
    except journal.JournalError as error:
        raise AKSReplacementActivationJournalError(str(error)) from error
    if value.lower() != value:
        raise AKSReplacementActivationJournalError(f"{label} is not lowercase")
    return value


def _digest(value: Any, label: str) -> str:
    try:
        journal.require_sha256(value, label)
    except journal.JournalError as error:
        raise AKSReplacementActivationJournalError(str(error)) from error
    if value.lower() != value:
        raise AKSReplacementActivationJournalError(f"{label} is not lowercase")
    return value


def _uint(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value < (1 << 32):
        raise AKSReplacementActivationJournalError(
            f"{label} is not a bounded integer"
        )
    return value


def _status(value: Any, label: str) -> int:
    if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
        raise AKSReplacementActivationJournalError(f"{label} is invalid")
    return value


def _baseline(value: Any) -> dict[str, Any]:
    result = _exact(
        value,
        {
            "replacement_head_hash",
            "replacement_initial_linux_boot_uuid",
            "replacement_final_linux_boot_uuid",
            "activation_linux_boot_uuid",
            "linux_account_generation",
            "target_linux_uid",
            "apple_uid",
            "account_uuid",
            "bag_uuid",
            "disabled_mapping_generation",
            "keybag_sha256",
            "activation_material_digest",
            "bundle_manifest_sha256",
            "special_alias",
            "initial_alias_state",
        },
        "replacement activation baseline",
    )
    for field in (
        "replacement_head_hash",
        "linux_account_generation",
        "disabled_mapping_generation",
        "keybag_sha256",
        "activation_material_digest",
        "bundle_manifest_sha256",
    ):
        _digest(result[field], field)
    for field in (
        "replacement_initial_linux_boot_uuid",
        "replacement_final_linux_boot_uuid",
        "activation_linux_boot_uuid",
        "account_uuid",
        "bag_uuid",
    ):
        _uuid(result[field], field)
    linux_uid = _uint(result["target_linux_uid"], "target Linux UID", minimum=1)
    del linux_uid
    apple_uid = _uint(result["apple_uid"], "Apple UID", minimum=10)
    if result["special_alias"] != -apple_uid:
        raise AKSReplacementActivationJournalError(
            "special alias is not derived from Apple UID"
        )
    if result["initial_alias_state"] not in {
        "alias-absent",
        "device-locked",
        "before-first-unlock",
    }:
        raise AKSReplacementActivationJournalError(
            "replacement activation baseline is not safely actionable"
        )
    return result


_ATTEMPT_PHASES = {
    "attempt-started",
    "load-intent",
    "loaded",
    "bind-intent",
    "bound",
    "configuration-intent",
    "configuration-resolved",
    "authorization-intent",
    "authorized",
    "unlock-intent",
    "unlocked",
    "unload-intent",
}
_RECOVERABLE_PHASES = _ATTEMPT_PHASES | {"interrupted", "unloaded"}


def validate_history(
    records: list[dict[str, Any]],
) -> AKSReplacementActivationHistory:
    if not records:
        raise AKSReplacementActivationJournalError(
            "replacement activation journal is empty"
        )
    operation_id = _uuid(records[0].get("operation_id"), "operation ID")
    phase = "new"
    baseline: dict[str, Any] = {}
    attempt_number = 0
    attempt_boot: str | None = None
    attempt_runtime: str | None = None
    attempt_boots: set[str] = set()
    temporary_handle: int | None = None
    retry_boot: str | None = None
    retry_runtime: str | None = None
    enabled_mapping_generation: str | None = None

    for record in records:
        if record.get("operation_id") != operation_id:
            raise AKSReplacementActivationJournalError(
                "operation ID changed in replacement activation journal"
            )
        milestone = record.get("milestone")
        if journal.is_repair_milestone(milestone):
            continue
        evidence = record.get("evidence")
        if milestone == "REPLACEMENT_ACTIVATION_BASELINE":
            if phase != "new":
                raise AKSReplacementActivationJournalError(
                    "replacement activation baseline is out of order"
                )
            outer = _exact(
                evidence,
                {"operation_kind", "baseline"},
                milestone,
            )
            if outer["operation_kind"] != "replacement-activation":
                raise AKSReplacementActivationJournalError(
                    "journal is not replacement activation"
                )
            baseline = _baseline(outer["baseline"])
            phase = "baseline"
            continue

        if milestone == "REPLACEMENT_ACTIVATION_ATTEMPT_STARTED":
            if phase not in {"baseline", "retry-authorized"}:
                raise AKSReplacementActivationJournalError(
                    "activation attempt is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "attempt_number",
                    "linux_boot_uuid",
                    "runtime_generation",
                    "mutation_possible",
                },
                milestone,
            )
            number = _uint(evidence["attempt_number"], "attempt number", minimum=1)
            boot = _uuid(evidence["linux_boot_uuid"], "attempt Linux boot UUID")
            runtime = _uuid(evidence["runtime_generation"], "attempt runtime generation")
            if (
                number != attempt_number + 1
                or boot in attempt_boots
                or evidence["mutation_possible"] is not False
                or (
                    phase == "baseline"
                    and boot != baseline["activation_linux_boot_uuid"]
                )
                or (
                    phase == "retry-authorized"
                    and (boot != retry_boot or runtime != retry_runtime)
                )
            ):
                raise AKSReplacementActivationJournalError(
                    "activation attempt authority is inconsistent"
                )
            attempt_number = number
            attempt_boot = boot
            attempt_runtime = runtime
            attempt_boots.add(boot)
            retry_boot = None
            retry_runtime = None
            temporary_handle = None
            phase = "attempt-started"
            continue

        if milestone == "REPLACEMENT_KEYBAG_LOAD_INTENT":
            expected = "attempt-started"
            fields = {"attempt_number", "keybag_sha256", "mutation_possible"}
            next_phase = "load-intent"
        elif milestone == "REPLACEMENT_KEYBAG_LOADED":
            expected = "load-intent"
            fields = {
                "attempt_number",
                "handle",
                "bag_uuid_matches",
                "command_status",
            }
            next_phase = "loaded"
        elif milestone == "REPLACEMENT_ALIAS_BIND_INTENT":
            expected = "loaded"
            fields = {
                "attempt_number",
                "handle",
                "special_alias",
                "mutation_possible",
            }
            next_phase = "bind-intent"
        elif milestone == "REPLACEMENT_ALIAS_BOUND":
            expected = "bind-intent"
            fields = {
                "attempt_number",
                "special_alias",
                "bag_uuid_matches",
                "alias_state",
                "command_status",
            }
            next_phase = "bound"
        elif milestone == "REPLACEMENT_ALIAS_CONFIGURATION_INTENT":
            expected = "bound"
            fields = {"attempt_number", "special_alias", "mutation_possible"}
            next_phase = "configuration-intent"
        elif milestone == "REPLACEMENT_ALIAS_CONFIGURATION_RESOLVED":
            expected = "configuration-intent"
            fields = {"attempt_number", "special_alias", "command_status"}
            next_phase = "configuration-resolved"
        elif milestone == "REPLACEMENT_IDENTITY_AUTHORIZATION_INTENT":
            expected = "configuration-resolved"
            fields = {
                "attempt_number",
                "activation_material_digest",
                "mutation_possible",
            }
            next_phase = "authorization-intent"
        elif milestone == "REPLACEMENT_IDENTITY_AUTHORIZED":
            expected = "authorization-intent"
            fields = {
                "attempt_number",
                "initial_requirement_type",
                "initial_policy_satisfied",
                "final_policy_satisfied",
                "command_status",
            }
            next_phase = "authorized"
        elif milestone == "REPLACEMENT_ALIAS_UNLOCK_INTENT":
            expected = "authorized"
            fields = {"attempt_number", "special_alias", "mutation_possible"}
            next_phase = "unlock-intent"
        elif milestone == "REPLACEMENT_ALIAS_UNLOCKED":
            expected = "unlock-intent"
            fields = {
                "attempt_number",
                "special_alias",
                "bag_uuid_matches",
                "alias_state",
                "command_status",
            }
            next_phase = "unlocked"
        elif milestone == "REPLACEMENT_KEYBAG_UNLOAD_INTENT":
            expected = "unlocked"
            fields = {"attempt_number", "handle", "mutation_possible"}
            next_phase = "unload-intent"
        elif milestone == "REPLACEMENT_KEYBAG_UNLOADED":
            expected = "unload-intent"
            fields = {"attempt_number", "handle", "command_status"}
            next_phase = "unloaded"
        else:
            expected = ""
            fields = set()
            next_phase = ""

        if expected:
            if phase != expected:
                raise AKSReplacementActivationJournalError(
                    f"{milestone} is out of order"
                )
            evidence = _exact(evidence, fields, milestone)
            if evidence["attempt_number"] != attempt_number:
                raise AKSReplacementActivationJournalError(
                    "activation record has the wrong attempt number"
                )
            if "mutation_possible" in evidence and evidence["mutation_possible"] is not True:
                raise AKSReplacementActivationJournalError(
                    "activation intent does not declare mutation"
                )
            if "special_alias" in evidence and evidence["special_alias"] != baseline["special_alias"]:
                raise AKSReplacementActivationJournalError(
                    "activation alias changed"
                )
            if "keybag_sha256" in evidence and evidence["keybag_sha256"] != baseline["keybag_sha256"]:
                raise AKSReplacementActivationJournalError(
                    "activation keybag changed"
                )
            if "activation_material_digest" in evidence and evidence["activation_material_digest"] != baseline["activation_material_digest"]:
                raise AKSReplacementActivationJournalError(
                    "activation material changed"
                )
            if "handle" in evidence:
                handle = _uint(evidence["handle"], "temporary handle", minimum=1)
                if temporary_handle is None:
                    temporary_handle = handle
                elif handle != temporary_handle:
                    raise AKSReplacementActivationJournalError(
                        "temporary handle changed"
                    )
            if "bag_uuid_matches" in evidence and evidence["bag_uuid_matches"] is not True:
                raise AKSReplacementActivationJournalError(
                    "activation bag UUID did not match"
                )
            if "alias_state" in evidence and evidence["alias_state"] not in {
                "device-locked",
                "before-first-unlock",
                "ready",
            }:
                raise AKSReplacementActivationJournalError(
                    "activation alias state is invalid"
                )
            if "command_status" in evidence and _status(evidence["command_status"], "command status") != 0:
                raise AKSReplacementActivationJournalError(
                    "activation command did not succeed"
                )
            if milestone == "REPLACEMENT_IDENTITY_AUTHORIZED" and (
                evidence["initial_requirement_type"] != 1
                or evidence["initial_policy_satisfied"] is not False
                or evidence["final_policy_satisfied"] is not True
            ):
                raise AKSReplacementActivationJournalError(
                    "identity authorization policy evidence is invalid"
                )
            if milestone == "REPLACEMENT_ALIAS_UNLOCKED" and evidence["alias_state"] != "ready":
                raise AKSReplacementActivationJournalError(
                    "alias did not become ready"
                )
            phase = next_phase
            continue

        if milestone == "REPLACEMENT_ACTIVATION_ATTEMPT_INTERRUPTED":
            if phase not in _ATTEMPT_PHASES:
                raise AKSReplacementActivationJournalError(
                    "activation interruption is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "attempt_number",
                    "from_phase",
                    "stage",
                    "reason",
                    "cleanup_attempted",
                    "cleanup_succeeded",
                    "mutation_possible",
                },
                milestone,
            )
            if (
                evidence["attempt_number"] != attempt_number
                or evidence["from_phase"] != phase
                or not isinstance(evidence["stage"], str)
                or not evidence["stage"]
                or not isinstance(evidence["reason"], str)
                or not evidence["reason"]
                or type(evidence["cleanup_attempted"]) is not bool
                or type(evidence["cleanup_succeeded"]) is not bool
                or (evidence["cleanup_succeeded"] and not evidence["cleanup_attempted"])
                or evidence["mutation_possible"] is not True
            ):
                raise AKSReplacementActivationJournalError(
                    "activation interruption evidence is invalid"
                )
            phase = "interrupted"
            continue

        if milestone == "REPLACEMENT_ACTIVATION_RETRY_AUTHORIZED":
            if phase not in _RECOVERABLE_PHASES:
                raise AKSReplacementActivationJournalError(
                    "activation retry is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "previous_attempt_number",
                    "linux_boot_uuid",
                    "runtime_generation",
                    "alias_state",
                    "alias_present",
                    "bag_uuid_matches",
                    "mutation_performed",
                },
                milestone,
            )
            boot = _uuid(evidence["linux_boot_uuid"], "retry Linux boot UUID")
            runtime = _uuid(evidence["runtime_generation"], "retry runtime generation")
            state = evidence["alias_state"]
            present = evidence["alias_present"]
            matches = evidence["bag_uuid_matches"]
            if (
                evidence["previous_attempt_number"] != attempt_number
                or boot in attempt_boots
                or boot
                in {
                    baseline["replacement_initial_linux_boot_uuid"],
                    baseline["replacement_final_linux_boot_uuid"],
                }
                or state not in {"alias-absent", "device-locked", "before-first-unlock"}
                or type(present) is not bool
                or type(matches) is not bool
                or present != (state != "alias-absent")
                or matches != present
                or evidence["mutation_performed"] is not False
            ):
                raise AKSReplacementActivationJournalError(
                    "activation retry evidence is invalid"
                )
            retry_boot = boot
            retry_runtime = runtime
            phase = "retry-authorized"
            continue

        if milestone == "REPLACEMENT_ACTIVATION_INDEPENDENT_READY":
            if phase not in _RECOVERABLE_PHASES:
                raise AKSReplacementActivationJournalError(
                    "independent activation proof is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "attempt_number",
                    "linux_boot_uuid",
                    "runtime_generation",
                    "source",
                    "independent_owner",
                    "alias_state",
                    "bag_uuid_matches",
                    "mutation_performed",
                },
                milestone,
            )
            proof_boot = _uuid(evidence["linux_boot_uuid"], "proof Linux boot UUID")
            _uuid(evidence["runtime_generation"], "proof runtime generation")
            source = evidence["source"]
            if (
                evidence["attempt_number"] != attempt_number
                or source not in {"fresh-owner", "different-boot-recovery"}
                or evidence["independent_owner"] is not True
                or evidence["alias_state"] != "ready"
                or evidence["bag_uuid_matches"] is not True
                or evidence["mutation_performed"] is not False
                or (source == "fresh-owner" and (phase != "unloaded" or proof_boot != attempt_boot))
                or (source == "different-boot-recovery" and proof_boot in attempt_boots)
            ):
                raise AKSReplacementActivationJournalError(
                    "independent activation proof is invalid"
                )
            phase = "independent-ready"
            continue

        if milestone == "REPLACEMENT_MAPPING_ENABLE_INTENT":
            if phase != "independent-ready":
                raise AKSReplacementActivationJournalError(
                    "mapping enable intent is out of order"
                )
            evidence = _exact(
                evidence,
                {"disabled_mapping_generation", "mutation_possible"},
                milestone,
            )
            if (
                evidence["disabled_mapping_generation"]
                != baseline["disabled_mapping_generation"]
                or evidence["mutation_possible"] is not True
            ):
                raise AKSReplacementActivationJournalError(
                    "mapping enable intent is not bound"
                )
            phase = "enable-intent"
            continue

        if milestone == "REPLACEMENT_ACTIVATION_COMPLETE":
            if phase != "enable-intent":
                raise AKSReplacementActivationJournalError(
                    "replacement activation completion is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "disabled_mapping_generation",
                    "enabled_mapping_generation",
                    "mapping_enabled",
                },
                milestone,
            )
            enabled_mapping_generation = _digest(
                evidence["enabled_mapping_generation"],
                "enabled mapping generation",
            )
            if (
                evidence["disabled_mapping_generation"]
                != baseline["disabled_mapping_generation"]
                or evidence["mapping_enabled"] is not True
            ):
                raise AKSReplacementActivationJournalError(
                    "replacement activation completion is not bound"
                )
            phase = "complete"
            continue

        if milestone == "REPLACEMENT_ACTIVATION_QUARANTINED":
            if phase not in _RECOVERABLE_PHASES:
                raise AKSReplacementActivationJournalError(
                    "replacement activation quarantine is out of order"
                )
            evidence = _exact(
                evidence,
                {"linux_boot_uuid", "runtime_generation", "reason", "mutation_performed"},
                milestone,
            )
            boot = _uuid(evidence["linux_boot_uuid"], "quarantine Linux boot UUID")
            _uuid(evidence["runtime_generation"], "quarantine runtime generation")
            if (
                boot in attempt_boots
                or not isinstance(evidence["reason"], str)
                or not evidence["reason"]
                or evidence["mutation_performed"] is not False
            ):
                raise AKSReplacementActivationJournalError(
                    "replacement activation quarantine evidence is invalid"
                )
            phase = "quarantined"
            continue

        raise AKSReplacementActivationJournalError(
            "unknown replacement activation journal milestone"
        )

    return AKSReplacementActivationHistory(
        operation_id,
        phase,
        baseline,
        attempt_number,
        attempt_boot,
        attempt_runtime,
        temporary_handle,
        enabled_mapping_generation,
        len(records),
        records[-1].get("record_hash", ""),
    )


def create(
    path: Path,
    operation_id: str,
    baseline: dict[str, Any],
) -> AKSReplacementActivationHistory:
    _uuid(operation_id, "operation ID")
    _baseline(baseline)
    journal.append(
        path,
        operation_id,
        "REPLACEMENT_ACTIVATION_BASELINE",
        {"operation_kind": "replacement-activation", "baseline": baseline},
        exclusive=True,
    )
    return read(path)


def read(path: Path) -> AKSReplacementActivationHistory:
    try:
        return validate_history(journal.read(path))
    except journal.JournalError as error:
        raise AKSReplacementActivationJournalError(str(error)) from error


def append_checked(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, Any],
) -> AKSReplacementActivationHistory:
    try:
        records = journal.read(path)
        current = validate_history(records)
        if current.operation_id != operation_id:
            raise AKSReplacementActivationJournalError(
                "operation ID does not match replacement activation journal"
            )
        validate_history(
            [
                *records,
                {
                    "operation_id": operation_id,
                    "milestone": milestone,
                    "evidence": evidence,
                    "record_hash": "0" * 64,
                },
            ]
        )
        journal.append(
            path,
            operation_id,
            milestone,
            evidence,
            expected_record_count=current.record_count,
            expected_previous_hash=current.head_hash,
        )
        return read(path)
    except journal.JournalError as error:
        raise AKSReplacementActivationJournalError(str(error)) from error
