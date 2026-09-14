# SPDX-License-Identifier: GPL-2.0-only
"""Write-ahead journal for the non-retryable half of D171 replacement.

This state machine covers the two non-retryable mutations: operation 0x49
deletion and operation 0x01 creation.  It intentionally has no transport.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import t2_mutation_journal as journal


class AKSReplacementJournalError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class AKSReplacementHistory:
    operation_id: str
    phase: str
    replacement_kind: str
    old_account_uuid: str
    new_account_uuid: str
    old_bag_uuid: str
    old_mapping_generation: str
    initial_linux_boot_uuid: str
    initial_connection_generation: str
    session: int
    preflight_digest: str
    activation_material_digest: str | None
    delete_request_digest: str | None
    reconciliation_linux_boot_uuid: str | None
    reconciliation_connection_generation: str | None
    direct_delete_reply_observed: bool | None
    create_request_digest: str | None
    live_handle: int | None
    live_bag_uuid: str | None
    direct_create_reply_observed: bool | None
    saved_keybag_digest: str | None
    saved_keybag_length: int | None
    bundle_generation: str | None
    mapping_generation: str | None
    handle_release_primary_state: str | None
    record_count: int
    head_hash: str


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AKSReplacementJournalError(f"{label} evidence has an invalid schema")
    return value


def _uuid(value: Any, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise AKSReplacementJournalError(f"{label} is not a UUID") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AKSReplacementJournalError(
            f"{label} is not a canonical nonzero UUID"
        )
    return value


def _digest(value: Any, label: str) -> str:
    try:
        journal.require_sha256(value, label)
    except journal.JournalError as error:
        raise AKSReplacementJournalError(str(error)) from error
    if value.lower() != value:
        raise AKSReplacementJournalError(f"{label} is not lowercase")
    return value


def _session(value: Any) -> int:
    if type(value) is not int or not 0 < value < (1 << 64):
        raise AKSReplacementJournalError("session is not a nonzero uint64")
    return value


def _positive_handle(value: Any) -> int:
    if type(value) is not int or not 0 < value <= 0x7FFFFFFF:
        raise AKSReplacementJournalError("live handle is not a positive int32")
    return value


def validate_history(records: list[dict[str, Any]]) -> AKSReplacementHistory:
    if not records:
        raise AKSReplacementJournalError("replacement journal is empty")
    operation_id = _uuid(records[0].get("operation_id"), "operation ID")
    phase = "new"
    replacement_kind = ""
    old_account_uuid = ""
    new_account_uuid = ""
    old_bag_uuid = ""
    old_mapping_generation = ""
    initial_linux_boot_uuid = ""
    initial_connection_generation = ""
    session = 0
    preflight_digest = ""
    activation_material_digest = None
    delete_request_digest = None
    reconciliation_linux_boot_uuid = None
    reconciliation_connection_generation = None
    direct_delete_reply_observed = None
    create_request_digest = None
    live_handle = None
    live_bag_uuid = None
    direct_create_reply_observed = None
    saved_keybag_digest = None
    saved_keybag_length = None
    bundle_generation = None
    mapping_generation = None
    handle_release_primary_state = None

    for record in records:
        if record.get("operation_id") != operation_id:
            raise AKSReplacementJournalError(
                "operation ID changed in replacement journal"
            )
        milestone = record.get("milestone")
        evidence = record.get("evidence")
        if milestone == "REPLACEMENT_PREPARED":
            if phase != "new":
                raise AKSReplacementJournalError(
                    "replacement preparation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "old_account_uuid",
                    "new_account_uuid",
                    "old_bag_uuid",
                    "old_mapping_generation",
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "preflight_digest",
                    "old_primary_matches",
                    "inventory_stable",
                },
                milestone,
            )
            old_account_uuid = _uuid(
                evidence["old_account_uuid"], "old account UUID"
            )
            new_account_uuid = _uuid(
                evidence["new_account_uuid"], "new account UUID"
            )
            if new_account_uuid == old_account_uuid:
                raise AKSReplacementJournalError(
                    "replacement account UUID was not changed"
                )
            old_bag_uuid = _uuid(evidence["old_bag_uuid"], "old bag UUID")
            old_mapping_generation = _digest(
                evidence["old_mapping_generation"], "old mapping generation"
            )
            initial_linux_boot_uuid = _uuid(
                evidence["linux_boot_uuid"], "initial Linux boot UUID"
            )
            initial_connection_generation = _uuid(
                evidence["connection_generation"], "initial connection generation"
            )
            session = _session(evidence["session"])
            preflight_digest = _digest(
                evidence["preflight_digest"], "replacement preflight digest"
            )
            if (
                evidence["old_primary_matches"] is not True
                or evidence["inventory_stable"] is not True
            ):
                raise AKSReplacementJournalError(
                    "old primary precondition does not stably match"
                )
            replacement_kind = "replace-present"
            phase = "prepared"
        elif milestone == "ABSENT_REPROVISION_PREPARED":
            if phase != "new":
                raise AKSReplacementJournalError(
                    "absence reprovision preparation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "old_account_uuid",
                    "new_account_uuid",
                    "old_bag_uuid",
                    "old_mapping_generation",
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "preflight_digest",
                    "primary_absent",
                    "inventory_stable",
                    "delete_required",
                },
                milestone,
            )
            old_account_uuid = _uuid(
                evidence["old_account_uuid"], "old account UUID"
            )
            new_account_uuid = _uuid(
                evidence["new_account_uuid"], "new account UUID"
            )
            if new_account_uuid == old_account_uuid:
                raise AKSReplacementJournalError(
                    "reprovisioned account UUID was not changed"
                )
            old_bag_uuid = _uuid(evidence["old_bag_uuid"], "old bag UUID")
            old_mapping_generation = _digest(
                evidence["old_mapping_generation"], "old mapping generation"
            )
            initial_linux_boot_uuid = _uuid(
                evidence["linux_boot_uuid"], "initial Linux boot UUID"
            )
            initial_connection_generation = _uuid(
                evidence["connection_generation"], "initial connection generation"
            )
            session = _session(evidence["session"])
            preflight_digest = _digest(
                evidence["preflight_digest"], "absence preflight digest"
            )
            if (
                evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or evidence["delete_required"] is not False
            ):
                raise AKSReplacementJournalError(
                    "absence reprovision precondition is not stable and exact"
                )
            replacement_kind = "reprovision-absent"
            phase = "absence-prepared"
        elif milestone == "ACTIVATION_MATERIAL_STAGED":
            if phase not in {"prepared", "absence-prepared"}:
                raise AKSReplacementJournalError(
                    "activation material staging is out of order"
                )
            prior_phase = phase
            evidence = _exact(
                evidence,
                {
                    "activation_material_digest",
                    "activation_material_length",
                    "bundle_generation",
                    "pending_directory_synced",
                },
                milestone,
            )
            activation_material_digest = _digest(
                evidence["activation_material_digest"],
                "activation material digest",
            )
            if (
                evidence["activation_material_length"] != 16
                or type(evidence["activation_material_length"]) is not int
                or evidence["bundle_generation"] != operation_id
                or evidence["pending_directory_synced"] is not True
            ):
                raise AKSReplacementJournalError(
                    "activation material staging evidence is invalid"
                )
            phase = (
                "activation-staged"
                if prior_phase == "prepared"
                else "absence-activation-staged"
            )
        elif milestone == "ABANDONED_BEFORE_DELETE":
            if phase not in {"prepared", "activation-staged"}:
                raise AKSReplacementJournalError(
                    "pre-delete abandonment is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "old_primary_matches",
                    "inventory_stable",
                    "no_delete_intent",
                },
                milestone,
            )
            abandonment_boot = _uuid(
                evidence["linux_boot_uuid"], "abandonment Linux boot UUID"
            )
            abandonment_connection = _uuid(
                evidence["connection_generation"],
                "abandonment connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            if (
                abandonment_boot == initial_linux_boot_uuid
                or abandonment_connection == initial_connection_generation
                or evidence["old_primary_matches"] is not True
                or evidence["inventory_stable"] is not True
                or evidence["no_delete_intent"] is not True
            ):
                raise AKSReplacementJournalError(
                    "pre-delete abandonment is not fresh and exact"
                )
            phase = "abandoned-before-delete"
        elif milestone == "ABANDONED_BEFORE_CREATE":
            if phase != "absence-prepared":
                raise AKSReplacementJournalError(
                    "pre-create abandonment is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_absent",
                    "inventory_stable",
                    "no_create_intent",
                },
                milestone,
            )
            abandonment_boot = _uuid(
                evidence["linux_boot_uuid"], "abandonment Linux boot UUID"
            )
            abandonment_connection = _uuid(
                evidence["connection_generation"],
                "abandonment connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            if (
                abandonment_boot == initial_linux_boot_uuid
                or abandonment_connection == initial_connection_generation
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or evidence["no_create_intent"] is not True
            ):
                raise AKSReplacementJournalError(
                    "pre-create abandonment is not fresh and exact"
                )
            phase = "abandoned-before-create"
        elif milestone == "ABSENCE_RECONCILED":
            if phase != "absence-activation-staged":
                raise AKSReplacementJournalError(
                    "absence reconciliation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_absent",
                    "inventory_stable",
                    "direct_observation",
                },
                milestone,
            )
            reconciliation_linux_boot_uuid = _uuid(
                evidence["linux_boot_uuid"], "reconciliation Linux boot UUID"
            )
            reconciliation_connection_generation = _uuid(
                evidence["connection_generation"],
                "reconciliation connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            same_owner = (
                reconciliation_linux_boot_uuid == initial_linux_boot_uuid
                and reconciliation_connection_generation
                == initial_connection_generation
            )
            fresh_owner = (
                reconciliation_linux_boot_uuid != initial_linux_boot_uuid
                and reconciliation_connection_generation
                != initial_connection_generation
            )
            if (
                evidence["session"] != session
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or type(evidence["direct_observation"]) is not bool
                or evidence["direct_observation"] is not same_owner
                or not (same_owner or fresh_owner)
            ):
                raise AKSReplacementJournalError(
                    "absence reconciliation is not exact"
                )
            phase = "absence-reconciled"
        elif milestone == "ABSENCE_RECONFIRMED":
            if phase != "absence-reconciled":
                raise AKSReplacementJournalError(
                    "absence reconfirmation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_absent",
                    "inventory_stable",
                },
                milestone,
            )
            reconfirmed_boot = _uuid(
                evidence["linux_boot_uuid"], "reconfirmed Linux boot UUID"
            )
            reconfirmed_connection = _uuid(
                evidence["connection_generation"],
                "reconfirmed connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            if (
                evidence["session"] != session
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or reconfirmed_boot == reconciliation_linux_boot_uuid
                or reconfirmed_connection == reconciliation_connection_generation
            ):
                raise AKSReplacementJournalError(
                    "absence reconfirmation is not fresh and exact"
                )
            reconciliation_linux_boot_uuid = reconfirmed_boot
            reconciliation_connection_generation = reconfirmed_connection
        elif milestone == "DELETE_INTENT":
            if phase != "activation-staged":
                raise AKSReplacementJournalError("delete intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "session",
                    "old_account_uuid",
                    "request_digest",
                    "single_dispatch",
                },
                milestone,
            )
            if (
                evidence["session"] != session
                or evidence["old_account_uuid"] != old_account_uuid
                or evidence["single_dispatch"] is not True
            ):
                raise AKSReplacementJournalError(
                    "delete intent is not bound to the prepared identity"
                )
            delete_request_digest = _digest(
                evidence["request_digest"], "delete request digest"
            )
            phase = "delete-intent"
        elif milestone == "DELETE_OUTCOME_UNKNOWN":
            if phase != "delete-intent":
                raise AKSReplacementJournalError(
                    "delete ambiguity marker is out of order"
                )
            evidence = _exact(
                evidence,
                {"mutation_possible", "descriptor_closed"},
                milestone,
            )
            if (
                evidence["mutation_possible"] is not True
                or evidence["descriptor_closed"] is not True
            ):
                raise AKSReplacementJournalError(
                    "delete ambiguity was not safely contained"
                )
            phase = "delete-outcome-unknown"
        elif milestone == "DELETE_SUCCEEDED":
            if phase != "delete-intent":
                raise AKSReplacementJournalError(
                    "delete success is out of order"
                )
            evidence = _exact(
                evidence, {"session", "old_account_uuid"}, milestone
            )
            if (
                evidence["session"] != session
                or evidence["old_account_uuid"] != old_account_uuid
            ):
                raise AKSReplacementJournalError(
                    "delete success is not bound to the prepared identity"
                )
            direct_delete_reply_observed = True
            phase = "delete-succeeded"
        elif milestone == "DELETE_RECONCILED":
            if phase not in {
                "delete-intent",
                "delete-succeeded",
                "delete-outcome-unknown",
            }:
                raise AKSReplacementJournalError(
                    "delete reconciliation is out of order"
                )
            prior_phase = phase
            ambiguous = prior_phase in {"delete-intent", "delete-outcome-unknown"}
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "old_account_uuid",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_absent",
                    "inventory_stable",
                    "direct_reply_observed",
                },
                milestone,
            )
            reconciliation_linux_boot_uuid = _uuid(
                evidence["linux_boot_uuid"], "reconciliation Linux boot UUID"
            )
            reconciliation_connection_generation = _uuid(
                evidence["connection_generation"],
                "reconciliation connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            direct_delete_reply_observed = evidence["direct_reply_observed"]
            if (
                evidence["session"] != session
                or evidence["old_account_uuid"] != old_account_uuid
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or type(evidence["direct_reply_observed"]) is not bool
                or evidence["direct_reply_observed"] is ambiguous
            ):
                raise AKSReplacementJournalError(
                    "delete reconciliation is not exact"
                )
            if ambiguous:
                if (
                    reconciliation_linux_boot_uuid == initial_linux_boot_uuid
                    or reconciliation_connection_generation
                    == initial_connection_generation
                ):
                    raise AKSReplacementJournalError(
                        "ambiguous delete was not reconciled on a fresh boot and connection"
                    )
            phase = "delete-reconciled"
        elif milestone == "DELETE_RECONFIRMED":
            if phase != "delete-reconciled":
                raise AKSReplacementJournalError(
                    "delete reconfirmation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_absent",
                    "inventory_stable",
                },
                milestone,
            )
            reconfirmed_boot = _uuid(
                evidence["linux_boot_uuid"], "reconfirmed Linux boot UUID"
            )
            reconfirmed_connection = _uuid(
                evidence["connection_generation"],
                "reconfirmed connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            if (
                evidence["session"] != session
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or reconfirmed_boot == reconciliation_linux_boot_uuid
                or reconfirmed_connection == reconciliation_connection_generation
            ):
                raise AKSReplacementJournalError(
                    "delete reconfirmation is not fresh and exact"
                )
            reconciliation_linux_boot_uuid = reconfirmed_boot
            reconciliation_connection_generation = reconfirmed_connection
        elif milestone == "DELETE_NOT_APPLIED":
            if phase not in {"delete-intent", "delete-outcome-unknown"}:
                raise AKSReplacementJournalError(
                    "not-applied deletion is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "old_account_uuid",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_present",
                    "inventory_stable",
                },
                milestone,
            )
            reconciliation_linux_boot_uuid = _uuid(
                evidence["linux_boot_uuid"], "reconciliation Linux boot UUID"
            )
            reconciliation_connection_generation = _uuid(
                evidence["connection_generation"],
                "reconciliation connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            if (
                evidence["old_account_uuid"] != old_account_uuid
                or evidence["primary_present"] is not True
                or evidence["inventory_stable"] is not True
                or reconciliation_linux_boot_uuid == initial_linux_boot_uuid
                or reconciliation_connection_generation
                == initial_connection_generation
            ):
                raise AKSReplacementJournalError(
                    "not-applied deletion reconciliation is not exact"
                )
            phase = "delete-not-applied"
        elif milestone == "CREATE_INTENT":
            if phase not in {"delete-reconciled", "absence-reconciled"}:
                raise AKSReplacementJournalError("create intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "new_account_uuid",
                    "activation_material_digest",
                    "request_digest",
                    "primary_absent",
                    "inventory_stable",
                    "single_dispatch",
                },
                milestone,
            )
            if (
                evidence["linux_boot_uuid"] != reconciliation_linux_boot_uuid
                or evidence["connection_generation"]
                != reconciliation_connection_generation
                or evidence["session"] != session
                or evidence["new_account_uuid"] != new_account_uuid
                or evidence["activation_material_digest"]
                != activation_material_digest
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or evidence["single_dispatch"] is not True
            ):
                raise AKSReplacementJournalError(
                    "create intent is not bound to reconciled primary absence"
                )
            create_request_digest = _digest(
                evidence["request_digest"], "create request digest"
            )
            phase = "create-intent"
        elif milestone == "CREATE_SUCCEEDED":
            if phase != "create-intent":
                raise AKSReplacementJournalError("create result is out of order")
            evidence = _exact(
                evidence,
                {"session", "live_handle", "kek_length"},
                milestone,
            )
            if evidence["session"] != session:
                raise AKSReplacementJournalError("create session changed")
            live_handle = _positive_handle(evidence["live_handle"])
            if (
                type(evidence["kek_length"]) is not int
                or not 0 <= evidence["kek_length"] <= 1024 * 1024
            ):
                raise AKSReplacementJournalError("create KEK length is invalid")
            direct_create_reply_observed = True
            phase = "identity-live"
        elif milestone == "CREATE_OUTCOME_UNKNOWN":
            if phase != "create-intent":
                raise AKSReplacementJournalError(
                    "create ambiguity marker is out of order"
                )
            evidence = _exact(
                evidence,
                {"mutation_possible", "descriptor_closed"},
                milestone,
            )
            if (
                evidence["mutation_possible"] is not True
                or evidence["descriptor_closed"] is not True
            ):
                raise AKSReplacementJournalError(
                    "create ambiguity was not safely contained"
                )
            phase = "create-outcome-unknown"
        elif milestone == "CREATE_NOT_APPLIED":
            if phase not in {"create-intent", "create-outcome-unknown"}:
                raise AKSReplacementJournalError(
                    "not-applied creation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "new_account_uuid",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_absent",
                    "inventory_stable",
                },
                milestone,
            )
            recovery_boot = _uuid(
                evidence["linux_boot_uuid"], "create recovery Linux boot UUID"
            )
            recovery_connection = _uuid(
                evidence["connection_generation"],
                "create recovery connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            if (
                evidence["new_account_uuid"] != new_account_uuid
                or evidence["primary_absent"] is not True
                or evidence["inventory_stable"] is not True
                or recovery_boot == reconciliation_linux_boot_uuid
                or recovery_connection == reconciliation_connection_generation
            ):
                raise AKSReplacementJournalError(
                    "not-applied creation reconciliation is not exact"
                )
            reconciliation_linux_boot_uuid = recovery_boot
            reconciliation_connection_generation = recovery_connection
            direct_create_reply_observed = False
            phase = "create-not-applied"
        elif milestone == "IDENTITY_RECOVERED":
            if phase not in {"create-intent", "create-outcome-unknown"}:
                raise AKSReplacementJournalError(
                    "identity recovery is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "new_account_uuid",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_matches",
                    "inventory_stable",
                    "open_request_digest",
                    "live_handle",
                    "bag_uuid",
                    "live_uuid_verified",
                },
                milestone,
            )
            recovery_boot = _uuid(
                evidence["linux_boot_uuid"], "identity recovery Linux boot UUID"
            )
            recovery_connection = _uuid(
                evidence["connection_generation"],
                "identity recovery connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            _digest(evidence["open_request_digest"], "identity-open request digest")
            if (
                evidence["session"] != session
                or evidence["new_account_uuid"] != new_account_uuid
                or evidence["primary_matches"] is not True
                or evidence["inventory_stable"] is not True
                or evidence["live_uuid_verified"] is not True
                or recovery_boot == reconciliation_linux_boot_uuid
                or recovery_connection == reconciliation_connection_generation
            ):
                raise AKSReplacementJournalError(
                    "identity recovery is not exact and fresh"
                )
            live_handle = _positive_handle(evidence["live_handle"])
            live_bag_uuid = _uuid(evidence["bag_uuid"], "recovered bag UUID")
            reconciliation_linux_boot_uuid = recovery_boot
            reconciliation_connection_generation = recovery_connection
            direct_create_reply_observed = False
            phase = "identity-live"
        elif milestone == "IDENTITY_REOPENED":
            if phase not in {
                "identity-live",
                "export-intent",
                "export-outcome-unknown",
                "export-succeeded",
                "live-uuid-verified",
            }:
                raise AKSReplacementJournalError(
                    "identity reopen is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "session",
                    "new_account_uuid",
                    "first_inventory_digest",
                    "second_inventory_digest",
                    "primary_matches",
                    "inventory_stable",
                    "open_request_digest",
                    "live_handle",
                    "bag_uuid",
                    "live_uuid_verified",
                },
                milestone,
            )
            recovery_boot = _uuid(
                evidence["linux_boot_uuid"], "identity reopen Linux boot UUID"
            )
            recovery_connection = _uuid(
                evidence["connection_generation"],
                "identity reopen connection generation",
            )
            _digest(evidence["first_inventory_digest"], "first inventory digest")
            _digest(evidence["second_inventory_digest"], "second inventory digest")
            _digest(evidence["open_request_digest"], "identity-open request digest")
            reopened_bag_uuid = _uuid(evidence["bag_uuid"], "reopened bag UUID")
            if (
                evidence["session"] != session
                or evidence["new_account_uuid"] != new_account_uuid
                or evidence["primary_matches"] is not True
                or evidence["inventory_stable"] is not True
                or evidence["live_uuid_verified"] is not True
                or recovery_boot == reconciliation_linux_boot_uuid
                or recovery_connection == reconciliation_connection_generation
                or (
                    live_bag_uuid is not None
                    and reopened_bag_uuid != live_bag_uuid
                )
            ):
                raise AKSReplacementJournalError(
                    "identity reopen is not exact and fresh"
                )
            live_handle = _positive_handle(evidence["live_handle"])
            live_bag_uuid = reopened_bag_uuid
            reconciliation_linux_boot_uuid = recovery_boot
            reconciliation_connection_generation = recovery_connection
            phase = "identity-live"
        elif milestone == "EXPORT_INTENT":
            if phase != "identity-live":
                raise AKSReplacementJournalError("export intent is out of order")
            evidence = _exact(
                evidence,
                {"session", "live_handle", "request_digest"},
                milestone,
            )
            if (
                evidence["session"] != session
                or evidence["live_handle"] != live_handle
            ):
                raise AKSReplacementJournalError(
                    "export intent is not bound to the live identity"
                )
            _digest(evidence["request_digest"], "export request digest")
            phase = "export-intent"
        elif milestone == "EXPORT_SUCCEEDED":
            if phase != "export-intent":
                raise AKSReplacementJournalError("export result is out of order")
            evidence = _exact(
                evidence,
                {"saved_keybag_digest", "saved_keybag_length"},
                milestone,
            )
            observed_digest = _digest(
                evidence["saved_keybag_digest"], "saved keybag digest"
            )
            observed_length = evidence["saved_keybag_length"]
            if (
                type(observed_length) is not int
                or not 0 < observed_length <= 1024 * 1024
                or (
                    saved_keybag_digest is not None
                    and observed_digest != saved_keybag_digest
                )
                or (
                    saved_keybag_length is not None
                    and observed_length != saved_keybag_length
                )
            ):
                raise AKSReplacementJournalError(
                    "exported keybag differs from prior evidence"
                )
            saved_keybag_digest = observed_digest
            saved_keybag_length = observed_length
            phase = "export-succeeded"
        elif milestone == "EXPORT_OUTCOME_UNKNOWN":
            if phase != "export-intent":
                raise AKSReplacementJournalError(
                    "export ambiguity marker is out of order"
                )
            evidence = _exact(evidence, {"descriptor_closed"}, milestone)
            if evidence["descriptor_closed"] is not True:
                raise AKSReplacementJournalError(
                    "export ambiguity was not safely contained"
                )
            phase = "export-outcome-unknown"
        elif milestone == "LIVE_UUID_VERIFIED":
            if phase != "export-succeeded":
                raise AKSReplacementJournalError(
                    "live UUID verification is out of order"
                )
            evidence = _exact(
                evidence,
                {"session", "live_handle", "bag_uuid", "uuid_verified"},
                milestone,
            )
            observed_bag_uuid = _uuid(evidence["bag_uuid"], "live bag UUID")
            if (
                evidence["session"] != session
                or evidence["live_handle"] != live_handle
                or evidence["uuid_verified"] is not True
                or (
                    live_bag_uuid is not None
                    and observed_bag_uuid != live_bag_uuid
                )
            ):
                raise AKSReplacementJournalError(
                    "live UUID is not bound to the exported identity"
                )
            live_bag_uuid = observed_bag_uuid
            phase = "live-uuid-verified"
        elif milestone == "BUNDLE_COMMITTED":
            if phase != "live-uuid-verified":
                raise AKSReplacementJournalError(
                    "activation bundle commit is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "bundle_generation",
                    "activation_material_digest",
                    "saved_keybag_digest",
                    "saved_keybag_length",
                    "manifest_digest",
                    "artifacts_verified",
                    "publication_reconciled",
                },
                milestone,
            )
            if (
                evidence["bundle_generation"] != operation_id
                or evidence["activation_material_digest"]
                != activation_material_digest
                or evidence["saved_keybag_digest"] != saved_keybag_digest
                or evidence["saved_keybag_length"] != saved_keybag_length
                or evidence["artifacts_verified"] is not True
                or type(evidence["publication_reconciled"]) is not bool
            ):
                raise AKSReplacementJournalError(
                    "activation bundle differs from transaction evidence"
                )
            _digest(evidence["manifest_digest"], "activation manifest digest")
            bundle_generation = operation_id
            phase = "bundle-committed"
        elif milestone == "MAPPING_COMMITTED":
            if phase != "bundle-committed":
                raise AKSReplacementJournalError(
                    "disabled mapping commit is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "mapping_generation",
                    "bundle_generation",
                    "bag_uuid",
                    "enabled",
                },
                milestone,
            )
            mapping_generation = _digest(
                evidence["mapping_generation"], "disabled mapping generation"
            )
            if (
                evidence["bundle_generation"] != bundle_generation
                or evidence["bag_uuid"] != live_bag_uuid
                or evidence["enabled"] is not False
            ):
                raise AKSReplacementJournalError(
                    "disabled mapping differs from activation bundle"
                )
            phase = "mapping-committed"
        elif milestone in {
            "HANDLE_UNLOADED",
            "HANDLE_RECONCILED_ABSENT",
            "HANDLE_RECONCILED_PRIMARY_ABSENT",
        }:
            if phase != "mapping-committed":
                raise AKSReplacementJournalError(
                    "handle release is out of order"
                )
            if milestone == "HANDLE_UNLOADED":
                evidence = _exact(
                    evidence,
                    {"session", "live_handle", "unload_succeeded"},
                    milestone,
                )
                if (
                    evidence["session"] != session
                    or evidence["live_handle"] != live_handle
                    or evidence["unload_succeeded"] is not True
                ):
                    raise AKSReplacementJournalError(
                        "unload is not bound to the owned handle"
                    )
                handle_release_primary_state = "same-boot-unloaded"
            elif milestone == "HANDLE_RECONCILED_ABSENT":
                evidence = _exact(
                    evidence,
                    {
                        "linux_boot_uuid",
                        "connection_generation",
                        "session",
                        "new_account_uuid",
                        "first_inventory_digest",
                        "second_inventory_digest",
                        "primary_matches",
                        "inventory_stable",
                        "no_live_holders",
                    },
                    milestone,
                )
                release_boot = _uuid(
                    evidence["linux_boot_uuid"], "release Linux boot UUID"
                )
                release_connection = _uuid(
                    evidence["connection_generation"],
                    "release connection generation",
                )
                _digest(
                    evidence["first_inventory_digest"],
                    "release first inventory digest",
                )
                _digest(
                    evidence["second_inventory_digest"],
                    "release second inventory digest",
                )
                if (
                    evidence["no_live_holders"] is not True
                    or evidence["session"] != session
                    or evidence["new_account_uuid"] != new_account_uuid
                    or evidence["primary_matches"] is not True
                    or evidence["inventory_stable"] is not True
                    or release_boot == reconciliation_linux_boot_uuid
                    or release_connection == reconciliation_connection_generation
                ):
                    raise AKSReplacementJournalError(
                        "handle absence was not proved on a fresh boot and connection"
                    )
                reconciliation_linux_boot_uuid = release_boot
                reconciliation_connection_generation = release_connection
                handle_release_primary_state = "matching"
            else:
                evidence = _exact(
                    evidence,
                    {
                        "linux_boot_uuid",
                        "connection_generation",
                        "session",
                        "new_account_uuid",
                        "first_inventory_digest",
                        "second_inventory_digest",
                        "primary_absent",
                        "inventory_stable",
                        "bundle_verified",
                        "mapping_verified",
                        "no_live_holders",
                    },
                    milestone,
                )
                release_boot = _uuid(
                    evidence["linux_boot_uuid"], "release Linux boot UUID"
                )
                release_connection = _uuid(
                    evidence["connection_generation"],
                    "release connection generation",
                )
                _digest(
                    evidence["first_inventory_digest"],
                    "release first inventory digest",
                )
                _digest(
                    evidence["second_inventory_digest"],
                    "release second inventory digest",
                )
                if (
                    evidence["no_live_holders"] is not True
                    or evidence["session"] != session
                    or evidence["new_account_uuid"] != new_account_uuid
                    or evidence["primary_absent"] is not True
                    or evidence["inventory_stable"] is not True
                    or evidence["bundle_verified"] is not True
                    or evidence["mapping_verified"] is not True
                    or release_boot == reconciliation_linux_boot_uuid
                    or release_connection == reconciliation_connection_generation
                ):
                    raise AKSReplacementJournalError(
                        "handle absence with unloaded primary was not proved exactly"
                    )
                reconciliation_linux_boot_uuid = release_boot
                reconciliation_connection_generation = release_connection
                handle_release_primary_state = "absent"
            phase = "complete"
        else:
            raise AKSReplacementJournalError(
                f"unsupported replacement milestone {milestone!r}"
            )

    head_hash = _digest(records[-1].get("record_hash"), "journal head hash")
    return AKSReplacementHistory(
        operation_id,
        phase,
        replacement_kind,
        old_account_uuid,
        new_account_uuid,
        old_bag_uuid,
        old_mapping_generation,
        initial_linux_boot_uuid,
        initial_connection_generation,
        session,
        preflight_digest,
        activation_material_digest,
        delete_request_digest,
        reconciliation_linux_boot_uuid,
        reconciliation_connection_generation,
        direct_delete_reply_observed,
        create_request_digest,
        live_handle,
        live_bag_uuid,
        direct_create_reply_observed,
        saved_keybag_digest,
        saved_keybag_length,
        bundle_generation,
        mapping_generation,
        handle_release_primary_state,
        len(records),
        head_hash,
    )


def create(
    path: Path,
    *,
    operation_id: str,
    old_account_uuid: str,
    new_account_uuid: str,
    old_bag_uuid: str,
    old_mapping_generation: str,
    linux_boot_uuid: str,
    connection_generation: str,
    session: int,
    preflight_digest: str,
    old_primary_matches: bool,
    inventory_stable: bool,
) -> AKSReplacementHistory:
    _uuid(operation_id, "operation ID")
    evidence = {
        "old_account_uuid": old_account_uuid,
        "new_account_uuid": new_account_uuid,
        "old_bag_uuid": old_bag_uuid,
        "old_mapping_generation": old_mapping_generation,
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": connection_generation,
        "session": session,
        "preflight_digest": preflight_digest,
        "old_primary_matches": old_primary_matches,
        "inventory_stable": inventory_stable,
    }
    unsigned = {
        "format_version": journal.FORMAT_VERSION,
        "operation_id": operation_id,
        "sequence": 0,
        "previous_hash": None,
        "milestone": "REPLACEMENT_PREPARED",
        "evidence": evidence,
    }
    validate_history([{**unsigned, "record_hash": journal.record_hash(unsigned)}])
    try:
        journal.append(
            path,
            operation_id,
            "REPLACEMENT_PREPARED",
            evidence,
            exclusive=True,
        )
    except journal.JournalError as error:
        raise AKSReplacementJournalError(str(error)) from error
    return read(path)


def create_absent_reprovision(
    path: Path,
    *,
    operation_id: str,
    old_account_uuid: str,
    new_account_uuid: str,
    old_bag_uuid: str,
    old_mapping_generation: str,
    linux_boot_uuid: str,
    connection_generation: str,
    session: int,
    preflight_digest: str,
    primary_absent: bool,
    inventory_stable: bool,
) -> AKSReplacementHistory:
    """Start a transaction when the stale mapped primary is absent."""

    _uuid(operation_id, "operation ID")
    evidence = {
        "old_account_uuid": old_account_uuid,
        "new_account_uuid": new_account_uuid,
        "old_bag_uuid": old_bag_uuid,
        "old_mapping_generation": old_mapping_generation,
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": connection_generation,
        "session": session,
        "preflight_digest": preflight_digest,
        "primary_absent": primary_absent,
        "inventory_stable": inventory_stable,
        "delete_required": False,
    }
    unsigned = {
        "format_version": journal.FORMAT_VERSION,
        "operation_id": operation_id,
        "sequence": 0,
        "previous_hash": None,
        "milestone": "ABSENT_REPROVISION_PREPARED",
        "evidence": evidence,
    }
    validate_history([{**unsigned, "record_hash": journal.record_hash(unsigned)}])
    try:
        journal.append(
            path,
            operation_id,
            "ABSENT_REPROVISION_PREPARED",
            evidence,
            exclusive=True,
        )
    except journal.JournalError as error:
        raise AKSReplacementJournalError(str(error)) from error
    return read(path)


def read(path: Path) -> AKSReplacementHistory:
    try:
        return validate_history(journal.read(path))
    except journal.JournalError as error:
        raise AKSReplacementJournalError(str(error)) from error


def append_checked(
    path: Path, operation_id: str, milestone: str, evidence: dict[str, Any]
) -> AKSReplacementHistory:
    try:
        records = journal.read(path)
    except journal.JournalError as error:
        raise AKSReplacementJournalError(str(error)) from error
    history = validate_history(records)
    if history.operation_id != operation_id:
        raise AKSReplacementJournalError(
            "operation ID differs from replacement journal"
        )
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
        raise AKSReplacementJournalError(str(error)) from error
    return read(path)
