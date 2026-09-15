# SPDX-License-Identifier: GPL-2.0-only
"""Typed outer journal for an ordered, resumable delete-all operation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_fprint_projection
import t2_mutation_journal as journal


class IdentityDeleteBatchJournalError(journal.JournalError):
    pass


class IdentityDeleteBatchPhase(Enum):
    BASELINE = "baseline-reconciled"
    STARTED = "batch-started"
    INTENT = "delete-intent"
    RECONCILED = "reconciled"


@dataclass(frozen=True, repr=False)
class IdentityDeleteBatchHistory:
    operation_id: str
    phase: IdentityDeleteBatchPhase
    baseline: dict[str, Any]
    finger_names: tuple[str, ...]
    completed: tuple[str, ...]
    pending: str | None
    record_count: int
    head_hash: str


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IdentityDeleteBatchJournalError(
            f"{field} evidence does not match its schema"
        )
    return value


def _nonnegative(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise IdentityDeleteBatchJournalError(f"{field} is not non-negative")
    return value


def validate_history(records: list[dict[str, Any]]) -> IdentityDeleteBatchHistory:
    if not records:
        raise IdentityDeleteBatchJournalError("batch-delete journal is empty")
    first = records[0]
    if first.get("milestone") != "BASELINE_RECONCILED":
        raise IdentityDeleteBatchJournalError("batch-delete journal has no baseline")
    initial = _exact(
        first.get("evidence"), {"operation_kind", "baseline"}, "baseline"
    )
    if initial["operation_kind"] != "delete-batch":
        raise IdentityDeleteBatchJournalError("journal is not a batch deletion")
    baseline = initial["baseline"]
    try:
        journal.validate_baseline(baseline)
        journal.require_uuid(first.get("operation_id"), "operation ID")
    except journal.JournalError as error:
        raise IdentityDeleteBatchJournalError(str(error)) from error

    operation_id = first["operation_id"]
    phase = IdentityDeleteBatchPhase.BASELINE
    finger_names: tuple[str, ...] = ()
    completed: list[str] = []
    pending = None

    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise IdentityDeleteBatchJournalError(
                "operation ID changed inside batch-delete journal"
            )
        milestone = record.get("milestone")
        evidence = record.get("evidence")

        if milestone == "DELETE_BATCH_STARTED":
            if phase is not IdentityDeleteBatchPhase.BASELINE:
                raise IdentityDeleteBatchJournalError("batch start is out of order")
            evidence = _exact(
                evidence,
                {"finger_names", "identity_count", "identifiers_redacted"},
                milestone,
            )
            names = evidence["finger_names"]
            if (
                not isinstance(names, list)
                or not names
                or len(names) > 5
                or len(names) != len(set(names))
                or any(not t2_fprint_projection.is_finger_name(name) for name in names)
                or tuple(names)
                != tuple(
                    name for name in t2_fprint_projection.FINGER_NAMES if name in names
                )
                or evidence["identity_count"] != len(names)
                or len(baseline["identity_records"]) != len(names)
                or evidence["identifiers_redacted"] is not True
            ):
                raise IdentityDeleteBatchJournalError("batch start binding is invalid")
            finger_names = tuple(names)
            phase = IdentityDeleteBatchPhase.STARTED
            continue

        if milestone == "DELETE_BATCH_ITEM_INTENT":
            if phase is not IdentityDeleteBatchPhase.STARTED or pending is not None:
                raise IdentityDeleteBatchJournalError("batch item intent is out of order")
            evidence = _exact(evidence, {"finger_name", "ordinal"}, milestone)
            ordinal = _nonnegative(evidence["ordinal"], "batch item ordinal")
            if (
                ordinal != len(completed)
                or ordinal >= len(finger_names)
                or evidence["finger_name"] != finger_names[ordinal]
            ):
                raise IdentityDeleteBatchJournalError("batch item intent is misbound")
            pending = evidence["finger_name"]
            phase = IdentityDeleteBatchPhase.INTENT
            continue

        if milestone == "DELETE_BATCH_ITEM_RECONCILED":
            if phase is not IdentityDeleteBatchPhase.INTENT or pending is None:
                raise IdentityDeleteBatchJournalError(
                    "batch item reconciliation is out of order"
                )
            evidence = _exact(
                evidence,
                {"finger_name", "ordinal", "remaining_count"},
                milestone,
            )
            ordinal = _nonnegative(evidence["ordinal"], "batch item ordinal")
            remaining = _nonnegative(
                evidence["remaining_count"], "remaining identity count"
            )
            if (
                ordinal != len(completed)
                or evidence["finger_name"] != pending
                or remaining != len(finger_names) - ordinal - 1
            ):
                raise IdentityDeleteBatchJournalError(
                    "batch item reconciliation is misbound"
                )
            completed.append(pending)
            pending = None
            phase = IdentityDeleteBatchPhase.STARTED
            continue

        if milestone == "DELETE_BATCH_RECONCILED":
            if (
                phase is not IdentityDeleteBatchPhase.STARTED
                or pending is not None
                or tuple(completed) != finger_names
            ):
                raise IdentityDeleteBatchJournalError(
                    "batch reconciliation is out of order"
                )
            evidence = _exact(
                evidence,
                {"deleted_count", "identity_count", "identifiers_redacted"},
                milestone,
            )
            if (
                evidence["deleted_count"] != len(finger_names)
                or evidence["identity_count"] != 0
                or evidence["identifiers_redacted"] is not True
            ):
                raise IdentityDeleteBatchJournalError(
                    "batch reconciliation is misbound"
                )
            phase = IdentityDeleteBatchPhase.RECONCILED
            continue

        raise IdentityDeleteBatchJournalError(
            f"unsupported batch-delete milestone {milestone!r}"
        )

    return IdentityDeleteBatchHistory(
        operation_id,
        phase,
        baseline,
        finger_names,
        tuple(completed),
        pending,
        len(records),
        records[-1]["record_hash"],
    )


def read(path: Path) -> IdentityDeleteBatchHistory:
    try:
        return validate_history(journal.read(path))
    except journal.JournalError as error:
        if isinstance(error, IdentityDeleteBatchJournalError):
            raise
        raise IdentityDeleteBatchJournalError(str(error)) from error


def append_checked(
    path: Path,
    history: IdentityDeleteBatchHistory,
    milestone: str,
    evidence: dict[str, Any],
) -> IdentityDeleteBatchHistory:
    journal.reject_secrets(evidence)
    journal.append(
        path,
        history.operation_id,
        milestone,
        evidence,
        expected_record_count=history.record_count,
        expected_previous_hash=history.head_hash,
    )
    return read(path)
