# SPDX-License-Identifier: GPL-2.0-only
"""Bind immutable Linux-native account proof to the mutable identity set."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

import t2_enrollment_journal
import t2_mutation_journal
import t2_mutation_registry
import t2_user_authority


class NativeMutationAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeMutationAuthority:
    reference: str
    sha256: str


def _completed_heads(
    root: Path,
    *,
    excluded_operation_id: str | None,
    apple_user_id: int,
    account_uuid: str,
    bag_uuid: str,
    mapping_generation: str,
) -> list[dict[str, str]]:
    try:
        entries = t2_mutation_registry.scan(root)
        paths = sorted(root.iterdir(), key=lambda item: item.name)
    except (OSError, t2_mutation_registry.MutationRegistryError) as error:
        raise NativeMutationAuthorityError(
            "native mutation history is unavailable"
        ) from error
    if len(entries) != len(paths):
        raise NativeMutationAuthorityError("native mutation history changed")
    found_excluded = False
    heads: list[dict[str, str]] = []
    for path, entry in zip(paths, entries, strict=True):
        try:
            records = t2_mutation_journal.read(path)
        except t2_mutation_journal.JournalError as error:
            raise NativeMutationAuthorityError(
                "native mutation history is invalid"
            ) from error
        operation_id = records[0].get("operation_id") if records else None
        evidence = records[0].get("evidence") if records else None
        # Enrollment, rename, and native single-delete journals wrap the
        # shared biometric baseline under ``evidence.baseline``.  External
        # deletion reconciliation is deliberately a host-only projection and
        # its validated baseline is the evidence object itself.  Its mapping
        # generation already commits the complete account/bag mapping, so the
        # Apple user plus that generation is the immutable authority binding
        # available for this journal kind.
        external_delete = entry.kind == "reconcile-external-delete"
        baseline = (
            evidence
            if external_delete and isinstance(evidence, dict)
            else evidence.get("baseline")
            if isinstance(evidence, dict)
            else None
        )
        if operation_id == excluded_operation_id:
            if found_excluded or entry.kind != "enroll":
                raise NativeMutationAuthorityError(
                    "excluded addition journal is invalid"
                )
            found_excluded = True
            continue
        if entry.blocks_new_mutation:
            raise NativeMutationAuthorityError(
                "another biometric mutation is unfinished"
            )
        if (
            not isinstance(baseline, dict)
            or baseline.get("apple_uid") != apple_user_id
            or baseline.get("mapping_generation") != mapping_generation
            or (
                not external_delete
                and (
                    baseline.get("account_uuid") != account_uuid
                    or baseline.get("bag_uuid") != bag_uuid
                )
            )
        ):
            raise NativeMutationAuthorityError(
                "completed mutation belongs to another native authority"
            )
        heads.append(
            {
                "kind": entry.kind,
                "operation_id": operation_id,
                "phase": entry.phase,
                "head_hash": records[-1]["record_hash"],
            }
        )
    if excluded_operation_id is not None and not found_excluded:
        raise NativeMutationAuthorityError("pending addition journal is absent")
    return heads


def from_baseline(
    baseline: dict[str, Any],
    authority_history: t2_enrollment_journal.EnrollmentHistory,
    authority: t2_user_authority.RuntimeUserAuthority,
    *,
    mutation_root: Path,
    excluded_operation_id: str | None = None,
) -> NativeMutationAuthority:
    """Digest the exact current Catacomb and all prior completed mutations."""

    try:
        t2_mutation_journal.validate_baseline(baseline)
    except t2_mutation_journal.JournalError as error:
        raise NativeMutationAuthorityError(
            "current native baseline is invalid"
        ) from error
    selected = authority.selected
    if (
        authority.origin != "linux-native-e4"
        or authority_history.operation_id != authority.enrollment_journal.stem
        or authority_history.phase
        is not t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        or baseline["apple_uid"] != selected.apple_uid
        or baseline["account_uuid"] != selected.account_uuid
        or baseline["bag_uuid"] != selected.bag_uuid
        or baseline["mapping_generation"] != authority.mapping_set.generation
    ):
        raise NativeMutationAuthorityError(
            "immutable native account authority changed"
        )
    heads = _completed_heads(
        mutation_root,
        excluded_operation_id=excluded_operation_id,
        apple_user_id=selected.apple_uid,
        account_uuid=selected.account_uuid,
        bag_uuid=selected.bag_uuid,
        mapping_generation=authority.mapping_set.generation,
    )
    document = {
        "schema_version": 1,
        "account_authority": {
            "operation_id": authority_history.operation_id,
            "head_hash": authority_history.head_hash,
        },
        "apple_uid": selected.apple_uid,
        "account_uuid": selected.account_uuid,
        "bag_uuid": selected.bag_uuid,
        "mapping_generation": authority.mapping_set.generation,
        "identity_records": baseline["identity_records"],
        "host_components": baseline["host_components"],
        "master_enrollment_count": baseline["master_enrollment_count"],
        "sep_catacomb": baseline["sep_catacomb"],
        "completed_mutations": heads,
    }
    try:
        digest = hashlib.sha256(t2_mutation_journal.canonical(document)).hexdigest()
    except t2_mutation_journal.JournalError as error:
        raise NativeMutationAuthorityError(
            "current native authority cannot be encoded"
        ) from error
    return NativeMutationAuthority(
        "linux-native-current:" + authority_history.operation_id,
        digest,
    )
