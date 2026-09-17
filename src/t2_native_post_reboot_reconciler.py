# SPDX-License-Identifier: GPL-2.0-only
"""Dispatch one pending Linux-native post-reboot proof to its proven owner."""

from __future__ import annotations

import importlib.util
import json
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from collections.abc import Callable

import t2_post_reboot_reconciler
import t2_post_reboot_diagnostic
import t2_enrollment_journal
import t2_identity_delete_journal
import t2_identity_delete_batch_journal
import t2_mutation_journal
import t2_mutation_registry
import t2_user_authority
import t2_user_mapping


ROOT_UID = 0
SOURCE_ROOT = Path(__file__).resolve().parent
MUTATION_ROOT = t2_post_reboot_reconciler.MUTATION_ROOT
CATACOMB_ROOT = Path("/var/lib/t2-touchid/catacomb")


class NativePostRebootReconcilerError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativePostRebootReconcilerResult:
    state: str
    journal_updated: bool

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": self.state,
            "journal_updated": self.journal_updated,
            "fingerprint_mutation_performed": False,
            "identifiers_redacted": True,
        }


def _native_enrollment_module():
    path = SOURCE_ROOT / "t2-native-enroll.py"
    specification = importlib.util.spec_from_file_location(
        "t2_native_automatic_post_reboot_enrollment", path
    )
    if specification is None or specification.loader is None:
        raise NativePostRebootReconcilerError(
            "native enrollment verifier is unavailable"
        )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _verify_enrollment(trusted_linux_uid: int) -> dict[str, object]:
    try:
        native = _native_enrollment_module()
        configuration = native._configuration(
            trusted_linux_uid=trusted_linux_uid
        )
        mapping_set, selected, _history = native._load_provisioned_authority(
            configuration["linux_uid"], configuration["apple_uid"]
        )
        if mapping_set.schema_version != t2_user_mapping.SCHEMA_VERSION:
            raise NativePostRebootReconcilerError(
                "automatic native verification requires schema-2 activation material"
            )
    except Exception as error:
        raise t2_post_reboot_diagnostic.staged(
            "configuration-mapping-validation", error
        ) from error
    return native._run_post_reboot_verification(
        configuration=configuration,
        mapping_set=mapping_set,
        selected=selected,
        credential=bytearray(),
    )


def _recover_enrollment_publication(
    trusted_linux_uid: int, expected_operation_id: str
) -> dict[str, object]:
    try:
        native = _native_enrollment_module()
        configuration = native._configuration(
            trusted_linux_uid=trusted_linux_uid
        )
        mapping_set, selected, _history = native._load_provisioned_authority(
            configuration["linux_uid"], configuration["apple_uid"]
        )
        if mapping_set.schema_version != t2_user_mapping.SCHEMA_VERSION:
            raise NativePostRebootReconcilerError(
                "native authority recovery requires schema-2 activation material"
            )
    except Exception as error:
        raise t2_post_reboot_diagnostic.staged(
            "configuration-mapping-validation", error
        ) from error
    return native._run_post_reboot_publication_recovery(
        mapping_set=mapping_set,
        selected=selected,
        expected_operation_id=expected_operation_id,
    )


def _pending_native_candidate() -> object | None:
    """Select hardware work first, then one exact interrupted E4 publication."""

    pending = t2_post_reboot_reconciler._pending_candidate()
    if pending is not None:
        return pending
    try:
        registry = t2_mutation_registry.scan(MUTATION_ROOT)
        candidates = []
        interrupted_deletes = []
        active_delete_batches = []
        later_mutation = False
        for path in sorted(MUTATION_ROOT.iterdir(), key=lambda item: item.name):
            records = t2_mutation_journal.read(path)
            evidence = records[0].get("evidence") if records else None
            kind = (
                evidence.get("operation_kind")
                if isinstance(evidence, dict)
                else None
            )
            if kind == "delete-one":
                deletion = t2_identity_delete_journal.validate_history(records)
                if deletion.phase in {
                    t2_identity_delete_journal.IdentityDeletePhase.INTENT,
                    t2_identity_delete_journal.IdentityDeletePhase.DISPATCH_INTENT,
                    t2_identity_delete_journal.IdentityDeletePhase.COMMAND_OBSERVED,
                    t2_identity_delete_journal.IdentityDeletePhase.SEP_DELETED,
                    t2_identity_delete_journal.IdentityDeletePhase.PERSISTING,
                    t2_identity_delete_journal.IdentityDeletePhase.PERSISTENCE_READY,
                    t2_identity_delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
                }:
                    interrupted_deletes.append(
                        t2_post_reboot_reconciler.PendingMutation(
                            "delete-recovery", "identity-management", path, deletion
                        )
                    )
            if kind == "delete-batch":
                batch = t2_identity_delete_batch_journal.validate_history(records)
                if batch.phase in {
                    t2_identity_delete_batch_journal.IdentityDeleteBatchPhase.STARTED,
                    t2_identity_delete_batch_journal.IdentityDeleteBatchPhase.INTENT,
                }:
                    active_delete_batches.append((path, batch))
            if kind != "enroll":
                later_mutation = True
                continue
            history = t2_enrollment_journal.validate_history(records)
            if (
                history.phase
                is t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
            ):
                candidates.append((path, history))
            elif (
                history.baseline.get("baseline_version") != 2
                or history.phase
                not in {
                    t2_enrollment_journal.EnrollmentPhase.BASELINE,
                    t2_enrollment_journal.EnrollmentPhase.ABORTED_BEFORE_START,
                }
            ):
                later_mutation = True
        if interrupted_deletes:
            blockers = [entry for entry in registry if entry.blocks_new_mutation]
            deletion = interrupted_deletes[0].history
            batch_bound = (
                len(active_delete_batches) == 1
                and active_delete_batches[0][1].pending is not None
                and deletion.target_name_sha256
                == hashlib.sha256(
                    active_delete_batches[0][1].pending.encode("utf-8")
                ).hexdigest()
                and deletion.baseline["apple_uid"]
                == active_delete_batches[0][1].baseline["apple_uid"]
                and deletion.baseline["mapping_generation"]
                == active_delete_batches[0][1].baseline["mapping_generation"]
                and len(deletion.baseline["identity_records"])
                == len(active_delete_batches[0][1].finger_names)
                - len(active_delete_batches[0][1].completed)
            )
            valid_blockers = (
                len(blockers) == 1
                and blockers[0].kind == "delete-one"
                and not active_delete_batches
            ) or (
                len(blockers) == 2
                and {entry.kind for entry in blockers}
                == {"delete-one", "delete-batch"}
                and batch_bound
            )
            if len(interrupted_deletes) != 1 or not valid_blockers:
                raise NativePostRebootReconcilerError(
                    "interrupted deletion is not the sole pending mutation"
                )
            return interrupted_deletes[0]
        if active_delete_batches:
            blockers = [entry for entry in registry if entry.blocks_new_mutation]
            if (
                len(active_delete_batches) != 1
                or len(blockers) != 1
                or blockers[0].kind != "delete-batch"
            ):
                raise NativePostRebootReconcilerError(
                    "pending batch deletion is ambiguous"
                )
            path, batch = active_delete_batches[0]
            return t2_post_reboot_reconciler.PendingMutation(
                "delete-batch", "identity-management", path, batch
            )
        if not candidates:
            return None
        if len(candidates) != 1:
            raise NativePostRebootReconcilerError(
                "native E4 publication candidate is ambiguous"
            )
        path, history = candidates[0]
        baseline = history.baseline
        trusted_linux_uid = baseline.get("target_linux_uid")
        if (
            type(trusted_linux_uid) is not int
            or trusted_linux_uid <= 0
            or baseline.get("baseline_version") != 2
            or baseline.get("caller_linux_uid") != trusted_linux_uid
            or path.name != f"{history.operation_id}.jsonl"
        ):
            raise NativePostRebootReconcilerError(
                "native E4 publication candidate binding is invalid"
            )
        try:
            authority = t2_user_authority.load(trusted_linux_uid)
        except t2_user_authority.UserAuthorityError as error:
            manifest = (
                t2_user_authority.USERS_ROOT
                / str(trusted_linux_uid)
                / "authority.json"
            )
            if os.path.lexists(manifest):
                raise NativePostRebootReconcilerError(
                    "existing native runtime authority is invalid"
                ) from error
        else:
            if (
                authority.enrollment_journal.name == path.name
                and authority.mapping_set.generation
                == baseline.get("mapping_generation")
            ):
                return None
            raise NativePostRebootReconcilerError(
                "another native runtime authority is already published"
            )
        if later_mutation or any(entry.blocks_new_mutation for entry in registry):
            raise NativePostRebootReconcilerError(
                "native E4 publication is superseded or blocked"
            )
        return t2_post_reboot_reconciler.PendingMutation(
            "enroll-publication", "enroll", path, history
        )
    except NativePostRebootReconcilerError:
        raise
    except Exception as error:
        raise NativePostRebootReconcilerError(
            "native E4 publication inventory is invalid"
        ) from error


def _verify_management(
    kind: str,
    trusted_linux_uid: int,
    *,
    runner: Callable[..., object] = subprocess.run,
) -> dict[str, object]:
    command = [
        sys.executable,
        str(SOURCE_ROOT / "t2-touchid-manage.py"),
        (
            "recover-delete" if kind == "delete-recovery"
            else "verify-post-reboot" if kind == "rename"
            else "verify-delete-post-reboot"
        ),
    ]
    if kind == "delete-recovery":
        # This owner compares a fresh connection with the recorded intent and
        # repairs persistence. It never sends the deletion command again.
        command.append("--acknowledge-interrupted-delete-recovery")
    completed = runner(
        command,
        env={**os.environ, "SUDO_UID": str(trusted_linux_uid)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=80,
        check=False,
    )
    if getattr(completed, "returncode", None) != 0:
        error = NativePostRebootReconcilerError(
            f"native {kind} post-reboot owner stopped"
        )
        raise t2_post_reboot_diagnostic.staged(
            "native-owner",
            error,
            child_exit_status=getattr(completed, "returncode", None),
        ) from error
    stdout = getattr(completed, "stdout", None)
    try:
        document = json.loads(stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativePostRebootReconcilerError(
            f"native {kind} post-reboot owner returned malformed output"
        ) from error
    if not isinstance(document, dict):
        raise NativePostRebootReconcilerError(
            f"native {kind} post-reboot owner returned malformed output"
        )
    return document


def reconcile_external_deletion_if_needed(
    *, runner: Callable[..., object] = subprocess.run
) -> NativePostRebootReconcilerResult:
    """Reconcile an exact host-only external deletion before fprintd starts."""
    try:
        mapping_set = t2_user_mapping.load(Path("/var/lib/t2-touchid/users.json"))
        enabled = [item for item in mapping_set.mappings if item.enabled]
    except Exception as error:
        raise NativePostRebootReconcilerError(
            "native external reconciliation mapping is invalid"
        ) from error
    if len(enabled) != 1 or enabled[0].linux_uid <= 0:
        raise NativePostRebootReconcilerError(
            "native external reconciliation requires one enabled mapping"
        )
    user_root = t2_user_authority.USERS_ROOT / str(enabled[0].linux_uid)
    # A newly activated account has no enrollment authority or Catacomb yet.
    # External deletion reconciliation requires an earlier enrollment; making
    # it a prerequisite here prevents fprintd from accepting the first one.
    # Only the empty initial state is a no-op. Retained mutation/Catacomb
    # evidence or an existing (even dangling) manifest still needs validation.
    if (
        not os.path.lexists(user_root / "authority.json")
        and not any(MUTATION_ROOT.iterdir())
        and not any(CATACOMB_ROOT.iterdir())
        and not any(user_root.glob("*.jsonl"))
    ):
        return NativePostRebootReconcilerResult("no-pending-mutation", False)
    completed = runner(
        [
            sys.executable,
            str(SOURCE_ROOT / "t2-touchid-manage.py"),
            "reconcile-external-deletion-if-needed",
        ],
        env={**os.environ, "SUDO_UID": str(enabled[0].linux_uid)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=80,
        check=False,
    )
    if getattr(completed, "returncode", None) != 0:
        error = NativePostRebootReconcilerError(
            "native external deletion reconciliation stopped"
        )
        raise t2_post_reboot_diagnostic.staged(
            "external-deletion-reconciliation",
            error,
            child_exit_status=getattr(completed, "returncode", None),
            reason=t2_post_reboot_diagnostic.child_failure_reason(
                getattr(completed, "stderr", None)
            ),
        ) from error
    try:
        document = json.loads(getattr(completed, "stdout", None))
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativePostRebootReconcilerError(
            "native external reconciliation returned malformed output"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or document.get("identifiers_redacted") is not True
        or not (
            document.get("sep_mutation_performed") is False
            or (document.get("external_inventory_reconciled") is True
                and document.get("sep_mutation_performed") is True
                and document.get("fingerprint_mutation_performed") is False)
        )
        or not (
            document.get("external_deletion_reconciled") is True
            or document.get("external_deletion_reconciliation_needed") is False
        )
    ):
        raise NativePostRebootReconcilerError(
            "native external reconciliation returned an invalid proof"
        )
    if document.get("external_inventory_reconciled") is True:
        return NativePostRebootReconcilerResult("external-inventory-reconciled", True)
    changed = document.get("external_deletion_reconciled") is True
    return NativePostRebootReconcilerResult(
        "external-deletion-reconciled" if changed else "no-pending-mutation",
        changed,
    )


def run(
    *,
    candidate_loader: Callable[[], object] = _pending_native_candidate,
    enrollment_verifier: Callable[[int], dict[str, object]] = _verify_enrollment,
    publication_recoverer: Callable[[int, str], dict[str, object]] = (
        _recover_enrollment_publication
    ),
    management_runner: Callable[..., object] = subprocess.run,
) -> NativePostRebootReconcilerResult:
    """Close exactly one E3/management journal, or perform a no-op."""

    if os.geteuid() != ROOT_UID:
        raise NativePostRebootReconcilerError(
            "native post-reboot reconciliation requires root"
        )
    if not all(
        callable(item)
        for item in (
            candidate_loader,
            enrollment_verifier,
            publication_recoverer,
            management_runner,
        )
    ):
        raise NativePostRebootReconcilerError(
            "native post-reboot reconciliation dependency is unavailable"
        )
    try:
        candidate = candidate_loader()
    except Exception as error:
        raise t2_post_reboot_diagnostic.staged(
            "candidate-selection", error
        ) from error
    if candidate is None:
        return NativePostRebootReconcilerResult("no-pending-mutation", False)

    kind = getattr(candidate, "kind", None)
    baseline = getattr(getattr(candidate, "history", None), "baseline", None)
    trusted_linux_uid = (
        baseline.get("target_linux_uid") if isinstance(baseline, dict) else None
    )
    if (
        type(trusted_linux_uid) is not int
        or trusted_linux_uid <= 0
        or baseline.get("caller_linux_uid") != trusted_linux_uid
    ):
        raise NativePostRebootReconcilerError(
            "native post-reboot caller binding is invalid"
        )
    if kind == "delete-batch":
        return NativePostRebootReconcilerResult(
            "delete-batch-awaits-resume", False
        )
    if kind == "enroll":
        document = enrollment_verifier(trusted_linux_uid)
        expected = (
            document.get("enrollment_post_reboot_verified") is True
            and document.get("runtime_authority_published") is True
            and document.get("fingerprint_mutation_performed") is False
        )
        state = "enroll-post-reboot-verified"
        journal_updated = True
    elif kind == "enroll-publication":
        operation_id = getattr(getattr(candidate, "history", None), "operation_id", None)
        if not isinstance(operation_id, str):
            raise NativePostRebootReconcilerError(
                "native authority publication operation binding is invalid"
            )
        document = publication_recoverer(trusted_linux_uid, operation_id)
        expected = (
            document.get("enrollment_post_reboot_verified") is True
            and document.get("runtime_authority_published") is True
            and document.get("fingerprint_mutation_performed") is False
        )
        state = "enroll-authority-published"
        journal_updated = False
    elif kind in {"rename", "delete-one", "delete-recovery"}:
        document = _verify_management(
            kind, trusted_linux_uid, runner=management_runner
        )
        field = (
            "delete_recovery_succeeded" if kind == "delete-recovery"
            else "post_reboot_verified" if kind == "rename"
            else "delete_post_reboot_verified"
        )
        expected = document.get(field) is True
        if kind == "delete-recovery":
            expected = expected and document.get("post_reboot_verification_required") is False
        state = "delete-recovered" if kind == "delete-recovery" else f"{kind}-post-reboot-verified"
        journal_updated = True
    else:
        raise NativePostRebootReconcilerError(
            "native post-reboot mutation kind is unsupported"
        )
    if (
        not expected
        or document.get("identifiers_redacted") is not True
        or document.get("schema_version") != 1
    ):
        error = NativePostRebootReconcilerError(
            "native post-reboot owner did not return its terminal proof"
        )
        raise t2_post_reboot_diagnostic.staged(
            "terminal-proof-validation", error
        ) from error
    return NativePostRebootReconcilerResult(state, journal_updated)
