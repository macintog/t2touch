#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guided transition of a legacy macOS-export install to oracle authority.

This module does not perform any hardware work of its own. It inspects the
on-disk compatibility proof chain and delegates each stage to the maintained
one-shot module that owns it, so that a pre-oracle ``macos-control-oracle``
installation can be brought back to a complete authority without hand-running
separate research tools across separate boots. The explicit recovery stage
binds and unlocks in one session after a pre-state-only unlock failure.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import t2_aks_transport
import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as alias_unlock
import t2_apple_control_alias_recovery as alias_recovery
import t2_apple_control_discriminator as keybag_discriminator
import t2_apple_control_import
import t2_linux_account


STATE_ROOT = keybag_discriminator.STATE_ROOT
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")

NEED_IMPORT = "needs-oracle-import"
IMPORT_INVALID = "oracle-import-invalid"
NEED_DISCRIMINATE = "needs-keybag-discriminator"
NEED_BIND = "needs-alias-binding"
NEED_RECONCILE = "needs-alias-reconciliation"
NEED_UNLOCK = "needs-alias-unlock"
UNLOCK_RECOVERY_REQUIRED = "alias-unlock-recovery-required"
COMPLETE = "complete"

_DISCRIMINATOR_JOURNAL = "apple-control-discriminator.jsonl"
_BIND_JOURNAL = "apple-control-alias-discriminator.jsonl"
_RECONCILIATION_JOURNAL = "apple-control-alias-reconciliation.jsonl"
_RECONCILIATION_STATE = "apple-control-alias-state.der"
_UNLOCK_JOURNAL = "apple-control-alias-unlock.jsonl"
_AMBIGUOUS_BIND_JOURNAL = "apple-control-alias-discriminator-2.jsonl"


class CompatibilityTransitionError(RuntimeError):
    pass


@dataclass(frozen=True)
class TransitionStatus:
    phase: str
    detail: str
    legacy_keybag_present: bool
    next_command: str | None

    def public_summary(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "detail": self.detail,
            "legacy_keybag_present": self.legacy_keybag_present,
            "next_command": self.next_command,
            "identifiers_redacted": True,
        }


def _oracle_root(state_root: Path) -> Path:
    return state_root / "oracle"


def _boot_id() -> str:
    return BOOT_ID.read_text(encoding="utf-8").strip()


def _evidence(state_root: Path, linux_uid: int) -> object:
    return keybag_discriminator.read_oracle_import(state_root, linux_uid)


def _discriminate_command(linux_user: str) -> str:
    return (
        "t2-touchid-migrate-compatibility discriminate "
        f"--linux-user {linux_user} --acknowledge-one-shot-sep-discriminator"
    )


def _import_command(linux_user: str) -> str:
    return (
        "t2-touchid-migrate-compatibility import "
        f"--linux-user {linux_user} --apple-uid <uid> "
        "--keybag-archive <keybags.tar.gz> --catacomb-archive <catacomb.tar.gz> "
        "--acknowledge-macos-control-oracle"
    )


def _bind_command(linux_user: str) -> str:
    return (
        "t2-touchid-migrate-compatibility bind "
        f"--linux-user {linux_user} --acknowledge-one-shot-sep-alias-binding"
    )


def _reconcile_command(linux_user: str) -> str:
    return (
        "t2-touchid-migrate-compatibility reconcile "
        f"--linux-user {linux_user} "
        "--acknowledge-one-shot-read-only-alias-reconciliation"
    )


def _unlock_command(linux_user: str) -> str:
    return (
        "t2-touchid-migrate-compatibility unlock "
        f"--linux-user {linux_user} --password-stdin "
        "--acknowledge-one-shot-password-alias-unlock"
    )


def inspect(
    *, linux_uid: int, linux_user: str, state_root: Path = STATE_ROOT
) -> TransitionStatus:
    """Return the current transition phase without touching the SEP.

    Phases are evaluated in the same order as ``load_compatibility`` so that
    the reported phase is exactly the first stage the authority is missing.
    """

    legacy_keybag_present = (state_root / "user.kb").is_file()
    if not (state_root / "users.json").is_file():
        return TransitionStatus(
            NEED_IMPORT,
            "no disabled oracle mapping is present for this install",
            legacy_keybag_present,
            _import_command(linux_user),
        )

    try:
        evidence = _evidence(state_root, linux_uid)
    except keybag_discriminator.AppleControlDiscriminatorError as error:
        return TransitionStatus(
            IMPORT_INVALID,
            f"oracle import is present but unusable: {error}",
            legacy_keybag_present,
            _import_command(linux_user),
        )

    oracle = _oracle_root(state_root)
    try:
        matched = alias_discriminator.read_matched_keybag_proof(
            oracle / _DISCRIMINATOR_JOURNAL, evidence
        )
    except alias_discriminator.AppleControlAliasDiscriminatorError as error:
        return TransitionStatus(
            NEED_DISCRIMINATE,
            f"keybag discriminator proof is missing: {error}",
            legacy_keybag_present,
            _discriminate_command(linux_user),
        )

    proof: alias_unlock.AliasUnlockAuthorityProof
    try:
        bind_proof = reconciliation.read_ambiguous_bind_proof(
            oracle, evidence, matched
        )
    except reconciliation.AppleControlAliasReconciliationError as ambiguous_error:
        try:
            bound = alias_discriminator.read_bound_alias_proof(
                oracle / _BIND_JOURNAL, evidence, matched
            )
        except alias_discriminator.AppleControlAliasDiscriminatorError:
            return TransitionStatus(
                NEED_BIND,
                f"alias binding proof is missing: {ambiguous_error}",
                legacy_keybag_present,
                _bind_command(linux_user),
            )
        if any(os.path.lexists(oracle / name) for name in (
            _AMBIGUOUS_BIND_JOURNAL,
            _RECONCILIATION_JOURNAL,
            _RECONCILIATION_STATE,
        )):
            return TransitionStatus(
                NEED_RECONCILE,
                "clean alias authority conflicts with reconciliation artifacts; "
                "preserve them and do not continue",
                legacy_keybag_present,
                None,
            )
        proof = bound
    else:
        try:
            proof = reconciliation.read_reconciled_alias_proof(
                oracle, evidence, bind_proof
            )
        except reconciliation.AppleControlAliasReconciliationError as error:
            return TransitionStatus(
                NEED_RECONCILE,
                f"alias reconciliation proof is missing: {error}",
                legacy_keybag_present,
                _reconcile_command(linux_user),
            )

    try:
        alias_unlock.read_completed_unlock_proof(
            oracle / _UNLOCK_JOURNAL, evidence, proof
        )
    except alias_unlock.AppleControlAliasUnlockError as error:
        if os.path.lexists(oracle / _UNLOCK_JOURNAL):
            if isinstance(proof, alias_discriminator.BoundAliasProof):
                try:
                    alias_recovery.read_completed_recovery(oracle, evidence, matched, proof)
                except alias_recovery.AliasRecoveryError:
                    try:
                        alias_recovery.read_completed_capacity_fix(
                            oracle, evidence, matched, proof
                        )
                    except alias_recovery.AliasRecoveryError:
                        try:
                            failed_recovery = alias_recovery.read_failed_recovery_for_capacity_fix(
                                oracle, evidence, matched, proof
                            )
                        except alias_recovery.AliasRecoveryError:
                            pass
                        else:
                            if not any(
                                os.path.lexists(oracle / name)
                                for name in alias_recovery.CAPACITY_ARTIFACTS
                            ):
                                if _boot_id() == failed_recovery.linux_boot_uuid:
                                    return TransitionStatus(
                                        UNLOCK_RECOVERY_REQUIRED,
                                        "exact response-capacity recovery failure; reboot "
                                        "before the one allowed capacity-fix continuation",
                                        legacy_keybag_present,
                                        None,
                                    )
                                return TransitionStatus(
                                    UNLOCK_RECOVERY_REQUIRED,
                                    "exact response-capacity recovery failure; one "
                                    "capacity-fix continuation is available on a later boot",
                                    legacy_keybag_present,
                                    "t2-touchid-migrate-compatibility recover-capacity-fix "
                                    f"--linux-user {linux_user} --password-prompt "
                                    "--acknowledge-one-shot-capacity-fix "
                                    "--acknowledge-known-predispatch-capacity-defect "
                                    "--acknowledge-research-mac-and-macos-recovery",
                                )
                    else:
                        return TransitionStatus(
                            COMPLETE,
                            "compatibility authority capacity-fix proof chain is complete",
                            legacy_keybag_present,
                            None,
                        )
                    try:
                        alias_recovery.read_failed_prestate_proof(
                            oracle, evidence, matched, proof
                        )
                    except alias_recovery.AliasRecoveryError:
                        pass
                    else:
                        if not any(os.path.lexists(oracle / name) for name in alias_recovery.ARTIFACTS):
                            return TransitionStatus(
                                UNLOCK_RECOVERY_REQUIRED,
                                "pre-state-only unlock failure; one journaled absent-alias "
                                "recovery is available on a later boot",
                                legacy_keybag_present,
                                "t2-touchid-migrate-compatibility recover "
                                f"--linux-user {linux_user} --password-prompt "
                                "--acknowledge-one-shot-alias-recovery "
                                "--acknowledge-research-mac-and-macos-recovery",
                            )
                else:
                    return TransitionStatus(
                        COMPLETE, "compatibility authority recovery proof chain is complete",
                        legacy_keybag_present, None,
                    )
            return TransitionStatus(
                UNLOCK_RECOVERY_REQUIRED,
                f"existing alias unlock journal is not a successful proof: {error}; "
                "preserve the journal; the one-shot unlock cannot be rerun",
                legacy_keybag_present,
                None,
            )
        return TransitionStatus(
            UNLOCK_RECOVERY_REQUIRED,
            f"alias unlock proof is missing: {error}; standalone unlock is disabled "
            "because operation 0x04 requires the bind session's active keybag handle",
            legacy_keybag_present,
            None,
        )

    return TransitionStatus(
        COMPLETE,
        "compatibility authority proof chain is complete",
        legacy_keybag_present,
        None,
    )


def import_state(
    *,
    keybag_archive: Path,
    catacomb_archive: Path,
    linux_uid: int,
    apple_uid: int,
    state_root: Path = STATE_ROOT,
) -> dict[str, object]:
    account = t2_linux_account.collect(linux_uid)
    _plan, summary = t2_apple_control_import.import_control_archives(
        keybag_archive=keybag_archive,
        catacomb_archive=catacomb_archive,
        linux_uid=linux_uid,
        linux_account_generation=account.generation,
        apple_uid=apple_uid,
        state_root=state_root,
    )
    return summary


def discriminate(
    *, linux_uid: int, state_root: Path = STATE_ROOT
) -> dict[str, object]:
    evidence = _evidence(state_root, linux_uid)
    journal_path = _oracle_root(state_root) / _DISCRIMINATOR_JOURNAL
    with t2_aks_transport.AKSActivationTransport() as transport:
        result = keybag_discriminator.run(
            journal_path=journal_path,
            evidence=evidence,
            linux_boot_uuid=_boot_id(),
            transport=transport,
        )
    return result.public_summary()


def bind(*, linux_uid: int, state_root: Path = STATE_ROOT) -> dict[str, object]:
    evidence = _evidence(state_root, linux_uid)
    oracle = _oracle_root(state_root)
    matched = alias_discriminator.read_matched_keybag_proof(
        oracle / _DISCRIMINATOR_JOURNAL, evidence
    )
    try:
        alias_discriminator.read_bound_alias_proof(
            oracle / _BIND_JOURNAL, evidence, matched
        )
    except alias_discriminator.AppleControlAliasDiscriminatorError:
        pass
    else:
        raise CompatibilityTransitionError("alias is already cleanly bound; run unlock")
    boot = _boot_id()
    alias_discriminator.require_later_boot(matched, boot)
    plan = alias_discriminator.select_alias_journal(oracle, evidence, matched, boot)
    with t2_aks_transport.AKSActivationTransport() as transport:
        result = alias_discriminator.run(
            journal_path=plan.path,
            evidence=evidence,
            matched_proof=matched,
            linux_boot_uuid=boot,
            transport=transport,
            reconciled_prestate_operation_id=plan.reconciled_prestate_operation_id,
        )
    return result.public_summary()


def reconcile(
    *, linux_uid: int, state_root: Path = STATE_ROOT
) -> dict[str, object]:
    evidence = _evidence(state_root, linux_uid)
    oracle = _oracle_root(state_root)
    matched = alias_discriminator.read_matched_keybag_proof(
        oracle / _DISCRIMINATOR_JOURNAL, evidence
    )
    try:
        bind_proof = reconciliation.read_ambiguous_bind_proof(oracle, evidence, matched)
    except reconciliation.AppleControlAliasReconciliationError:
        alias_discriminator.read_bound_alias_proof(
            oracle / _BIND_JOURNAL, evidence, matched
        )
        raise CompatibilityTransitionError("alias is cleanly bound; run unlock")
    journal_path = oracle / _RECONCILIATION_JOURNAL
    capture_path = oracle / _RECONCILIATION_STATE
    if os.path.lexists(journal_path) or os.path.lexists(capture_path):
        raise CompatibilityTransitionError(
            "alias reconciliation artifacts already exist"
        )
    boot = _boot_id()
    reconciliation.require_later_boot(bind_proof, boot)
    with t2_aks_transport.AKSActivationTransport() as transport:
        result = reconciliation.run(
            journal_path=journal_path,
            capture_path=capture_path,
            evidence=evidence,
            bind_proof=bind_proof,
            linux_boot_uuid=boot,
            transport=transport,
        )
    return result.public_summary()


def unlock(
    *, linux_uid: int, password: bytearray, state_root: Path = STATE_ROOT
) -> dict[str, object]:
    password[:] = b"\0" * len(password)
    raise CompatibilityTransitionError(
        "standalone alias unlock is disabled because operation 0x04 requires "
        "the bind session's active keybag handle"
    )


def recover(
    *, linux_uid: int, password: bytearray, state_root: Path = STATE_ROOT,
) -> dict[str, object]:
    try:
        evidence = _evidence(state_root, linux_uid)
        oracle = _oracle_root(state_root)
        matched = alias_discriminator.read_matched_keybag_proof(
            oracle / _DISCRIMINATOR_JOURNAL, evidence
        )
        bound = alias_discriminator.read_bound_alias_proof(
            oracle / _BIND_JOURNAL, evidence, matched
        )
        boot = _boot_id()
        alias_recovery.prepare(oracle, evidence, matched, bound, boot)
        alias_discriminator.require_later_boot(matched, boot)
        with t2_aks_transport.AKSActivationTransport() as transport:
            return alias_recovery.run(
                oracle=oracle, evidence=evidence, matched=matched, bound=bound,
                linux_boot_uuid=boot, transport=transport, password=password,
            )
    finally:
        password[:] = b"\0" * len(password)


def recover_capacity_fix(
    *, linux_uid: int, password: bytearray,
    predispatch_capacity_defect_acknowledged: bool,
    state_root: Path = STATE_ROOT,
) -> dict[str, object]:
    try:
        evidence = _evidence(state_root, linux_uid)
        oracle = _oracle_root(state_root)
        matched = alias_discriminator.read_matched_keybag_proof(
            oracle / _DISCRIMINATOR_JOURNAL, evidence
        )
        bound = alias_discriminator.read_bound_alias_proof(
            oracle / _BIND_JOURNAL, evidence, matched
        )
        boot = _boot_id()
        alias_recovery.prepare_capacity_fix(
            oracle, evidence, matched, bound, boot
        )
        with t2_aks_transport.AKSActivationTransport() as transport:
            return alias_recovery.run_capacity_fix(
                oracle=oracle,
                evidence=evidence,
                matched=matched,
                bound=bound,
                linux_boot_uuid=boot,
                transport=transport,
                password=password,
                predispatch_capacity_defect_acknowledged=(
                    predispatch_capacity_defect_acknowledged
                ),
            )
    finally:
        password[:] = b"\0" * len(password)
