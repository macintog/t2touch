# SPDX-License-Identifier: GPL-2.0-only
"""Fresh-owner proof and promotion for one replacement activation secret."""

from __future__ import annotations

import inspect
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable, Protocol

import t2_aks_replacement_activation_journal as activation_journal
import t2_user_mapping_store
import t2_user_readiness


class AKSReplacementActivationOperationError(RuntimeError):
    pass


class ReplacementActivationTransport(Protocol):
    runtime_generation: str

    def load_keybag(self, keybag_path: str) -> int: ...

    def bag_uuid(self, handle: int) -> str: ...

    def bind_alias(self, handle: int, special_alias: int) -> int: ...

    def observe_alias(
        self, special_alias: int
    ) -> t2_user_readiness.AliasEvidence: ...

    def resolve_alias_configuration(self, special_alias: int) -> None: ...

    def bind_loaded_identity_secret_to_acm_context(
        self, identity_reference: bytes, authorization_context: bytes
    ) -> None: ...

    def unlock_alias_with_acm_context(
        self, special_alias: int, login_credential: bytes
    ) -> int: ...

    def unload_keybag(self, handle: int) -> int: ...


class PolicyResult(Protocol):
    requirement_type: int
    satisfied: bool


TransportFactory = Callable[[], AbstractContextManager[ReplacementActivationTransport]]
AuthorizationFactory = Callable[
    [
        int,
        bytearray,
        Callable[[bytes, bytes], None],
    ],
    AbstractContextManager[tuple[PolicyResult, PolicyResult, bytes]],
]
SecretReader = Callable[[], AbstractContextManager[bytearray]]


def _sync(value: object, label: str):
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise AKSReplacementActivationOperationError(f"{label} must be synchronous")
    return value


def _status(value: object, label: str) -> int:
    value = _sync(value, label)
    if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
        raise AKSReplacementActivationOperationError(
            f"{label} returned an invalid status"
        )
    return value


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
) -> activation_journal.AKSReplacementActivationHistory:
    return activation_journal.append_checked(
        path, operation_id, milestone, evidence
    )


def _alias_state(
    evidence: object,
    *,
    special_alias: int,
    bag_uuid: str,
) -> str:
    if not isinstance(evidence, t2_user_readiness.AliasEvidence):
        raise AKSReplacementActivationOperationError(
            "replacement alias observation returned the wrong type"
        )
    if not evidence.present:
        if any(
            value is not None
            for value in (
                evidence.special_alias,
                evidence.bag_uuid,
                evidence.lock_state,
            )
        ):
            raise AKSReplacementActivationOperationError(
                "absent replacement alias has contradictory evidence"
            )
        return "alias-absent"
    if (
        evidence.special_alias != special_alias
        or evidence.bag_uuid != bag_uuid
        or type(evidence.lock_state) is not int
        or not 0 <= evidence.lock_state <= 0xFFFF
    ):
        return "binding-mismatch"
    lock_state = evidence.lock_state
    if lock_state & ~t2_user_readiness.KNOWN_LOCK_STATE_BITS:
        return "unknown-lock-state"
    if lock_state & t2_user_readiness.CATACOMB_CORRUPTED:
        return "catacomb-corrupted"
    if lock_state & (
        t2_user_readiness.PASSCODE_LOCKOUT
        | t2_user_readiness.BIO_LOCKOUT
        | t2_user_readiness.IDENTIFICATION_LOCKOUT
    ):
        return "keybag-lockout"
    if lock_state & t2_user_readiness.BEFORE_FIRST_UNLOCK:
        return "before-first-unlock"
    if lock_state & t2_user_readiness.DEVICE_LOCKED:
        return "device-locked"
    return "ready"


def classify_alias(
    evidence: object, *, special_alias: int, bag_uuid: str
) -> str:
    """Classify identifier-bound alias evidence without authorizing mutation."""

    return _alias_state(
        evidence, special_alias=special_alias, bag_uuid=bag_uuid
    )


def _observe(
    transport: ReplacementActivationTransport,
    *,
    special_alias: int,
    bag_uuid: str,
) -> tuple[t2_user_readiness.AliasEvidence, str]:
    evidence = _sync(
        transport.observe_alias(special_alias), "replacement alias observation"
    )
    return evidence, _alias_state(
        evidence, special_alias=special_alias, bag_uuid=bag_uuid
    )


def create(
    *,
    journal_path: Path,
    operation_id: str,
    replacement_head_hash: str,
    replacement_initial_linux_boot_uuid: str,
    replacement_final_linux_boot_uuid: str,
    activation_linux_boot_uuid: str,
    linux_account_generation: str,
    target_linux_uid: int,
    apple_uid: int,
    account_uuid: str,
    bag_uuid: str,
    disabled_mapping_generation: str,
    keybag_sha256: str,
    activation_material_digest: str,
    bundle_manifest_sha256: str,
    initial_alias_state: str,
) -> activation_journal.AKSReplacementActivationHistory:
    return activation_journal.create(
        journal_path,
        operation_id,
        {
            "replacement_head_hash": replacement_head_hash,
            "replacement_initial_linux_boot_uuid": replacement_initial_linux_boot_uuid,
            "replacement_final_linux_boot_uuid": replacement_final_linux_boot_uuid,
            "activation_linux_boot_uuid": activation_linux_boot_uuid,
            "linux_account_generation": linux_account_generation,
            "target_linux_uid": target_linux_uid,
            "apple_uid": apple_uid,
            "account_uuid": account_uuid,
            "bag_uuid": bag_uuid,
            "disabled_mapping_generation": disabled_mapping_generation,
            "keybag_sha256": keybag_sha256,
            "activation_material_digest": activation_material_digest,
            "bundle_manifest_sha256": bundle_manifest_sha256,
            "special_alias": -apple_uid,
            "initial_alias_state": initial_alias_state,
        },
    )


def _finish_enable(
    *,
    journal_path: Path,
    history: activation_journal.AKSReplacementActivationHistory,
    mapping_writer: t2_user_mapping_store.InitialUserMappingStore,
) -> activation_journal.AKSReplacementActivationHistory:
    baseline = history.baseline
    if history.phase == "independent-ready":
        history = _append(
            journal_path,
            history.operation_id,
            "REPLACEMENT_MAPPING_ENABLE_INTENT",
            {
                "disabled_mapping_generation": baseline[
                    "disabled_mapping_generation"
                ],
                "mutation_possible": True,
            },
        )
    if history.phase != "enable-intent":
        raise AKSReplacementActivationOperationError(
            "mapping enable is not authorized by independent activation proof"
        )
    enabled_generation = mapping_writer.enable_after_reboot(
        disabled_mapping_generation=baseline["disabled_mapping_generation"],
        account_uuid=baseline["account_uuid"],
        bag_uuid=baseline["bag_uuid"],
        keybag_sha256=baseline["keybag_sha256"],
    )
    return _append(
        journal_path,
        history.operation_id,
        "REPLACEMENT_ACTIVATION_COMPLETE",
        {
            "disabled_mapping_generation": baseline[
                "disabled_mapping_generation"
            ],
            "enabled_mapping_generation": enabled_generation,
            "mapping_enabled": True,
        },
    )


def _record_interruption(
    *,
    journal_path: Path,
    operation_id: str,
    stage: str,
    cleanup_attempted: bool,
    cleanup_succeeded: bool,
) -> None:
    try:
        current = activation_journal.read(journal_path)
        if current.phase not in activation_journal._ATTEMPT_PHASES:
            return
        _append(
            journal_path,
            operation_id,
            "REPLACEMENT_ACTIVATION_ATTEMPT_INTERRUPTED",
            {
                "attempt_number": current.attempt_number,
                "from_phase": current.phase,
                "stage": stage,
                "reason": "operation-error",
                "cleanup_attempted": cleanup_attempted,
                "cleanup_succeeded": cleanup_succeeded,
                "mutation_possible": True,
            },
        )
    except BaseException:
        pass


def run_attempt(
    *,
    journal_path: Path,
    linux_boot_uuid: str,
    transport_factory: TransportFactory,
    authorization_factory: AuthorizationFactory,
    secret_reader: SecretReader,
    mapping_writer: t2_user_mapping_store.InitialUserMappingStore,
) -> activation_journal.AKSReplacementActivationHistory:
    history = activation_journal.read(journal_path)
    if history.phase not in {"baseline", "retry-authorized"}:
        raise AKSReplacementActivationOperationError(
            "replacement activation attempt is not authorized"
        )
    baseline = history.baseline
    special_alias = baseline["special_alias"]
    bag_uuid = baseline["bag_uuid"]
    operation_id = history.operation_id
    handle: int | None = None
    unloaded = False
    stage = "transport-open"
    try:
        manager = _sync(transport_factory(), "replacement transport factory")
        with manager as transport:
            runtime_generation = transport.runtime_generation
            history = _append(
                journal_path,
                operation_id,
                "REPLACEMENT_ACTIVATION_ATTEMPT_STARTED",
                {
                    "attempt_number": history.attempt_number + 1,
                    "linux_boot_uuid": linux_boot_uuid,
                    "runtime_generation": runtime_generation,
                    "mutation_possible": False,
                },
            )
            attempt = history.attempt_number
            stage = "load"
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_KEYBAG_LOAD_INTENT",
                {
                    "attempt_number": attempt,
                    "keybag_sha256": baseline["keybag_sha256"],
                    "mutation_possible": True,
                },
            )
            handle = _sync(
                transport.load_keybag(mapping_writer.keybag_path.as_posix()),
                "replacement keybag load",
            )
            if type(handle) is not int or not 0 < handle <= 0x7FFFFFFF:
                raise AKSReplacementActivationOperationError(
                    "replacement load returned an invalid handle"
                )
            observed_uuid = _sync(
                transport.bag_uuid(handle), "replacement loaded UUID observation"
            )
            if observed_uuid != bag_uuid:
                raise AKSReplacementActivationOperationError(
                    "replacement loaded keybag UUID differs"
                )
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_KEYBAG_LOADED",
                {
                    "attempt_number": attempt,
                    "handle": handle,
                    "bag_uuid_matches": True,
                    "command_status": 0,
                },
            )

            stage = "bind"
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_ALIAS_BIND_INTENT",
                {
                    "attempt_number": attempt,
                    "handle": handle,
                    "special_alias": special_alias,
                    "mutation_possible": True,
                },
            )
            bind_status = _status(
                transport.bind_alias(handle, special_alias),
                "replacement alias bind",
            )
            _, bound_state = _observe(
                transport, special_alias=special_alias, bag_uuid=bag_uuid
            )
            if bind_status != 0 or bound_state not in {
                "device-locked",
                "before-first-unlock",
                "ready",
            }:
                raise AKSReplacementActivationOperationError(
                    "replacement alias bind did not reconcile"
                )
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_ALIAS_BOUND",
                {
                    "attempt_number": attempt,
                    "special_alias": special_alias,
                    "bag_uuid_matches": True,
                    "alias_state": bound_state,
                    "command_status": bind_status,
                },
            )

            stage = "configuration"
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_ALIAS_CONFIGURATION_INTENT",
                {
                    "attempt_number": attempt,
                    "special_alias": special_alias,
                    "mutation_possible": True,
                },
            )
            result = _sync(
                transport.resolve_alias_configuration(special_alias),
                "replacement alias configuration",
            )
            if result is not None:
                raise AKSReplacementActivationOperationError(
                    "replacement alias configuration returned an invalid result"
                )
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_ALIAS_CONFIGURATION_RESOLVED",
                {
                    "attempt_number": attempt,
                    "special_alias": special_alias,
                    "command_status": 0,
                },
            )

            stage = "authorization"
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_IDENTITY_AUTHORIZATION_INTENT",
                {
                    "attempt_number": attempt,
                    "activation_material_digest": baseline[
                        "activation_material_digest"
                    ],
                    "mutation_possible": True,
                },
            )

            def bind_identity(
                identity_reference: bytes, authorization_context: bytes
            ) -> None:
                transport.bind_loaded_identity_secret_to_acm_context(
                    identity_reference, authorization_context
                )

            reader = _sync(secret_reader(), "activation material reader")
            with reader as activation_material:
                if not isinstance(activation_material, bytearray):
                    raise AKSReplacementActivationOperationError(
                        "activation material is not mutable storage"
                    )
                authorization = _sync(
                    authorization_factory(
                        baseline["apple_uid"], activation_material, bind_identity
                    ),
                    "replacement authorization factory",
                )
                with authorization as proof:
                    if (
                        not isinstance(proof, tuple)
                        or len(proof) != 3
                        or not isinstance(proof[2], bytes)
                        or len(proof[2]) != 16
                        or not any(proof[2])
                    ):
                        raise AKSReplacementActivationOperationError(
                            "replacement authorization proof is invalid"
                        )
                    initial, final, login_credential = proof
                    if (
                        initial.requirement_type != 1
                        or initial.satisfied is not False
                        or final.satisfied is not True
                    ):
                        raise AKSReplacementActivationOperationError(
                            "replacement authorization policy did not reconcile"
                        )
                    _append(
                        journal_path,
                        operation_id,
                        "REPLACEMENT_IDENTITY_AUTHORIZED",
                        {
                            "attempt_number": attempt,
                            "initial_requirement_type": 1,
                            "initial_policy_satisfied": False,
                            "final_policy_satisfied": True,
                            "command_status": 0,
                        },
                    )

                    stage = "unlock"
                    _append(
                        journal_path,
                        operation_id,
                        "REPLACEMENT_ALIAS_UNLOCK_INTENT",
                        {
                            "attempt_number": attempt,
                            "special_alias": special_alias,
                            "mutation_possible": True,
                        },
                    )
                    unlock_status = _status(
                        transport.unlock_alias_with_acm_context(
                            special_alias, login_credential
                        ),
                        "replacement alias unlock",
                    )
                    _, unlocked_state = _observe(
                        transport,
                        special_alias=special_alias,
                        bag_uuid=bag_uuid,
                    )
                    if unlock_status != 0 or unlocked_state != "ready":
                        raise AKSReplacementActivationOperationError(
                            "replacement alias did not become ready"
                        )
                    _append(
                        journal_path,
                        operation_id,
                        "REPLACEMENT_ALIAS_UNLOCKED",
                        {
                            "attempt_number": attempt,
                            "special_alias": special_alias,
                            "bag_uuid_matches": True,
                            "alias_state": "ready",
                            "command_status": unlock_status,
                        },
                    )

            stage = "unload"
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_KEYBAG_UNLOAD_INTENT",
                {
                    "attempt_number": attempt,
                    "handle": handle,
                    "mutation_possible": True,
                },
            )
            unload_status = _status(
                transport.unload_keybag(handle), "replacement keybag unload"
            )
            if unload_status != 0:
                raise AKSReplacementActivationOperationError(
                    "replacement keybag unload did not succeed"
                )
            unloaded = True
            _append(
                journal_path,
                operation_id,
                "REPLACEMENT_KEYBAG_UNLOADED",
                {
                    "attempt_number": attempt,
                    "handle": handle,
                    "command_status": unload_status,
                },
            )
    except BaseException as error:
        cleanup_attempted = handle is not None and not unloaded
        _record_interruption(
            journal_path=journal_path,
            operation_id=operation_id,
            stage=stage,
            cleanup_attempted=cleanup_attempted,
            # The transport context has already closed here.  Its emergency
            # unload cannot be independently read back after descriptor loss,
            # so the journal deliberately records no cleanup success claim.
            cleanup_succeeded=False,
        )
        raise AKSReplacementActivationOperationError(
            "replacement activation attempt stopped; reconcile on a new boot"
        ) from error

    stage = "independent-readback"
    try:
        independent_manager = _sync(
            transport_factory(), "independent replacement transport factory"
        )
        with independent_manager as independent:
            _, state = _observe(
                independent, special_alias=special_alias, bag_uuid=bag_uuid
            )
            if state != "ready":
                raise AKSReplacementActivationOperationError(
                    "independent replacement owner did not observe readiness"
                )
            history = _append(
                journal_path,
                operation_id,
                "REPLACEMENT_ACTIVATION_INDEPENDENT_READY",
                {
                    "attempt_number": attempt,
                    "linux_boot_uuid": linux_boot_uuid,
                    "runtime_generation": independent.runtime_generation,
                    "source": "fresh-owner",
                    "independent_owner": True,
                    "alias_state": "ready",
                    "bag_uuid_matches": True,
                    "mutation_performed": False,
                },
            )
    except BaseException as error:
        raise AKSReplacementActivationOperationError(
            "independent activation proof failed; reconcile on a new boot"
        ) from error
    return _finish_enable(
        journal_path=journal_path,
        history=history,
        mapping_writer=mapping_writer,
    )


def reconcile(
    *,
    journal_path: Path,
    linux_boot_uuid: str,
    transport_factory: TransportFactory,
    authorization_factory: AuthorizationFactory,
    secret_reader: SecretReader,
    mapping_writer: t2_user_mapping_store.InitialUserMappingStore,
) -> activation_journal.AKSReplacementActivationHistory:
    history = activation_journal.read(journal_path)
    if history.phase == "complete":
        return history
    if history.phase in {"independent-ready", "enable-intent"}:
        return _finish_enable(
            journal_path=journal_path,
            history=history,
            mapping_writer=mapping_writer,
        )
    if history.phase == "quarantined":
        raise AKSReplacementActivationOperationError(
            "replacement activation is quarantined"
        )
    if history.phase == "baseline":
        return run_attempt(
            journal_path=journal_path,
            linux_boot_uuid=linux_boot_uuid,
            transport_factory=transport_factory,
            authorization_factory=authorization_factory,
            secret_reader=secret_reader,
            mapping_writer=mapping_writer,
        )

    baseline = history.baseline
    try:
        manager = _sync(transport_factory(), "recovery transport factory")
        with manager as transport:
            evidence, state = _observe(
                transport,
                special_alias=baseline["special_alias"],
                bag_uuid=baseline["bag_uuid"],
            )
            runtime = transport.runtime_generation
            if state == "ready":
                history = _append(
                    journal_path,
                    history.operation_id,
                    "REPLACEMENT_ACTIVATION_INDEPENDENT_READY",
                    {
                        "attempt_number": history.attempt_number,
                        "linux_boot_uuid": linux_boot_uuid,
                        "runtime_generation": runtime,
                        "source": "different-boot-recovery",
                        "independent_owner": True,
                        "alias_state": "ready",
                        "bag_uuid_matches": True,
                        "mutation_performed": False,
                    },
                )
                return _finish_enable(
                    journal_path=journal_path,
                    history=history,
                    mapping_writer=mapping_writer,
                )
            if state in {
                "alias-absent",
                "device-locked",
                "before-first-unlock",
            }:
                history = _append(
                    journal_path,
                    history.operation_id,
                    "REPLACEMENT_ACTIVATION_RETRY_AUTHORIZED",
                    {
                        "previous_attempt_number": history.attempt_number,
                        "linux_boot_uuid": linux_boot_uuid,
                        "runtime_generation": runtime,
                        "alias_state": state,
                        "alias_present": evidence.present,
                        "bag_uuid_matches": evidence.present,
                        "mutation_performed": False,
                    },
                )
            else:
                _append(
                    journal_path,
                    history.operation_id,
                    "REPLACEMENT_ACTIVATION_QUARANTINED",
                    {
                        "linux_boot_uuid": linux_boot_uuid,
                        "runtime_generation": runtime,
                        "reason": state,
                        "mutation_performed": False,
                    },
                )
                raise AKSReplacementActivationOperationError(
                    "replacement alias evidence requires quarantine"
                )
    except activation_journal.AKSReplacementActivationJournalError:
        raise
    except AKSReplacementActivationOperationError:
        raise
    except BaseException as error:
        raise AKSReplacementActivationOperationError(
            "replacement activation recovery observation failed"
        ) from error
    return run_attempt(
        journal_path=journal_path,
        linux_boot_uuid=linux_boot_uuid,
        transport_factory=transport_factory,
        authorization_factory=authorization_factory,
        secret_reader=secret_reader,
        mapping_writer=mapping_writer,
    )
