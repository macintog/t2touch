# SPDX-License-Identifier: GPL-2.0-only
"""Dependency-injected runtime activation operation for one mapped Apple user.

No concrete transport or CLI is supplied.  Every possibly mutating call is
preceded by durable intent and followed by independent observation.  Reported
command status never substitutes for alias, bag UUID, or lock-state read-back.
"""

from __future__ import annotations

import inspect
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ContextManager, Iterator, Protocol

import t2_user_activation_journal as activation_journal
import t2_user_mapping
import t2_user_policy
import t2_user_readiness


class UserActivationOperationError(RuntimeError):
    pass


class UserActivationTransport(Protocol):
    runtime_generation: str

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence: ...

    def load_keybag(self, keybag_path: str) -> int: ...

    def bag_uuid(self, handle: int) -> str: ...

    def bind_alias(self, handle: int, special_alias: int) -> int: ...

    def unload_keybag(self, handle: int) -> int: ...

    def resolve_alias_configuration(self, special_alias: int) -> None: ...

    def unlock_alias(self, special_alias: int, password: memoryview) -> int: ...

    def bind_loaded_identity_secret_to_acm_context(
        self, identity_reference: bytes, authorization_context: bytes
    ) -> None: ...

    def verify_loaded_identity_secret(self, identity_reference: bytes) -> None: ...

    def unlock_alias_with_acm_context(
        self, special_alias: int, acm_external_form: bytes
    ) -> int: ...


@dataclass(frozen=True)
class UserActivationOperationResult:
    outcome: str
    mutation_performed: bool
    reconciliation_required: bool


def _sync(value, label: str):
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise UserActivationOperationError(f"{label} must be synchronous")
    return value


def _status(value, label: str) -> int:
    value = _sync(value, label)
    if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
        raise UserActivationOperationError(f"{label} returned an invalid status")
    return value


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
) -> activation_journal.UserActivationHistory:
    return activation_journal.append_checked(
        path, operation_id, milestone, evidence
    )


def _terminal(
    path: Path,
    operation_id: str,
    runtime_generation: str,
    *,
    stage: str,
    reason: str,
    unknown: bool,
    cause: BaseException | None = None,
) -> None:
    milestone = (
        "USER_ACTIVATION_OUTCOME_UNKNOWN"
        if unknown
        else "USER_ACTIVATION_STOPPED"
    )
    try:
        _append(
            path,
            operation_id,
            milestone,
            {
                "runtime_generation": runtime_generation,
                "stage": stage,
                "reason": reason,
                "mutation_possible": True,
            },
        )
    except BaseException:
        pass
    qualifier = "reconciliation is required" if unknown else "operation stopped"
    error = UserActivationOperationError(
        f"user activation stopped at {stage}; {qualifier}"
    )
    if cause is None:
        raise error
    raise error from cause


def _append_after_mutation(
    path: Path,
    operation_id: str,
    runtime_generation: str,
    milestone: str,
    evidence: dict[str, object],
    *,
    stage: str,
) -> activation_journal.UserActivationHistory:
    try:
        return _append(path, operation_id, milestone, evidence)
    except BaseException as error:
        _terminal(
            path,
            operation_id,
            runtime_generation,
            stage=stage,
            reason="journal-error",
            unknown=True,
            cause=error,
        )


def _observe(
    transport: UserActivationTransport,
    special_alias: int,
) -> t2_user_readiness.AliasEvidence:
    value = _sync(transport.observe_alias(special_alias), "alias observation")
    if not isinstance(value, t2_user_readiness.AliasEvidence):
        raise UserActivationOperationError("alias observation returned the wrong type")
    return value


def _command_and_readback(command, observe):
    status: int | None = None
    raised = False
    try:
        status = _status(command(), "activation command")
    except BaseException:
        raised = True
    return status, raised, observe()


@contextmanager
def retain_ready_identity_handle(
    path: Path,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    capability: str,
    persistent: t2_user_readiness.PersistentEvidence,
    transport: UserActivationTransport,
    *,
    authorization: t2_user_policy.UserPolicyDecision,
    linux_boot_uuid: str,
    clock: Callable[[], int] = time.monotonic_ns,
) -> Iterator[str]:
    """Retain one positive handle while an authorized identity is consumed."""

    activation_authorized = (
        isinstance(authorization, t2_user_policy.UserPolicyDecision)
        and authorization.state == "activation-authorized"
    )
    try:
        authority_time = clock()
    except BaseException as error:
        raise UserActivationOperationError(
            "retained identity authorization time is unavailable"
        ) from error
    try:
        operation_id = t2_user_policy.require_bound_authority(
            authorization,
            mapping_set,
            selected,
            capability,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=transport.runtime_generation,
            observed_monotonic_ns=authority_time,
            activation=activation_authorized,
        )
    except t2_user_policy.UserPolicyError as error:
        raise UserActivationOperationError(
            "retained identity lacks exact caller and policy authority"
        ) from error
    before = _observe(transport, selected.special_bag_alias)
    before_state = t2_user_readiness.assess(
        selected, capability, persistent, before
    ).state
    if before_state not in {
        "alias-absent",
        "ready",
        "device-locked",
        "before-first-unlock",
    }:
        raise UserActivationOperationError(
            "retained identity is not actionable before positive-handle load"
        )
    activation_journal.create(
        path,
        mapping_set,
        selected,
        capability,
        persistent,
        before,
        linux_boot_uuid=linux_boot_uuid,
        runtime_generation=transport.runtime_generation,
        operation_id=operation_id,
        allow_ready=True,
    )
    _append(
        path,
        operation_id,
        "USER_KEYBAG_LOAD_INTENT",
        {
            "runtime_generation": transport.runtime_generation,
            "keybag_sha256": selected.keybag_sha256,
            "mutation_possible": True,
        },
    )
    handle: int | None = None
    primary_error: BaseException | None = None
    try:
        handle = _sync(transport.load_keybag(selected.keybag_path), "keybag load")
        if type(handle) is not int or not 1 <= handle <= 0xFFFFFFFF:
            raise UserActivationOperationError(
                "retained keybag load returned an invalid handle"
            )
        if (
            _sync(transport.bag_uuid(handle), "loaded keybag UUID observation")
            != selected.bag_uuid
        ):
            raise UserActivationOperationError("retained keybag UUID differs")
        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_KEYBAG_HANDLE_OBSERVED",
            {
                "runtime_generation": transport.runtime_generation,
                "handle": handle,
                "bag_uuid_matches": True,
            },
            stage="handle",
        )
        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_ALIAS_BIND_INTENT",
            {
                "runtime_generation": transport.runtime_generation,
                "handle": handle,
                "special_alias": selected.special_bag_alias,
                "mutation_possible": True,
            },
            stage="bind",
        )
        bind_status, bind_raised, after_bind = _command_and_readback(
            lambda: transport.bind_alias(handle, selected.special_bag_alias),
            lambda: _observe(transport, selected.special_bag_alias),
        )
        after_bind_state = t2_user_readiness.assess(
            selected, capability, persistent, after_bind
        ).state
        if after_bind_state not in {
            "ready",
            "device-locked",
            "before-first-unlock",
        }:
            raise UserActivationOperationError(
                "retained alias is not actionable after bind"
            )
        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_ALIAS_OBSERVED",
            {
                "runtime_generation": transport.runtime_generation,
                "special_alias": selected.special_bag_alias,
                "bag_uuid_matches": True,
                "account_uuid_matches": True,
                "command_status": bind_status,
                "command_raised": bind_raised,
            },
            stage="readback",
        )
        try:
            yield after_bind_state
        except BaseException as error:
            primary_error = error
    except BaseException as error:
        primary_error = error

    if handle is None:
        _terminal(
            path,
            operation_id,
            transport.runtime_generation,
            stage="load",
            reason="retained-handle-unavailable",
            unknown=True,
            cause=primary_error,
        )
    current = activation_journal.read(path)
    if current.phase not in {
        activation_journal.UserActivationPhase.ALIAS_OBSERVED,
        activation_journal.UserActivationPhase.ALIAS_UNLOCKED,
    }:
        if current.phase in {
            activation_journal.UserActivationPhase.STOPPED,
            activation_journal.UserActivationPhase.OUTCOME_UNKNOWN,
        }:
            if primary_error is not None:
                raise primary_error
            raise UserActivationOperationError(
                "retained identity stopped before its release boundary"
            )
        failure_stage = {
            activation_journal.UserActivationPhase.LOAD_INTENT: "handle",
            activation_journal.UserActivationPhase.HANDLE_OBSERVED: "bind",
            activation_journal.UserActivationPhase.BIND_INTENT: "readback",
        }.get(current.phase, "readback")
        _terminal(
            path,
            operation_id,
            transport.runtime_generation,
            stage=failure_stage,
            reason="retained-identity-preparation-failed",
            unknown=True,
            cause=primary_error,
        )
    _append_after_mutation(
        path,
        operation_id,
        transport.runtime_generation,
        "USER_KEYBAG_UNLOAD_INTENT",
        {
            "runtime_generation": transport.runtime_generation,
            "handle": handle,
            "mutation_possible": True,
        },
        stage="unload",
    )
    try:
        unload_status, unload_raised, after_unload = _command_and_readback(
            lambda: transport.unload_keybag(handle),
            lambda: _observe(transport, selected.special_bag_alias),
        )
    except BaseException as error:
        _terminal(
            path,
            operation_id,
            transport.runtime_generation,
            stage="readback",
            reason="retained-release-observation-failed",
            unknown=True,
            cause=error,
        )
    if (
        unload_raised
        or unload_status != 0
        or t2_user_readiness.assess(
            selected, capability, persistent, after_unload
        ).state
        != "ready"
    ):
        _terminal(
            path,
            operation_id,
            transport.runtime_generation,
            stage="unload",
            reason="retained-handle-release-ambiguous",
            unknown=True,
        )
    _append_after_mutation(
        path,
        operation_id,
        transport.runtime_generation,
        "USER_KEYBAG_HANDLE_RELEASED",
        {
            "runtime_generation": transport.runtime_generation,
            "handle": handle,
            "special_alias": selected.special_bag_alias,
            "bag_uuid_matches": True,
            "command_status": unload_status,
            "command_raised": unload_raised,
        },
        stage="readback",
    )
    _append_after_mutation(
        path,
        operation_id,
        transport.runtime_generation,
        "USER_ACTIVATION_READY",
        {
            "runtime_generation": transport.runtime_generation,
            "special_alias": selected.special_bag_alias,
            "bag_uuid_matches": True,
            "account_uuid_matches": True,
            "readiness_state": "ready",
            "source": "release-readback",
            "command_status": unload_status,
            "command_raised": unload_raised,
        },
        stage="readback",
    )
    if primary_error is not None:
        raise primary_error


def prepare_retained_identity(
    path: Path,
    selected: t2_user_mapping.UserMapping,
    transport: UserActivationTransport,
) -> None:
    """Resolve a rebound identity before creating its authorization contexts."""

    history = activation_journal.read(path)
    if history.phase is not activation_journal.UserActivationPhase.ALIAS_OBSERVED:
        raise UserActivationOperationError(
            "retained identity is not at its configuration boundary"
        )
    operation_id = history.operation_id
    runtime_generation = transport.runtime_generation
    _append_after_mutation(
        path,
        operation_id,
        runtime_generation,
        "USER_ALIAS_CONFIGURATION_INTENT",
        {
            "runtime_generation": runtime_generation,
            "special_alias": selected.special_bag_alias,
            "mutation_possible": True,
        },
        stage="configuration",
    )
    try:
        configuration_result = _sync(
            transport.resolve_alias_configuration(selected.special_bag_alias),
            "alias configuration resolution",
        )
        if configuration_result is not None:
            raise UserActivationOperationError(
                "alias configuration returned an invalid result"
            )
    except BaseException as error:
        _terminal(
            path,
            operation_id,
            runtime_generation,
            stage="configuration",
            reason="configuration-resolution-failed",
            unknown=True,
            cause=error,
        )
    _append_after_mutation(
        path,
        operation_id,
        runtime_generation,
        "USER_ALIAS_CONFIGURATION_RESOLVED",
        {
            "runtime_generation": runtime_generation,
            "special_alias": selected.special_bag_alias,
            "bag_uuid_matches": True,
            "command_status": 0,
            "command_raised": False,
        },
        stage="readback",
    )


def unlock_retained_identity(
    path: Path,
    selected: t2_user_mapping.UserMapping,
    capability: str,
    persistent: t2_user_readiness.PersistentEvidence,
    transport: UserActivationTransport,
    identity_reference: bytes,
) -> None:
    """Restore one prepared identity to ready inside its live ACM scope."""

    history = activation_journal.read(path)
    if (
        history.phase
        is not activation_journal.UserActivationPhase.CONFIGURATION_RESOLVED
    ):
        raise UserActivationOperationError(
            "retained identity is not at its authorization boundary"
        )
    if (
        not isinstance(identity_reference, bytes)
        or len(identity_reference) != 16
        or not any(identity_reference)
    ):
        raise UserActivationOperationError(
            "retained identity authorization input is invalid"
        )
    operation_id = history.operation_id
    runtime_generation = transport.runtime_generation
    _append_after_mutation(
        path,
        operation_id,
        runtime_generation,
        "USER_ALIAS_UNLOCK_INTENT",
        {
            "runtime_generation": runtime_generation,
            "special_alias": selected.special_bag_alias,
            "mutation_possible": True,
        },
        stage="unlock",
    )
    try:
        unlock_status, unlock_raised, after_unlock = _command_and_readback(
            lambda: transport.unlock_alias_with_acm_context(
                selected.special_bag_alias, identity_reference
            ),
            lambda: _observe(transport, selected.special_bag_alias),
        )
    except BaseException as error:
        _terminal(
            path,
            operation_id,
            runtime_generation,
            stage="readback",
            reason="unlock-observation-failed",
            unknown=True,
            cause=error,
        )
    try:
        after_unlock_state = t2_user_readiness.assess(
            selected, capability, persistent, after_unlock
        ).state
    except BaseException as error:
        _terminal(
            path,
            operation_id,
            runtime_generation,
            stage="readback",
            reason="unlock-evidence-invalid",
            unknown=True,
            cause=error,
        )
    if after_unlock_state != "ready":
        _terminal(
            path,
            operation_id,
            runtime_generation,
            stage="unlock",
            reason=after_unlock_state,
            unknown=after_unlock_state in {"alias-absent", "unknown-lock-state"},
        )
    _append_after_mutation(
        path,
        operation_id,
        runtime_generation,
        "USER_ALIAS_UNLOCKED",
        {
            "runtime_generation": runtime_generation,
            "special_alias": selected.special_bag_alias,
            "bag_uuid_matches": True,
            "readiness_state": "ready",
            "command_status": unlock_status,
            "command_raised": unlock_raised,
        },
        stage="readback",
    )


def _unlock_with_acm_context(
    transport: UserActivationTransport,
    special_alias: int,
    apple_user_id: int,
    password: bytearray,
    context_factory: Callable[
        [int, bytearray, Callable[[bytes, bytes], None]], ContextManager[bytes]
    ],
) -> int:
    def bind_identity_reference(
        identity_reference: bytes, authorization_context: bytes
    ) -> None:
        if authorization_context:
            transport.bind_loaded_identity_secret_to_acm_context(
                identity_reference, authorization_context
            )
        else:
            transport.verify_loaded_identity_secret(identity_reference)

    context_manager = _sync(
        context_factory(apple_user_id, password, bind_identity_reference),
        "authorized ACM context factory",
    )
    with context_manager as external_form:
        if (
            not isinstance(external_form, bytes)
            or len(external_form) != 16
            or not any(external_form)
        ):
            raise UserActivationOperationError(
                "authorized ACM context has an invalid external form"
            )
        return transport.unlock_alias_with_acm_context(
            special_alias, external_form
        )


def run(
    path: Path,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    capability: str,
    persistent: t2_user_readiness.PersistentEvidence,
    transport: UserActivationTransport,
    password: bytearray | None,
    *,
    authorization: t2_user_policy.UserPolicyDecision,
    linux_boot_uuid: str,
    acm_context_factory: Callable[
        [int, bytearray, Callable[[bytes, bytes], None]], ContextManager[bytes]
    ] | None = None,
    clock: Callable[[], int] = time.monotonic_ns,
) -> UserActivationOperationResult:
    if password is not None and not isinstance(password, bytearray):
        raise UserActivationOperationError(
            "activation password must use wipeable storage"
        )
    try:
        if not isinstance(transport.runtime_generation, str):
            raise UserActivationOperationError("runtime generation is invalid")
        try:
            authority_time = clock()
        except BaseException as error:
            raise UserActivationOperationError(
                "authorization consumption time is unavailable"
            ) from error
        activation_authorized = (
            isinstance(authorization, t2_user_policy.UserPolicyDecision)
            and authorization.state == "activation-authorized"
        )
        try:
            authorized_operation_id = t2_user_policy.require_bound_authority(
                authorization,
                mapping_set,
                selected,
                capability,
                linux_boot_uuid=linux_boot_uuid,
                runtime_generation=transport.runtime_generation,
                observed_monotonic_ns=authority_time,
                activation=activation_authorized,
            )
        except t2_user_policy.UserPolicyError as error:
            raise UserActivationOperationError(
                "activation lacks exact caller and policy authority"
            ) from error
        if isinstance(password, bytearray) and not 1 <= len(password) <= 1024:
            raise UserActivationOperationError(
                "activation password storage has an invalid size"
            )
        mutation_performed = False
        try:
            before = _observe(transport, selected.special_bag_alias)
            decision = t2_user_readiness.assess(
                selected, capability, persistent, before
            )
        except BaseException as error:
            raise UserActivationOperationError(
                "activation preflight could not establish target readiness"
            ) from error
        if decision.state == "ready":
            return UserActivationOperationResult("already-ready", False, False)
        if not activation_authorized:
            raise UserActivationOperationError(
                "target became not-ready without separate activation authority"
            )
        if not isinstance(password, bytearray):
            raise UserActivationOperationError(
                "activation requires a nonempty password in wipeable storage"
            )
        try:
            history = activation_journal.create(
                path,
                mapping_set,
                selected,
                capability,
                persistent,
                before,
                linux_boot_uuid=linux_boot_uuid,
                runtime_generation=transport.runtime_generation,
                operation_id=authorized_operation_id,
            )
        except activation_journal.UserActivationJournalError as error:
            raise UserActivationOperationError(
                "activation preflight is not safely actionable"
            ) from error
        operation_id = history.operation_id
        bind_status: int | None = None
        bind_raised = False
        handle: int | None = None
        current_decision = decision

        # Persisted-user restoration always reloads and promotes the saved
        # positive bag before resolving or unlocking its negative alias.  An
        # alias surviving a reboot is evidence of association, not a live
        # positive handle that can be skipped.
        if decision.state in {
            "alias-absent",
            "device-locked",
            "before-first-unlock",
        }:
            _append(
                path,
                operation_id,
                "USER_KEYBAG_LOAD_INTENT",
                {
                    "runtime_generation": transport.runtime_generation,
                    "keybag_sha256": selected.keybag_sha256,
                    "mutation_possible": True,
                },
            )
            mutation_performed = True
            try:
                handle = _sync(
                    transport.load_keybag(selected.keybag_path), "keybag load"
                )
                if type(handle) is not int or not 1 <= handle <= 0xFFFFFFFF:
                    raise UserActivationOperationError(
                        "keybag load returned an invalid handle"
                    )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="load",
                    reason="handle-unavailable",
                    unknown=True,
                    cause=error,
                )
            try:
                observed_bag_uuid = _sync(
                    transport.bag_uuid(handle), "loaded keybag UUID observation"
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="handle",
                    reason="bag-observation-failed",
                    unknown=True,
                    cause=error,
                )
            if observed_bag_uuid != selected.bag_uuid:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="handle",
                    reason="bag-binding-mismatch",
                    unknown=False,
                )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": transport.runtime_generation,
                    "handle": handle,
                    "bag_uuid_matches": True,
                },
                stage="handle",
            )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_BIND_INTENT",
                {
                    "runtime_generation": transport.runtime_generation,
                    "handle": handle,
                    "special_alias": selected.special_bag_alias,
                    "mutation_possible": True,
                },
                stage="bind",
            )
            try:
                bind_status, bind_raised, after_bind = _command_and_readback(
                    lambda: transport.bind_alias(
                        handle, selected.special_bag_alias
                    ),
                    lambda: _observe(transport, selected.special_bag_alias),
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="readback",
                    reason="alias-observation-failed",
                    unknown=True,
                    cause=error,
                )
            try:
                after_bind_decision = t2_user_readiness.assess(
                    selected, capability, persistent, after_bind
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="readback",
                    reason="alias-evidence-invalid",
                    unknown=True,
                    cause=error,
                )
            if after_bind_decision.state in {
                "alias-absent",
                "alias-binding-mismatch",
                "persistent-binding-mismatch",
                "unknown-lock-state",
                "catacomb-corrupted",
            }:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="bind",
                    reason=after_bind_decision.state,
                    unknown=after_bind_decision.state == "alias-absent",
                )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_OBSERVED",
                {
                    "runtime_generation": transport.runtime_generation,
                    "special_alias": selected.special_bag_alias,
                    "bag_uuid_matches": True,
                    "account_uuid_matches": True,
                    "command_status": bind_status,
                    "command_raised": bind_raised,
                },
                stage="readback",
            )
            current_decision = after_bind_decision

        if current_decision.state in {"device-locked", "before-first-unlock"}:
            configuration_intent = {
                "runtime_generation": transport.runtime_generation,
                "special_alias": selected.special_bag_alias,
                "mutation_possible": True,
            }
            if mutation_performed:
                _append_after_mutation(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    "USER_ALIAS_CONFIGURATION_INTENT",
                    configuration_intent,
                    stage="configuration",
                )
            else:
                _append(
                    path,
                    operation_id,
                    "USER_ALIAS_CONFIGURATION_INTENT",
                    configuration_intent,
                )
            mutation_performed = True
            try:
                configuration_result = _sync(
                    transport.resolve_alias_configuration(
                        selected.special_bag_alias
                    ),
                    "alias configuration resolution",
                )
                if configuration_result is not None:
                    raise UserActivationOperationError(
                        "alias configuration returned an invalid result"
                    )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="configuration",
                    reason="configuration-resolution-failed",
                    unknown=True,
                    cause=error,
                )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_CONFIGURATION_RESOLVED",
                {
                    "runtime_generation": transport.runtime_generation,
                    "special_alias": selected.special_bag_alias,
                    "bag_uuid_matches": True,
                    "command_status": 0,
                    "command_raised": False,
                },
                stage="readback",
            )

            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_UNLOCK_INTENT",
                {
                    "runtime_generation": transport.runtime_generation,
                    "special_alias": selected.special_bag_alias,
                    "mutation_possible": True,
                },
                stage="unlock",
            )
            try:
                if acm_context_factory is None:
                    unlock_command = lambda: transport.unlock_alias(
                        selected.special_bag_alias, memoryview(password)
                    )
                else:
                    unlock_command = lambda: _unlock_with_acm_context(
                        transport,
                        selected.special_bag_alias,
                        selected.apple_uid,
                        password,
                        acm_context_factory,
                    )
                unlock_status, unlock_raised, after_unlock = _command_and_readback(
                    unlock_command,
                    lambda: _observe(transport, selected.special_bag_alias),
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="readback",
                    reason="unlock-observation-failed",
                    unknown=True,
                    cause=error,
                )
            try:
                current_decision = t2_user_readiness.assess(
                    selected, capability, persistent, after_unlock
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="readback",
                    reason="unlock-evidence-invalid",
                    unknown=True,
                    cause=error,
                )
            if current_decision.state != "ready":
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="unlock",
                    reason=current_decision.state,
                    unknown=current_decision.state
                    in {"alias-absent", "unknown-lock-state"},
                )
            if handle is None:
                _append_after_mutation(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    "USER_ACTIVATION_READY",
                    {
                        "runtime_generation": transport.runtime_generation,
                        "special_alias": selected.special_bag_alias,
                        "bag_uuid_matches": True,
                        "account_uuid_matches": True,
                        "readiness_state": "ready",
                        "source": "unlock-readback",
                        "command_status": unlock_status,
                        "command_raised": unlock_raised,
                    },
                    stage="readback",
                )
                return UserActivationOperationResult("ready", True, False)
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_UNLOCKED",
                {
                    "runtime_generation": transport.runtime_generation,
                    "special_alias": selected.special_bag_alias,
                    "bag_uuid_matches": True,
                    "readiness_state": "ready",
                    "command_status": unlock_status,
                    "command_raised": unlock_raised,
                },
                stage="readback",
            )

        if handle is None:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="readback",
                reason=current_decision.state,
                unknown=False,
            )

        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_KEYBAG_UNLOAD_INTENT",
            {
                "runtime_generation": transport.runtime_generation,
                "handle": handle,
                "mutation_possible": True,
            },
            stage="unload",
        )
        try:
            unload_status, unload_raised, after_unload = _command_and_readback(
                lambda: transport.unload_keybag(handle),
                lambda: _observe(transport, selected.special_bag_alias),
            )
        except BaseException as error:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="readback",
                reason="post-unload-observation-failed",
                unknown=True,
                cause=error,
            )
        if unload_raised or unload_status != 0:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="unload",
                reason="handle-release-ambiguous",
                unknown=True,
            )
        try:
            after_unload_decision = t2_user_readiness.assess(
                selected, capability, persistent, after_unload
            )
        except BaseException as error:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="readback",
                reason="post-unload-evidence-invalid",
                unknown=True,
                cause=error,
            )
        if after_unload_decision.state in {
            "alias-absent",
            "alias-binding-mismatch",
            "persistent-binding-mismatch",
            "unknown-lock-state",
            "catacomb-corrupted",
        }:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="unload",
                reason=after_unload_decision.state,
                unknown=after_unload_decision.state == "alias-absent",
            )
        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_KEYBAG_HANDLE_RELEASED",
            {
                "runtime_generation": transport.runtime_generation,
                "handle": handle,
                "special_alias": selected.special_bag_alias,
                "bag_uuid_matches": True,
                "command_status": unload_status,
                "command_raised": unload_raised,
            },
            stage="readback",
        )
        if after_unload_decision.state != "ready":
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="readback",
                reason=after_unload_decision.state,
                unknown=False,
            )
        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_ACTIVATION_READY",
            {
                "runtime_generation": transport.runtime_generation,
                "special_alias": selected.special_bag_alias,
                "bag_uuid_matches": True,
                "account_uuid_matches": True,
                "readiness_state": "ready",
                "source": "release-readback",
                "command_status": unload_status,
                "command_raised": unload_raised,
            },
            stage="readback",
        )
        return UserActivationOperationResult("ready", mutation_performed, False)
    finally:
        if isinstance(password, bytearray):
            password[:] = b"\x00" * len(password)
