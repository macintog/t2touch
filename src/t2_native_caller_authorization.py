# SPDX-License-Identifier: GPL-2.0-only
"""Caller-bound PolicyKit grants for Linux-native biometric mutations."""

from __future__ import annotations

import time
from dataclasses import dataclass

import t2_ipc_session
import t2_user_authority
import t2_user_mapping
import t2_user_policy


class NativeCallerAuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class NativeMutationAuthorization:
    operation_grant: t2_user_policy.PolicyGrant
    activation_grant: t2_user_policy.PolicyGrant
    session: t2_ipc_session.AuthorizationSession
    authority: t2_user_authority.RuntimeUserAuthority

    def dispatch_allowed(self) -> bool:
        try:
            self.session.revalidate()
            try:
                current_mapping = t2_user_authority.load(
                    self.authority.selected.linux_uid
                ).mapping_set
            except t2_user_authority.UserAuthorityError:
                current_mapping = t2_user_mapping.load(
                    t2_user_authority.MAPPING_PATH
                )
            now = time.monotonic_ns()
            return (
                current_mapping == self.authority.mapping_set
                and current_mapping.resolve(
                    self.authority.selected.linux_uid,
                    "verify",
                ) == self.authority.selected
                and self.operation_grant.authorized is True
                and self.activation_grant.authorized is True
                and now <= self.operation_grant.expires_monotonic_ns
                and now <= self.activation_grant.expires_monotonic_ns
            )
        except BaseException:
            return False


def collect(
    session: t2_ipc_session.AuthorizationSession,
    authority: t2_user_authority.RuntimeUserAuthority,
    *,
    operation: str,
    operation_id: str,
    linux_boot_uuid: str,
    runtime_generation: str,
) -> NativeMutationAuthorization:
    if not isinstance(session, t2_ipc_session.AuthorizationSession):
        raise NativeCallerAuthorizationError("caller authorization session is invalid")
    policy = t2_user_policy.OPERATION_POLICIES.get(operation)
    selected = authority.selected
    if (
        policy is None
        or policy.mutation is not True
        or session.caller.linux_uid != selected.linux_uid
        or session.account.generation != selected.linux_account_generation
    ):
        raise NativeCallerAuthorizationError(
            "caller is not bound to the native mutation authority"
        )
    operation_evidence = session.collect(
        target_linux_uid=selected.linux_uid,
        action=policy.action,
        mapping_generation=authority.mapping_set.generation,
        operation_id=operation_id,
        linux_boot_uuid=linux_boot_uuid,
        runtime_generation=runtime_generation,
        allow_user_interaction=True,
    )
    activation_evidence = session.collect(
        target_linux_uid=selected.linux_uid,
        action=t2_user_policy.ACTIVATE_ACTION,
        mapping_generation=authority.mapping_set.generation,
        operation_id=operation_id,
        linux_boot_uuid=linux_boot_uuid,
        runtime_generation=runtime_generation,
        allow_user_interaction=True,
    )
    operation_grant = operation_evidence.policy.grant
    activation_grant = activation_evidence.policy.grant
    expected = {
        "caller_linux_uid": selected.linux_uid,
        "linux_account_generation": selected.linux_account_generation,
        "target_linux_uid": selected.linux_uid,
        "mapping_generation": authority.mapping_set.generation,
        "operation_id": operation_id,
        "linux_boot_uuid": linux_boot_uuid,
        "runtime_generation": runtime_generation,
        "authorized": True,
    }
    if any(getattr(operation_grant, key, None) != value for key, value in expected.items()):
        raise NativeCallerAuthorizationError("operation grant is not exactly bound")
    if any(getattr(activation_grant, key, None) != value for key, value in expected.items()):
        raise NativeCallerAuthorizationError("activation grant is not exactly bound")
    if operation_grant.action != policy.action or activation_grant.action != t2_user_policy.ACTIVATE_ACTION:
        raise NativeCallerAuthorizationError("native mutation grant action is invalid")
    result = NativeMutationAuthorization(
        operation_grant, activation_grant, session, authority
    )
    if not result.dispatch_allowed():
        raise NativeCallerAuthorizationError("native mutation authority expired")
    return result
