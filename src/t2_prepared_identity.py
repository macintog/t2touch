# SPDX-License-Identifier: GPL-2.0-only
"""Retain a generation-bound hardware capability, never a caller or verdict."""

from contextlib import contextmanager, nullcontext
import time

import t2_aks_transport
import t2_acm_device
import t2_user_activation_operation as activation
import t2_user_policy
import t2_user_readiness


class PreparedAuthorizationExpired(RuntimeError):
    """A reused capability needs a new, fully authorized preparation."""


class PreparedIdentity:
    def __init__(self, close_scope=nullcontext):
        self.transport = None
        self.retention = None
        self.binding = None
        self.close_scope = close_scope
        self.acm_device = None
        self.authorization = None
        self.proof = None

    def close(self):
        retention, transport = self.retention, self.transport
        authorization, acm_device = self.authorization, self.acm_device
        self.retention = self.transport = self.binding = None
        self.authorization = self.acm_device = self.proof = None
        try:
            if retention is not None or authorization is not None:
                with self.close_scope():
                    try:
                        if authorization is not None:
                            authorization.__exit__(None, None, None)
                    finally:
                        if retention is not None:
                            retention.__exit__(None, None, None)
        finally:
            try:
                if acm_device is not None:
                    acm_device.close()
            finally:
                if transport is not None:
                    transport.close()

    @contextmanager
    def open(self, authority, configuration, linux_boot_uuid):
        binding = (
            authority.mapping_set, authority.selected, authority.persistent,
            tuple(sorted(configuration.items())), linux_boot_uuid,
        )
        if self.binding is not None and self.binding != binding:
            self.close()
        if self.transport is None:
            self.transport = t2_aks_transport.AKSActivationTransport()
            self.binding = binding
        try:
            if self.retention is not None:
                self.transport.require_current_generation(
                    authorized_context=self.authorization is not None
                )
            yield self.transport
        except BaseException:
            self.close()
            raise

    @contextmanager
    def open_acm(self):
        if self.acm_device is None:
            self.acm_device = t2_acm_device.ACMDevice()
        else:
            self.acm_device.require_current_generation()
        yield self.acm_device

    @contextmanager
    def authorize(self, device, user_id, secret, binder, *,
                  include_authorization_context=False):
        if device is not self.acm_device or not include_authorization_context:
            raise RuntimeError("prepared authorization has no owned context")
        reused = self.authorization is not None
        if not reused:
            @contextmanager
            def owned_authorization():
                try:
                    with t2_acm_device.identity_authorized_context(
                        device, user_id, secret, binder,
                        include_authorization_context=True,
                    ) as proof:
                        yield proof
                except t2_acm_device.ACMContextCleanupError as error:
                    # The login transition may consume its input context.
                    # Apply the same fresh-owner cleanup proof as cold matching.
                    t2_acm_device.reconcile_identity_cleanup_after_close(error, device)
            authorization = owned_authorization()
            self.proof = authorization.__enter__()
            self.authorization = authorization
        # Externalization returns the exact live handle, not a serialized
        # cached policy decision. Ask SEP to evaluate that policy again now.
        protocol = t2_acm_device.protocol
        handle = protocol.ContextHandle(self.proof[3], 0, True, False)
        live = protocol.parse_policy_response(device.exchange(
            protocol.build_enrollment_policy(handle, preflight=False),
            protocol.POLICY_RESPONSE_CAPACITY,
        ))
        if not live.satisfied:
            if reused:
                raise PreparedAuthorizationExpired("prepared authorization policy is no longer satisfied")
            raise RuntimeError("prepared authorization policy is no longer satisfied")
        yield self.proof[0], live, self.proof[2], self.proof[3]

    @contextmanager
    def retain(self, path, mapping_set, selected, capability, persistent,
               transport, *, authorization, linux_boot_uuid):
        if transport is not self.transport or self.binding is None:
            raise RuntimeError("prepared identity has no owned transport")
        if self.retention is None:
            retention = activation.retain_ready_identity_handle(
                path, mapping_set, selected, capability, persistent, transport,
                authorization=authorization, linux_boot_uuid=linux_boot_uuid,
            )
            state = retention.__enter__()
            self.retention = retention
        else:
            # Every request still receives its own bound caller decision;
            # the retained ACM capability is separately re-evaluated by SEP.
            t2_user_policy.require_bound_authority(
                authorization, mapping_set, selected, capability,
                linux_boot_uuid=linux_boot_uuid,
                runtime_generation=transport.runtime_generation,
                observed_monotonic_ns=time.monotonic_ns(), activation=False,
            )
            state = t2_user_readiness.assess(
                selected, capability, persistent,
                transport.observe_alias(selected.special_bag_alias),
            ).state
            if state != "ready":
                raise RuntimeError("prepared identity is no longer ready")
        yield state
        if t2_user_readiness.assess(
            selected, capability, persistent,
            transport.observe_alias(selected.special_bag_alias),
        ).state != "ready":
            raise RuntimeError("prepared identity changed during verification")
