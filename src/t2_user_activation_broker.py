# SPDX-License-Identifier: GPL-2.0-only
"""Policy-bound composition for one native AKS user activation request."""

from __future__ import annotations

import os
import socket
import stat
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import t2_aks_transport
import t2_ipc_session
import t2_user_authority
import t2_user_activation_operation
import t2_user_mapping
import t2_user_policy
import t2_user_readiness


BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
JOURNAL_ROOT = Path("/var/lib/t2-touchid/activation")
AuthorizationCollector = Callable[..., t2_ipc_session.AuthorizationEvidence]
TransportFactory = Callable[[], Any]
AuthorityLoader = Callable[[int], t2_user_authority.RuntimeUserAuthority]


class UserActivationBrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class UserActivationBrokerResult:
    outcome: str
    mutation_performed: bool
    reconciliation_required: bool
    journal_path: Path | None


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _boot_uuid(path: Path = BOOT_ID) -> str:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        raw = os.read(descriptor, 64)
        if os.read(descriptor, 1):
            raise UserActivationBrokerError("Linux boot ID is oversized")
    except OSError as error:
        raise UserActivationBrokerError("Linux boot ID is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = raw.decode("ascii").strip()
        parsed = uuid.UUID(value)
    except (UnicodeError, ValueError) as error:
        raise UserActivationBrokerError("Linux boot ID is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise UserActivationBrokerError("Linux boot ID is not canonical")
    return value


def _journal_path(root: Path, operation_id: str) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise UserActivationBrokerError("activation journal root is invalid")
    try:
        info = root.stat(follow_symlinks=False)
    except OSError as error:
        raise UserActivationBrokerError(
            "activation journal root is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise UserActivationBrokerError(
            "activation journal root is not private and broker-owned"
        )
    return root / f"{operation_id}.jsonl"


def _collect(
    collector: AuthorizationCollector,
    connection: socket.socket,
    *,
    target_linux_uid: int,
    action: str,
    mapping_generation: str,
    operation_id: str,
    linux_boot_uuid: str,
    allow_user_interaction: bool,
) -> t2_ipc_session.AuthorizationEvidence:
    evidence = collector(
        connection,
        target_linux_uid=target_linux_uid,
        action=action,
        mapping_generation=mapping_generation,
        operation_id=operation_id,
        linux_boot_uuid=linux_boot_uuid,
        allow_user_interaction=allow_user_interaction,
    )
    if not isinstance(evidence, t2_ipc_session.AuthorizationEvidence):
        raise UserActivationBrokerError(
            "authorization collector returned invalid evidence"
        )
    return evidence


def _peer_uid(connection: socket.socket) -> int:
    try:
        domain = connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
        socket_type = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            t2_ipc_session.PEERCRED.size,
        )
        if len(credentials) != t2_ipc_session.PEERCRED.size:
            raise UserActivationBrokerError(
                "activation peer credentials have the wrong size"
            )
        _pid, uid, _gid = t2_ipc_session.PEERCRED.unpack(credentials)
    except (OSError, ValueError) as error:
        raise UserActivationBrokerError(
            "activation peer credentials are unavailable"
        ) from error
    if (
        domain != socket.AF_UNIX
        or socket_type not in t2_ipc_session.ALLOWED_SOCKET_TYPES
        or type(uid) is not int
        or not 1 <= uid < (1 << 32) - 1
    ):
        raise UserActivationBrokerError("activation peer is not a supported user")
    return uid


def activate_from_protected_state(
    connection: socket.socket,
    *,
    password: bytearray | None,
    authority_loader: AuthorityLoader = t2_user_authority.load_runtime,
    journal_root: Path = JOURNAL_ROOT,
    authorization_collector: AuthorizationCollector = (
        t2_ipc_session.collect_authorization
    ),
    transport_factory: TransportFactory = t2_aks_transport.AKSActivationTransport,
    clock: Callable[[], int] = time.monotonic_ns,
    linux_boot_uuid: str | None = None,
    operation_id: str | None = None,
) -> UserActivationBrokerResult:
    """Activate only the connected peer's root-published runtime authority."""

    try:
        if os.geteuid() != 0:
            raise UserActivationBrokerError("activation service must run as root")
        target_linux_uid = _peer_uid(connection)
        authority = authority_loader(target_linux_uid)
        if not isinstance(authority, t2_user_authority.RuntimeUserAuthority):
            raise UserActivationBrokerError("authority loader returned invalid state")
        if authority.selected.linux_uid != target_linux_uid:
            raise UserActivationBrokerError("authority loader selected another user")
        return activate_for_peer(
            connection,
            target_linux_uid=target_linux_uid,
            mapping_set=authority.mapping_set,
            persistent=authority.persistent,
            password=password,
            journal_root=journal_root,
            authorization_collector=authorization_collector,
            transport_factory=transport_factory,
            clock=clock,
            linux_boot_uuid=linux_boot_uuid,
            operation_id=operation_id,
        )
    finally:
        _wipe(password)


def activate_for_peer(
    connection: socket.socket,
    *,
    target_linux_uid: int,
    mapping_set: t2_user_mapping.UserMappingSet,
    persistent: t2_user_readiness.PersistentEvidence,
    password: bytearray | None,
    journal_root: Path = JOURNAL_ROOT,
    authorization_collector: AuthorizationCollector = (
        t2_ipc_session.collect_authorization
    ),
    transport_factory: TransportFactory = t2_aks_transport.AKSActivationTransport,
    clock: Callable[[], int] = time.monotonic_ns,
    linux_boot_uuid: str | None = None,
    operation_id: str | None = None,
) -> UserActivationBrokerResult:
    """Authorize a pinned local peer and run one exact activation transaction."""

    if password is not None and not isinstance(password, bytearray):
        raise UserActivationBrokerError(
            "activation password must use caller-owned wipeable storage"
        )
    if not isinstance(connection, socket.socket):
        _wipe(password)
        raise UserActivationBrokerError("activation peer is not a Unix socket")
    if not isinstance(mapping_set, t2_user_mapping.UserMappingSet):
        _wipe(password)
        raise UserActivationBrokerError("activation mapping set is invalid")
    try:
        selected = mapping_set.resolve(target_linux_uid, "verify")
    except t2_user_mapping.UserMappingError as error:
        _wipe(password)
        raise UserActivationBrokerError("activation target is not enabled") from error
    operation_id = operation_id or str(uuid.uuid4())
    try:
        parsed_operation = uuid.UUID(operation_id)
    except (AttributeError, TypeError, ValueError) as error:
        _wipe(password)
        raise UserActivationBrokerError("activation operation ID is invalid") from error
    if parsed_operation.int == 0 or str(parsed_operation) != operation_id:
        _wipe(password)
        raise UserActivationBrokerError("activation operation ID is not canonical")
    transport = None
    journal_path: Path | None = None
    primary_error: BaseException | None = None
    result: t2_user_activation_operation.UserActivationOperationResult | None = None
    try:
        linux_boot_uuid = linux_boot_uuid or _boot_uuid()
        journal_path = _journal_path(journal_root, operation_id)
        transport = transport_factory()
        initial = transport.observe_alias(selected.special_bag_alias)
        operation_evidence = _collect(
            authorization_collector,
            connection,
            target_linux_uid=target_linux_uid,
            action=t2_user_policy.OPERATION_POLICIES["verify"].action,
            mapping_generation=mapping_set.generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            allow_user_interaction=False,
        )
        request = t2_user_policy.OperationRequest(
            "verify",
            target_linux_uid,
            operation_id,
            linux_boot_uuid,
            clock(),
            False,
        )
        decision = t2_user_policy.authorize(
            mapping_set,
            request,
            operation_evidence.caller,
            persistent,
            initial,
            operation_evidence.policy.grant,
        )
        if decision.state == "activation-authorization-required":
            activation_evidence = _collect(
                authorization_collector,
                connection,
                target_linux_uid=target_linux_uid,
                action=t2_user_policy.ACTIVATE_ACTION,
                mapping_generation=mapping_set.generation,
                operation_id=operation_id,
                linux_boot_uuid=linux_boot_uuid,
                # The caller has already supplied the PAM-authenticated
                # password that SEP will verify.  Activation still needs its
                # own exact PolicyKit grant, but must never open a second
                # password prompt from this non-interactive broker.
                allow_user_interaction=False,
            )
            if (
                activation_evidence.caller != operation_evidence.caller
                or activation_evidence.account != operation_evidence.account
                or activation_evidence.session != operation_evidence.session
            ):
                raise UserActivationBrokerError(
                    "activation caller changed between policy decisions"
                )
            request = t2_user_policy.OperationRequest(
                "verify",
                target_linux_uid,
                operation_id,
                linux_boot_uuid,
                clock(),
                False,
            )
            decision = t2_user_policy.authorize(
                mapping_set,
                request,
                operation_evidence.caller,
                persistent,
                initial,
                operation_evidence.policy.grant,
                activation_evidence.policy.grant,
            )
        if decision.state not in {"authorized", "activation-authorized"}:
            raise UserActivationBrokerError(
                f"activation policy was not satisfied: {decision.state}"
            )
        result = t2_user_activation_operation.run(
            journal_path,
            mapping_set,
            selected,
            "verify",
            persistent,
            transport,
            password,
            authorization=decision,
            linux_boot_uuid=linux_boot_uuid,
        )
    except BaseException as error:
        primary_error = error
    finally:
        _wipe(password)
        if transport is not None:
            try:
                transport.close()
            except BaseException as error:
                if primary_error is None:
                    primary_error = error
    if primary_error is not None:
        if isinstance(primary_error, UserActivationBrokerError):
            raise primary_error
        raise UserActivationBrokerError("native user activation failed closed") from primary_error
    if result is None:
        raise UserActivationBrokerError("native user activation returned no result")
    if result.mutation_performed and journal_path is None:
        raise UserActivationBrokerError("native user activation lost its journal")
    return UserActivationBrokerResult(
        result.outcome,
        result.mutation_performed,
        result.reconciliation_required,
        journal_path if result.mutation_performed else None,
    )
