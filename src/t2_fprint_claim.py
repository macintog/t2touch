# SPDX-License-Identifier: GPL-2.0-only
"""Stable local-account and login-session evidence for an fprint claim."""

from __future__ import annotations

import os
import pwd
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import t2_dbus_identity
import t2_ipc_session
import t2_linux_account
import t2_polkit_grant


class FprintClaimError(RuntimeError):
    pass


NameResolver = Callable[[str], object]
AccountCollector = Callable[[int], t2_linux_account.AccountEvidence]

POLKIT_AGENT_HELPER = Path("/usr/lib/polkit-1/polkit-agent-helper-1")
POLKIT_AGENT_CGROUP = re.compile(
    rb"0::/system\.slice/system-polkit\\x2dagent\\x2dhelper\.slice/"
    rb"polkit-agent-helper@[0-9]{1,20}-[0-9]{1,20}-"
    rb"[0-9]{1,20}_[0-9]{1,20}-([0-9]{1,10})\.service\n?"
)


def _resolve_uid(username: object, resolver: NameResolver) -> int:
    if type(username) is not str:
        raise FprintClaimError("claimed Linux username is invalid")
    try:
        encoded = username.encode("ascii")
    except UnicodeEncodeError as error:
        raise FprintClaimError("claimed Linux username is invalid") from error
    if t2_linux_account.ACCOUNT_NAME.fullmatch(encoded) is None:
        raise FprintClaimError("claimed Linux username is invalid")
    try:
        record = resolver(username)
        record_name = record.pw_name
        uid = record.pw_uid
    except (KeyError, OSError, AttributeError) as error:
        raise FprintClaimError("claimed Linux account is unavailable") from error
    if (
        type(record_name) is not str
        or record_name != username
        or type(uid) is not int
        or not 1 <= uid < t2_linux_account.UINT32_MAX
    ):
        raise FprintClaimError("claimed Linux account is invalid")
    return uid


def _account(
    collector: AccountCollector, uid: int
) -> t2_linux_account.AccountEvidence:
    try:
        value = collector(uid)
    except t2_linux_account.LinuxAccountError as error:
        raise FprintClaimError("Linux account assertion failed") from error
    try:
        return t2_ipc_session.validate_account(value, uid)
    except t2_ipc_session.IPCSessionError as error:
        raise FprintClaimError("Linux account assertion failed") from error


def _is_polkit_agent_helper(
    caller: t2_dbus_identity.PinnedDBusCaller,
    target_uid: int,
) -> bool:
    """Bind one root PAM caller to Polkit's exact socket helper instance."""

    subject = caller.subject
    if (
        subject.uid != t2_linux_account.ROOT_UID
        or subject.setuid_real_uid is not None
        or type(target_uid) is not int
        or not 1 <= target_uid < t2_linux_account.UINT32_MAX
    ):
        return False
    process_root = caller.proc_root / str(subject.pid)
    try:
        caller.verify()
        process = os.stat(process_root / "exe")
        expected = os.stat(POLKIT_AGENT_HELPER)
        cgroup = t2_polkit_grant._read_bounded(process_root / "cgroup")
        matched = POLKIT_AGENT_CGROUP.fullmatch(cgroup)
        if (
            not stat.S_ISREG(expected.st_mode)
            or expected.st_uid != t2_linux_account.ROOT_UID
            or expected.st_mode & 0o022
            or (process.st_dev, process.st_ino)
            != (expected.st_dev, expected.st_ino)
            or matched is None
            or int(matched.group(1), 10) != target_uid
        ):
            return False
        caller.verify()
        return True
    except (
        OSError,
        ValueError,
        t2_dbus_identity.DBusIdentityError,
        t2_polkit_grant.PolkitGrantError,
    ):
        return False


def _polkit_target_session(
    caller: t2_dbus_identity.PinnedDBusCaller,
    backend: t2_ipc_session.SessionBackend,
    uid: int,
) -> t2_ipc_session.SessionEvidence:
    if not _is_polkit_agent_helper(caller, uid):
        raise t2_ipc_session.IPCSessionError(
            "root fprint caller is not the target-bound Polkit helper"
        )
    acceptable = []
    for session in backend.active_sessions(uid):
        try:
            description = backend.describe(session)
        except t2_ipc_session.SessionUnavailable:
            continue
        if t2_ipc_session._acceptable(description, uid):
            acceptable.append((session, description))
    if len(acceptable) != 1:
        raise t2_ipc_session.IPCSessionError(
            "Polkit target has no unique active local physical login session"
        )
    caller.verify()
    session, description = acceptable[0]
    return t2_ipc_session.SessionEvidence(
        "polkit-agent-helper-active-session",
        session,
        description.session_type,
        description.session_class,
        True,
        description.start_time_usec,
    )


def _session(
    caller: t2_dbus_identity.PinnedDBusCaller,
    backend: t2_ipc_session.SessionBackend,
    uid: int,
) -> t2_ipc_session.SessionEvidence:
    direct_error = None
    try:
        with caller.duplicate_peer() as peer:
            return t2_ipc_session.collect_session(
                peer, backend, expected_uid=uid
            )
    except (
        t2_dbus_identity.DBusIdentityError,
        t2_ipc_session.IPCSessionError,
    ) as error:
        direct_error = error
    try:
        return _polkit_target_session(caller, backend, uid)
    except (
        t2_dbus_identity.DBusIdentityError,
        t2_ipc_session.IPCSessionError,
    ) as error:
        raise FprintClaimError(
            "active local login assertion failed"
        ) from direct_error or error


@dataclass(frozen=True, repr=False)
class ClaimEvidence:
    username: str = field(repr=False)
    linux_uid: int = field(repr=False)
    account: t2_linux_account.AccountEvidence = field(repr=False)
    session: t2_ipc_session.SessionEvidence = field(repr=False)
    backend: t2_ipc_session.SessionBackend = field(repr=False, compare=False)
    resolver: NameResolver = field(repr=False, compare=False)
    account_collector: AccountCollector = field(repr=False, compare=False)

    def revalidate(
        self,
        caller: t2_dbus_identity.PinnedDBusCaller,
    ) -> None:
        if not isinstance(caller, t2_dbus_identity.PinnedDBusCaller):
            raise FprintClaimError("pinned D-Bus caller is invalid")
        try:
            caller.verify()
        except t2_dbus_identity.DBusIdentityError as error:
            raise FprintClaimError("D-Bus caller changed") from error
        if _resolve_uid(self.username, self.resolver) != self.linux_uid:
            raise FprintClaimError("claimed Linux account changed")
        if _session(caller, self.backend, self.linux_uid) != self.session:
            raise FprintClaimError("claimed login session changed")
        if _account(self.account_collector, self.linux_uid) != self.account:
            raise FprintClaimError("claimed Linux account changed")
        try:
            caller.verify()
        except t2_dbus_identity.DBusIdentityError as error:
            raise FprintClaimError("D-Bus caller changed") from error

    def authorization_session(
        self,
        caller: t2_dbus_identity.PinnedDBusCaller,
    ) -> t2_ipc_session.AuthorizationSession:
        """Create self-service authority only for a same-UID non-root caller."""
        self.revalidate(caller)
        if (
            caller.subject.uid != self.linux_uid
            or caller.subject.setuid_real_uid is not None
        ):
            raise FprintClaimError(
                "root or cross-user fprint claims cannot authorize mutation"
            )
        authorization = None
        try:
            peer = caller.duplicate_peer()
            authorization = t2_ipc_session.AuthorizationSession.from_peer(
                peer,
                expected_uid=self.linux_uid,
                expected_session=self.session,
                expected_account=self.account,
                backend=self.backend,
                account_collector=self.account_collector,
            )
            caller.verify()
            return authorization
        except (
            t2_dbus_identity.DBusIdentityError,
            t2_ipc_session.IPCSessionError,
        ) as error:
            if authorization is not None:
                authorization.close()
            raise FprintClaimError(
                "fprint mutation authority could not be derived"
            ) from error

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "account": self.account.redacted(),
            "session": self.session.redacted(),
            "identifiers_redacted": True,
        }


def collect(
    caller: t2_dbus_identity.PinnedDBusCaller,
    username: object,
    *,
    backend: t2_ipc_session.SessionBackend | None = None,
    resolver: NameResolver = pwd.getpwnam,
    account_collector: AccountCollector = t2_linux_account.collect,
) -> ClaimEvidence:
    """Join one pidfd-bound caller to one stable local account/session."""

    if not isinstance(caller, t2_dbus_identity.PinnedDBusCaller):
        raise FprintClaimError("pinned D-Bus caller is invalid")
    selected_backend = backend or t2_ipc_session.LibsystemdSessionBackend()
    try:
        caller.verify()
    except t2_dbus_identity.DBusIdentityError as error:
        raise FprintClaimError("D-Bus caller changed") from error
    uid = _resolve_uid(username, resolver)
    first_session = _session(caller, selected_backend, uid)
    account = _account(account_collector, uid)
    if _resolve_uid(username, resolver) != uid:
        raise FprintClaimError("claimed Linux account changed")
    if _session(caller, selected_backend, uid) != first_session:
        raise FprintClaimError("claimed login session changed")
    try:
        caller.verify()
    except t2_dbus_identity.DBusIdentityError as error:
        raise FprintClaimError("D-Bus caller changed") from error
    return ClaimEvidence(
        username,
        uid,
        account,
        first_session,
        selected_backend,
        resolver,
        account_collector,
    )
