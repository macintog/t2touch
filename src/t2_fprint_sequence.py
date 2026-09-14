# SPDX-License-Identifier: GPL-2.0-only
"""Stable five-slot allocation for neutral numbered fingerprint handles."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import secrets
import stat

import t2_fprint_identity


DEFAULT_ROOT = Path("/var/lib/t2-touchid/fprint-sequence")
MAX_STATE_BYTES = 4096
LEGACY_MAX_FINGER_NUMBER = 999_999_999


class FprintSequenceError(RuntimeError):
    pass


def next_reserved_handle(high_water: object, current_handles: object) -> str:
    """Choose the lowest vacant slot without renumbering retained handles.

    ``high_water`` remains validated for compatibility with already-installed
    state, but no longer selects a slot. Current reconciled membership is the
    authority for the fixed five-slot model.
    """

    if (
        type(high_water) is not int
        or not 0 <= high_water <= LEGACY_MAX_FINGER_NUMBER
    ):
        raise FprintSequenceError("finger sequence high-water mark is invalid")
    try:
        ordered = t2_fprint_identity.ordered(current_handles)
    except t2_fprint_identity.FprintIdentityError as error:
        raise FprintSequenceError("current neutral handle set is invalid") from error
    try:
        return t2_fprint_identity.next_handle(ordered)
    except t2_fprint_identity.FprintIdentityError as error:
        raise FprintSequenceError("fingerprint slot capacity is exhausted") from error


def _require_root(root: Path) -> None:
    if not isinstance(root, Path) or not root.is_absolute():
        raise FprintSequenceError("finger sequence root is invalid")
    try:
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = root.lstat()
    except OSError as error:
        raise FprintSequenceError("finger sequence root is unavailable") from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o077
    ):
        raise FprintSequenceError("finger sequence root is not private root state")


def _state(path: Path, apple_user_id: int) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return 0
    except OSError as error:
        raise FprintSequenceError("finger sequence state is unavailable") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_mode & 0o077
            or not 1 <= info.st_size <= MAX_STATE_BYTES
        ):
            raise FprintSequenceError("finger sequence state is not private")
        payload = os.read(descriptor, MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise FprintSequenceError("finger sequence state is malformed") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "apple_user_id", "high_water"}
        or value.get("schema_version") != 1
        or value.get("apple_user_id") != apple_user_id
        or type(value.get("high_water")) is not int
        or not 0 <= value["high_water"] <= LEGACY_MAX_FINGER_NUMBER
    ):
        raise FprintSequenceError("finger sequence state is inconsistent")
    return value["high_water"]


def _write(path: Path, apple_user_id: int, high_water: int) -> None:
    payload = (
        json.dumps(
            {
                "schema_version": 1,
                "apple_user_id": apple_user_id,
                "high_water": high_water,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    complete = False
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise FprintSequenceError("finger sequence write stopped")
            offset += written
        os.fsync(descriptor)
        os.replace(temporary, path)
        complete = True
    finally:
        os.close(descriptor)
        if not complete and os.path.lexists(temporary):
            temporary.unlink()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def reserve(
    apple_user_id: object,
    current_handles: object,
    *,
    root: Path = DEFAULT_ROOT,
) -> str:
    """Reserve the lowest vacant slot for one authorized enrollment attempt."""

    if type(apple_user_id) is not int or not 0 < apple_user_id < 1 << 32:
        raise FprintSequenceError("Apple user authority is invalid")
    try:
        ordered = t2_fprint_identity.ordered(current_handles)
    except t2_fprint_identity.FprintIdentityError as error:
        raise FprintSequenceError("current neutral handle set is invalid") from error
    _require_root(root)
    lock_path = root / f"{apple_user_id}.lock"
    state_path = root / f"{apple_user_id}.json"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise FprintSequenceError("finger sequence lock is unavailable") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_mode & 0o077
        ):
            raise FprintSequenceError("finger sequence lock is not private")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        result = next_reserved_handle(
            _state(state_path, apple_user_id), ordered
        )
        _write(state_path, apple_user_id, t2_fprint_identity.number(result))
        return result
    finally:
        os.close(descriptor)


def candidate(
    apple_user_id: object,
    current_handles: object,
    *,
    root: Path = DEFAULT_ROOT,
) -> str:
    """Choose the lowest vacant slot without consuming it before success.

    The biometric mutation lock serializes enrollment, and an uncertain
    mutation blocks every later mutation until reconciliation.  A cancelled
    or failed capture can therefore reuse this candidate safely. Retained
    identities keep their slots; only an actually vacant slot is reused.
    """

    if type(apple_user_id) is not int or not 0 < apple_user_id < 1 << 32:
        raise FprintSequenceError("Apple user authority is invalid")
    try:
        ordered = t2_fprint_identity.ordered(current_handles)
    except t2_fprint_identity.FprintIdentityError as error:
        raise FprintSequenceError("current neutral handle set is invalid") from error
    _require_root(root)
    lock_path = root / f"{apple_user_id}.lock"
    state_path = root / f"{apple_user_id}.json"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise FprintSequenceError("finger sequence lock is unavailable") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_mode & 0o077
        ):
            raise FprintSequenceError("finger sequence lock is not private")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return next_reserved_handle(_state(state_path, apple_user_id), ordered)
    finally:
        os.close(descriptor)


def reconcile(
    apple_user_id: object,
    known_handles: object,
    *,
    root: Path = DEFAULT_ROOT,
) -> int:
    """Retain compatibility state while validating fixed-slot history.

    Slot selection no longer depends on this historical high-water value.
    Existing deployments may keep the file, but current reconciled handles
    alone determine which of the five stable slots is vacant.
    """

    if type(apple_user_id) is not int or not 0 < apple_user_id < 1 << 32:
        raise FprintSequenceError("Apple user authority is invalid")
    try:
        ordered = t2_fprint_identity.ordered(known_handles)
    except t2_fprint_identity.FprintIdentityError as error:
        raise FprintSequenceError("known neutral handle history is invalid") from error
    if not ordered:
        raise FprintSequenceError("known neutral handle history is empty")
    _require_root(root)
    lock_path = root / f"{apple_user_id}.lock"
    state_path = root / f"{apple_user_id}.json"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise FprintSequenceError("finger sequence lock is unavailable") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_mode & 0o077
        ):
            raise FprintSequenceError("finger sequence lock is not private")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = _state(state_path, apple_user_id)
        observed = max(t2_fprint_identity.number(name) for name in ordered)
        reconciled = max(current, observed)
        if reconciled != current:
            _write(state_path, apple_user_id, reconciled)
        return reconciled
    finally:
        os.close(descriptor)
