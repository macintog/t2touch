# SPDX-License-Identifier: GPL-2.0-only
"""Explicitly bind an intact Linux-native authority to a replacement account.

The imported mapping and its enrollment history remain byte-for-byte intact.
This root-owned record makes the prior account generation a compatible alias
only while the complete protected authority still validates for the same UID.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


STATE_ROOT = Path("/var/lib/t2-touchid")
MANIFEST_NAME = "native-account-rebind.json"
ORIGIN = "linux-native-authority-migration"
ROOT_UID = 0
MAX_MANIFEST_SIZE = 16 * 1024


class NativeAccountRebindError(RuntimeError):
    pass


class _Selected(Protocol):
    linux_uid: int
    linux_account_generation: str
    keybag_path: str
    keybag_sha256: str
    activation_secret_path: str | None
    activation_secret_sha256: str | None
    activation_secret_length: int | None


class _MappingSet(Protocol):
    generation: str


class NativeAuthority(Protocol):
    mapping_set: _MappingSet
    selected: _Selected
    origin: str


AuthorityLoader = Callable[..., NativeAuthority]
AccountCollector = Callable[[int], object]


@dataclass(frozen=True, repr=False)
class NativeAccountRebindResult:
    state: str
    linux_uid: int
    mapping_generation: str

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": self.state,
            "linux_uid": self.linux_uid,
            "complete_authority_validated": True,
            "identifiers_redacted": True,
        }


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeAccountRebindError(
                "native account rebind contains a duplicate key"
            )
        result[key] = value
    return result


def _sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise NativeAccountRebindError(f"{label} is invalid")
    return value


def _uid(value: object) -> int:
    if type(value) is not int or not 1 <= value < (1 << 32) - 1:
        raise NativeAccountRebindError("Linux UID is invalid")
    return value


def _private_directory(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise NativeAccountRebindError(
            "native account rebind directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_mode & 0o077
    ):
        raise NativeAccountRebindError(
            "native account rebind directory is not private and root-owned"
        )


def _read(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != ROOT_UID
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= MAX_MANIFEST_SIZE
        ):
            raise NativeAccountRebindError(
                "native account rebind is not a private root-owned file"
            )
        data = bytearray()
        while len(data) < before.st_size:
            block = os.read(descriptor, before.st_size - len(data))
            if not block:
                raise NativeAccountRebindError(
                    "native account rebind read was short"
                )
            data.extend(block)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if os.read(descriptor, 1) or any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise NativeAccountRebindError(
                "native account rebind changed during read"
            )
        try:
            value = json.loads(data.decode("ascii"), object_pairs_hook=_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise NativeAccountRebindError(
                "native account rebind is not strict JSON"
            ) from error
    except OSError as error:
        raise NativeAccountRebindError(
            "native account rebind cannot be read safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise NativeAccountRebindError("native account rebind has the wrong type")
    return value


def _load_authority(
    linux_uid: int,
    state_root: Path,
    authority_loader: AuthorityLoader | None,
) -> NativeAuthority:
    if authority_loader is None:
        import t2_user_authority

        authority_loader = t2_user_authority.load
    try:
        authority = authority_loader(
            linux_uid,
            mapping_path=state_root / "users.json",
            users_root=state_root / "users",
        )
    except Exception as error:
        raise NativeAccountRebindError(
            "complete native authority does not validate"
        ) from error
    selected = authority.selected
    keybag = _relocated(selected.keybag_path, state_root, "keybag")
    keybag_digest, _ = _private_digest(keybag, 16 * 1024 * 1024)
    if keybag_digest != selected.keybag_sha256:
        raise NativeAccountRebindError("native authority keybag does not validate")
    if (
        selected.activation_secret_path is None
        or selected.activation_secret_sha256 is None
        or selected.activation_secret_length is None
    ):
        raise NativeAccountRebindError(
            "native authority activation material is incomplete"
        )
    activation = _relocated(
        selected.activation_secret_path, state_root, "activation material"
    )
    activation_digest, activation_length = _private_digest(
        activation, 1024 * 1024
    )
    if (
        activation_digest != selected.activation_secret_sha256
        or activation_length != selected.activation_secret_length
    ):
        raise NativeAccountRebindError(
            "native authority activation material does not validate"
        )
    return authority


def _relocated(recorded: str, state_root: Path, label: str) -> Path:
    try:
        source = Path(recorded)
        relative = source.relative_to(STATE_ROOT)
    except (TypeError, ValueError) as error:
        raise NativeAccountRebindError(
            f"native authority {label} path is invalid"
        ) from error
    if (
        not source.is_absolute()
        or not relative.parts
        or any(part in {".", ".."} for part in relative.parts)
    ):
        raise NativeAccountRebindError(
            f"native authority {label} path is invalid"
        )
    return state_root / relative


def _private_digest(path: Path, maximum: int) -> tuple[str, int]:
    descriptor = -1
    digest = hashlib.sha256()
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != ROOT_UID
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= maximum
        ):
            raise NativeAccountRebindError(
                "native authority private material is unsafe"
            )
        read = 0
        while read < before.st_size:
            block = os.read(descriptor, min(65536, before.st_size - read))
            if not block:
                raise NativeAccountRebindError(
                    "native authority private material read was short"
                )
            digest.update(block)
            read += len(block)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if os.read(descriptor, 1) or any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise NativeAccountRebindError(
                "native authority private material changed during read"
            )
        return digest.hexdigest(), read
    except OSError as error:
        raise NativeAccountRebindError(
            "native authority private material is unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def resolve(
    linux_uid: int,
    current_generation: str,
    *,
    state_root: Path = STATE_ROOT,
    authority_loader: AuthorityLoader | None = None,
) -> str | None:
    """Return the proven prior generation, or None when no rebind exists."""

    linux_uid = _uid(linux_uid)
    current_generation = _sha256(current_generation, "current account generation")
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise NativeAccountRebindError("native authority state root is invalid")
    path = state_root / "users" / str(linux_uid) / MANIFEST_NAME
    if not os.path.lexists(path):
        return None
    if os.geteuid() != ROOT_UID:
        raise NativeAccountRebindError("native account rebind requires root")
    _private_directory(state_root)
    _private_directory(state_root / "users")
    _private_directory(path.parent)
    document = _read(path)
    fields = {
        "schema_version",
        "origin",
        "operation_id",
        "linux_uid",
        "previous_account_generation",
        "current_account_generation",
        "mapping_generation",
    }
    try:
        operation_id = str(uuid.UUID(document.get("operation_id")))
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeAccountRebindError(
            "native account rebind operation ID is invalid"
        ) from error
    previous = _sha256(
        document.get("previous_account_generation"),
        "previous account generation",
    )
    rebound = _sha256(
        document.get("current_account_generation"),
        "rebound account generation",
    )
    mapping_generation = _sha256(
        document.get("mapping_generation"), "mapping generation"
    )
    if (
        set(document) != fields
        or document["schema_version"] != 1
        or document["origin"] != ORIGIN
        or document["operation_id"] != operation_id
        or document["linux_uid"] != linux_uid
        or rebound != current_generation
        or previous == rebound
    ):
        raise NativeAccountRebindError(
            "native account rebind does not match the current account"
        )
    authority = _load_authority(linux_uid, state_root, authority_loader)
    if (
        authority.origin != "linux-native-e4"
        or authority.selected.linux_uid != linux_uid
        or authority.selected.linux_account_generation != previous
        or authority.mapping_set.generation != mapping_generation
    ):
        raise NativeAccountRebindError(
            "native account rebind does not match its complete authority"
        )
    return previous


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    complete = False
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise NativeAccountRebindError(
                    "native account rebind write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        complete = True
    except OSError as error:
        raise NativeAccountRebindError(
            "native account rebind could not be published"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not complete:
            try:
                path.unlink()
            except OSError:
                pass


def publish(
    linux_uid: int,
    *,
    acknowledge_complete_native_authority_migration: bool,
    state_root: Path = STATE_ROOT,
    account_collector: AccountCollector | None = None,
    authority_loader: AuthorityLoader | None = None,
) -> NativeAccountRebindResult:
    """Publish one explicit rebind after complete native state migration."""

    if os.geteuid() != ROOT_UID:
        raise NativeAccountRebindError("native account rebind requires root")
    if acknowledge_complete_native_authority_migration is not True:
        raise NativeAccountRebindError(
            "complete native authority migration acknowledgement is required"
        )
    linux_uid = _uid(linux_uid)
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise NativeAccountRebindError("native authority state root is invalid")
    _private_directory(state_root)
    _private_directory(state_root / "users")
    user_root = state_root / "users" / str(linux_uid)
    _private_directory(user_root)
    path = user_root / MANIFEST_NAME
    if os.path.lexists(path):
        raise NativeAccountRebindError("native account rebind already exists")
    authority = _load_authority(linux_uid, state_root, authority_loader)
    if authority.origin != "linux-native-e4":
        raise NativeAccountRebindError("authority is not Linux-native")
    if account_collector is None:
        import t2_linux_account

        account_collector = t2_linux_account.collect
    try:
        current = account_collector(linux_uid)
        current_generation = _sha256(
            getattr(current, "generation", None), "current account generation"
        )
        matches = getattr(current, "matches_generation")
    except Exception as error:
        raise NativeAccountRebindError(
            "current Linux account cannot be asserted"
        ) from error
    previous = authority.selected.linux_account_generation
    if matches(previous):
        raise NativeAccountRebindError(
            "native authority account generation is already current"
        )
    operation_id = str(uuid.uuid4())
    document = {
        "schema_version": 1,
        "origin": ORIGIN,
        "operation_id": operation_id,
        "linux_uid": linux_uid,
        "previous_account_generation": previous,
        "current_account_generation": current_generation,
        "mapping_generation": authority.mapping_set.generation,
    }
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    _write_exclusive(path, encoded)
    directory = os.open(user_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    try:
        resolved = resolve(
            linux_uid,
            current_generation,
            state_root=state_root,
            authority_loader=authority_loader,
        )
    except Exception:
        try:
            path.unlink()
        finally:
            raise
    if resolved != previous:
        path.unlink()
        raise NativeAccountRebindError(
            "native account rebind failed protected readback"
        )
    return NativeAccountRebindResult(
        "native-authority-rebound-to-current-account",
        linux_uid,
        authority.mapping_set.generation,
    )
