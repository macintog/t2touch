# SPDX-License-Identifier: GPL-2.0-only
"""Collect a conservative generation for one local Linux account.

Traditional NSS/passwd accounts have no immutable account UUID.  This module
therefore supports only a deliberately strict local-files profile: it binds the
numeric UID to the exact local passwd record, the protected shadow record, the
root-owned passwd database epoch, and the home-directory filesystem object.
Deleting and recreating an account, changing its password/account record, or
replacing the passwd database changes the resulting generation. Home binding
uses statx birth time and inode plus a stable filesystem ID so immediate inode
reuse cannot impersonate the old directory. Btrfs identity is derived from its
on-disk filesystem UUID and subvolume ID because ``fstatvfs`` values can change
across kernel upgrades. Linux statx mount IDs are intentionally excluded
because they are allocated at mount time and can change across an otherwise
identical reboot.

The shadow record is hashed while held in a wipeable buffer.  It is never
returned, logged, or included in redacted output.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
import pwd
import re
import stat
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol


SCHEMA_VERSION = 2
ROOT_UID = 0
UINT32_MAX = (1 << 32) - 1
MAX_ACCOUNT_FILE = 4 * 1024 * 1024
MAX_ACCOUNT_LINE = 64 * 1024
LOCAL_PASSWD = Path("/etc/passwd")
LOCAL_SHADOW = Path("/etc/shadow")
ACCOUNT_NAME = re.compile(rb"[a-z_][a-z0-9_.-]{0,63}\Z", re.ASCII)
LENGTH = struct.Struct(">Q")
AT_EMPTY_PATH = 0x1000
STATX_BASIC_STATS = 0x000007FF
STATX_BTIME = 0x00000800
STATX_BUFFER_SIZE = 256
BTRFS_FS_INFO_SIZE = 1024
BTRFS_SUBVOL_INFO_SIZE = 504
BTRFS_IOC_FS_INFO = 0x8400941F
BTRFS_IOC_GET_SUBVOL_INFO = 0x81F8943C


class LinuxAccountError(RuntimeError):
    """Raised when a stable, protected local-account assertion is impossible."""


class PasswdRecord(Protocol):
    pw_name: str
    pw_passwd: str
    pw_uid: int
    pw_gid: int
    pw_gecos: str
    pw_dir: str
    pw_shell: str


Resolver = Callable[[int], PasswdRecord]


@dataclass(frozen=True, repr=False)
class AccountEvidence:
    linux_uid: int
    generation: str
    source: str = "local-files-v2"
    protected_password_record: bool = True
    home_object_bound: bool = True
    compatible_generations: frozenset[str] = field(
        default_factory=frozenset,
        repr=False,
        compare=False,
    )

    def matches_generation(self, generation: str) -> bool:
        """Match a supported filesystem encoding or explicit migration binding."""

        return generation == self.generation or generation in self.compatible_generations

    def generations_are_valid(self) -> bool:
        if not isinstance(self.compatible_generations, frozenset):
            return False
        generations = {self.generation, *self.compatible_generations}
        return (
            len(generations) == 1 + len(self.compatible_generations)
            and all(
                isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
                for value in generations
            )
        )

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "source": self.source,
            "protected_password_record": self.protected_password_record,
            "home_object_bound": self.home_object_bound,
            "identifiers_redacted": True,
        }


@dataclass(frozen=True, repr=False)
class _FileMetadata:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, repr=False)
class _PasswdSnapshot:
    metadata: _FileMetadata
    database_digest: bytes
    record_digest: bytes
    name: bytes
    gid: int
    gecos: bytes
    home: bytes
    shell: bytes


@dataclass(frozen=True, repr=False)
class _HomeIdentity:
    filesystem_id: int
    inode: int
    birth_time_sec: int
    birth_time_nsec: int
    compatible_filesystem_ids: frozenset[int] = field(
        default_factory=frozenset,
        repr=False,
        compare=False,
    )


def _btrfs_filesystem_id(descriptor: int) -> int | None:
    """Return the pre-7.2 Btrfs statfs identity from persistent inputs."""

    filesystem = bytearray(BTRFS_FS_INFO_SIZE)
    try:
        try:
            fcntl.ioctl(descriptor, BTRFS_IOC_FS_INFO, filesystem, True)
        except OSError:
            return None
        subvolume = bytearray(BTRFS_SUBVOL_INFO_SIZE)
        try:
            fcntl.ioctl(
                descriptor,
                BTRFS_IOC_GET_SUBVOL_INFO,
                subvolume,
                True,
            )
        except OSError as error:
            raise LinuxAccountError(
                "stable Btrfs home identity is unavailable"
            ) from error
        fsid = bytes(filesystem[16:32])
        tree_id = struct.unpack_from("=Q", subvolume)[0]
        if fsid == bytes(16) or tree_id == 0:
            raise LinuxAccountError("stable Btrfs home identity is incomplete")
        first, second, third, fourth = struct.unpack(">IIII", fsid)
        low = first ^ third ^ (tree_id >> 32)
        high = second ^ fourth ^ (tree_id & UINT32_MAX)
        filesystem_id = (high << 32) | low
        if filesystem_id == 0:
            raise LinuxAccountError("stable Btrfs home identity is incomplete")
        return filesystem_id
    finally:
        filesystem[:] = b"\0" * len(filesystem)


def _stable_filesystem_id(descriptor: int) -> int:
    btrfs_id = _btrfs_filesystem_id(descriptor)
    if btrfs_id is not None:
        return btrfs_id
    try:
        filesystem_id = os.fstatvfs(descriptor).f_fsid
    except (AttributeError, OSError) as error:
        raise LinuxAccountError(
            "stable home filesystem identity is unavailable"
        ) from error
    if type(filesystem_id) is not int or filesystem_id == 0:
        raise LinuxAccountError("stable home filesystem identity is unavailable")
    return filesystem_id


def _checked_uid(uid: object) -> int:
    if type(uid) is not int or not 1 <= uid < UINT32_MAX:
        raise LinuxAccountError("Linux account UID is invalid")
    return uid


def _metadata(info: os.stat_result) -> _FileMetadata:
    return _FileMetadata(
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _open_account_file(path: Path, *, secret: bool) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise LinuxAccountError("account database path is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise LinuxAccountError("local account database is unavailable") from error
    allowed = 0 if secret else 0o044
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or (secret and info.st_mode & 0o077)
        or (not secret and info.st_mode & 0o077) != allowed
        or not 0 < info.st_size <= MAX_ACCOUNT_FILE
    ):
        os.close(descriptor)
        raise LinuxAccountError("local account database metadata is unsafe")
    return descriptor


def _read_stable(path: Path, *, secret: bool) -> tuple[bytearray, _FileMetadata]:
    descriptor = _open_account_file(path, secret=secret)
    data = bytearray()
    try:
        before = os.fstat(descriptor)
        while len(data) <= MAX_ACCOUNT_FILE:
            block = os.read(
                descriptor, min(65536, MAX_ACCOUNT_FILE + 1 - len(data))
            )
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or len(data) > MAX_ACCOUNT_FILE
            or _metadata(before) != _metadata(after)
            or b"\0" in data
        ):
            raise LinuxAccountError("local account database changed during read")
        return data, _metadata(after)
    except BaseException:
        data[:] = b"\0" * len(data)
        raise
    finally:
        os.close(descriptor)


def _lines(data: bytearray):
    start = 0
    while start < len(data):
        end = data.find(b"\n", start)
        if end < 0:
            end = len(data)
        if end > start:
            if end - start > MAX_ACCOUNT_LINE:
                raise LinuxAccountError("local account record is overlong")
            yield memoryview(data)[start:end]
        start = end + 1


def _field_equals(field: memoryview, expected: bytes) -> bool:
    return len(field) == len(expected) and all(
        value == expected[index] for index, value in enumerate(field)
    )


def _split_fields(line: memoryview, count: int) -> tuple[memoryview, ...]:
    boundaries = [-1]
    for index, value in enumerate(line):
        if value == ord(":"):
            boundaries.append(index)
    boundaries.append(len(line))
    if len(boundaries) != count + 1:
        raise LinuxAccountError("local account record has an invalid field count")
    return tuple(
        line[boundaries[index] + 1 : boundaries[index + 1]]
        for index in range(count)
    )


def _decimal(field: memoryview, label: str) -> int:
    if not field or any(value < ord("0") or value > ord("9") for value in field):
        raise LinuxAccountError(f"local account {label} is invalid")
    value = 0
    for character in field:
        value = value * 10 + character - ord("0")
        if value >= UINT32_MAX:
            raise LinuxAccountError(f"local account {label} is invalid")
    return value


def _digest_view(view: memoryview) -> bytes:
    digest = hashlib.sha256()
    digest.update(view)
    return digest.digest()


def _passwd_snapshot(path: Path, uid: int) -> _PasswdSnapshot:
    data, metadata = _read_stable(path, secret=False)
    matches: list[tuple[memoryview, tuple[memoryview, ...]]] = []
    seen_names: set[bytes] = set()
    try:
        for line in _lines(data):
            fields = _split_fields(line, 7)
            name = bytes(fields[0])
            if ACCOUNT_NAME.fullmatch(name) is None or name in seen_names:
                raise LinuxAccountError("local passwd names are invalid or duplicated")
            seen_names.add(name)
            row_uid = _decimal(fields[2], "UID")
            if row_uid == uid:
                matches.append((line, fields))
        if len(matches) != 1:
            raise LinuxAccountError("Linux UID has no unique local passwd record")
        line, fields = matches[0]
        name = bytes(fields[0])
        gid = _decimal(fields[3], "primary GID")
        home = bytes(fields[5])
        shell = bytes(fields[6])
        try:
            home_text = home.decode("utf-8")
            shell_text = shell.decode("utf-8")
        except UnicodeDecodeError as error:
            raise LinuxAccountError("local account paths are not UTF-8") from error
        pure_home = PurePosixPath(home_text)
        pure_shell = PurePosixPath(shell_text)
        if (
            not pure_home.is_absolute()
            or str(pure_home) != home_text
            or home_text == "/"
            or len(home) > 4096
            or not pure_shell.is_absolute()
            or str(pure_shell) != shell_text
            or len(shell) > 4096
        ):
            raise LinuxAccountError("local account paths are unsafe")
        return _PasswdSnapshot(
            metadata,
            hashlib.sha256(data).digest(),
            _digest_view(line),
            name,
            gid,
            bytes(fields[4]),
            home,
            shell,
        )
    finally:
        # Passwd is public, but clearing keeps the reader's lifetime uniform.
        data[:] = b"\0" * len(data)


def _shadow_record_digest(path: Path, name: bytes) -> bytes:
    data, _ = _read_stable(path, secret=True)
    matches: list[memoryview] = []
    try:
        for line in _lines(data):
            fields = _split_fields(line, 9)
            if _field_equals(fields[0], name):
                matches.append(line)
                password = fields[1]
                if (
                    not password
                    or _field_equals(password, b"!")
                    or _field_equals(password, b"*")
                    or _field_equals(password, b"!!")
                ):
                    raise LinuxAccountError(
                        "local account has no usable protected password record"
                    )
        if len(matches) != 1:
            raise LinuxAccountError("Linux account has no unique shadow record")
        return _digest_view(matches[0])
    finally:
        data[:] = b"\0" * len(data)


def _statx_home_identity(
    descriptor: int, info: os.stat_result
) -> _HomeIdentity:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        statx = libc.statx
    except (OSError, AttributeError) as error:
        raise LinuxAccountError("kernel statx account binding is unavailable") from error
    statx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
    ]
    statx.restype = ctypes.c_int
    output = ctypes.create_string_buffer(STATX_BUFFER_SIZE)
    result = statx(
        descriptor,
        b"",
        AT_EMPTY_PATH,
        STATX_BASIC_STATS | STATX_BTIME,
        ctypes.byref(output),
    )
    if result != 0:
        raise LinuxAccountError("kernel statx account binding failed")
    raw = output.raw
    mask = struct.unpack_from("=I", raw, 0)[0]
    statx_uid = struct.unpack_from("=I", raw, 20)[0]
    statx_mode = struct.unpack_from("=H", raw, 28)[0]
    inode = struct.unpack_from("=Q", raw, 32)[0]
    birth_sec, birth_nsec = struct.unpack_from("=qI", raw, 80)
    device_major = struct.unpack_from("=I", raw, 136)[0]
    device_minor = struct.unpack_from("=I", raw, 140)[0]
    required = STATX_BASIC_STATS | STATX_BTIME
    filesystem_id = _stable_filesystem_id(descriptor)
    try:
        runtime_filesystem_id = os.fstatvfs(descriptor).f_fsid
    except (AttributeError, OSError) as error:
        raise LinuxAccountError(
            "runtime home filesystem identity is unavailable"
        ) from error
    if type(runtime_filesystem_id) is not int or runtime_filesystem_id == 0:
        raise LinuxAccountError("runtime home filesystem identity is unavailable")
    if (
        mask & required != required
        or statx_uid != info.st_uid
        or statx_mode != info.st_mode
        or inode != info.st_ino
        or device_major != os.major(info.st_dev)
        or device_minor != os.minor(info.st_dev)
        or birth_sec <= 0
        or not 0 <= birth_nsec < 1_000_000_000
    ):
        raise LinuxAccountError("kernel statx account binding is incomplete")
    return _HomeIdentity(
        filesystem_id,
        int(info.st_ino),
        birth_sec,
        birth_nsec,
        frozenset({runtime_filesystem_id} - {filesystem_id}),
    )


def _home_identity(path: bytes, uid: int) -> _HomeIdentity:
    try:
        decoded = path.decode("utf-8")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(decoded, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
                raise LinuxAccountError(
                    "local account home object has unsafe ownership"
                )
            identity = _statx_home_identity(descriptor, info)
        finally:
            os.close(descriptor)
    except (OSError, UnicodeDecodeError) as error:
        raise LinuxAccountError("local account home object is unavailable") from error
    return identity


def _nss_matches(snapshot: _PasswdSnapshot, uid: int, resolver: Resolver) -> None:
    try:
        record = resolver(uid)
        encoded = (
            record.pw_name.encode("utf-8"),
            record.pw_passwd.encode("utf-8"),
            record.pw_gecos.encode("utf-8"),
            record.pw_dir.encode("utf-8"),
            record.pw_shell.encode("utf-8"),
        )
    except (KeyError, UnicodeError, AttributeError, OSError) as error:
        raise LinuxAccountError("NSS cannot resolve the local Linux UID") from error
    expected = (
        snapshot.name,
        b"x",
        snapshot.gecos,
        snapshot.home,
        snapshot.shell,
    )
    if (
        encoded != expected
        or type(record.pw_uid) is not int
        or record.pw_uid != uid
        or type(record.pw_gid) is not int
        or record.pw_gid != snapshot.gid
    ):
        raise LinuxAccountError("NSS and the protected local account disagree")


def _update_framed(digest, label: bytes, value: bytes) -> None:
    digest.update(LENGTH.pack(len(label)))
    digest.update(label)
    digest.update(LENGTH.pack(len(value)))
    digest.update(value)


def _generation(
    uid: int,
    passwd: _PasswdSnapshot,
    shadow_digest: bytes,
    home: _HomeIdentity,
) -> str:
    digest = hashlib.sha256()
    values = (
        (b"schema", str(SCHEMA_VERSION).encode("ascii")),
        (b"uid", str(uid).encode("ascii")),
        (b"passwd-database-digest", passwd.database_digest),
        (b"record-digest", passwd.record_digest),
        (b"shadow-record-digest", shadow_digest),
        (b"home-filesystem-id", str(home.filesystem_id).encode("ascii")),
        (b"home-inode", str(home.inode).encode("ascii")),
        (b"home-birth-sec", str(home.birth_time_sec).encode("ascii")),
        (b"home-birth-nsec", str(home.birth_time_nsec).encode("ascii")),
    )
    for label, value in values:
        _update_framed(digest, label, value)
    return digest.hexdigest()


def collect(
    uid: int,
    *,
    passwd_path: Path = LOCAL_PASSWD,
    shadow_path: Path = LOCAL_SHADOW,
    resolver: Resolver = pwd.getpwuid,
) -> AccountEvidence:
    """Return stable local-account evidence or fail without partial authority."""

    uid = _checked_uid(uid)
    first_passwd = _passwd_snapshot(passwd_path, uid)
    first_shadow = _shadow_record_digest(shadow_path, first_passwd.name)
    _nss_matches(first_passwd, uid, resolver)
    home = _home_identity(first_passwd.home, uid)
    second_passwd = _passwd_snapshot(passwd_path, uid)
    second_shadow = _shadow_record_digest(shadow_path, second_passwd.name)
    _nss_matches(second_passwd, uid, resolver)
    if first_passwd != second_passwd or first_shadow != second_shadow:
        raise LinuxAccountError("local account changed during assertion")
    generation = _generation(uid, second_passwd, second_shadow, home)
    compatible_generations = frozenset(
        _generation(
            uid,
            second_passwd,
            second_shadow,
            _HomeIdentity(
                filesystem_id,
                home.inode,
                home.birth_time_sec,
                home.birth_time_nsec,
            ),
        )
        for filesystem_id in home.compatible_filesystem_ids
    )
    try:
        import t2_native_account_rebind

        migrated_generation = t2_native_account_rebind.resolve(
            uid, generation
        )
    except (ImportError, RuntimeError) as error:
        raise LinuxAccountError(
            "native account migration binding is invalid"
        ) from error
    if migrated_generation is not None:
        compatible_generations = frozenset(
            (*compatible_generations, migrated_generation)
        )
    return AccountEvidence(uid, generation, compatible_generations=compatible_generations)
