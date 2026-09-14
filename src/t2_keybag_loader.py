# SPDX-License-Identifier: GPL-2.0-only
"""Resolve the compatibility keybag from its validated runtime authority."""

from __future__ import annotations

import os
import pwd
import re
import stat
from pathlib import Path

import t2_user_authority


CONFIG = Path("/etc/t2-touchid.conf")
MAX_CONFIG_SIZE = 1024 * 1024


class KeybagLoaderError(RuntimeError):
    pass


def _configuration(path: Path = CONFIG) -> str:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= MAX_CONFIG_SIZE
        ):
            raise KeybagLoaderError("runtime configuration is unsafe")
        data = bytearray()
        while len(data) < info.st_size:
            block = os.read(descriptor, info.st_size - len(data))
            if not block:
                raise KeybagLoaderError("runtime configuration read was short")
            data.extend(block)
        if os.read(descriptor, 1):
            raise KeybagLoaderError("runtime configuration changed while read")
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise KeybagLoaderError("runtime configuration is not UTF-8") from error
    except OSError as error:
        raise KeybagLoaderError("runtime configuration is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    values = [
        match.group(1)
        for line in text.splitlines()
        if (match := re.fullmatch(r"T2_TOUCHID_USER=(.*)", line))
    ]
    modes = [
        match.group(1)
        for line in text.splitlines()
        if (match := re.fullmatch(r"T2_TOUCHID_AUTHORITY_MODE=(.*)", line))
    ]
    if (
        len(values) != 1
        or not re.fullmatch(r"[a-z_][a-z0-9_-]*", values[0])
        or modes != [t2_user_authority.COMPATIBILITY_MODE]
    ):
        raise KeybagLoaderError("compatibility keybag configuration is invalid")
    return values[0]


def resolve(path: Path = CONFIG) -> Path:
    if os.geteuid() != 0:
        raise KeybagLoaderError("compatibility keybag resolution requires root")
    user = _configuration(path)
    try:
        linux_uid = pwd.getpwnam(user).pw_uid
    except KeyError as error:
        raise KeybagLoaderError("configured Linux user is unavailable") from error
    if not 1 <= linux_uid < 1 << 32:
        raise KeybagLoaderError("configured Linux user ID is invalid")
    try:
        authority = t2_user_authority.load_compatibility(linux_uid)
    except t2_user_authority.UserAuthorityError as error:
        raise KeybagLoaderError("compatibility authority is invalid") from error
    keybag = Path(authority.selected.keybag_path)
    expected = t2_user_authority.USERS_ROOT / str(linux_uid) / "user.kb"
    if keybag != expected:
        raise KeybagLoaderError("compatibility keybag path is not canonical")
    return keybag


def main() -> int:
    try:
        print(resolve())
    except KeybagLoaderError as error:
        print(f"t2-keybag-loader: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
