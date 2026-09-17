#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free PAM readiness gate for one Linux-native E4 authority."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import stat
from collections.abc import Callable

import t2_catacomb_codec
import t2_catacomb_store
import t2_mutation_registry
import t2_user_authority


CONFIG = Path("/etc/t2-touchid.conf")
MUTATION_ROOT = Path("/var/lib/t2-touchid/mutations")
STORE_ROOT = Path("/var/lib/t2-touchid/catacomb")
ROOT_UID = 0


class NativePamReadyError(RuntimeError):
    pass


def _local_identity_count(apple_uid: int) -> int:
    store = t2_catacomb_store.CatacombStore(STORE_ROOT, apple_uid)
    components = store.read_committed_components()
    user = t2_catacomb_codec.decode_user_catacomb(
        components[f"user_{apple_uid:08x}.cat"], apple_uid
    )
    return len(user.identities)


def require_native_readiness(
    linux_uid: int,
    *,
    authority_loader: Callable[[int], object] = t2_user_authority.load_runtime,
    mutation_scanner: Callable[[Path], object] = t2_mutation_registry.scan,
    identity_counter: Callable[[int], int] = _local_identity_count,
) -> None:
    if type(linux_uid) is not int or linux_uid <= 0:
        raise NativePamReadyError("configured Linux UID is invalid")
    if (
        not callable(authority_loader)
        or not callable(mutation_scanner)
        or not callable(identity_counter)
    ):
        raise NativePamReadyError("native PAM readiness dependency is unavailable")
    try:
        authority = authority_loader(linux_uid)
        selected = authority.mapping_set.resolve(linux_uid, "verify")
        entries = mutation_scanner(MUTATION_ROOT)
        blocked = any(entry.blocks_new_mutation for entry in entries)
        identity_count = identity_counter(selected.apple_uid)
    except (
        OSError,
        AttributeError,
        RuntimeError,
    ) as error:
        raise NativePamReadyError("native PAM authority is unavailable") from error
    if (
        authority.origin != "linux-native-e4"
        or selected != authority.selected
        or selected.linux_uid != linux_uid
        or type(identity_count) is not int
        or identity_count <= 0
        or blocked
    ):
        raise NativePamReadyError("native PAM authority is not ready")


def _configured_uid() -> int:
    try:
        info = CONFIG.stat(follow_symlinks=False)
        lines = CONFIG.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise NativePamReadyError("Touch ID configuration is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise NativePamReadyError("Touch ID configuration is unsafe")
    modes = [
        line.removeprefix("T2_TOUCHID_AUTHORITY_MODE=")
        for line in lines
        if line.startswith("T2_TOUCHID_AUTHORITY_MODE=")
    ]
    users = [
        line.removeprefix("T2_TOUCHID_USER=")
        for line in lines
        if line.startswith("T2_TOUCHID_USER=")
    ]
    if len(modes) != 1 or modes[0] != "linux-native" or len(users) != 1:
        raise NativePamReadyError("native PAM configuration is invalid")
    try:
        account = pwd.getpwnam(users[0])
    except KeyError as error:
        raise NativePamReadyError("configured Linux account is unavailable") from error
    if account.pw_uid <= 0:
        raise NativePamReadyError("configured Linux account is invalid")
    return account.pw_uid


def main() -> int:
    try:
        if os.geteuid() != ROOT_UID:
            raise NativePamReadyError("native PAM readiness requires root")
        require_native_readiness(_configured_uid())
        return 0
    except NativePamReadyError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
