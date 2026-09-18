#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Retire only the exact sleep override installed by older T2Touch releases."""

import os
from pathlib import Path
import stat
import sys


POLICY = Path("/etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf")
LEGACY = (
    b"# SPDX-License-Identifier: GPL-2.0-only\n"
    b"# Deep (ACPI S3) resume breaks the T2 BCE CDC-NCM transport on the proven Mac.\n"
    b"[Sleep]\nMemorySleepMode=s2idle\n"
)


def retire(path: Path = POLICY) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    backup = path.with_name(path.name + ".t2touch-retired")
    try:
        saved = backup.lstat()
    except FileNotFoundError:
        saved = None
    # A stop after link() but before unlink() leaves exactly these two names
    # for one inode. Resume that archive without accepting unrelated hard links.
    interrupted_archive = (
        saved is not None and stat.S_ISREG(saved.st_mode)
        and (saved.st_dev, saved.st_ino) == (info.st_dev, info.st_ino)
        and saved.st_nlink == info.st_nlink == 2
    )
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or (info.st_nlink != 1 and not interrupted_archive)
            or path.read_bytes() != LEGACY):
        print(f"WARNING: preserved modified or unowned sleep policy: {path}", file=sys.stderr)
        print("Review it manually; suspend/resume is not qualified by T2Touch.", file=sys.stderr)
        return
    try:
        # Never overwrite an operator's existing backup; the suffix is not .conf
        # and systemd therefore does not load the retired policy.
        os.link(path, backup, follow_symlinks=False)
    except FileExistsError:
        saved = backup.lstat()
        if (not stat.S_ISREG(saved.st_mode) or saved.st_uid != os.geteuid()
                or (saved.st_nlink != 1 and not interrupted_archive)
                or backup.read_bytes() != LEGACY):
            print(f"WARNING: preserved sleep policy because backup conflicts: {backup}", file=sys.stderr)
            return
    path.unlink()
    print(f"Retired T2Touch sleep override; original retained at {backup}")
    print("System sleep policy now follows remaining configuration. This may select deep;")
    print("neither deep nor s2idle is qualified by this migration. See docs/SLEEP_POLICY.md.")


if __name__ == "__main__":
    if os.geteuid() != 0 or len(sys.argv) != 1:
        sys.exit("Run as root without arguments.")
    retire()
