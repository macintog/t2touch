#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Import one private macOS control capture as disabled oracle state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import sys


SOURCE = Path(__file__).resolve().parent
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

import t2_apple_control_import
import t2_linux_account


class AppleControlImportCommandError(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keybag-archive", required=True, type=Path)
    parser.add_argument("--catacomb-archive", required=True, type=Path)
    parser.add_argument("--linux-user", required=True)
    parser.add_argument("--apple-uid", required=True, type=int)
    parser.add_argument(
        "--acknowledge-macos-control-oracle",
        action="store_true",
        help="acknowledge that imported Apple state is not Linux-native provisioning",
    )
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise AppleControlImportCommandError("import must run as root")
        if not arguments.acknowledge_macos_control_oracle:
            raise AppleControlImportCommandError(
                "macOS control-oracle acknowledgement is required"
            )
        try:
            account = pwd.getpwnam(arguments.linux_user)
        except KeyError as error:
            raise AppleControlImportCommandError(
                "selected Linux user does not exist"
            ) from error
        if account.pw_uid <= 0:
            raise AppleControlImportCommandError(
                "selected Linux user must be unprivileged"
            )
        evidence = t2_linux_account.collect(account.pw_uid)
        _plan, summary = t2_apple_control_import.import_control_archives(
            keybag_archive=arguments.keybag_archive,
            catacomb_archive=arguments.catacomb_archive,
            linux_uid=account.pw_uid,
            linux_account_generation=evidence.generation,
            apple_uid=arguments.apple_uid,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
    except (
        AppleControlImportCommandError,
        OSError,
        t2_apple_control_import.AppleControlImportError,
        t2_linux_account.LinuxAccountError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
