#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bind a completely migrated Linux-native authority to the current account."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_native_account_rebind.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_native_account_rebind


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        prog="t2-native-authority-rebind",
        description=(
            "Bind an intact, already-migrated Linux-native T2 authority to "
            "the current local account without rewriting its history."
        ),
    )
    value.add_argument("--linux-uid", required=True, type=int)
    value.add_argument(
        "--acknowledge-complete-native-authority-migration",
        action="store_true",
        required=True,
        help=(
            "confirm that users.json, the keybag, activation material, "
            "authority journal, and Catacomb state were migrated together"
        ),
    )
    return value


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        result = t2_native_account_rebind.publish(
            arguments.linux_uid,
            acknowledge_complete_native_authority_migration=(
                arguments.acknowledge_complete_native_authority_migration
            ),
        )
    except t2_native_account_rebind.NativeAccountRebindError as error:
        print(f"t2-native-authority-rebind: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result.redacted(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
