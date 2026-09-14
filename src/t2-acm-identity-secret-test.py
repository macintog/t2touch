#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

"""Exercise request-10's transient ACM identity-secret producer."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import sys
import termios
from pathlib import Path

INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_acm_device.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

from t2_acm_device import ACMDevice, ACMDeviceError, identity_secret_lifecycle_test
from t2_acm_protocol import IDENTITY_SECRET_MAX_SIZE


CONFIG = Path("/etc/t2-touchid.conf")


def configuration() -> tuple[int, int]:
    info = CONFIG.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ACMDeviceError("configuration ownership or mode is unsafe")
    values: dict[str, list[str]] = {
        "T2_TOUCHID_MACOS_USER_ID": [],
        "T2_TOUCHID_USER": [],
    }
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    user_ids = values["T2_TOUCHID_MACOS_USER_ID"]
    linux_users = values["T2_TOUCHID_USER"]
    if (
        len(user_ids) != 1
        or not user_ids[0].isdecimal()
        or not 0 <= int(user_ids[0]) <= 0xFFFFFFFF
    ):
        raise ACMDeviceError("configuration has no unique valid macOS user ID")
    if len(linux_users) != 1 or not linux_users[0]:
        raise ACMDeviceError("configuration has no unique mapped Linux user")
    try:
        linux_uid = pwd.getpwnam(linux_users[0]).pw_uid
    except KeyError as error:
        raise ACMDeviceError("configured Linux user does not exist") from error
    if linux_uid <= 0:
        raise ACMDeviceError("configured Linux user cannot be root")
    return int(user_ids[0]), linux_uid


def validate_caller_environment(environment: dict[str, str], mapped_uid: int) -> None:
    values = [
        environment[key]
        for key in ("SUDO_UID", "PKEXEC_UID")
        if key in environment
    ]
    callers = {int(value) for value in values if value.isdecimal()}
    if not values or len(callers) != len(set(values)) or callers != {mapped_uid}:
        raise ACMDeviceError(
            "caller is not the configured mapped Linux user via sudo or pkexec"
        )


def read_secret(descriptor: int) -> bytearray:
    storage = bytearray(IDENTITY_SECRET_MAX_SIZE + 2)
    view = memoryview(storage)
    used = 0
    old_attributes = None
    if os.isatty(descriptor):
        old_attributes = termios.tcgetattr(descriptor)
        new_attributes = old_attributes.copy()
        new_attributes[3] &= ~termios.ECHO
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, new_attributes)
        print("Identity secret: ", end="", file=sys.stderr, flush=True)
    try:
        while used < len(storage):
            count = os.readv(descriptor, [view[used:]])
            if count == 0:
                break
            used += count
            newline = next(
                (index for index in range(used) if storage[index] == 0x0A),
                None,
            )
            if newline is not None:
                used = newline
                break
    finally:
        if old_attributes is not None:
            termios.tcsetattr(descriptor, termios.TCSAFLUSH, old_attributes)
            print(file=sys.stderr)
    if used and storage[used - 1] == 0x0D:
        used -= 1
    if not 1 <= used <= IDENTITY_SECRET_MAX_SIZE:
        storage[:] = b"\x00" * len(storage)
        raise ACMDeviceError("identity secret length is outside the fixed bound")
    secret = bytearray(view[:used])
    storage[:] = b"\x00" * len(storage)
    return secret


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--acknowledge-transient-identity-secret",
        action="store_true",
        help="acknowledge setting and externalizing a transient type-5 ACM secret",
    )
    parser.add_argument(
        "--legacy-context-create",
        action="store_true",
        help="use ACM context-create command 0x01 instead of tracking command 0x24",
    )
    args = parser.parse_args()
    if not args.acknowledge_transient_identity_secret:
        parser.error("transient identity-secret acknowledgement is required")
    if os.geteuid() != 0:
        print("t2-acm-identity-secret-test must run as root", file=sys.stderr)
        return 2
    secret = bytearray()
    try:
        user_id, mapped_linux_uid = configuration()
        validate_caller_environment(os.environ, mapped_linux_uid)
        secret = read_secret(sys.stdin.fileno())
        with ACMDevice() as device:
            result = identity_secret_lifecycle_test(
                device, user_id, secret, tracking=not args.legacy_context_create
            )
    except (OSError, ValueError, ACMDeviceError) as error:
        print(f"t2-acm-identity-secret-test: {error}", file=sys.stderr)
        return 1
    finally:
        secret[:] = b"\x00" * len(secret)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
