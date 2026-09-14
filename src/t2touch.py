#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Small product-facing command for T2 Touch ID on Linux."""

from __future__ import annotations

import argparse
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path


CONFIG = Path("/etc/t2-touchid.conf")
ENROLL = Path("/usr/local/sbin/t2-fprintd-enroll-tui-launch")
FINGER = re.compile(r"finger-[1-5]")


class T2TouchError(RuntimeError):
    pass


def configured_user() -> str:
    try:
        lines = CONFIG.read_text(encoding="utf-8").splitlines()
    except PermissionError:
        # The product configuration is intentionally root-only. The facade
        # independently enforces the protected mapping, so an unprivileged
        # client may identify only its own account here.
        try:
            return pwd.getpwuid(os.geteuid()).pw_name
        except KeyError as error:
            raise T2TouchError("the current account no longer exists") from error
    except OSError as error:
        raise T2TouchError("t2touch is not installed") from error
    values = [
        line.partition("=")[2]
        for line in lines
        if line.startswith("T2_TOUCHID_USER=")
    ]
    if len(values) != 1 or not values[0]:
        raise T2TouchError("installed account configuration is invalid")
    try:
        pwd.getpwnam(values[0])
    except KeyError as error:
        raise T2TouchError("the configured account no longer exists") from error
    return values[0]


def require_current_user(user: str) -> None:
    if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != user:
        raise T2TouchError(f"run this command as {user}, without sudo")


def service_ready() -> bool:
    return subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", "fprintd.service"],
        check=False,
        timeout=5,
    ).returncode == 0


def enroll(user: str) -> int:
    require_current_user(user)
    if not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    if not ENROLL.is_file():
        raise T2TouchError("the enrollment interface is not installed")
    os.execv(str(ENROLL), [str(ENROLL), "finger-1"])
    return 1


def status(user: str) -> int:
    state = "ready" if service_ready() else "not ready"
    print(f"Touch ID service: {state}")
    if state != "ready":
        return 1
    completed = subprocess.run(
        ["/usr/bin/fprintd-list", user],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
    )
    output = completed.stdout.strip()
    if output:
        print(output)
    return completed.returncode


def verify(user: str) -> int:
    require_current_user(user)
    if not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    return subprocess.run(
        ["/usr/bin/fprintd-verify", "-f", "any", user],
        check=False,
    ).returncode


def delete(user: str, finger: str) -> int:
    require_current_user(user)
    if not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    if FINGER.fullmatch(finger) is None:
        raise T2TouchError("fingerprint must be named Finger N, for example finger-2")
    return subprocess.run(
        ["/usr/bin/fprintd-delete", user, "-f", finger], check=False
    ).returncode


def main() -> int:
    parser = argparse.ArgumentParser(prog="t2touch", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("enroll", help="enroll a fingerprint")
    commands.add_parser("status", help="show service and fingerprint status")
    commands.add_parser("verify", help="verify with any enrolled fingerprint")
    delete_parser = commands.add_parser("delete", help="delete enrolled fingerprints")
    delete_parser.add_argument("finger", help="a neutral slot such as finger-2")
    args = parser.parse_args()
    try:
        user = configured_user()
        if args.command == "enroll":
            return enroll(user)
        if args.command == "status":
            return status(user)
        if args.command == "verify":
            return verify(user)
        if args.command == "delete":
            return delete(user, args.finger)
    except (OSError, subprocess.SubprocessError, T2TouchError) as error:
        print(f"t2touch: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
