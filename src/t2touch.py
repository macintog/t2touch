#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Small product-facing command for T2 Touch ID on Linux."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path


CONFIG = Path("/etc/t2-touchid.conf")
ENROLL = Path("/usr/local/sbin/t2-fprintd-enroll-tui-launch")
DELETE = Path("/usr/local/sbin/t2-touchid-delete")
PURGE = Path("/usr/local/sbin/t2-touchid-purge")
FINGER = re.compile(r"finger-[1-5]")
INVENTORY_PYTHON = Path("/opt/t2-touchid/.venv/bin/python")
INVENTORY = Path("/opt/t2-touchid/src/t2-touchid-list.py")


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


def _finger_label(finger: str) -> str:
    return f"Finger {finger.rpartition('-')[2]}"


def _parse_finger_reply(output: str) -> tuple[str, ...]:
    try:
        reply = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise T2TouchError("the fingerprint service returned malformed inventory") from error
    data = reply.get("data") if isinstance(reply, dict) else None
    if (
        not isinstance(reply, dict)
        or set(reply) != {"type", "data"}
        or reply.get("type") != "as"
        or not isinstance(data, list)
        or len(data) != 1
        or not isinstance(data[0], list)
        or len(data[0]) > 5
        or any(not isinstance(item, str) or FINGER.fullmatch(item) is None for item in data[0])
        or len(data[0]) != len(set(data[0]))
    ):
        raise T2TouchError("the fingerprint service returned malformed inventory")
    return tuple(sorted(data[0], key=lambda item: int(item.rpartition("-")[2])))


def enrolled_fingers(user: str) -> tuple[str, ...]:
    """Return the caller's complete neutral inventory through fprintd D-Bus."""

    require_current_user(user)
    if not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    completed = subprocess.run(
        [
            str(INVENTORY_PYTHON),
            "-I",
            str(INVENTORY),
            user,
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=20,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if completed.returncode:
        raise T2TouchError("unable to list enrolled fingerprints")
    return _parse_finger_reply(completed.stdout)


def _inventory_document(fingers: tuple[str, ...]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "fingerprint_count": len(fingers),
        "fingerprints": [
            {"handle": finger, "label": _finger_label(finger)} for finger in fingers
        ],
        "identifiers_redacted": True,
    }


def list_fingerprints(user: str, *, json_output: bool = False) -> int:
    fingers = enrolled_fingers(user)
    if json_output:
        print(json.dumps(_inventory_document(fingers), sort_keys=True))
    elif fingers:
        for finger in fingers:
            print(f"{_finger_label(finger)} ({finger})")
    else:
        print("No fingerprints enrolled.")
    return 0


def count_fingerprints(user: str) -> int:
    print(len(enrolled_fingers(user)))
    return 0


def enroll(user: str) -> int:
    require_current_user(user)
    if not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    if not ENROLL.is_file():
        raise T2TouchError("the enrollment interface is not installed")
    os.execv(str(ENROLL), [str(ENROLL), "finger-1"])
    return 1


def status(user: str, *, json_output: bool = False) -> int:
    require_current_user(user)
    state = "ready" if service_ready() else "not ready"
    if state != "ready":
        if json_output:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "service_ready": False,
                        "fingerprint_count": None,
                        "fingerprints": None,
                        "identifiers_redacted": True,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"Touch ID service: {state}")
        return 1
    fingers = enrolled_fingers(user)
    if json_output:
        document = _inventory_document(fingers)
        document["service_ready"] = True
        print(json.dumps(document, sort_keys=True))
        return 0
    print(f"Touch ID service: {state}")
    print(f"Enrolled fingerprints: {len(fingers)}")
    for finger in fingers:
        print(f"  {_finger_label(finger)} ({finger})")
    return 0


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
    require_local_mutation_session()
    if not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    if FINGER.fullmatch(finger) is None:
        raise T2TouchError("fingerprint must be named Finger N, for example finger-2")
    return authorized_mutation(["/usr/bin/pkexec", str(DELETE), finger])


def require_local_mutation_session() -> None:
    # A UX preflight only; PolicyKit remains the authority for session checks.
    if any(os.environ.get(name) for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")):
        raise T2TouchError(
            "fingerprint deletion requires an active local desktop session; "
            "run this command on the Touch ID machine, outside SSH"
        )


def authorized_mutation(command: list[str]) -> int:
    completed = subprocess.run(
        command, check=False, text=True, stderr=subprocess.PIPE
    )
    if completed.returncode == 126:
        print("t2touch: authorization cancelled; deletion did not start", file=sys.stderr)
    elif completed.returncode == 127:
        print(
            "t2touch: authorization denied; deletion did not start. "
            "Use your mapped account in an active local desktop session.",
            file=sys.stderr,
        )
    elif completed.stderr:
        # Preserve the helper's redacted partial-progress/recovery diagnostics.
        print(completed.stderr, end="", file=sys.stderr)
    return completed.returncode


def purge(
    user: str,
    *,
    resume: bool = False,
    assume_yes: bool = False,
    input_stream=None,
    output_stream=None,
) -> int:
    require_current_user(user)
    require_local_mutation_session()
    if not resume and not service_ready():
        raise T2TouchError("Touch ID is not ready; run sudo t2-touchid-doctor")
    if not PURGE.is_file():
        raise T2TouchError("the fingerprint purge helper is not installed")
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    if not resume and not assume_yes:
        if not input_stream.isatty():
            raise T2TouchError("purge requires an interactive confirmation or --yes")
        print(
            "Delete every enrolled fingerprint? This cannot be undone. [y/N] ",
            end="",
            flush=True,
            file=output_stream,
        )
        if input_stream.readline().strip().lower() not in {"y", "yes"}:
            print("Purge cancelled.", file=output_stream)
            return 0
    command = ["/usr/bin/pkexec", str(PURGE)]
    if resume:
        command.append("--resume")
    return authorized_mutation(command)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t2touch", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("enroll", help="enroll a fingerprint")
    status_parser = commands.add_parser(
        "status", help="show service and fingerprint status"
    )
    status_parser.add_argument("--json", action="store_true")
    list_parser = commands.add_parser("list", help="list enrolled fingerprints")
    list_parser.add_argument("--json", action="store_true")
    commands.add_parser("count", help="print the enrolled fingerprint count")
    commands.add_parser("verify", help="verify with any enrolled fingerprint")
    delete_parser = commands.add_parser("delete", help="delete enrolled fingerprints")
    delete_parser.add_argument("finger", help="a neutral slot such as finger-2")
    purge_parser = commands.add_parser("purge", help="delete every enrolled fingerprint")
    purge_parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    purge_parser.add_argument(
        "--resume", action="store_true", help="resume an interrupted purge"
    )
    args = parser.parse_args(argv)
    try:
        user = configured_user()
        if args.command == "enroll":
            return enroll(user)
        if args.command == "status":
            return status(user, json_output=args.json)
        if args.command == "list":
            return list_fingerprints(user, json_output=args.json)
        if args.command == "count":
            return count_fingerprints(user)
        if args.command == "verify":
            return verify(user)
        if args.command == "delete":
            return delete(user, args.finger)
        if args.command == "purge":
            return purge(user, resume=args.resume, assume_yes=args.yes)
    except (OSError, subprocess.SubprocessError, T2TouchError) as error:
        print(f"t2touch: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
