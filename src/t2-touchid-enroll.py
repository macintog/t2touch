#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stable command interface for journaled T2 Touch ID enrollment."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path


SOURCE = Path(__file__).resolve().parent
INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, INSTALLED_SOURCE)
        if (candidate / "t2_fprint_identity.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_fprint_identity
import t2_touchid_cli


LOCAL_BROKER = Path(__file__).resolve().with_name("t2-touchid-enroll-test.py")
INSTALLED_BROKER = Path("/opt/t2-touchid/bin/t2-touchid-enroll-test")
LOCAL_IDENTITIES = Path(__file__).resolve().with_name("t2-touchid-identities.py")
INSTALLED_IDENTITIES = Path("/usr/local/sbin/t2-touchid-identities")
LOCAL_NATIVE = Path(__file__).resolve().with_name("t2-native-enroll.py")
LOCAL_MANAGE = Path(__file__).resolve().with_name("t2-touchid-manage.py")
INSTALLED_NATIVE = INSTALLED_SOURCE / "t2-native-enroll.py"
INSTALLED_MANAGE = Path("/usr/local/sbin/t2-touchid-manage")
CONFIG = Path("/etc/t2-touchid.conf")


def finger_handle(value: str) -> str:
    if not t2_fprint_identity.is_handle(value):
        raise argparse.ArgumentTypeError(
            "finger identity must be a neutral handle such as finger-1"
        )
    return value


def authority_mode() -> str:
    info = CONFIG.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 0 < info.st_size <= 1024 * 1024
    ):
        raise RuntimeError("runtime configuration is not private")
    values = [
        match.group(1)
        for line in CONFIG.read_text(encoding="utf-8").splitlines()
        if (match := re.fullmatch(r"T2_TOUCHID_AUTHORITY_MODE=(.*)", line))
    ]
    if len(values) != 1 or values[0] not in {
        "linux-native", "macos-control-oracle"
    }:
        raise RuntimeError("runtime authority mode is invalid")
    return values[0]


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Enroll through fprintd as your desktop user; no arguments starts enrollment.",
        epilog="Status, preflight and recovery subcommands are administrative operations. "
               "Direct native/oracle capture is research-only; start no longer accepts "
               "--name or mutation acknowledgement flags.",
    )
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="show redacted enrollment state")
    identities = commands.add_parser(
        "list", help="list truthful reconciled identity labels"
    )
    identities.add_argument(
        "--json", action="store_true", help="emit compact JSON"
    )

    preflight = commands.add_parser(
        "preflight", help="validate readiness without enrolling"
    )
    preflight.add_argument(
        "--acknowledge-password-fallback-tested", action="store_true"
    )

    commands.add_parser("start", help="enroll through the desktop fprintd workflow (default)")

    commands.add_parser(
        "verify-post-reboot",
        help="verify a reconciled enrollment after reboot",
    )
    commands.add_parser(
        "recover-outcome",
        help="reconcile one outcome-unknown enrollment without replay",
    )
    commands.add_parser(
        "recover-local",
        help="resolve one journal-bound local Catacomb transaction",
    )
    observed = commands.add_parser(
        "recover-observed",
        help="persist one newly observed identity after explicit review",
    )
    observed.add_argument(
        "--name", default="finger-1", type=finger_handle
    )
    observed.add_argument(
        "--acknowledge-observed-identity-recovery", action="store_true"
    )
    observed.add_argument(
        "--acknowledge-local-catacomb-mutation", action="store_true"
    )
    return value


def broker_arguments(args: argparse.Namespace) -> list[str]:
    if args.command == "status":
        return ["--status-only"]
    if args.command == "preflight":
        result = ["--preflight-only"]
        if args.acknowledge_password_fallback_tested:
            result.append("--acknowledge-password-fallback-tested")
        return result
    if args.command == "verify-post-reboot":
        return ["--verify-post-reboot"]
    if args.command == "recover-outcome":
        return ["--reconcile-outcome-unknown"]
    if args.command == "recover-local":
        return ["--recover-local-transaction"]
    if args.command == "recover-observed":
        result = ["--recover-observed-identity", "--identity-name", args.name]
        if args.acknowledge_observed_identity_recovery:
            result.append("--acknowledge-observed-identity-recovery")
        if args.acknowledge_local_catacomb_mutation:
            result.append("--acknowledge-local-catacomb-mutation")
        return result
    raise ValueError("unsupported enrollment command")


def command_path(local: Path, installed: Path) -> Path:
    selected = local if local.is_file() else installed
    if not selected.is_file():
        raise FileNotFoundError(f"{installed.name} is not installed")
    return selected


def command_invocation(args: argparse.Namespace) -> tuple[Path, list[str]]:
    if args.command == "list":
        arguments = ["--json"] if args.json else []
        return command_path(LOCAL_IDENTITIES, INSTALLED_IDENTITIES), arguments
    return command_path(LOCAL_BROKER, INSTALLED_BROKER), broker_arguments(args)


def native_invocation(args: argparse.Namespace) -> tuple[Path, list[str]]:
    native = command_path(LOCAL_NATIVE, INSTALLED_NATIVE)
    manage = command_path(LOCAL_MANAGE, INSTALLED_MANAGE)
    if args.command == "list":
        return command_path(LOCAL_IDENTITIES, INSTALLED_IDENTITIES), (
            ["--json"] if args.json else []
        )
    if args.command == "status":
        return manage, ["status"]
    if args.command == "preflight":
        return native, ["--preflight-add-finger"]
    if args.command == "verify-post-reboot":
        return native, [
            "--post-reboot-verification",
            "--acknowledge-one-shot-native-enrollment-verification",
            "--acknowledge-password-fallback-tested",
        ]
    if args.command == "recover-outcome":
        return native, ["--reconcile-outcome-unknown"]
    if args.command == "recover-observed":
        if not (
            args.acknowledge_observed_identity_recovery
            and args.acknowledge_local_catacomb_mutation
        ):
            raise ValueError("both observed-recovery acknowledgements are required")
        return native, [
            "--recover-observed-identity",
            "--identity-name",
            args.name,
            "--acknowledge-observed-identity-recovery",
            "--acknowledge-local-catacomb-mutation",
        ]
    raise ValueError(
        f"{args.command} is not a safe Linux-native recovery action; inspect status"
    )


def main() -> int:
    args = parser().parse_args(sys.argv[1:] or ["start"])
    if args.command == "start":
        # Do not inspect root-only config or fall back to a native capture.
        return t2_touchid_cli.main([], command="enroll")
    try:
        selected, translated = (
            native_invocation(args)
            if authority_mode() == "linux-native"
            else command_invocation(args)
        )
        if not selected.is_file():
            raise FileNotFoundError(f"{selected.name} is unavailable")
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        print(f"t2-touchid-enroll: {error}", file=sys.stderr)
        return 1
    os.execv(sys.executable, [sys.executable, str(selected), *translated])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
