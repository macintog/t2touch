#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guided transition of a legacy macOS-export install to oracle authority.

Use ``status`` to see which stage is missing and the exact command to run next.
Discriminator stages require later boots. Recovery starts after a failed
pre-state-only unlock on a later boot, then binds and unlocks in one session.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import pwd
import sys


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_compatibility_transition.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_aks_transport
import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as alias_unlock
import t2_apple_control_alias_recovery as alias_recovery
import t2_apple_control_discriminator as keybag_discriminator
import t2_apple_control_import
import t2_compatibility_transition as transition
import t2_linux_account


CONFIG = Path("/etc/t2-touchid.conf")


class CommandError(RuntimeError):
    pass


def _password_from_stdin() -> bytearray:
    raw = bytearray(sys.stdin.buffer.readline(1026))
    try:
        if raw.endswith(b"\n"):
            raw.pop()
        if raw.endswith(b"\r"):
            raw.pop()
        if not raw or len(raw) > 1023 or b"\0" in raw:
            raise CommandError("password input is empty or invalid")
        if sys.stdin.buffer.read(1):
            raise CommandError("password input contains trailing data")
        return bytearray(raw)
    finally:
        raw[:] = b"\0" * len(raw)


def _password_from_prompt() -> bytearray:
    if not sys.stdin.isatty():
        raise CommandError("hidden password prompt requires a terminal")
    password = bytearray(getpass.getpass("Imported macOS account password: "), "utf-8")
    confirmation = bytearray(getpass.getpass("Confirm imported macOS account password: "), "utf-8")
    try:
        if password != confirmation:
            password[:] = b"\0" * len(password)
            raise CommandError("password confirmation did not match; no recovery was attempted")
        return password
    finally:
        confirmation[:] = b"\0" * len(confirmation)


def _default_linux_user() -> str | None:
    try:
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            if line.startswith("T2_TOUCHID_USER="):
                return line.split("=", 1)[1]
    except OSError:
        return None
    return None


def _account(linux_user: str):
    try:
        account = pwd.getpwnam(linux_user)
    except KeyError as error:
        raise CommandError("selected Linux user does not exist") from error
    if account.pw_uid <= 0:
        raise CommandError("selected Linux user must be unprivileged")
    return account


def _acknowledge(flag: bool, message: str) -> None:
    if not flag:
        raise CommandError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="report the transition phase")
    status.add_argument("--linux-user")

    importing = subparsers.add_parser(
        "import", help="import one private macOS control capture as disabled oracle state"
    )
    importing.add_argument("--linux-user", required=True)
    importing.add_argument("--apple-uid", required=True, type=int)
    importing.add_argument("--keybag-archive", required=True, type=Path)
    importing.add_argument("--catacomb-archive", required=True, type=Path)
    importing.add_argument("--acknowledge-macos-control-oracle", action="store_true")

    discriminate = subparsers.add_parser(
        "discriminate", help="run the one-shot imported keybag UUID discriminator"
    )
    discriminate.add_argument("--linux-user", required=True)
    discriminate.add_argument(
        "--acknowledge-one-shot-sep-discriminator", action="store_true"
    )

    bind = subparsers.add_parser(
        "bind", help="run the one-shot imported keybag alias-binding discriminator"
    )
    bind.add_argument("--linux-user", required=True)
    bind.add_argument("--acknowledge-one-shot-sep-alias-binding", action="store_true")

    reconcile = subparsers.add_parser(
        "reconcile", help="run one read-only reconciliation of an ambiguous alias bind"
    )
    reconcile.add_argument("--linux-user", required=True)
    reconcile.add_argument(
        "--acknowledge-one-shot-read-only-alias-reconciliation", action="store_true"
    )

    unlock = subparsers.add_parser(
        "unlock", help="run one password-unlock discriminator for the reconciled alias"
    )
    unlock.add_argument("--linux-user", required=True)
    unlock.add_argument("--password-stdin", action="store_true")
    unlock.add_argument(
        "--acknowledge-one-shot-password-alias-unlock", action="store_true"
    )

    recover = subparsers.add_parser(
        "recover", help="one journaled absent-alias recovery after a pre-state-only unlock failure"
    )
    recover.add_argument("--linux-user", required=True)
    password = recover.add_mutually_exclusive_group(required=True)
    password.add_argument("--password-stdin", action="store_true")
    password.add_argument("--password-prompt", action="store_true")
    recover.add_argument("--acknowledge-one-shot-alias-recovery", action="store_true")
    recover.add_argument(
        "--acknowledge-research-mac-and-macos-recovery", action="store_true",
        help="confirm this is an explicitly designated research Mac with a working macOS recovery path",
    )

    capacity_fix = subparsers.add_parser(
        "recover-capacity-fix",
        help="one continuation of the exact response-capacity recovery failure",
    )
    capacity_fix.add_argument("--linux-user", required=True)
    password = capacity_fix.add_mutually_exclusive_group(required=True)
    password.add_argument("--password-stdin", action="store_true")
    password.add_argument("--password-prompt", action="store_true")
    capacity_fix.add_argument(
        "--acknowledge-one-shot-capacity-fix", action="store_true"
    )
    capacity_fix.add_argument(
        "--acknowledge-known-predispatch-capacity-defect", action="store_true",
        help=(
            "confirm the failed recovery used the installed client that requested "
            "a 4-byte operation-0x04 reply and was rejected before dispatch"
        ),
    )
    capacity_fix.add_argument(
        "--acknowledge-research-mac-and-macos-recovery",
        action="store_true",
        help="confirm this is an explicitly designated research Mac with a working macOS recovery path",
    )

    return parser


def _dispatch(arguments: argparse.Namespace) -> int:
    if arguments.command == "status":
        linux_user = arguments.linux_user or _default_linux_user()
        if not linux_user:
            raise CommandError(
                "no Linux user given and T2_TOUCHID_USER is not configured"
            )
        account = _account(linux_user)
        status = transition.inspect(linux_uid=account.pw_uid, linux_user=linux_user)
        print(json.dumps(status.public_summary(), indent=2, sort_keys=True))
        return 0

    account = _account(arguments.linux_user)

    if arguments.command == "import":
        _acknowledge(
            arguments.acknowledge_macos_control_oracle,
            "macOS control-oracle acknowledgement is required",
        )
        summary = transition.import_state(
            keybag_archive=arguments.keybag_archive,
            catacomb_archive=arguments.catacomb_archive,
            linux_uid=account.pw_uid,
            apple_uid=arguments.apple_uid,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.command == "discriminate":
        _acknowledge(
            arguments.acknowledge_one_shot_sep_discriminator,
            "one-shot SEP discriminator acknowledgement is required",
        )
        summary = transition.discriminate(linux_uid=account.pw_uid)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.command == "bind":
        _acknowledge(
            arguments.acknowledge_one_shot_sep_alias_binding,
            "one-shot SEP alias-binding acknowledgement is required",
        )
        summary = transition.bind(linux_uid=account.pw_uid)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.command == "reconcile":
        _acknowledge(
            arguments.acknowledge_one_shot_read_only_alias_reconciliation,
            "one-shot read-only reconciliation acknowledgement is required",
        )
        summary = transition.reconcile(linux_uid=account.pw_uid)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.command == "unlock":
        _acknowledge(
            arguments.acknowledge_one_shot_password_alias_unlock,
            "one-shot password alias unlock acknowledgement is required",
        )
        if not arguments.password_stdin:
            raise CommandError("password must be supplied through standard input")
        password = _password_from_stdin()
        try:
            summary = transition.unlock(linux_uid=account.pw_uid, password=password)
        finally:
            password[:] = b"\0" * len(password)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.command == "recover":
        _acknowledge(
            arguments.acknowledge_one_shot_alias_recovery,
            "one-shot alias recovery acknowledgement is required",
        )
        _acknowledge(
            arguments.acknowledge_research_mac_and_macos_recovery,
            "recovery requires an explicitly designated research Mac and a working macOS recovery path",
        )
        if arguments.password_prompt:
            password = _password_from_prompt()
        else:
            password = _password_from_stdin()
        try:
            summary = transition.recover(linux_uid=account.pw_uid, password=password)
        finally:
            password[:] = b"\0" * len(password)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.command == "recover-capacity-fix":
        _acknowledge(
            arguments.acknowledge_one_shot_capacity_fix,
            "one-shot response-capacity fix acknowledgement is required",
        )
        _acknowledge(
            arguments.acknowledge_known_predispatch_capacity_defect,
            "acknowledgement of the known pre-dispatch capacity defect is required",
        )
        _acknowledge(
            arguments.acknowledge_research_mac_and_macos_recovery,
            "recovery requires an explicitly designated research Mac and a working macOS recovery path",
        )
        if arguments.password_prompt:
            password = _password_from_prompt()
        else:
            password = _password_from_stdin()
        try:
            summary = transition.recover_capacity_fix(
                linux_uid=account.pw_uid,
                password=password,
                predispatch_capacity_defect_acknowledged=True,
            )
        finally:
            password[:] = b"\0" * len(password)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    raise CommandError("unsupported command")


def main() -> int:
    parser = _build_parser()
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise CommandError("this command must run as root")
        return _dispatch(arguments)
    except (
        CommandError,
        transition.CompatibilityTransitionError,
        OSError,
        t2_apple_control_import.AppleControlImportError,
        t2_linux_account.LinuxAccountError,
        keybag_discriminator.AppleControlDiscriminatorError,
        alias_discriminator.AppleControlAliasDiscriminatorError,
        reconciliation.AppleControlAliasReconciliationError,
        alias_unlock.AppleControlAliasUnlockError,
        alias_recovery.AliasRecoveryError,
        t2_aks_transport.AKSActivationTransportError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
