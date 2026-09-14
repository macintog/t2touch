#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one password-unlock discriminator for the reconciled Apple alias."""

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

import t2_aks_transport
import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as unlock
import t2_apple_control_discriminator as keybag_discriminator


def _password_from_stdin() -> bytearray:
    raw = bytearray(sys.stdin.buffer.readline(1026))
    try:
        if raw.endswith(b"\n"):
            raw.pop()
        if raw.endswith(b"\r"):
            raw.pop()
        if not raw or len(raw) > 1024 or b"\0" in raw:
            raise unlock.AppleControlAliasUnlockError(
                "password input is empty or invalid"
            )
        if sys.stdin.buffer.read(1):
            raise unlock.AppleControlAliasUnlockError(
                "password input contains trailing data"
            )
        return bytearray(raw)
    finally:
        raw[:] = b"\0" * len(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-user", required=True)
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument(
        "--acknowledge-one-shot-password-alias-unlock",
        action="store_true",
    )
    password: bytearray | None = None
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise unlock.AppleControlAliasUnlockError(
                "alias unlock discriminator must run as root"
            )
        if not arguments.acknowledge_one_shot_password_alias_unlock:
            raise unlock.AppleControlAliasUnlockError(
                "one-shot password alias unlock acknowledgement is required"
            )
        if not arguments.password_stdin:
            raise unlock.AppleControlAliasUnlockError(
                "password must be supplied through standard input"
            )
        account = pwd.getpwnam(arguments.linux_user)
        root = keybag_discriminator.STATE_ROOT
        oracle = root / "oracle"
        evidence = keybag_discriminator.read_oracle_import(root, account.pw_uid)
        matched = alias_discriminator.read_matched_keybag_proof(
            oracle / "apple-control-discriminator.jsonl", evidence
        )
        bind = reconciliation.read_ambiguous_bind_proof(oracle, evidence, matched)
        proof = reconciliation.read_reconciled_alias_proof(oracle, evidence, bind)
        journal_path = oracle / "apple-control-alias-unlock.jsonl"
        if journal_path.exists():
            raise unlock.AppleControlAliasUnlockError(
                "alias unlock discriminator journal already exists"
            )
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        unlock.require_later_boot(proof, boot)
        password = _password_from_stdin()
        with t2_aks_transport.AKSActivationTransport() as transport:
            result = unlock.run(
                journal_path=journal_path,
                evidence=evidence,
                proof=proof,
                linux_boot_uuid=boot,
                transport=transport,
                password=password,
            )
        print(json.dumps(result.public_summary(), indent=2, sort_keys=True))
    except (
        KeyError,
        OSError,
        alias_discriminator.AppleControlAliasDiscriminatorError,
        keybag_discriminator.AppleControlDiscriminatorError,
        reconciliation.AppleControlAliasReconciliationError,
        t2_aks_transport.AKSActivationTransportError,
        unlock.AppleControlAliasUnlockError,
    ) as error:
        parser.error(str(error))
    finally:
        if password is not None:
            password[:] = b"\0" * len(password)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
