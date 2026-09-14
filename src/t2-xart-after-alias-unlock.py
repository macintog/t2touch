#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unlock the proven Apple alias, then issue one deferred xART publication."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import sys
import uuid

SOURCE = Path(__file__).resolve().parent
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

import t2_aks_transport
import t2_apple_control_alias_discriminator as alias_discriminator
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as unlock
import t2_apple_control_discriminator as keybag_discriminator
import t2_mutation_journal as journal


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


def _append(path: Path, operation_id: str, milestone: str,
            evidence: dict[str, object]) -> None:
    try:
        journal.append(path, operation_id, milestone, evidence)
    except (OSError, journal.JournalError) as error:
        raise unlock.AppleControlAliasUnlockError(
            "xART ordering journal cannot advance"
        ) from error


def main() -> int:
    print(
        "retired: direct PCI xART command 8 reaches AMDM, not internal xars",
        file=sys.stderr,
    )
    return 2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-user", required=True)
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument(
        "--acknowledge-one-shot-alias-unlock-then-xart",
        action="store_true",
    )
    password: bytearray | None = None
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise unlock.AppleControlAliasUnlockError(
                "xART ordering discriminator must run as root"
            )
        if not arguments.acknowledge_one_shot_alias_unlock_then_xart:
            raise unlock.AppleControlAliasUnlockError(
                "one-shot alias-unlock-then-xART acknowledgement is required"
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
        journal_path = oracle / "apple-control-alias-xart-ordering.jsonl"
        if journal_path.exists():
            raise unlock.AppleControlAliasUnlockError(
                "xART ordering discriminator journal already exists"
            )
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        unlock.require_later_boot(proof, boot)
        operation_id = str(uuid.uuid4())
        password = _password_from_stdin()
        with t2_aks_transport.AKSActivationTransport() as transport:
            alias_result = unlock.run(
                journal_path=journal_path,
                evidence=evidence,
                proof=proof,
                linux_boot_uuid=boot,
                transport=transport,
                password=password,
                operation_id=operation_id,
            )
            if not alias_result.unlocked:
                raise unlock.AppleControlAliasUnlockError(
                    "Apple alias did not become unlocked"
                )
            _append(
                journal_path,
                operation_id,
                "XART_AFTER_ALIAS_UNLOCK_INTENT",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "alias_unlocked": True,
                    "mutation_possible": True,
                    "retry_before_reboot_permitted": False,
                },
            )
            published = transport.publish_deferred_xart_uuid()
            _append(
                journal_path,
                operation_id,
                "XART_AFTER_ALIAS_UNLOCK_COMPLETE",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "alias_unlocked": True,
                    "xart_published": published,
                    "mutation_performed": True,
                    "retry_before_reboot_permitted": False,
                },
            )
        print(json.dumps({
            "alias_unlocked": True,
            "identifiers_redacted": True,
            "mapping_enabled": False,
            "xart_published": published,
        }, indent=2, sort_keys=True))
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
