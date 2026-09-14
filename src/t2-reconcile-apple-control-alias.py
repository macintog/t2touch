#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one read-only reconciliation of an ambiguous Apple alias bind."""

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
import t2_apple_control_discriminator as keybag_discriminator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-user", required=True)
    parser.add_argument(
        "--acknowledge-one-shot-read-only-alias-reconciliation",
        action="store_true",
    )
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise reconciliation.AppleControlAliasReconciliationError(
                "alias reconciliation must run as root"
            )
        if not arguments.acknowledge_one_shot_read_only_alias_reconciliation:
            raise reconciliation.AppleControlAliasReconciliationError(
                "one-shot read-only reconciliation acknowledgement is required"
            )
        try:
            account = pwd.getpwnam(arguments.linux_user)
        except KeyError as error:
            raise reconciliation.AppleControlAliasReconciliationError(
                "selected Linux user does not exist"
            ) from error
        root = keybag_discriminator.STATE_ROOT
        oracle = root / "oracle"
        evidence = keybag_discriminator.read_oracle_import(root, account.pw_uid)
        matched = alias_discriminator.read_matched_keybag_proof(
            oracle / "apple-control-discriminator.jsonl", evidence
        )
        bind_proof = reconciliation.read_ambiguous_bind_proof(
            oracle, evidence, matched
        )
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        reconciliation.require_later_boot(bind_proof, boot)
        journal_path = oracle / "apple-control-alias-reconciliation.jsonl"
        capture_path = oracle / "apple-control-alias-state.der"
        if journal_path.exists() or capture_path.exists():
            raise reconciliation.AppleControlAliasReconciliationError(
                "alias reconciliation artifacts already exist"
            )
        with t2_aks_transport.AKSActivationTransport() as transport:
            result = reconciliation.run(
                journal_path=journal_path,
                capture_path=capture_path,
                evidence=evidence,
                bind_proof=bind_proof,
                linux_boot_uuid=boot,
                transport=transport,
            )
        print(json.dumps(result.public_summary(), indent=2, sort_keys=True))
    except (
        OSError,
        alias_discriminator.AppleControlAliasDiscriminatorError,
        keybag_discriminator.AppleControlDiscriminatorError,
        reconciliation.AppleControlAliasReconciliationError,
        t2_aks_transport.AKSActivationTransportError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
