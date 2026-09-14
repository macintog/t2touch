#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the one-shot imported Apple keybag alias-binding discriminator."""

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
import t2_apple_control_discriminator as keybag_discriminator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-user", required=True)
    parser.add_argument(
        "--acknowledge-one-shot-sep-alias-binding", action="store_true"
    )
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise alias_discriminator.AppleControlAliasDiscriminatorError(
                "alias discriminator must run as root"
            )
        if not arguments.acknowledge_one_shot_sep_alias_binding:
            raise alias_discriminator.AppleControlAliasDiscriminatorError(
                "one-shot SEP alias-binding acknowledgement is required"
            )
        try:
            account = pwd.getpwnam(arguments.linux_user)
        except KeyError as error:
            raise alias_discriminator.AppleControlAliasDiscriminatorError(
                "selected Linux user does not exist"
            ) from error
        evidence = keybag_discriminator.read_oracle_import(
            keybag_discriminator.STATE_ROOT, account.pw_uid
        )
        oracle_root = keybag_discriminator.STATE_ROOT / "oracle"
        proof = alias_discriminator.read_matched_keybag_proof(
            oracle_root / "apple-control-discriminator.jsonl", evidence
        )
        linux_boot_uuid = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        alias_discriminator.require_later_boot(proof, linux_boot_uuid)
        journal_plan = alias_discriminator.select_alias_journal(
            oracle_root, evidence, proof, linux_boot_uuid
        )
        with t2_aks_transport.AKSActivationTransport() as transport:
            result = alias_discriminator.run(
                journal_path=journal_plan.path,
                evidence=evidence,
                matched_proof=proof,
                linux_boot_uuid=linux_boot_uuid,
                transport=transport,
                reconciled_prestate_operation_id=(
                    journal_plan.reconciled_prestate_operation_id
                ),
            )
        print(json.dumps(result.public_summary(), indent=2, sort_keys=True))
    except (
        OSError,
        alias_discriminator.AppleControlAliasDiscriminatorError,
        keybag_discriminator.AppleControlDiscriminatorError,
        t2_aks_transport.AKSActivationTransportError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
