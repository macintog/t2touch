#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the one-shot imported Apple keybag UUID discriminator."""

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
import t2_apple_control_discriminator as discriminator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-user", required=True)
    parser.add_argument(
        "--acknowledge-one-shot-sep-discriminator", action="store_true"
    )
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise discriminator.AppleControlDiscriminatorError(
                "discriminator must run as root"
            )
        if not arguments.acknowledge_one_shot_sep_discriminator:
            raise discriminator.AppleControlDiscriminatorError(
                "one-shot SEP discriminator acknowledgement is required"
            )
        try:
            account = pwd.getpwnam(arguments.linux_user)
        except KeyError as error:
            raise discriminator.AppleControlDiscriminatorError(
                "selected Linux user does not exist"
            ) from error
        evidence = discriminator.read_oracle_import(
            discriminator.STATE_ROOT, account.pw_uid
        )
        linux_boot_uuid = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        journal_path = (
            discriminator.STATE_ROOT / "oracle" / "apple-control-discriminator.jsonl"
        )
        with t2_aks_transport.AKSActivationTransport() as transport:
            result = discriminator.run(
                journal_path=journal_path,
                evidence=evidence,
                linux_boot_uuid=linux_boot_uuid,
                transport=transport,
            )
        print(json.dumps(result.public_summary(), indent=2, sort_keys=True))
    except (
        OSError,
        discriminator.AppleControlDiscriminatorError,
        t2_aks_transport.AKSActivationTransportError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
