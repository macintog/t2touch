#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Issue one Linux-native xART publication after the repaired backing proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_aks_transport.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_aks_transport
import t2_mutation_journal as journal


JOURNAL = Path("/var/lib/t2-touchid/oracle/xart-post-repair.jsonl")
MATCH_PROOF = Path(
    "/var/lib/t2-touchid/oracle/tui-match-20260903T155319000686Z.json"
)
MATCH_PROOF_SHA256 = (
    "454d8a858af09e2b1862cbbedff56784510b94b0cb0b68e74c8bcf3eecf78841"
)
CONFIG = Path("/etc/t2-touchid.conf")


def _require_match_proof() -> None:
    digest = hashlib.sha256()
    with MATCH_PROOF.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != MATCH_PROOF_SHA256:
        raise RuntimeError("repaired-backing match proof does not validate")


def _require_linux_native() -> None:
    selections = [
        line.removeprefix("T2_TOUCHID_AUTHORITY_MODE=").strip()
        for line in CONFIG.read_text().splitlines()
        if line.startswith("T2_TOUCHID_AUTHORITY_MODE=")
    ]
    if selections != ["linux-native"]:
        raise RuntimeError("authority mode is not exactly linux-native")


def main() -> int:
    print(
        "retired: direct PCI xART command 8 reaches AMDM, not internal xars",
        file=sys.stderr,
    )
    return 2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-one-shot-post-repair-xart",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("post-repair xART discriminator must run as root")
        if not args.acknowledge_one_shot_post_repair_xart:
            raise RuntimeError("one-shot post-repair acknowledgement is required")
        if JOURNAL.exists():
            raise RuntimeError("post-repair xART journal already exists")
        _require_match_proof()
        _require_linux_native()

        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        operation_id = str(uuid.uuid4())
        with t2_aks_transport.AKSDeferredXARTTransport() as transport:
            first = journal.append(
                JOURNAL,
                operation_id,
                "XART_POST_REPAIR_INTENT",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "header_version": transport.header_version,
                    "authority_mode": "linux-native",
                    "repaired_backing_proof_valid": True,
                    "mutation_possible": True,
                    "retry_before_reboot_permitted": False,
                },
                exclusive=True,
            )
            published = transport.publish_deferred_xart_uuid()
            journal.append(
                JOURNAL,
                operation_id,
                "XART_POST_REPAIR_COMPLETE",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "header_version": transport.header_version,
                    "xart_published": published,
                    "mutation_performed": True,
                    "retry_before_reboot_permitted": False,
                },
                expected_record_count=1,
                expected_previous_hash=first["record_hash"],
            )
        print(
            json.dumps(
                {
                    "header_version": transport.header_version,
                    "identifiers_redacted": True,
                    "xart_published": published,
                },
                indent=2,
                sort_keys=True,
            )
        )
    except (
        OSError,
        RuntimeError,
        journal.JournalError,
        t2_aks_transport.AKSActivationTransportError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
