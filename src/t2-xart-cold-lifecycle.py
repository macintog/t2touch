#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Issue one journaled xART publication after a cold bridgeOS lifecycle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

SOURCE = Path(__file__).resolve().parent
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

import t2_aks_transport
import t2_mutation_journal as journal


JOURNAL = Path("/var/lib/t2-touchid/oracle/xart-cold-lifecycle.jsonl")


def main() -> int:
    print(
        "retired: direct PCI xART command 8 reaches AMDM, not internal xars",
        file=sys.stderr,
    )
    return 2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-one-shot-cold-lifecycle-xart",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("cold-lifecycle xART discriminator must run as root")
        if not args.acknowledge_one_shot_cold_lifecycle_xart:
            raise RuntimeError("one-shot cold-lifecycle acknowledgement is required")
        if JOURNAL.exists():
            raise RuntimeError("cold-lifecycle xART journal already exists")

        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        operation_id = str(uuid.uuid4())
        with t2_aks_transport.AKSDeferredXARTTransport() as transport:
            first = journal.append(
                JOURNAL,
                operation_id,
                "XART_COLD_LIFECYCLE_INTENT",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "header_version": transport.header_version,
                    "mutation_possible": True,
                    "retry_before_reboot_permitted": False,
                },
                exclusive=True,
            )
            published = transport.publish_deferred_xart_uuid()
            journal.append(
                JOURNAL,
                operation_id,
                "XART_COLD_LIFECYCLE_COMPLETE",
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
    except (OSError, RuntimeError, journal.JournalError,
            t2_aks_transport.AKSActivationTransportError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
