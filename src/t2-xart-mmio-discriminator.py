#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Issue one xART publication with the D121 MMIO-word diagnostics active."""

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


JOURNAL = Path("/var/lib/t2-touchid/oracle/xart-mmio-discriminator.jsonl")
CONFIG = Path("/etc/t2-touchid.conf")
D120_MANIFEST = Path(
    "/var/lib/t2-touchid/research-artifact-snapshots/"
    "D120-xart-routing-boundary-20260903T210232Z/SHA256SUMS"
)
D120_MANIFEST_SHA256 = (
    "c194bb61e0d045e0b9c8b7c8c87e0ca394e7679ce6a968d1cff1f58285439784"
)


def _require_file_hash(path: Path, expected: str) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise RuntimeError("D120 routing evidence manifest does not validate")


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
        "--acknowledge-one-shot-xart-mmio-discriminator",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("xART MMIO discriminator must run as root")
        if not args.acknowledge_one_shot_xart_mmio_discriminator:
            raise RuntimeError("one-shot xART MMIO acknowledgement is required")
        if JOURNAL.exists():
            raise RuntimeError("xART MMIO discriminator journal already exists")
        _require_file_hash(D120_MANIFEST, D120_MANIFEST_SHA256)
        _require_linux_native()

        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        operation_id = str(uuid.uuid4())
        with t2_aks_transport.AKSDeferredXARTTransport() as transport:
            first = journal.append(
                JOURNAL,
                operation_id,
                "XART_MMIO_INTENT",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "header_version": transport.header_version,
                    "authority_mode": "linux-native",
                    "d120_manifest_valid": True,
                    "mmio_word_diagnostics_expected": True,
                    "mutation_possible": True,
                    "retry_permitted": False,
                },
                exclusive=True,
            )
            try:
                published = transport.publish_deferred_xart_uuid()
            except t2_aks_transport.AKSActivationTransportError:
                journal.append(
                    JOURNAL,
                    operation_id,
                    "XART_MMIO_FAILED",
                    {
                        "linux_boot_uuid": boot,
                        "runtime_generation": transport.runtime_generation,
                        "header_version": transport.header_version,
                        "mutation_attempted": True,
                        "retry_permitted": False,
                    },
                    expected_record_count=1,
                    expected_previous_hash=first["record_hash"],
                )
                raise
            journal.append(
                JOURNAL,
                operation_id,
                "XART_MMIO_COMPLETE",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.runtime_generation,
                    "header_version": transport.header_version,
                    "xart_published": published,
                    "mutation_performed": True,
                    "retry_permitted": False,
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
