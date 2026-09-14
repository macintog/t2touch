#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one read-only stable-empty AKS provisioning preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import uuid

SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_aks_provisioning_transport.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_aks_provisioning_transport as provisioning_transport
import t2_mutation_journal as journal


JOURNAL = Path(
    "/var/lib/t2-touchid/oracle/native-provisioning-preflight-v3.jsonl"
)
CONFIG = Path("/etc/t2-touchid.conf")
D124_MANIFEST = Path(
    "/var/lib/t2-touchid/research-artifact-snapshots/"
    "D124-xart-routing-correction-20260903T212912Z/SHA256SUMS"
)
D124_MANIFEST_SHA256 = (
    "d1c3c2ebfcbc2bf868a7e5b8c7835294847ebe1ee86e38dc29a1dd25703a67f6"
)


def _require_file_hash(path: Path, expected: str) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise RuntimeError("D124 routing-correction manifest does not validate")


def _require_linux_native() -> None:
    selections = [
        line.removeprefix("T2_TOUCHID_AUTHORITY_MODE=").strip()
        for line in CONFIG.read_text().splitlines()
        if line.startswith("T2_TOUCHID_AUTHORITY_MODE=")
    ]
    if selections != ["linux-native"]:
        raise RuntimeError("authority mode is not exactly linux-native")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-one-shot-native-provisioning-preflight",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("native provisioning preflight must run as root")
        if not args.acknowledge_one_shot_native_provisioning_preflight:
            raise RuntimeError("one-shot provisioning-preflight acknowledgement is required")
        if JOURNAL.exists():
            raise RuntimeError("native provisioning preflight journal already exists")
        _require_file_hash(D124_MANIFEST, D124_MANIFEST_SHA256)
        _require_linux_native()

        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        operation_id = str(uuid.uuid4())
        session = secrets.randbits(63) or 1
        with provisioning_transport.AKSProvisioningTransport() as transport:
            first = journal.append(
                JOURNAL,
                operation_id,
                "NATIVE_PROVISIONING_PREFLIGHT_INTENT",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.connection_generation,
                    "authority_mode": "linux-native",
                    "d124_manifest_valid": True,
                    "read_only_operations": 2,
                    "mutation_possible": False,
                    "retry_permitted": False,
                },
                exclusive=True,
            )
            try:
                attestation = transport.collect_stable_empty_preflight(session)
            except provisioning_transport.AKSProvisioningTransportError:
                journal.append(
                    JOURNAL,
                    operation_id,
                    "NATIVE_PROVISIONING_PREFLIGHT_FAILED",
                    {
                        "linux_boot_uuid": boot,
                        "runtime_generation": transport.connection_generation,
                        "hardware_observation_attempted": True,
                        "stable_empty": False,
                        "retry_permitted": False,
                    },
                    expected_record_count=1,
                    expected_previous_hash=first["record_hash"],
                )
                raise
            journal.append(
                JOURNAL,
                operation_id,
                "NATIVE_PROVISIONING_PREFLIGHT_COMPLETE",
                {
                    "linux_boot_uuid": boot,
                    "runtime_generation": transport.connection_generation,
                    "evidence_sha256": attestation.evidence_sha256,
                    "primary_identity_absent": attestation.primary_identity_absent,
                    "inventory_stable": attestation.inventory_stable,
                    "mutation_performed": False,
                    "retry_permitted": False,
                },
                expected_record_count=1,
                expected_previous_hash=first["record_hash"],
            )
        print(
            json.dumps(
                {
                    "identifiers_redacted": True,
                    "inventory_stable": attestation.inventory_stable,
                    "primary_identity_absent": attestation.primary_identity_absent,
                },
                indent=2,
                sort_keys=True,
            )
        )
    except (
        OSError,
        RuntimeError,
        journal.JournalError,
        provisioning_transport.AKSProvisioningTransportError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
