#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Derive one-shot native transport gates from validated first-run state."""

from __future__ import annotations

import os
from pathlib import Path

import t2_aks_provisioning
import t2_aks_replacement_journal
import t2_user_mapping


STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
PROVISIONING_JOURNAL = STATE_ROOT / "native-provisioning.jsonl"
REPLACEMENT_JOURNAL = STATE_ROOT / "native-replacement.jsonl"


class NativeTransportGateError(RuntimeError):
    pass


def required_gates() -> tuple[bool, bool]:
    mapping_present = os.path.lexists(MAPPING)
    provisioning_present = os.path.lexists(PROVISIONING_JOURNAL)
    if not mapping_present and not provisioning_present:
        # Product setup completes create, replacement-bundle publication, and
        # activation in one loaded transport lifetime.  Arm both narrowly
        # gated capabilities up front; durable primary-absence checks still
        # authorize each individual mutation.
        return True, True
    if not mapping_present or not provisioning_present:
        raise NativeTransportGateError("native first-run state is incomplete")

    try:
        mappings = t2_user_mapping.load(MAPPING)
        provisioning = t2_aks_provisioning.read(PROVISIONING_JOURNAL)
    except (t2_user_mapping.UserMappingError, t2_aks_provisioning.AKSProvisioningError) as error:
        raise NativeTransportGateError("native first-run state is invalid") from error
    if len(mappings.mappings) != 1 or provisioning.phase not in {
        "mapping-committed",
        "reboot-verified",
        "mapping-enabled",
    }:
        raise NativeTransportGateError("native first-run state is not actionable")
    if mappings.schema_version == t2_user_mapping.LEGACY_SCHEMA_VERSION:
        return False, True
    if mappings.schema_version != t2_user_mapping.SCHEMA_VERSION:
        raise NativeTransportGateError("native mapping schema is unsupported")
    if provisioning.phase != "mapping-enabled" or not os.path.lexists(
        REPLACEMENT_JOURNAL
    ):
        raise NativeTransportGateError("native schema-2 authority is incomplete")
    try:
        replacement = t2_aks_replacement_journal.read(REPLACEMENT_JOURNAL)
    except t2_aks_replacement_journal.AKSReplacementJournalError as error:
        raise NativeTransportGateError("native replacement state is invalid") from error

    selected = mappings.mappings[0]
    if selected.enabled:
        if replacement.phase != "complete":
            raise NativeTransportGateError("enabled native authority is inconsistent")
        return False, False
    if replacement.phase == "mapping-committed":
        return False, True
    if replacement.phase == "complete":
        return False, False
    raise NativeTransportGateError("disabled native authority is not actionable")


def main() -> int:
    try:
        provisioning, replacement = required_gates()
    except (OSError, NativeTransportGateError):
        print("t2-native-transport-gates: state validation failed", file=os.sys.stderr)
        return 1
    print(f"{int(provisioning)} {int(replacement)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
