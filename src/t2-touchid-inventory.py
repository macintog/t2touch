#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Return a privacy-safe live SEP identity inventory for the configured user."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


CONFIG = Path("/etc/t2-touchid.conf")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")


class InventoryError(RuntimeError):
    pass


def read_assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z0-9_]+", key):
            values[key] = value
    return values


def successful_reply(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("valid") is True
        and value.get("status") == 0
    )


def summarize_probe(probe: Any, expected_uid: int) -> dict[str, Any]:
    if not isinstance(probe, dict):
        raise InventoryError("probe returned a non-object result")
    if probe.get("biometric_protocol_v2_attested") is not True:
        raise InventoryError("full SEP inventory requires attested biometric protocol v2")
    if not successful_reply(probe.get("identity_list_reply")):
        raise InventoryError("SEP identity inventory failed")
    count = probe.get("identity_record_count")
    if not isinstance(count, int) or count < 0:
        raise InventoryError("SEP returned an invalid identity count")
    if probe.get("identity_record_bytes_valid") is not True:
        raise InventoryError("SEP returned malformed identity records")
    user_field = probe.get("identity_user_field")
    if count and user_field != "prefix":
        raise InventoryError("SEP identity records do not match the expected layout")
    for field, description in (
        ("identity_inventory_repeat_equal", "identity inventory"),
        ("global_identity_inventory_repeat_equal", "global identity inventory"),
        ("identity_capacity_repeat_equal", "identity capacity"),
        ("catacomb_component_repeat_equal", "Catacomb component"),
        ("catacomb_state_repeat_equal", "Catacomb state"),
        ("sks_lock_state_repeat_equal", "SKS lock state"),
        ("full_snapshot_repeat_equal", "complete inventory snapshot"),
    ):
        if probe.get(field) is not True:
            raise InventoryError(f"{description} changed during double collection")
    if not successful_reply(probe.get("global_identity_list_reply")):
        raise InventoryError("global SEP identity inventory failed")
    if probe.get("global_identity_record_bytes_valid") is not True:
        raise InventoryError("SEP returned malformed global identity records")
    if probe.get("configured_identity_records_reconciled") is not True:
        raise InventoryError("per-user and global SEP identities disagree")
    for field, description in (
        ("identity_capacity_reply", "maximum identity capacity"),
        ("identity_free_count_reply", "free identity capacity"),
        ("catacomb_uuid_reply", "Catacomb UUID"),
        ("catacomb_hash_reply", "Catacomb hash"),
    ):
        if not successful_reply(probe.get(field)):
            raise InventoryError(f"{description} query failed")
    if probe.get("catacomb_uuid_length_valid") is not True:
        raise InventoryError("SEP returned a malformed Catacomb UUID")
    if probe.get("catacomb_hash_length_valid") is not True:
        raise InventoryError("SEP returned a malformed Catacomb hash")
    maximum = probe.get("identity_maximum_capacity")
    free = probe.get("identity_free_count")
    global_count = probe.get("global_identity_record_count")
    if not all(isinstance(value, int) and value >= 0 for value in (maximum, free, global_count)):
        raise InventoryError("SEP returned invalid identity capacity metadata")
    if free > maximum or global_count > maximum:
        raise InventoryError("SEP identity counts exceed reported capacity")

    result: dict[str, Any] = {
        "schema_version": 1,
        "biometric_protocol_version": 2,
        "user_id": expected_uid,
        "sep_identity_count": count,
        "global_sep_identity_count": global_count,
        "maximum_identity_capacity": maximum,
        "configured_user_free_capacity": free,
        "per_user_global_reconciled": True,
        "catacomb_component_present": probe.get("catacomb_component_present"),
        "identity_records_valid": True,
        "double_collection_equal": True,
        "identifiers_redacted": True,
    }
    catacomb = probe.get("catacomb_state_reply")
    result["catacomb_state_query_ok"] = successful_reply(catacomb)
    words = probe.get("catacomb_state_words")
    if isinstance(words, list) and all(isinstance(word, int) for word in words):
        result["catacomb_state_word_count"] = len(words)
    sks = probe.get("sks_lock_state_reply")
    result["sks_lock_state_query_ok"] = successful_reply(sks)
    if successful_reply(sks) and isinstance(probe.get("sks_lock_state"), int):
        result["sks_lock_state_raw"] = probe["sks_lock_state"]
    return result


def summarize_preclient_probe(probe: Any) -> dict[str, Any]:
    if not isinstance(probe, dict):
        raise InventoryError("pre-authority probe returned a non-object result")
    if probe.get("schema_version") != 1:
        raise InventoryError("pre-authority schema version is not supported")
    if probe.get("mode") != "preclient-inventory":
        raise InventoryError("probe did not return a pre-authority inventory")
    if probe.get("diagnostic_contract") != "pre-authority-v1":
        raise InventoryError("pre-authority diagnostic contract is not supported")
    if probe.get("mutation_performed") is not False:
        raise InventoryError("pre-authority probe reports a mutation")
    if probe.get("authority") != "unknown":
        raise InventoryError("pre-authority probe claims authority")
    if probe.get("identifiers_redacted") is not True:
        raise InventoryError("pre-authority probe did not redact identifiers")
    if probe.get("double_collection_equal") is not True:
        raise InventoryError("pre-authority inventory changed during collection")
    state = probe.get("state")
    if state not in {"absent-baseline", "present"}:
        raise InventoryError("pre-authority state is unknown")
    if (
        probe.get("biometric_protocol_version") != 2
        or probe.get("biometric_protocol_attestation")
        not in {"command-1", "v2-global-identity-command"}
    ):
        raise InventoryError("biometric protocol v2 is not attested")
    for field in (
        "per_user_identity_count",
        "global_identity_count",
        "maximum_identity_capacity",
        "configured_user_free_capacity",
        "catacomb_master_state",
        "catacomb_state_word_count",
        "sks_lock_state_raw",
    ):
        value = probe.get(field)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise InventoryError(f"pre-authority {field} is invalid")
    maximum = probe["maximum_identity_capacity"]
    free = probe["configured_user_free_capacity"]
    per_user = probe["per_user_identity_count"]
    global_count = probe["global_identity_count"]
    if free > maximum or per_user > maximum or global_count > maximum:
        raise InventoryError("pre-authority identity counts exceed capacity")
    for field in (
        "catacomb_uuid_present",
        "catacomb_component_present",
        "selected_user_component_present",
    ):
        if type(probe.get(field)) is not bool:
            raise InventoryError(f"pre-authority {field} is invalid")
    if state == "absent-baseline" and (
        per_user
        or global_count
        or probe["catacomb_uuid_present"]
        or probe["catacomb_component_present"]
        or probe["selected_user_component_present"]
    ):
        raise InventoryError("absent baseline contains live state")
    if state == "present" and not (
        per_user
        or global_count
        or probe["catacomb_uuid_present"]
        or probe["catacomb_component_present"]
        or probe["selected_user_component_present"]
    ):
        raise InventoryError("present state has no matching evidence")
    return {
        "schema_version": 1,
        "mode": "preclient-inventory",
        "diagnostic_contract": "pre-authority-v1",
        "state": state,
        "biometric_protocol_version": 2,
        "biometric_protocol_attestation": probe[
            "biometric_protocol_attestation"
        ],
        "per_user_identity_count": per_user,
        "global_identity_count": global_count,
        "maximum_identity_capacity": maximum,
        "configured_user_free_capacity": free,
        "catacomb_uuid_present": probe["catacomb_uuid_present"],
        "catacomb_component_present": probe["catacomb_component_present"],
        "catacomb_master_state": probe["catacomb_master_state"],
        "selected_user_component_present": probe[
            "selected_user_component_present"
        ],
        "catacomb_state_word_count": probe["catacomb_state_word_count"],
        "sks_lock_state_raw": probe["sks_lock_state_raw"],
        "double_collection_equal": True,
        "authority": "unknown",
        "mutation_performed": False,
        "identifiers_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    parser.add_argument(
        "--preclient",
        action="store_true",
        help=(
            "read-only pre-authority inventory; never provisions or adopts "
            "authority"
        ),
    )
    args = parser.parse_args()
    try:
        config = read_assignments(CONFIG)
        uid_text = config.get("T2_TOUCHID_MACOS_USER_ID", "")
        if not uid_text.isdecimal() or int(uid_text) > 0xFFFFFFFF:
            raise InventoryError("invalid configured macOS user ID")
        uid = int(uid_text)
        host = config.get("T2_TOUCHID_HOST", "")
        interface = config.get("T2_TOUCHID_INTERFACE", "")
        project = Path(config.get("T2_TOUCHID_PROJECT_DIR", "/opt/t2-touchid"))
        port_text = PORT_CACHE.read_text().strip()
        if not port_text.isdecimal() or not 49152 <= int(port_text) <= 65535:
            raise InventoryError("invalid cached BiometricKit port")
        python = project / ".venv/bin/python"
        probe = project / "src/bridge-xpc-probe.py"
        if not python.is_file() or not probe.is_file() or not host or not interface:
            raise InventoryError("Touch ID installation is incomplete")
        probe_mode = (
            "--preclient-inventory" if args.preclient else "--full-inventory"
        )
        completed = subprocess.run(
            [
                "/usr/bin/flock",
                "--exclusive",
                "--timeout",
                "10",
                "--no-fork",
                "/run/t2-touchid/operation.lock",
                str(python),
                str(probe),
                "--host", host,
                "--interface", interface,
                "--port", port_text,
                "--macos-user-id", str(uid),
                "--initialize",
                probe_mode,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin"},
        )
        if completed.returncode:
            detail = completed.stderr.strip().splitlines()[-1:] or ["unknown error"]
            raise InventoryError(f"BridgeXPC probe failed: {detail[0]}")
        probe_result = json.loads(completed.stdout)
        result = (
            summarize_preclient_probe(probe_result)
            if args.preclient
            else summarize_probe(probe_result, uid)
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired, InventoryError) as error:
        parser.error(str(error))
    print(json.dumps(result, separators=(",", ":") if args.json else None, indent=None if args.json else 2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
