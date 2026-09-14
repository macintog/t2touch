#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stop an add-finger preflight after redacted host/live identity counts."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import sys


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
INSTALLED_ENROLL = Path("/usr/local/sbin/t2-native-enroll")
PREFIX = "D206_SAFE_IDENTITY_COUNTS "


def _load_enrollment_owner():
    sys.path.insert(0, str(INSTALLED_SOURCE))
    name = "d206_installed_native_enroll"
    loader = SourceFileLoader(name, str(INSTALLED_ENROLL))
    spec = importlib.util.spec_from_loader(
        name, loader
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("installed enrollment owner is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    owner = _load_enrollment_owner()
    original = owner.t2_baseline.build_linux_native_existing_baseline

    def observe(**kwargs):
        host = kwargs["host"]
        live = kwargs["live"]
        host_records = host.get("identity_records", [])
        per_user = live.get("per_user_identity_records", [])
        global_records = live.get("global_identity_records", [])
        host_set = {
            (record.get("user_id"), record.get("uuid"))
            for record in host_records
            if isinstance(record, dict)
        }
        per_user_set = {
            (record.get("user_id"), record.get("identity_uuid"))
            for record in per_user
            if isinstance(record, dict)
        }
        global_set = {
            (record.get("user_id"), record.get("identity_uuid"))
            for record in global_records
            if isinstance(record, dict)
        }
        catacomb = live.get("catacomb")
        states = catacomb.get("user_states", []) if isinstance(catacomb, dict) else []
        safe_states = [
            {
                "kind": record.get("kind"),
                "state": record.get("state"),
                "needs_save": record.get("needs_save"),
            }
            for record in states
            if isinstance(record, dict)
        ]
        document = {
            "host_identity_count": len(host_records),
            "live_per_user_identity_count": len(per_user),
            "live_global_identity_count": len(global_records),
            "per_user_equals_host": per_user_set == host_set,
            "global_projection_equals_per_user": global_set == per_user_set,
            "live_catacomb_present": (
                catacomb.get("present") if isinstance(catacomb, dict) else None
            ),
            "safe_component_states": safe_states,
            "maximum_capacity": live.get("maximum_capacity"),
            "configured_user_free_capacity": live.get(
                "configured_user_free_capacity"
            ),
            "host_master_enrollment_count": host.get("master_enrollment_count"),
            "identifiers_redacted": True,
        }
        print(PREFIX + json.dumps(document, sort_keys=True), file=sys.stderr, flush=True)
        raise owner.t2_baseline.BaselineError(
            "diagnostic stop after redacted identity-count observation"
        )

    owner.t2_baseline.build_linux_native_existing_baseline = observe
    try:
        sys.argv = [str(INSTALLED_ENROLL), "--preflight-add-finger"]
        return owner.main()
    finally:
        owner.t2_baseline.build_linux_native_existing_baseline = original


if __name__ == "__main__":
    raise SystemExit(main())
