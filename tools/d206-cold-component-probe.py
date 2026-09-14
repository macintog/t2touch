#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stop a cold add-finger preflight after the first redacted component read."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import sys


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
INSTALLED_ENROLL = Path("/usr/local/sbin/t2-native-enroll")
PREFIX = "D206_COLD_COMPONENTS "


def _load_enrollment_owner():
    sys.path.insert(0, str(INSTALLED_SOURCE))
    name = "d206_cold_component_installed_native_enroll"
    loader = SourceFileLoader(name, str(INSTALLED_ENROLL))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError("installed enrollment owner is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    owner = _load_enrollment_owner()
    restore = owner.t2_native_state_restore
    original = restore._component_map

    def observe(states, apple_user_id, *, allow_master_only=False):
        document = {
            "component_count": len(states),
            "components": [
                {
                    "kind": record.component.kind.value,
                    "selected_user": (
                        record.component.kind.value == "user"
                        and record.component.user_id == apple_user_id
                    ),
                    "state": record.state,
                    "needs_save": record.needs_save,
                }
                for record in states
            ],
            "allow_master_only": allow_master_only,
            "identifiers_redacted": True,
        }
        print(PREFIX + json.dumps(document, sort_keys=True), file=sys.stderr, flush=True)
        raise restore.NativeStateRestoreError(
            "diagnostic stop after redacted cold component observation"
        )

    restore._component_map = observe
    try:
        sys.argv = [str(INSTALLED_ENROLL), "--preflight-add-finger"]
        return owner.main()
    finally:
        restore._component_map = original


if __name__ == "__main__":
    raise SystemExit(main())
