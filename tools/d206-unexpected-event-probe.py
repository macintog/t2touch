#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Expose only the shape of a rejected preparation callback, then fail closed."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct
import sys


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
INSTALLED_ENROLL = Path("/usr/local/sbin/t2-native-enroll")
PREFIX = "D206_UNEXPECTED_SERVICE_EVENTS "
SERVICE_HEADER = struct.Struct("<QIIQ")


def _load_enrollment_owner():
    sys.path.insert(0, str(INSTALLED_SOURCE))
    name = "d206_unexpected_event_installed_native_enroll"
    loader = SourceFileLoader(name, str(INSTALLED_ENROLL))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError("installed enrollment owner is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _summary(value: object) -> dict[str, object]:
    result: dict[str, object] = {
        "outer_type": type(value).__name__,
        "outer_length": len(value) if isinstance(value, list) else None,
    }
    if not isinstance(value, list):
        return result
    result["field_types"] = [type(field).__name__ for field in value]
    if len(value) >= 2:
        result["method"] = value[0] if type(value[0]) is int else None
        result["bridge_status"] = value[1] if type(value[1]) is int else None
    if len(value) >= 3 and isinstance(value[2], bytes):
        data = value[2]
        result["data_length"] = len(data)
        if len(data) >= SERVICE_HEADER.size:
            reserved, envelope_type, version, ordinal = SERVICE_HEADER.unpack_from(data)
            result.update(
                reserved_zero=reserved == 0,
                envelope_type=f"0x{envelope_type:08x}",
                version=version,
                ordinal=ordinal,
                payload_length=len(data) - SERVICE_HEADER.size,
            )
    return result


def main() -> int:
    owner = _load_enrollment_owner()
    inventory = owner.t2_bridge_inventory
    original = inventory.require_preparation_service_events

    def observe(events, apple_user_id=None):
        try:
            return original(events, apple_user_id)
        except inventory.BridgeInventoryError:
            document = {
                "event_count": len(events) if isinstance(events, list) else None,
                "events": [
                    _summary(value) for value in events
                ] if isinstance(events, list) else [],
                "identifiers_redacted": True,
            }
            print(
                PREFIX + json.dumps(document, sort_keys=True),
                file=sys.stderr,
                flush=True,
            )
            raise

    inventory.require_preparation_service_events = observe
    try:
        sys.argv = [str(INSTALLED_ENROLL), "--preflight-add-finger"]
        return owner.main()
    finally:
        inventory.require_preparation_service_events = original


if __name__ == "__main__":
    raise SystemExit(main())
