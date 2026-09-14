#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Observe whether reloading only the committed user restores identities."""

from __future__ import annotations

from importlib.machinery import SourceFileLoader
import importlib.util
import json
from pathlib import Path
import struct
import sys


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
INSTALLED_ENROLL = Path("/usr/local/sbin/t2-native-enroll")
PREFIX = "D206_SAFE_USER_RELOAD_COUNTS "


def _load_enrollment_owner():
    sys.path.insert(0, str(INSTALLED_SOURCE))
    name = "d206_installed_native_enroll_user_reload_probe"
    loader = SourceFileLoader(name, str(INSTALLED_ENROLL))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError("installed enrollment owner is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _safe_states(states) -> list[dict[str, object]]:
    return [
        {
            "kind": record.component.kind.value,
            "state": record.state,
            "needs_save": record.needs_save,
        }
        for record in states
    ]


def main() -> int:
    owner = _load_enrollment_owner()
    restore = owner.t2_native_state_restore
    original = restore.restore_for_enrollment

    def observe(lease, *, apple_user_id, catacomb_store, biolockout_store):
        del biolockout_store
        components = catacomb_store.read_committed_components()
        user = owner.t2_catacomb_codec.decode_user_catacomb(
            components[f"user_{apple_user_id:08x}.cat"], apple_user_id
        )
        committed = {(identity.user_id, identity.uuid) for identity in user.identities}
        before_states = restore._states(lease, apple_user_id)
        restore._require_no_groups(lease, apple_user_id)
        before = restore._identities(lease, apple_user_id)
        for component, label in (
            (0xFFFFFFFF, "master Catacomb selection"),
            (apple_user_id, "selected user Catacomb selection"),
        ):
            reply, events = lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", component),
                output_capacity=0,
            )
            if restore._output(reply, events, label, apple_user_id):
                raise restore.NativeStateRestoreError(
                    f"{label} returned unexpected output"
                )
        reply, events = lease.biometric_command(
            0x40,
            version=1,
            value=0,
            data=user.secure_data,
            output_capacity=0,
        )
        try:
            owner.t2_bridge_inventory.require_preparation_service_events(
                events, apple_user_id
            )
        except owner.t2_bridge_inventory.BridgeInventoryError as error:
            raise restore.NativeStateRestoreError(
                "selected user Catacomb reload emitted an unexpected service event"
            ) from error
        reply_status = (
            reply[0]
            if type(reply) is list
            and reply
            and type(reply[0]) is int
            and not isinstance(reply[0], bool)
            else None
        )
        output_valid = False
        if reply_status is not None and len(reply) in (1, 2):
            output = b"" if len(reply) == 1 else reply[1]
            if restore.wire.is_biometric_nil_output(output):
                output = b""
            output_valid = output == b""
        after_states = restore._states(lease, apple_user_id)
        restore._require_no_groups(lease, apple_user_id)
        after = restore._identities(lease, apple_user_id)
        document = {
            "committed_identity_count": len(committed),
            "before_live_identity_count": len(before),
            "reload_status": reply_status,
            "reload_output_empty": output_valid,
            "after_live_identity_count": len(after),
            "after_equals_committed": after == committed,
            "before_component_states": _safe_states(before_states),
            "after_component_states": _safe_states(after_states),
            "identifiers_redacted": True,
        }
        print(PREFIX + json.dumps(document, sort_keys=True), file=sys.stderr, flush=True)
        raise restore.NativeStateRestoreError(
            "diagnostic stop after redacted user-reload observation"
        )

    restore.restore_for_enrollment = observe
    try:
        sys.argv = [str(INSTALLED_ENROLL), "--preflight-add-finger"]
        return owner.main()
    finally:
        restore.restore_for_enrollment = original


if __name__ == "__main__":
    raise SystemExit(main())
