#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guarded one-shot reset for an empty loaded compatibility biometric user."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_compatibility_user_rebind.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_bridge_connection
import t2_catacomb_store
import t2_compatibility_user_rebind
import t2_mutation_registry
import t2_user_authority


STATE_ROOT = Path("/var/lib/t2-touchid")
STORE_ROOT = STATE_ROOT / "catacomb"
MUTATION_ROOT = STATE_ROOT / "mutations"
JOURNAL_PATH = (
    STATE_ROOT
    / "research-artifacts/d225-compatibility-empty-user-rebind/operation.jsonl"
)
KEYBAG_STATE = Path("/run/t2-touchid/keybag.env")
UNLOCK_STATE = Path("/run/t2-touchid/keybags-unlocked")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")


class EmptyUserRebindCommandError(RuntimeError):
    pass


def _management_module():
    path = LOCAL_SOURCE / "t2-touchid-manage.py"
    if not path.is_file():
        path = INSTALLED_SOURCE / "t2-touchid-manage.py"
    specification = importlib.util.spec_from_file_location(
        "t2_touchid_rebind_management", path
    )
    if specification is None or specification.loader is None:
        raise EmptyUserRebindCommandError("identity management module is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _fresh_port(configuration: dict[str, object]) -> int:
    completed = subprocess.run(
        [
            sys.executable,
            str(LOCAL_SOURCE / "discover-biometric-port.py"),
            "--host",
            str(configuration["host"]),
            "--interface",
            str(configuration["interface"]),
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    value = completed.stdout.decode("ascii", errors="strict").strip()
    if completed.returncode or not value.isdecimal() or not 49152 <= int(value) <= 65535:
        detail = completed.stderr.decode(errors="replace").strip()
        raise EmptyUserRebindCommandError(detail or "biometric service discovery failed")
    return int(value)


def _require_runtime_state() -> None:
    if KEYBAG_STATE.read_bytes() != UNLOCK_STATE.read_bytes():
        raise EmptyUserRebindCommandError("keybag load and unlock markers disagree")
    active = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "fprintd.service"],
        check=False,
        capture_output=True,
        timeout=5,
    )
    if active.returncode == 0:
        raise EmptyUserRebindCommandError("fprintd must be stopped for empty-user recovery")


def run(
    *,
    restore_saved_user: bool = False,
    settle_removed_master: bool = False,
    prepare_missing_user: bool = False,
    prepare_missing_components: bool = False,
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise EmptyUserRebindCommandError("run through sudo")
    if (
        not restore_saved_user
        and not settle_removed_master
        and not prepare_missing_user
        and not prepare_missing_components
        and os.path.lexists(JOURNAL_PATH)
    ):
        raise EmptyUserRebindCommandError(
            "the one-shot recovery journal already exists; refusing a second dispatch"
        )
    if (
        restore_saved_user
        or settle_removed_master
        or prepare_missing_user
        or prepare_missing_components
    ) and not os.path.lexists(JOURNAL_PATH):
        raise EmptyUserRebindCommandError(
            "the one-shot recovery journal is absent; refusing saved-user load"
        )
    management = _management_module()
    configuration = management.runtime_configuration()
    if configuration["authority_mode"] != t2_user_authority.COMPATIBILITY_MODE:
        raise EmptyUserRebindCommandError("selected authority is not compatibility mode")
    authority = t2_user_authority.load_compatibility(
        int(configuration["linux_uid"]), state_root=STATE_ROOT
    )
    selected = authority.selected
    if (
        authority.origin != "macos-control-oracle-v1"
        or selected.apple_uid != configuration["apple_uid"]
        or selected.special_bag_alias != configuration["special_bag"]
        or "identity-management" not in selected.capabilities
    ):
        raise EmptyUserRebindCommandError("compatibility authority does not reconcile")
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise EmptyUserRebindCommandError("an ordinary biometric mutation is unfinished")
    management.keybag_runtime(int(configuration["special_bag"]))
    _require_runtime_state()
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, int(configuration["apple_uid"])
    )
    canonical = t2_compatibility_user_rebind.read_canonical_authority(
        store,
        int(configuration["apple_uid"]),
        expected_account_uuid=selected.account_uuid,
        expected_keybag_uuid=selected.bag_uuid,
    )
    port = _fresh_port(configuration)
    with management.operation_lock(), management.sleep_inhibitor():
        arguments = {
            "apple_user_id": int(configuration["apple_uid"]),
            "canonical": canonical,
            "authority_generation": authority.mapping_set.generation,
            "linux_boot_uuid": BOOT_ID.read_text(encoding="ascii").strip(),
            "journal_path": JOURNAL_PATH,
        }
        if prepare_missing_components:
            with t2_bridge_connection.BridgeConnectionLease.connect(
                str(configuration["host"]),
                str(configuration["interface"]),
                port,
                timeout=30,
            ) as preflight_lease:
                preflight_surface = (
                    t2_compatibility_user_rebind.read_stable_surface(
                        preflight_lease, int(configuration["apple_uid"])
                    )
                )
            with t2_bridge_connection.BridgeConnectionLease.connect(
                str(configuration["host"]),
                str(configuration["interface"]),
                port,
                timeout=30,
                defer_client_version=True,
            ) as lease:
                return t2_compatibility_user_rebind.prepare_missing_components_once(
                    lease, preflight_surface=preflight_surface, **arguments
                )
        with t2_bridge_connection.BridgeConnectionLease.connect(
            str(configuration["host"]),
            str(configuration["interface"]),
            port,
            timeout=30,
        ) as lease:
            if prepare_missing_user:
                return t2_compatibility_user_rebind.prepare_missing_user_once(
                    lease, **arguments
                )
            if settle_removed_master:
                return t2_compatibility_user_rebind.settle_removed_master_once(
                    lease, **arguments
                )
            if restore_saved_user:
                return t2_compatibility_user_rebind.restore_saved_user_once(
                    lease, **arguments
                )
            return t2_compatibility_user_rebind.reset_empty_loaded_user_once(
                lease, **arguments
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--restore-saved-user",
        action="store_true",
        help="continue an accepted reset by loading its journal-bound saved user",
    )
    parser.add_argument(
        "--settle-removed-master",
        action="store_true",
        help="export and confirm the dirty master retained by an accepted reset",
    )
    parser.add_argument(
        "--prepare-missing-user",
        action="store_true",
        help="admit the selected user component removed by command 0x48",
    )
    parser.add_argument(
        "--prepare-missing-components",
        action="store_true",
        help="run the pre-client master-then-user missing-component sequence",
    )
    args = parser.parse_args()
    if sum(
        (
            args.restore_saved_user,
            args.settle_removed_master,
            args.prepare_missing_user,
            args.prepare_missing_components,
        )
    ) > 1:
        parser.error("select exactly one recovery continuation")
    try:
        result = run(
            restore_saved_user=args.restore_saved_user,
            settle_removed_master=args.settle_removed_master,
            prepare_missing_user=args.prepare_missing_user,
            prepare_missing_components=args.prepare_missing_components,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
        EmptyUserRebindCommandError,
        t2_bridge_connection.BridgeConnectionError,
        t2_catacomb_store.CatacombStoreError,
        t2_compatibility_user_rebind.CompatibilityUserRebindError,
        t2_mutation_registry.MutationRegistryError,
        t2_user_authority.UserAuthorityError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
