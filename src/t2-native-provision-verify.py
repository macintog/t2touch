#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reload one newly provisioned keybag through a fresh owner and enable it."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import uuid

SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_aks_provisioning_operation.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_aks_provisioning
import t2_aks_provisioning_operation
import t2_aks_transport
import t2_linux_account
import t2_user_mapping
import t2_user_mapping_store


CONFIG = Path("/etc/t2-touchid.conf")
STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
JOURNAL = STATE_ROOT / "native-provisioning.jsonl"


class NativeProvisioningVerificationError(RuntimeError):
    pass


def _configuration() -> tuple[int, int]:
    info = CONFIG.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise NativeProvisioningVerificationError("configuration metadata is unsafe")
    wanted = {
        "T2_TOUCHID_USER": [],
        "T2_TOUCHID_MACOS_USER_ID": [],
        "T2_TOUCHID_AUTHORITY_MODE": [],
    }
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name in wanted:
            wanted[name].append(value)
    if any(len(values) != 1 for values in wanted.values()):
        raise NativeProvisioningVerificationError(
            "configuration has missing or duplicate values"
        )
    if wanted["T2_TOUCHID_AUTHORITY_MODE"] != ["linux-native"]:
        raise NativeProvisioningVerificationError(
            "authority mode is not exactly linux-native"
        )
    try:
        linux_uid = pwd.getpwnam(wanted["T2_TOUCHID_USER"][0]).pw_uid
    except KeyError as error:
        raise NativeProvisioningVerificationError(
            "configured Linux user does not exist"
        ) from error
    apple_uid_text = wanted["T2_TOUCHID_MACOS_USER_ID"][0]
    if not apple_uid_text.isdecimal() or not 0 < int(apple_uid_text) < (1 << 32):
        raise NativeProvisioningVerificationError(
            "configured biometric UID is invalid"
        )
    return linux_uid, int(apple_uid_text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-one-shot-native-provisioning-verification",
        action="store_true",
    )
    parser.add_argument(
        "--acknowledge-fresh-owner-activation",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise NativeProvisioningVerificationError(
                "native provisioning verification must run as root"
            )
        if not (
            args.acknowledge_one_shot_native_provisioning_verification
            or args.acknowledge_fresh_owner_activation
        ):
            raise NativeProvisioningVerificationError(
                "one-shot runtime-verification acknowledgement is required"
            )
        history = t2_aks_provisioning.read(JOURNAL)
        if history.phase not in {"mapping-committed", "reboot-verified"}:
            raise NativeProvisioningVerificationError(
                "native provisioning is not awaiting reboot verification"
            )
        linux_uid, apple_uid = _configuration()
        account = t2_linux_account.collect(linux_uid)
        mappings = t2_user_mapping.load(MAPPING)
        if len(mappings.mappings) != 1 or not account.matches_generation(
            mappings.mappings[0].linux_account_generation
        ):
            raise NativeProvisioningVerificationError(
                "native provisioning Linux account generation changed"
            )
        account_generation = mappings.mappings[0].linux_account_generation
        keybag_path = STATE_ROOT / "users" / str(linux_uid) / "user.kb"
        mapping_writer = t2_user_mapping_store.InitialUserMappingStore(
            path=MAPPING,
            operation_id=history.operation_id,
            linux_uid=linux_uid,
            linux_account_generation=account_generation,
            apple_uid=apple_uid,
            keybag_path=keybag_path,
        )

        def load_and_copy_uuid() -> str | tuple[str, str]:
            with t2_aks_transport.AKSActivationTransport() as transport:
                handle = transport.load_keybag(str(keybag_path))
                bag_uuid = transport.bag_uuid(handle)
                transport.unload_keybag(handle)
                return (
                    (bag_uuid, transport.runtime_generation)
                    if args.acknowledge_fresh_owner_activation
                    else bag_uuid
                )

        linux_boot_uuid = str(
            uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        )
        verifier = (
            t2_aks_provisioning_operation.verify_after_owner_change
            if args.acknowledge_fresh_owner_activation
            else t2_aks_provisioning_operation.verify_after_reboot
        )
        history = verifier(
            journal_path=JOURNAL,
            operation_id=history.operation_id,
            linux_boot_uuid=linux_boot_uuid,
            load_and_copy_uuid=load_and_copy_uuid,
            mapping_writer=mapping_writer,
        )
        print(
            json.dumps(
                {
                    "identifiers_redacted": True,
                    "mapping_enabled": history.phase == "mapping-enabled",
                    "runtime_keybag_verified": True,
                    "reboot_keybag_verified": (
                        not args.acknowledge_fresh_owner_activation
                    ),
                },
                sort_keys=True,
            )
        )
    except (
        OSError,
        ValueError,
        NativeProvisioningVerificationError,
        t2_aks_provisioning.AKSProvisioningError,
        t2_aks_provisioning_operation.AKSProvisioningOperationError,
        t2_aks_transport.AKSActivationTransportError,
        t2_linux_account.LinuxAccountError,
        t2_user_mapping_store.UserMappingStoreError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
