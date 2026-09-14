#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Create and persist the first Linux-owned T2 AppleKeyStore identity once."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
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

import t2_acm_device
import t2_aks_provisioning
import t2_aks_provisioning_operation
import t2_aks_provisioning_transport
import t2_linux_account
import t2_user_mapping_store


CONFIG = Path("/etc/t2-touchid.conf")
STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
JOURNAL = STATE_ROOT / "native-provisioning.jsonl"
MAX_SECRET_BYTES = 128


class NativeProvisioningError(RuntimeError):
    pass


def _configuration() -> tuple[str, int]:
    info = CONFIG.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise NativeProvisioningError("configuration metadata is unsafe")
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
        raise NativeProvisioningError("configuration has missing or duplicate values")
    if wanted["T2_TOUCHID_AUTHORITY_MODE"] != ["linux-native"]:
        raise NativeProvisioningError("authority mode is not exactly linux-native")
    user_name = wanted["T2_TOUCHID_USER"][0]
    apple_uid_text = wanted["T2_TOUCHID_MACOS_USER_ID"][0]
    if not user_name or not apple_uid_text.isdecimal():
        raise NativeProvisioningError("configured identity is invalid")
    apple_uid = int(apple_uid_text)
    if not 0 < apple_uid < (1 << 32):
        raise NativeProvisioningError("configured biometric UID is invalid")
    return user_name, apple_uid


def _read_secret(descriptor: int) -> bytearray:
    storage = bytearray(MAX_SECRET_BYTES + 2)
    view = memoryview(storage)
    used = 0
    try:
        while used < len(storage):
            count = os.readv(descriptor, [view[used:]])
            if count == 0:
                break
            used += count
            newline = storage.find(0x0A, 0, used)
            if newline >= 0:
                used = newline
                break
        if used and storage[used - 1] == 0x0D:
            used -= 1
        if not 1 <= used <= MAX_SECRET_BYTES:
            raise NativeProvisioningError(
                "identity credential length is outside the fixed bound"
            )
        return bytearray(view[:used])
    finally:
        storage[:] = b"\0" * len(storage)


def _require_empty_destinations(linux_uid: int) -> Path:
    user_root = STATE_ROOT / "users" / str(linux_uid)
    root_info = STATE_ROOT.stat(follow_symlinks=False)
    user_info = user_root.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or not stat.S_ISDIR(user_info.st_mode)
        or root_info.st_uid != 0
        or root_info.st_mode & 0o077
        or user_info.st_uid != 0
        or user_info.st_mode & 0o077
    ):
        raise NativeProvisioningError("native state directories are not private")
    if any(
        os.path.lexists(path)
        for path in (MAPPING, user_root / "user.kb", JOURNAL)
    ):
        raise NativeProvisioningError(
            "native provisioning destinations are not clean; reconcile retained state"
        )
    return user_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-one-shot-native-identity-create",
        action="store_true",
    )
    parser.add_argument(
        "--credential-fd",
        type=int,
        default=0,
        help="descriptor carrying one newline-terminated credential; never prompted",
    )
    args = parser.parse_args()
    credential = bytearray()
    try:
        if os.geteuid() != 0:
            raise NativeProvisioningError("native provisioning must run as root")
        if not args.acknowledge_one_shot_native_identity_create:
            raise NativeProvisioningError("one-shot identity-create acknowledgement is required")
        if args.credential_fd < 0:
            raise NativeProvisioningError("credential descriptor is invalid")
        user_name, apple_uid = _configuration()
        try:
            linux_uid = pwd.getpwnam(user_name).pw_uid
        except KeyError as error:
            raise NativeProvisioningError("configured Linux user does not exist") from error
        account = t2_linux_account.collect(linux_uid)
        user_root = _require_empty_destinations(linux_uid)
        credential = _read_secret(args.credential_fd)

        operation_id = str(uuid.uuid4())
        account_uuid = str(uuid.uuid4())
        session = secrets.randbits(64) or 1
        linux_boot_uuid = str(
            uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        )
        keybag_store = t2_aks_provisioning.SavedKeybagStore(user_root)
        mapping_writer = t2_user_mapping_store.InitialUserMappingStore(
            path=MAPPING,
            operation_id=operation_id,
            linux_uid=linux_uid,
            linux_account_generation=account.generation,
            apple_uid=apple_uid,
            keybag_path=user_root / "user.kb",
        )

        with t2_aks_provisioning_transport.AKSProvisioningTransport() as transport:
            preflight = transport.collect_stable_empty_preflight(session)
            with t2_acm_device.ACMDevice() as acm_device:
                history = t2_aks_provisioning_operation.run_identity_secret_to_mapping(
                    acm_device=acm_device,
                    apple_user_id=apple_uid,
                    identity_secret=credential,
                    journal_path=JOURNAL,
                    operation_id=operation_id,
                    linux_boot_uuid=linux_boot_uuid,
                    account_uuid=account_uuid,
                    session=session,
                    preflight=preflight,
                    transport=transport,
                    keybag_store=keybag_store,
                    mapping_writer=mapping_writer,
                )
        print(
            json.dumps(
                {
                    "identifiers_redacted": True,
                    "native_identity_created": history.phase == "mapping-committed",
                    "mapping_enabled": False,
                    "fresh_owner_activation_required": True,
                    "reboot_verification_required": False,
                },
                sort_keys=True,
            )
        )
    except (
        OSError,
        ValueError,
        NativeProvisioningError,
        t2_acm_device.ACMDeviceError,
        t2_aks_provisioning.AKSProvisioningError,
        t2_aks_provisioning_operation.AKSProvisioningOperationError,
        t2_aks_provisioning_transport.AKSProvisioningTransportError,
        t2_linux_account.LinuxAccountError,
        t2_user_mapping_store.UserMappingStoreError,
    ) as error:
        parser.error(str(error))
    finally:
        credential[:] = b"\0" * len(credential)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
