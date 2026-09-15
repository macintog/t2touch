#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Start or reconcile the one journaled Linux-native T2 identity replacement."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import secrets
import stat
import subprocess
import sys
import uuid
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_aks_replacement_operation.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_acm_device
import t2_activation_bundle
import t2_aks_provisioning
import t2_aks_provisioning_transport
import t2_aks_replacement_journal
import t2_aks_replacement_operation
import t2_aks_replacement_transport
import t2_linux_account
import t2_user_mapping
import t2_user_mapping_store


CONFIG = Path("/etc/t2-touchid.conf")
STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
PROVISIONING_JOURNAL = STATE_ROOT / "native-provisioning.jsonl"
REPLACEMENT_JOURNAL = STATE_ROOT / "native-replacement.jsonl"
ARCHIVE_ROOT = STATE_ROOT / "replacement-archive"
RUN_ROOT = Path("/run/t2-touchid")
OPERATION_LOCK = RUN_ROOT / "operation.lock"
MAX_SECRET_BYTES = 128
GATED_UNITS = (
    "fprintd.service",
    "t2-biometric-ready.service",
    "t2-keybag-load.service",
    "t2-credential-unlock.service",
)
class NativeReplacementError(RuntimeError):
    pass


def _require_private_directory(path: Path, label: str) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise NativeReplacementError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise NativeReplacementError(f"{label} is not root-private")


def _sha256_file(path: Path, label: str, *, root_private: bool = False) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeReplacementError(f"{label} cannot be opened safely") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or (
                root_private
                and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600)
            )
        ):
            raise NativeReplacementError(f"{label} metadata is unsafe")
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            if not block:
                raise NativeReplacementError(f"{label} read was short")
            digest.update(block)
            remaining -= len(block)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _configuration() -> tuple[int, int]:
    info = CONFIG.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise NativeReplacementError("configuration metadata is unsafe")
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
        raise NativeReplacementError("configuration has missing or duplicate values")
    if wanted["T2_TOUCHID_AUTHORITY_MODE"] != ["linux-native"]:
        raise NativeReplacementError("authority mode is not exactly linux-native")
    try:
        linux_uid = pwd.getpwnam(wanted["T2_TOUCHID_USER"][0]).pw_uid
    except KeyError as error:
        raise NativeReplacementError("configured Linux user does not exist") from error
    apple_uid_text = wanted["T2_TOUCHID_MACOS_USER_ID"][0]
    if not apple_uid_text.isdecimal() or not 0 < int(apple_uid_text) < (1 << 32):
        raise NativeReplacementError("configured biometric UID is invalid")
    return linux_uid, int(apple_uid_text)


def _require_consumers_gated() -> None:
    if os.environ.get("T2_TOUCHID_FIRST_RUN_OWNER") == "1":
        return
    for unit in GATED_UNITS:
        enabled = subprocess.run(
            ["/usr/bin/systemctl", "is-enabled", unit],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        active = subprocess.run(
            ["/usr/bin/systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if enabled.stdout.strip() != "disabled" or active.stdout.strip() != "inactive":
            raise NativeReplacementError("downstream biometric consumers are not gated")


def _original_authority(
    linux_uid: int,
    apple_uid: int,
    account: t2_linux_account.AccountEvidence,
) -> tuple[t2_aks_provisioning.ProvisioningHistory, t2_user_mapping.UserMappingSet]:
    provisioning = t2_aks_provisioning.read(PROVISIONING_JOURNAL)
    if provisioning.phase != "mapping-enabled":
        raise NativeReplacementError("D137/D138 provisioning authority is incomplete")
    mappings = t2_user_mapping.load(MAPPING)
    if mappings.schema_version != t2_user_mapping.LEGACY_SCHEMA_VERSION or len(
        mappings.mappings
    ) != 1:
        raise NativeReplacementError("canonical mapping is not the D138 legacy authority")
    old = mappings.mappings[0]
    if (
        not old.enabled
        or old.linux_uid != linux_uid
        or old.apple_uid != apple_uid
        or not account.matches_generation(old.linux_account_generation)
        or old.account_uuid != provisioning.account_uuid
        or old.bag_uuid != provisioning.bag_uuid
        or old.keybag_sha256 != provisioning.saved_keybag_sha256
        or mappings.generation != provisioning.enabled_mapping_generation
    ):
        raise NativeReplacementError("D137/D138 mapping authority does not reconcile")
    if _sha256_file(
        Path(old.keybag_path), "D137 saved keybag", root_private=True
    ) != old.keybag_sha256:
        raise NativeReplacementError("D137 saved keybag differs")
    return provisioning, mappings


def _require_journal_authority(
    history: t2_aks_replacement_journal.AKSReplacementHistory,
    linux_uid: int,
    apple_uid: int,
    account_generation: str,
) -> t2_aks_provisioning.ProvisioningHistory:
    provisioning = t2_aks_provisioning.read(PROVISIONING_JOURNAL)
    if (
        provisioning.phase != "mapping-enabled"
        or provisioning.account_uuid != history.old_account_uuid
        or provisioning.bag_uuid != history.old_bag_uuid
        or provisioning.enabled_mapping_generation != history.old_mapping_generation
    ):
        raise NativeReplacementError("replacement journal is not bound to D137/D138")
    old_keybag = STATE_ROOT / "users" / str(linux_uid) / "user.kb"
    if _sha256_file(
        old_keybag, "D137 saved keybag", root_private=True
    ) != provisioning.saved_keybag_sha256:
        raise NativeReplacementError("D137 saved keybag differs")
    if apple_uid < 10 or len(account_generation) != 64:
        raise NativeReplacementError("local account authority is invalid")
    return provisioning


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
            raise NativeReplacementError("identity credential length is outside the bound")
        return bytearray(view[:used])
    finally:
        view.release()
        storage[:] = b"\0" * len(storage)


def _boot_uuid() -> str:
    return str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))


def _bundle_store(
    operation_id: str, account_uuid: str, linux_uid: int
) -> t2_activation_bundle.ActivationBundleStore:
    identities = STATE_ROOT / "users" / str(linux_uid) / "identities"
    _require_private_directory(identities, "activation identity root")
    return t2_activation_bundle.ActivationBundleStore(
        root=identities,
        operation_id=operation_id,
        account_uuid=account_uuid,
        linux_uid=linux_uid,
    )


def _mapping_writer(
    history: t2_aks_replacement_journal.AKSReplacementHistory,
    linux_uid: int,
    apple_uid: int,
    account_generation: str,
    bundle_store: t2_activation_bundle.ActivationBundleStore,
) -> t2_user_mapping_store.ReplacementUserMappingStore:
    if history.activation_material_digest is None:
        raise NativeReplacementError("replacement activation material is not staged")
    return t2_user_mapping_store.ReplacementUserMappingStore(
        path=MAPPING,
        operation_id=history.operation_id,
        linux_uid=linux_uid,
        linux_account_generation=account_generation,
        apple_uid=apple_uid,
        keybag_path=bundle_store.final_keybag_path,
        bundle_generation=history.operation_id,
        activation_secret_path=bundle_store.final_secret_path,
        activation_secret_sha256=history.activation_material_digest,
        old_mapping_generation=history.old_mapping_generation,
        old_account_uuid=history.old_account_uuid,
        old_bag_uuid=history.old_bag_uuid,
        archive_root=ARCHIVE_ROOT,
    )


def _operation_lock() -> int:
    if not os.path.lexists(RUN_ROOT):
        os.mkdir(RUN_ROOT, 0o700)
    _require_private_directory(RUN_ROOT, "replacement runtime directory")
    descriptor = os.open(
        OPERATION_LOCK,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise NativeReplacementError("replacement operation lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _archive_abandoned_journal(history: t2_aks_replacement_journal.AKSReplacementHistory) -> None:
    _require_private_directory(ARCHIVE_ROOT, "replacement archive root")
    directory = ARCHIVE_ROOT / history.operation_id
    if not os.path.lexists(directory):
        os.mkdir(directory, 0o700)
    _require_private_directory(directory, "replacement archive generation")
    suffix = (
        "before-delete"
        if history.phase == "abandoned-before-delete"
        else "before-create"
    )
    destination = directory / f"replacement.{suffix}.jsonl"
    if os.path.lexists(destination):
        raise NativeReplacementError("abandoned replacement journal archive already exists")
    os.rename(REPLACEMENT_JOURNAL, destination)
    for parent in (directory, ARCHIVE_ROOT, STATE_ROOT):
        descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _common() -> tuple[int, int, t2_linux_account.AccountEvidence]:
    if os.geteuid() != 0:
        raise NativeReplacementError("native identity replacement must run as root")
    linux_uid, apple_uid = _configuration()
    account = t2_linux_account.collect(linux_uid)
    _require_private_directory(STATE_ROOT, "native state root")
    _require_private_directory(ARCHIVE_ROOT, "replacement archive root")
    _require_consumers_gated()
    return linux_uid, apple_uid, account


def _mapped_account_generation(
    linux_uid: int, account: t2_linux_account.AccountEvidence
) -> str:
    mappings = t2_user_mapping.load(MAPPING)
    selected = [item for item in mappings.mappings if item.linux_uid == linux_uid]
    if len(selected) != 1 or not account.matches_generation(
        selected[0].linux_account_generation
    ):
        raise NativeReplacementError("replacement Linux account generation changed")
    return selected[0].linux_account_generation


def _start(credential_fd: int) -> t2_aks_replacement_journal.AKSReplacementHistory:
    if os.path.lexists(REPLACEMENT_JOURNAL):
        raise NativeReplacementError("a replacement journal already exists; reconcile it")
    linux_uid, apple_uid, account = _common()
    provisioning, mappings = _original_authority(
        linux_uid, apple_uid, account
    )
    account_generation = mappings.mappings[0].linux_account_generation
    credential = _read_secret(credential_fd)
    operation_id = str(uuid.uuid4())
    new_account_uuid = str(uuid.uuid4())
    session = secrets.randbits(64) or 1
    boot = _boot_uuid()
    store = _bundle_store(operation_id, new_account_uuid, linux_uid)
    try:
        with t2_aks_replacement_transport.AKSReplacementTransport() as transport:
            history = t2_aks_replacement_operation.prepare_replacement(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=operation_id,
                old_account_uuid=provisioning.account_uuid,
                new_account_uuid=new_account_uuid,
                old_bag_uuid=provisioning.bag_uuid,
                old_mapping_generation=mappings.generation,
                linux_boot_uuid=boot,
                session=session,
                transport=transport,
            )
            with t2_acm_device.ACMDevice() as acm:
                with t2_acm_device.identity_secret_context(
                    acm, apple_uid, credential
                ) as external_form:
                    if history.phase == "prepared":
                        history = t2_aks_replacement_operation.stage_delete_and_reconcile(
                            journal_path=REPLACEMENT_JOURNAL,
                            operation_id=operation_id,
                            linux_boot_uuid=boot,
                            activation_material=bytearray(external_form),
                            transport=transport,
                            bundle_store=store,
                        )
                    elif history.phase == "absence-prepared":
                        history = t2_aks_replacement_operation.stage_absent_and_reconcile(
                            journal_path=REPLACEMENT_JOURNAL,
                            operation_id=operation_id,
                            linux_boot_uuid=boot,
                            activation_material=bytearray(external_form),
                            transport=transport,
                            bundle_store=store,
                        )
                    else:
                        raise NativeReplacementError(
                            "identity preparation selected an invalid operation kind"
                        )
                    writer = _mapping_writer(
                        history,
                        linux_uid,
                        apple_uid,
                        account_generation,
                        store,
                    )
                    return t2_aks_replacement_operation.create_export_commit(
                        journal_path=REPLACEMENT_JOURNAL,
                        operation_id=operation_id,
                        linux_boot_uuid=boot,
                        transport=transport,
                        bundle_store=store,
                        mapping_writer=writer,
                    )
    finally:
        credential[:] = b"\0" * len(credential)


def _resume() -> t2_aks_replacement_journal.AKSReplacementHistory:
    linux_uid, apple_uid, account = _common()
    history = t2_aks_replacement_journal.read(REPLACEMENT_JOURNAL)
    account_generation = _mapped_account_generation(linux_uid, account)
    _require_journal_authority(
        history, linux_uid, apple_uid, account_generation
    )
    boot = _boot_uuid()
    if history.phase in {"abandoned-before-delete", "abandoned-before-create"}:
        _archive_abandoned_journal(history)
        return history
    if history.phase in {"complete", "delete-not-applied", "create-not-applied"}:
        return history
    store = _bundle_store(history.operation_id, history.new_account_uuid, linux_uid)
    with t2_aks_replacement_transport.AKSReplacementTransport() as transport:
        if history.phase in {"prepared", "activation-staged"}:
            history = t2_aks_replacement_operation.abandon_before_delete(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
            )
            _archive_abandoned_journal(history)
            return history
        if history.phase == "absence-prepared":
            history = t2_aks_replacement_operation.abandon_before_create(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
            )
            _archive_abandoned_journal(history)
            return history
        if history.phase == "absence-activation-staged":
            history = t2_aks_replacement_operation.reconcile_absence(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
            )
        elif history.phase == "absence-reconciled":
            history = t2_aks_replacement_operation.reconfirm_absence(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
            )
        writer = _mapping_writer(
            history, linux_uid, apple_uid, account_generation, store
        )
        if history.phase in {
            "delete-intent",
            "delete-succeeded",
            "delete-outcome-unknown",
        }:
            history = t2_aks_replacement_operation.reconcile_delete(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
            )
            if history.phase != "delete-reconciled":
                return history
        elif history.phase == "delete-reconciled":
            history = t2_aks_replacement_operation.reconfirm_delete(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
            )
        if history.phase in {"delete-reconciled", "absence-reconciled"}:
            return t2_aks_replacement_operation.create_export_commit(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
                bundle_store=store,
                mapping_writer=writer,
            )
        if history.phase in {
            "create-intent",
            "create-outcome-unknown",
            "identity-live",
            "export-intent",
            "export-outcome-unknown",
            "export-succeeded",
            "live-uuid-verified",
        }:
            return t2_aks_replacement_operation.recover_create_or_export(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
                bundle_store=store,
                mapping_writer=writer,
            )
        if history.phase in {"bundle-committed", "mapping-committed"}:
            return t2_aks_replacement_operation.resume_local_commit(
                journal_path=REPLACEMENT_JOURNAL,
                operation_id=history.operation_id,
                linux_boot_uuid=boot,
                transport=transport,
                bundle_store=store,
                mapping_writer=writer,
            )
        return history


def _result(history: t2_aks_replacement_journal.AKSReplacementHistory) -> str:
    return json.dumps(
        {
            "identifiers_redacted": True,
            "phase": history.phase,
            "operation_kind": history.replacement_kind,
            "post_reboot_primary_state": history.handle_release_primary_state,
            "record_count": history.record_count,
            "replacement_complete": history.phase == "complete",
            "mapping_enabled": False if history.mapping_generation else None,
            "fresh_owner_activation_required": history.phase == "complete",
            "different_boot_activation_required": False,
            "hardware_retry_permitted": False,
        },
        sort_keys=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    start = subparsers.add_parser("start")
    start.add_argument(
        "--acknowledge-one-shot-native-identity-replacement", action="store_true"
    )
    start.add_argument("--credential-fd", type=int, default=0)
    resume = subparsers.add_parser("resume")
    resume.add_argument(
        "--acknowledge-native-identity-replacement-recovery", action="store_true"
    )
    subparsers.add_parser("status")
    args = parser.parse_args()
    lock_descriptor = -1
    try:
        if args.action == "status":
            history = t2_aks_replacement_journal.read(REPLACEMENT_JOURNAL)
            print(_result(history))
            return 0
        if args.action == "start" and not args.acknowledge_one_shot_native_identity_replacement:
            raise NativeReplacementError("one-shot identity replacement acknowledgement is required")
        if args.action == "resume" and not args.acknowledge_native_identity_replacement_recovery:
            raise NativeReplacementError("identity replacement recovery acknowledgement is required")
        if args.action == "start" and args.credential_fd < 0:
            raise NativeReplacementError("credential descriptor is invalid")
        lock_descriptor = _operation_lock()
        history = _start(args.credential_fd) if args.action == "start" else _resume()
        print(_result(history))
        return 0
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        NativeReplacementError,
        t2_acm_device.ACMDeviceError,
        t2_activation_bundle.ActivationBundleError,
        t2_aks_provisioning.AKSProvisioningError,
        t2_aks_provisioning_transport.AKSProvisioningTransportError,
        t2_aks_replacement_journal.AKSReplacementJournalError,
        t2_aks_replacement_operation.AKSReplacementOperationError,
        t2_linux_account.LinuxAccountError,
        t2_user_mapping.UserMappingError,
        t2_user_mapping_store.UserMappingStoreError,
    ) as error:
        parser.error(str(error))
    finally:
        if lock_descriptor >= 0:
            os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
