#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prove one replacement activation through fresh owners and enable it."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import pwd
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Iterator

SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_aks_replacement_activation_operation.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_acm_device
import t2_activation_bundle
import t2_aks_replacement_activation_journal
import t2_aks_replacement_activation_operation
import t2_aks_replacement_journal
import t2_aks_transport
import t2_linux_account
import t2_user_mapping
import t2_user_mapping_store


CONFIG = Path("/etc/t2-touchid.conf")
STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
REPLACEMENT_JOURNAL = STATE_ROOT / "native-replacement.jsonl"
ACTIVATION_JOURNAL = STATE_ROOT / "native-replacement-activation.jsonl"
ARCHIVE_ROOT = STATE_ROOT / "replacement-archive"
RUN_ROOT = Path("/run/t2-touchid")
OPERATION_LOCK = RUN_ROOT / "operation.lock"
GATED_UNITS = (
    "fprintd.service",
    "t2-biometric-ready.service",
    "t2-keybag-load.service",
    "t2-credential-unlock.service",
)


class NativeReplacementActivationError(RuntimeError):
    pass


def _require_private_directory(path: Path, label: str) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise NativeReplacementActivationError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise NativeReplacementActivationError(f"{label} is not root-private")


def _configuration() -> tuple[int, int]:
    try:
        info = CONFIG.stat(follow_symlinks=False)
    except OSError as error:
        raise NativeReplacementActivationError("configuration is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise NativeReplacementActivationError("configuration metadata is unsafe")
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
        raise NativeReplacementActivationError(
            "configuration has missing or duplicate values"
        )
    if wanted["T2_TOUCHID_AUTHORITY_MODE"] != ["linux-native"]:
        raise NativeReplacementActivationError(
            "authority mode is not exactly linux-native"
        )
    try:
        linux_uid = pwd.getpwnam(wanted["T2_TOUCHID_USER"][0]).pw_uid
    except KeyError as error:
        raise NativeReplacementActivationError(
            "configured Linux user does not exist"
        ) from error
    apple_uid_text = wanted["T2_TOUCHID_MACOS_USER_ID"][0]
    if not apple_uid_text.isdecimal() or not 10 <= int(apple_uid_text) < (1 << 32):
        raise NativeReplacementActivationError(
            "configured biometric UID is invalid"
        )
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
            raise NativeReplacementActivationError(
                "downstream biometric consumers are not gated"
            )


def _boot_uuid() -> str:
    return str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))


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
            raise NativeReplacementActivationError(
                "replacement operation lock is unsafe"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def _authorization(
    apple_uid: int,
    activation_material: bytearray,
    binder,
) -> Iterator[tuple[object, object, bytes]]:
    with t2_acm_device.ACMDevice() as device:
        try:
            with t2_acm_device.identity_authorized_context(
                device, apple_uid, activation_material, binder
            ) as proof:
                yield proof
        except t2_acm_device.ACMContextCleanupError as error:
            t2_acm_device.reconcile_identity_cleanup_after_close(error, device)


def _authority():
    linux_uid, apple_uid = _configuration()
    account_generation = t2_linux_account.collect(linux_uid).generation
    replacement = t2_aks_replacement_journal.read(REPLACEMENT_JOURNAL)
    if (
        replacement.phase != "complete"
        or replacement.activation_material_digest is None
        or replacement.saved_keybag_digest is None
        or replacement.saved_keybag_length is None
        or replacement.bundle_generation != replacement.operation_id
        or replacement.mapping_generation is None
        or replacement.live_bag_uuid is None
    ):
        raise NativeReplacementActivationError(
            "replacement transaction is not complete"
        )
    final_replacement_boot = (
        replacement.reconciliation_linux_boot_uuid
        or replacement.initial_linux_boot_uuid
    )
    identities = STATE_ROOT / "users" / str(linux_uid) / "identities"
    _require_private_directory(identities, "activation identity root")
    store = t2_activation_bundle.ActivationBundleStore(
        root=identities,
        operation_id=replacement.operation_id,
        account_uuid=replacement.new_account_uuid,
        linux_uid=linux_uid,
    )
    bundle = store.published(
        expected_keybag_sha256=replacement.saved_keybag_digest,
        activation_secret_sha256=replacement.activation_material_digest,
        bag_uuid=replacement.live_bag_uuid,
        expected_keybag_length=replacement.saved_keybag_length,
    )
    mappings = t2_user_mapping.load(MAPPING)
    if mappings.schema_version != t2_user_mapping.SCHEMA_VERSION or len(
        mappings.mappings
    ) != 1:
        raise NativeReplacementActivationError(
            "canonical replacement mapping is not one schema-2 authority"
        )
    selected = mappings.mappings[0]
    if (
        selected.linux_uid != linux_uid
        or selected.linux_account_generation != account_generation
        or selected.apple_uid != apple_uid
        or selected.account_uuid != replacement.new_account_uuid
        or selected.bag_uuid != replacement.live_bag_uuid
        or selected.keybag_path != str(bundle.keybag_path)
        or selected.keybag_sha256 != bundle.keybag_sha256
        or selected.unlock_mode != "password-on-demand"
        or selected.capabilities != t2_user_mapping.CAPABILITIES
        or selected.bundle_generation != bundle.generation
        or selected.activation_secret_path != str(bundle.activation_secret_path)
        or selected.activation_secret_sha256 != bundle.activation_secret_sha256
        or selected.activation_secret_length != 16
    ):
        raise NativeReplacementActivationError(
            "canonical replacement mapping does not match its final bundle"
        )
    writer = t2_user_mapping_store.ReplacementUserMappingStore(
        path=MAPPING,
        operation_id=replacement.operation_id,
        linux_uid=linux_uid,
        linux_account_generation=account_generation,
        apple_uid=apple_uid,
        keybag_path=bundle.keybag_path,
        bundle_generation=bundle.generation,
        activation_secret_path=bundle.activation_secret_path,
        activation_secret_sha256=bundle.activation_secret_sha256,
        old_mapping_generation=replacement.old_mapping_generation,
        old_account_uuid=replacement.old_account_uuid,
        old_bag_uuid=replacement.old_bag_uuid,
        archive_root=ARCHIVE_ROOT,
    )
    activation = None
    if os.path.lexists(ACTIVATION_JOURNAL):
        activation = t2_aks_replacement_activation_journal.read(
            ACTIVATION_JOURNAL
        )
        expected = {
            "replacement_head_hash": replacement.head_hash,
            "replacement_initial_linux_boot_uuid": replacement.initial_linux_boot_uuid,
            "replacement_final_linux_boot_uuid": final_replacement_boot,
            "linux_account_generation": account_generation,
            "target_linux_uid": linux_uid,
            "apple_uid": apple_uid,
            "account_uuid": replacement.new_account_uuid,
            "bag_uuid": replacement.live_bag_uuid,
            "disabled_mapping_generation": replacement.mapping_generation,
            "keybag_sha256": replacement.saved_keybag_digest,
            "activation_material_digest": replacement.activation_material_digest,
            "bundle_manifest_sha256": bundle.manifest_sha256,
            "special_alias": -apple_uid,
        }
        if activation.operation_id != replacement.operation_id or any(
            activation.baseline.get(key) != value for key, value in expected.items()
        ):
            raise NativeReplacementActivationError(
                "activation journal is not bound to the completed replacement"
            )
        if activation.phase == "complete":
            if (
                not selected.enabled
                or activation.enabled_mapping_generation is None
                or mappings.generation != activation.enabled_mapping_generation
            ):
                raise NativeReplacementActivationError(
                    "completed activation mapping is unexpectedly disabled"
                )
        elif activation.phase != "enable-intent":
            if selected.enabled or mappings.generation != replacement.mapping_generation:
                raise NativeReplacementActivationError(
                    "replacement mapping changed before activation proof"
                )
    elif selected.enabled or mappings.generation != replacement.mapping_generation:
        raise NativeReplacementActivationError(
            "replacement mapping is not the exact disabled generation"
        )
    return (
        replacement,
        activation,
        writer,
        bundle,
        linux_uid,
        apple_uid,
        account_generation,
        final_replacement_boot,
    )


def _start():
    (
        replacement,
        activation,
        writer,
        bundle,
        linux_uid,
        apple_uid,
        account_generation,
        final_replacement_boot,
    ) = _authority()
    if activation is not None:
        raise NativeReplacementActivationError(
            "replacement activation journal already exists; reconcile it"
        )
    boot = _boot_uuid()
    with t2_aks_transport.AKSActivationTransport() as transport:
        alias = transport.observe_alias(-apple_uid)
        initial_state = (
            t2_aks_replacement_activation_operation.classify_alias(
                alias,
                special_alias=-apple_uid,
                bag_uuid=replacement.live_bag_uuid,
            )
        )
    history = t2_aks_replacement_activation_operation.create(
        journal_path=ACTIVATION_JOURNAL,
        operation_id=replacement.operation_id,
        replacement_head_hash=replacement.head_hash,
        replacement_initial_linux_boot_uuid=replacement.initial_linux_boot_uuid,
        replacement_final_linux_boot_uuid=final_replacement_boot,
        activation_linux_boot_uuid=boot,
        linux_account_generation=account_generation,
        target_linux_uid=linux_uid,
        apple_uid=apple_uid,
        account_uuid=replacement.new_account_uuid,
        bag_uuid=replacement.live_bag_uuid,
        disabled_mapping_generation=replacement.mapping_generation,
        keybag_sha256=replacement.saved_keybag_digest,
        activation_material_digest=replacement.activation_material_digest,
        bundle_manifest_sha256=bundle.manifest_sha256,
        initial_alias_state=initial_state,
    )
    del history
    return t2_aks_replacement_activation_operation.reconcile(
        journal_path=ACTIVATION_JOURNAL,
        linux_boot_uuid=boot,
        transport_factory=t2_aks_transport.AKSActivationTransport,
        authorization_factory=_authorization,
        secret_reader=lambda: t2_activation_bundle.activation_secret(
            bundle.activation_secret_path, bundle.activation_secret_sha256
        ),
        mapping_writer=writer,
    )


def _resume():
    _, activation, writer, bundle, _, _, _, _ = _authority()
    if activation is None:
        raise NativeReplacementActivationError(
            "replacement activation has not been started"
        )
    return t2_aks_replacement_activation_operation.reconcile(
        journal_path=ACTIVATION_JOURNAL,
        linux_boot_uuid=_boot_uuid(),
        transport_factory=t2_aks_transport.AKSActivationTransport,
        authorization_factory=_authorization,
        secret_reader=lambda: t2_activation_bundle.activation_secret(
            bundle.activation_secret_path, bundle.activation_secret_sha256
        ),
        mapping_writer=writer,
    )


def _result(history) -> str:
    return json.dumps(
        {
            "identifiers_redacted": True,
            "phase": history.phase,
            "attempt_count": history.attempt_number,
            "independent_activation_proved": history.phase == "complete",
            "mapping_enabled": history.phase == "complete",
            "fingerprint_mutation_performed": False,
        },
        sort_keys=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    start = subparsers.add_parser("start")
    start.add_argument(
        "--acknowledge-one-shot-replacement-activation", action="store_true"
    )
    resume = subparsers.add_parser("resume")
    resume.add_argument(
        "--acknowledge-replacement-activation-recovery", action="store_true"
    )
    subparsers.add_parser("status")
    args = parser.parse_args()
    lock_descriptor = -1
    try:
        if os.geteuid() != 0:
            raise NativeReplacementActivationError(
                "replacement activation must run as root"
            )
        _require_private_directory(STATE_ROOT, "native state root")
        _require_private_directory(ARCHIVE_ROOT, "replacement archive root")
        _require_consumers_gated()
        if args.action == "status":
            print(
                _result(
                    t2_aks_replacement_activation_journal.read(
                        ACTIVATION_JOURNAL
                    )
                )
            )
            return 0
        if args.action == "start" and not args.acknowledge_one_shot_replacement_activation:
            raise NativeReplacementActivationError(
                "one-shot replacement activation acknowledgement is required"
            )
        if args.action == "resume" and not args.acknowledge_replacement_activation_recovery:
            raise NativeReplacementActivationError(
                "replacement activation recovery acknowledgement is required"
            )
        lock_descriptor = _operation_lock()
        history = _start() if args.action == "start" else _resume()
        print(_result(history))
        return 0
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        NativeReplacementActivationError,
        t2_acm_device.ACMDeviceError,
        t2_activation_bundle.ActivationBundleError,
        t2_aks_replacement_activation_journal.AKSReplacementActivationJournalError,
        t2_aks_replacement_activation_operation.AKSReplacementActivationOperationError,
        t2_aks_replacement_journal.AKSReplacementJournalError,
        t2_aks_transport.AKSActivationTransportError,
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
