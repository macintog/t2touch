#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Enroll the first fingerprint against one Linux-provisioned T2 identity."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import sys
import time
from threading import Event
from typing import Callable, Iterator
import uuid


SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_enrollment_coordinator.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_acm_device
import t2_activation_bundle
import t2_aks_provisioning
import t2_aks_replacement_activation_journal
import t2_aks_replacement_journal
import t2_aks_transport
import t2_baseline
import t2_biolockout_store
import t2_bridge_connection
import t2_bridge_inventory
import t2_catacomb_codec
import t2_catacomb_store
import t2_enrollment_coordinator
import t2_enrollment_finalizer
import t2_enrollment_journal
import t2_enrollment_operation
import t2_enrollment_persistence_journal
import t2_enrollment_protocol
import t2_enrollment_reconciliation
import t2_fprint_identity
import t2_fprint_projection
import t2_fprint_sequence
import t2_identity_inventory
import t2_linux_account
import t2_mesa_enrollment_preparation
import t2_native_state_restore
import t2_mutation_journal
import t2_mutation_registry
import t2_native_caller_authorization
import t2_native_mutation_authority
import t2_post_reboot_diagnostic
import t2_user_activation_operation
import t2_user_authority
import t2_user_mapping
import t2_user_policy
import t2_user_readiness


CONFIG = Path("/etc/t2-touchid.conf")
STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
PROVISIONING_JOURNAL = STATE_ROOT / "native-provisioning.jsonl"
REPLACEMENT_JOURNAL = STATE_ROOT / "native-replacement.jsonl"
REPLACEMENT_ACTIVATION_JOURNAL = (
    STATE_ROOT / "native-replacement-activation.jsonl"
)
CATACOMB_ROOT = STATE_ROOT / "catacomb"
MUTATION_ROOT = STATE_ROOT / "mutations"
ACTIVATION_ROOT = STATE_ROOT / "activation"
RUN_ROOT = Path("/run/t2-touchid")
OPERATION_LOCK = RUN_ROOT / "operation.lock"
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SYSTEMD_INHIBIT = Path("/usr/bin/systemd-inhibit")
CAT = Path("/usr/bin/cat")
DISCOVERY_PYTHON = Path("/opt/t2-touchid/.venv/bin/python")
DISCOVERY_TOOL = Path("/opt/t2-touchid/src/discover-biometric-port.py")
FIRST_DYNAMIC_PORT = 49152
MAX_SECRET_BYTES = 128
DISCOVERY_TIMEOUT_SECONDS = 45
EVENT_PREFIX = "T2_ENROLL_EVENT "


class NativeEnrollmentError(RuntimeError):
    pass


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


def _read_secret(descriptor: int) -> bytearray:
    if descriptor < 0:
        raise NativeEnrollmentError("credential descriptor is invalid")
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
            raise NativeEnrollmentError(
                "identity credential length is outside the fixed bound"
            )
        return bytearray(view[:used])
    finally:
        _wipe(storage)


def _private(path: Path, *, directory: bool) -> os.stat_result:
    info = path.stat(follow_symlinks=False)
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not correct_type
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o077
        or (not directory and info.st_nlink != 1)
    ):
        raise NativeEnrollmentError("native enrollment state is not private")
    return info


def _configuration(*, trusted_linux_uid: int | None = None) -> dict[str, object]:
    _private(CONFIG, directory=False)
    wanted = {
        "T2_TOUCHID_USER": [],
        "T2_TOUCHID_MACOS_USER_ID": [],
        "T2_TOUCHID_AUTHORITY_MODE": [],
        "T2_TOUCHID_HOST": [],
        "T2_TOUCHID_INTERFACE": [],
    }
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name in wanted:
            wanted[name].append(value)
    if any(len(values) != 1 for values in wanted.values()):
        raise NativeEnrollmentError("configuration has missing or duplicate values")
    if wanted["T2_TOUCHID_AUTHORITY_MODE"] != ["linux-native"]:
        raise NativeEnrollmentError("authority mode is not exactly linux-native")
    user_name = wanted["T2_TOUCHID_USER"][0]
    try:
        linux_uid = pwd.getpwnam(user_name).pw_uid
    except KeyError as error:
        raise NativeEnrollmentError("configured Linux user does not exist") from error
    apple_uid_text = wanted["T2_TOUCHID_MACOS_USER_ID"][0]
    if (
        linux_uid <= 0
        or not apple_uid_text.isdecimal()
        or not 10 <= int(apple_uid_text) < (1 << 32) - 1
        or not wanted["T2_TOUCHID_HOST"][0]
        or not wanted["T2_TOUCHID_INTERFACE"][0]
    ):
        raise NativeEnrollmentError("configured native identity is invalid")
    sudo_uid = os.environ.get("SUDO_UID", "")
    if trusted_linux_uid is None and (
        not sudo_uid.isdecimal() or int(sudo_uid) != linux_uid
    ):
        raise NativeEnrollmentError(
            "native enrollment must be invoked through sudo by the mapped user"
        )
    if trusted_linux_uid is not None and trusted_linux_uid != linux_uid:
        raise NativeEnrollmentError("trusted enrollment caller is not the mapped user")
    return {
        "user": user_name,
        "linux_uid": linux_uid,
        "apple_uid": int(apple_uid_text),
        "host": wanted["T2_TOUCHID_HOST"][0],
        "interface": wanted["T2_TOUCHID_INTERFACE"][0],
    }


def _load_provisioned_authority(
    linux_uid: int, apple_uid: int
) -> tuple[
    t2_user_mapping.UserMappingSet,
    t2_user_mapping.UserMapping,
    object,
]:
    mapping_set = t2_user_mapping.load(MAPPING)
    selected = mapping_set.resolve(linux_uid, "enroll")
    account = t2_linux_account.collect(linux_uid)
    keybag_path = Path(selected.keybag_path)
    keybag_info = _private(keybag_path, directory=False)
    digest = hashlib.sha256(keybag_path.read_bytes()).hexdigest()
    if (
        digest != selected.keybag_sha256
        or selected.apple_uid != apple_uid
        or selected.linux_account_generation != account.generation
    ):
        raise NativeEnrollmentError(
            "protected Linux-native mapping authority does not reconcile"
        )

    provisioning = t2_aks_provisioning.read(PROVISIONING_JOURNAL)
    if mapping_set.schema_version == t2_user_mapping.LEGACY_SCHEMA_VERSION:
        if (
            provisioning.phase != "mapping-enabled"
            or provisioning.record_count != 9
            or provisioning.reboot_linux_boot_uuid is None
            or provisioning.enabled_mapping_generation != mapping_set.generation
            or provisioning.account_uuid != selected.account_uuid
            or provisioning.bag_uuid != selected.bag_uuid
            or provisioning.saved_keybag_sha256 != selected.keybag_sha256
            or provisioning.saved_keybag_length != keybag_info.st_size
        ):
            raise NativeEnrollmentError(
                "protected Linux-native provisioning authority does not reconcile"
            )
        return mapping_set, selected, provisioning

    if mapping_set.schema_version != t2_user_mapping.SCHEMA_VERSION:
        raise NativeEnrollmentError("Linux-native mapping schema is unsupported")
    replacement = t2_aks_replacement_journal.read(REPLACEMENT_JOURNAL)
    activation = t2_aks_replacement_activation_journal.read(
        REPLACEMENT_ACTIVATION_JOURNAL
    )
    if (
        len(mapping_set.mappings) != 1
        or replacement.phase != "complete"
        or replacement.activation_material_digest is None
        or replacement.saved_keybag_digest is None
        or replacement.saved_keybag_length is None
        or replacement.bundle_generation != replacement.operation_id
        or replacement.mapping_generation is None
        or replacement.live_bag_uuid is None
        or activation.phase != "complete"
        or activation.operation_id != replacement.operation_id
        or activation.enabled_mapping_generation != mapping_set.generation
        or provisioning.phase != "mapping-enabled"
        or provisioning.record_count != 9
        or provisioning.reboot_linux_boot_uuid is None
        or provisioning.enabled_mapping_generation
        != replacement.old_mapping_generation
        or provisioning.account_uuid != replacement.old_account_uuid
        or provisioning.bag_uuid != replacement.old_bag_uuid
        or selected.account_uuid != replacement.new_account_uuid
        or selected.bag_uuid != replacement.live_bag_uuid
        or selected.keybag_sha256 != replacement.saved_keybag_digest
        or keybag_info.st_size != replacement.saved_keybag_length
        or selected.unlock_mode != "password-on-demand"
        or selected.capabilities != t2_user_mapping.CAPABILITIES
        or selected.bundle_generation != replacement.operation_id
        or selected.activation_secret_sha256
        != replacement.activation_material_digest
        or selected.activation_secret_length
        != t2_activation_bundle.ACTIVATION_SECRET_LENGTH
    ):
        raise NativeEnrollmentError(
            "protected Linux-native replacement authority does not reconcile"
        )

    identity_root = STATE_ROOT / "users" / str(linux_uid) / "identities"
    _private(identity_root, directory=True)
    bundle = t2_activation_bundle.ActivationBundleStore(
        root=identity_root,
        operation_id=replacement.operation_id,
        account_uuid=replacement.new_account_uuid,
        linux_uid=linux_uid,
    ).published(
        expected_keybag_sha256=replacement.saved_keybag_digest,
        activation_secret_sha256=replacement.activation_material_digest,
        bag_uuid=replacement.live_bag_uuid,
        expected_keybag_length=replacement.saved_keybag_length,
    )
    final_replacement_boot = (
        replacement.reconciliation_linux_boot_uuid
        or replacement.initial_linux_boot_uuid
    )
    expected_activation = {
        "replacement_head_hash": replacement.head_hash,
        "replacement_initial_linux_boot_uuid": replacement.initial_linux_boot_uuid,
        "replacement_final_linux_boot_uuid": final_replacement_boot,
        "linux_account_generation": account.generation,
        "target_linux_uid": linux_uid,
        "apple_uid": apple_uid,
        "account_uuid": replacement.new_account_uuid,
        "bag_uuid": replacement.live_bag_uuid,
        "disabled_mapping_generation": replacement.mapping_generation,
        "keybag_sha256": replacement.saved_keybag_digest,
        "activation_material_digest": replacement.activation_material_digest,
        "bundle_manifest_sha256": bundle.manifest_sha256,
        "special_alias": selected.special_bag_alias,
    }
    if (
        any(
            activation.baseline.get(name) != value
            for name, value in expected_activation.items()
        )
        or selected.keybag_path != str(bundle.keybag_path)
        or selected.activation_secret_path != str(bundle.activation_secret_path)
        or selected.bundle_generation != bundle.generation
        or selected.keybag_sha256 != bundle.keybag_sha256
        or selected.activation_secret_sha256 != bundle.activation_secret_sha256
    ):
        raise NativeEnrollmentError(
            "protected Linux-native replacement activation does not reconcile"
        )
    return mapping_set, selected, activation


def _require_fresh_enrollment_state() -> None:
    _private(STATE_ROOT, directory=True)
    for path in (CATACOMB_ROOT, MUTATION_ROOT, ACTIVATION_ROOT):
        _private(path, directory=True)
        with os.scandir(path) as entries:
            if any(True for _entry in entries):
                raise NativeEnrollmentError(
                    "native first-enrollment state is not empty; reconcile retained state"
                )


def _require_private_runtime_root() -> None:
    try:
        RUN_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = RUN_ROOT.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o077
    ):
        raise NativeEnrollmentError("native runtime directory is not private")


def _discover_port(host: object, interface: object) -> int:
    if (
        not isinstance(host, str)
        or not host
        or not isinstance(interface, str)
        or not interface
    ):
        raise NativeEnrollmentError("BiometricKit discovery target is invalid")
    if not DISCOVERY_PYTHON.is_file() or not os.access(
        DISCOVERY_PYTHON, os.X_OK
    ):
        raise NativeEnrollmentError("BiometricKit discovery runtime is unavailable")
    if not DISCOVERY_TOOL.is_file():
        raise NativeEnrollmentError("BiometricKit discovery tool is unavailable")
    try:
        completed = subprocess.run(
            [
                str(DISCOVERY_PYTHON),
                str(DISCOVERY_TOOL),
                "--host",
                host,
                "--interface",
                interface,
                "--probe-timeout",
                "0.2",
                "--concurrency",
                "512",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=DISCOVERY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise NativeEnrollmentError(
            "BiometricKit endpoint discovery timed out"
        ) from error
    if completed.returncode != 0:
        raise NativeEnrollmentError("BiometricKit endpoint discovery failed")
    try:
        text = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise NativeEnrollmentError("BiometricKit discovery output is invalid") from error
    if (
        not text.isdecimal()
        or not FIRST_DYNAMIC_PORT <= int(text) <= 65535
        or str(int(text)) != text
    ):
        raise NativeEnrollmentError("BiometricKit discovery output is invalid")
    return int(text)


@contextmanager
def _prepared_native_enrollment_lease(
    *,
    configuration: dict[str, object],
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    linux_boot_uuid: str,
    existing_authority: t2_user_authority.RuntimeUserAuthority | None,
) -> Iterator[tuple[
    t2_bridge_connection.BridgeConnectionLease,
    dict[str, object],
    int,
    dict[str, str],
    dict[str, object],
]]:
    """Yield one fully prepared pre-mutation connection and its exact E0.

    Exact master/selected-user SKS lock-state notifications are acknowledged
    on this lease. Every other service event fails closed; connection discard
    is not used as a retry because closing itself emits another notification.
    """
    port = _discover_port(configuration["host"], configuration["interface"])
    retriable = (
        t2_bridge_inventory.PreclientServiceEventError,
        t2_bridge_inventory.InventoryServiceEventError,
        t2_native_state_restore.NativeStateServiceEventError,
    )
    for _attempt in range(1):
        resources = ExitStack()
        try:
            lease = resources.enter_context(
                t2_bridge_connection.BridgeConnectionLease.connect(
                    configuration["host"],
                    configuration["interface"],
                    port,
                    timeout=60,
                    defer_client_version=True,
                )
            )
            t2_bridge_inventory.attest_preclient_protocol(
                lease, selected.apple_uid
            )
            if existing_authority is None:
                t2_bridge_inventory.prepare_empty_native_components(
                    lease, selected.apple_uid
                )
                lease.select_client_version()
                live = t2_bridge_inventory.collect_stable_private_inventory(
                    lease, selected.apple_uid
                )
                t2_baseline.build_linux_native_empty_baseline(
                    live=live,
                    caller_linux_uid=selected.linux_uid,
                    target_linux_uid=selected.linux_uid,
                    linux_boot_uuid=linux_boot_uuid,
                    mapping_generation=mapping_set.generation,
                    account_uuid=selected.account_uuid,
                    bag_uuid=selected.bag_uuid,
                    password_fallback_verified=True,
                )
                prepared = (
                    lease,
                    {},
                    0,
                    {
                        "account_uuid": selected.account_uuid,
                        "bag_uuid": selected.bag_uuid,
                    },
                    live,
                )
                event = "empty-baseline-verified"
            else:
                if (
                    existing_authority.origin != "linux-native-e4"
                    or existing_authority.mapping_set != mapping_set
                    or existing_authority.selected != selected
                ):
                    raise NativeEnrollmentError(
                        "additional enrollment authority changed"
                    )
                lease.select_client_version()
                store = t2_catacomb_store.CatacombStore(
                    CATACOMB_ROOT, selected.apple_uid
                )
                expected_identity_count = (
                    t2_native_state_restore.restore_for_enrollment(
                        lease,
                        apple_user_id=selected.apple_uid,
                        catacomb_store=store,
                        biolockout_store=t2_biolockout_store.BioLockoutStore(
                            str(STATE_ROOT / "biolockout")
                        ),
                    )
                )
                authority_history = t2_enrollment_journal.read(
                    existing_authority.enrollment_journal
                )
                host_inventory = (
                    t2_enrollment_finalizer.read_local_host_snapshot(
                        store, authority_history.baseline
                    )
                )
                identities = host_inventory.get("identity_records")
                identity_uuids = {
                    record.get("uuid")
                    for record in identities
                    if isinstance(record, dict)
                } if isinstance(identities, list) else set()
                if (
                    not isinstance(expected_identity_count, int)
                    or expected_identity_count < 0
                    or not isinstance(identities, list)
                    or len(identities) != expected_identity_count
                    or len(identity_uuids) != expected_identity_count
                ):
                    raise NativeEnrollmentError(
                        "additional enrollment requires one reconciled E4 identity set"
                    )
                live = t2_bridge_inventory.collect_stable_private_inventory(
                    lease, selected.apple_uid
                )
                preview = t2_baseline.build_linux_native_existing_baseline(
                    host=host_inventory,
                    live=live,
                    caller_linux_uid=selected.linux_uid,
                    target_linux_uid=selected.linux_uid,
                    linux_boot_uuid=linux_boot_uuid,
                    mapping_generation=mapping_set.generation,
                    account_uuid=selected.account_uuid,
                    bag_uuid=selected.bag_uuid,
                    authority_reference=(
                        "linux-native-e4:" + authority_history.operation_id
                    ),
                    authority_sha256=authority_history.head_hash,
                    password_fallback_verified=True,
                )
                current_authority = t2_native_mutation_authority.from_baseline(
                    preview,
                    authority_history,
                    existing_authority,
                    mutation_root=MUTATION_ROOT,
                )
                t2_baseline.build_linux_native_existing_baseline(
                    host=host_inventory,
                    live=live,
                    caller_linux_uid=selected.linux_uid,
                    target_linux_uid=selected.linux_uid,
                    linux_boot_uuid=linux_boot_uuid,
                    mapping_generation=mapping_set.generation,
                    account_uuid=selected.account_uuid,
                    bag_uuid=selected.bag_uuid,
                    authority_reference=current_authority.reference,
                    authority_sha256=current_authority.sha256,
                    password_fallback_verified=True,
                )
                prepared = (
                    lease,
                    host_inventory,
                    expected_identity_count,
                    {
                        "account_uuid": selected.account_uuid,
                        "bag_uuid": selected.bag_uuid,
                        "authority_reference": current_authority.reference,
                        "authority_sha256": current_authority.sha256,
                    },
                    live,
                )
                event = "existing-baseline-verified"
        except retriable as error:
            resources.close()
            raise NativeEnrollmentError(
                "Bridge service did not become quiescent before enrollment: "
                f"{error}"
            )
        except BaseException:
            resources.close()
            raise
        _emit(event)
        try:
            yield prepared
        finally:
            resources.close()
        return
    raise NativeEnrollmentError("Bridge service did not become quiescent")


def _emit(event_kind: str, **fields: object) -> None:
    document = {"event_kind": event_kind, "identifiers_redacted": True, **fields}
    print(EVENT_PREFIX + json.dumps(document, sort_keys=True), file=sys.stderr, flush=True)


def _sleep_inhibitor_is_registered(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return False
    completed = subprocess.run(
        [str(SYSTEMD_INHIBIT), "--list", "--json=short"],
        check=False,
        capture_output=True,
        timeout=2,
    )
    if completed.returncode:
        return False
    try:
        records = json.loads(completed.stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(records, list) and any(
        isinstance(record, dict)
        and record.get("pid") == process.pid
        and record.get("who") == "t2-touchid-native-enrollment"
        and record.get("what") == "sleep"
        and record.get("mode") == "block"
        for record in records
    )


@contextmanager
def _sleep_inhibitor() -> Iterator[subprocess.Popen[bytes]]:
    process = subprocess.Popen(
        [
            str(SYSTEMD_INHIBIT),
            "--what=sleep",
            "--who=t2-touchid-native-enrollment",
            "--why=Linux-native Touch ID enrollment is active",
            "--mode=block",
            str(CAT),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        for _attempt in range(20):
            if _sleep_inhibitor_is_registered(process):
                break
            if process.poll() is not None:
                raise NativeEnrollmentError("sleep inhibitor exited during setup")
            time.sleep(0.05)
        else:
            raise NativeEnrollmentError("sleep inhibitor could not be verified")
        yield process
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def _grant(
    *,
    action: str,
    linux_uid: int,
    account_generation: str,
    mapping_generation: str,
    operation_id: str,
    linux_boot_uuid: str,
    runtime_generation: str,
    now: int,
) -> t2_user_policy.PolicyGrant:
    return t2_user_policy.PolicyGrant(
        authorization_id=str(uuid.uuid4()),
        action=action,
        caller_linux_uid=linux_uid,
        linux_account_generation=account_generation,
        target_linux_uid=linux_uid,
        mapping_generation=mapping_generation,
        operation_id=operation_id,
        linux_boot_uuid=linux_boot_uuid,
        runtime_generation=runtime_generation,
        issued_monotonic_ns=now,
        expires_monotonic_ns=now + 60 * 1_000_000_000,
        authorized=True,
    )


@contextmanager
def _authorized_activation_context(
    acm_device: t2_acm_device.ACMDevice,
    apple_user_id: int,
    password: bytearray,
    identity_binder: Callable[[bytes, bytes], None],
) -> Iterator[bytes]:
    with t2_acm_device.identity_authorized_context(
        acm_device,
        apple_user_id,
        password,
        identity_binder,
    ) as (_initial, final, external_form):
        if not final.satisfied:
            raise NativeEnrollmentError(
                "native activation ACM policy did not become authorized"
            )
        yield external_form


@contextmanager
def _verification_only_activation_context(
    acm_device: t2_acm_device.ACMDevice,
    apple_user_id: int,
    password: bytearray,
    identity_binder: Callable[[bytes, bytes], None],
) -> Iterator[bytes]:
    with t2_acm_device.identity_verification_only_context(
        acm_device,
        apple_user_id,
        password,
        identity_binder,
    ) as (_initial, _final, external_form):
        yield external_form


def _authorize_operation(
    *,
    transport: t2_aks_transport.AKSActivationTransport,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    linux_boot_uuid: str,
    operation: str,
    operation_id: str | None = None,
    operation_grant: t2_user_policy.PolicyGrant | None = None,
    activation_grant: t2_user_policy.PolicyGrant | None = None,
) -> tuple[
    t2_user_policy.UserPolicyDecision,
    t2_user_readiness.PersistentEvidence,
    str,
]:
    policy = t2_user_policy.OPERATION_POLICIES.get(operation)
    if policy is None:
        raise NativeEnrollmentError("native activation operation is unsupported")
    operation_id = str(uuid.uuid4()) if operation_id is None else operation_id
    initial = transport.observe_alias(selected.special_bag_alias)
    persistent = t2_user_readiness.PersistentEvidence(
        selected.linux_account_generation,
        selected.keybag_sha256,
        selected.apple_uid,
        selected.account_uuid,
        selected.bag_uuid,
        True,
    )
    now = time.monotonic_ns()
    request = t2_user_policy.OperationRequest(
        operation,
        selected.linux_uid,
        operation_id,
        linux_boot_uuid,
        transport.runtime_generation,
        now,
        policy.mutation,
    )
    caller = t2_user_policy.CallerEvidence(
        selected.linux_uid,
        selected.linux_account_generation,
        True,
        True,
    )
    if operation_grant is None:
        operation_grant = _grant(
            action=policy.action,
            linux_uid=selected.linux_uid,
            account_generation=selected.linux_account_generation,
            mapping_generation=mapping_set.generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=transport.runtime_generation,
            now=now,
        )
    if activation_grant is None:
        activation_grant = _grant(
            action=t2_user_policy.ACTIVATE_ACTION,
            linux_uid=selected.linux_uid,
            account_generation=selected.linux_account_generation,
            mapping_generation=mapping_set.generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=transport.runtime_generation,
            now=now,
        )
    decision = t2_user_policy.authorize(
        mapping_set,
        request,
        caller,
        persistent,
        initial,
        operation_grant,
        activation_grant,
    )
    if decision.state not in {"authorized", "activation-authorized"}:
        raise NativeEnrollmentError("native enrollment activation was not authorized")
    return decision, persistent, operation_id


def _activate_for_operation(
    *,
    transport: t2_aks_transport.AKSActivationTransport,
    acm_device: t2_acm_device.ACMDevice,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    password: bytearray,
    linux_boot_uuid: str,
    operation: str,
) -> t2_user_activation_operation.UserActivationOperationResult:
    decision, persistent, operation_id = _authorize_operation(
        transport=transport,
        mapping_set=mapping_set,
        selected=selected,
        linux_boot_uuid=linux_boot_uuid,
        operation=operation,
    )
    policy = t2_user_policy.OPERATION_POLICIES[operation]
    result = t2_user_activation_operation.run(
        ACTIVATION_ROOT / f"{operation_id}.jsonl",
        mapping_set,
        selected,
        policy.capability,
        persistent,
        transport,
        password,
        authorization=decision,
        linux_boot_uuid=linux_boot_uuid,
        acm_context_factory=lambda apple_user_id, identity_secret, password_binder: (
            _verification_only_activation_context(
                acm_device, apple_user_id, identity_secret, password_binder
            )
        ),
    )
    if result.outcome not in {"ready", "already-ready"} or result.reconciliation_required:
        raise NativeEnrollmentError("Linux-native keybag activation did not reach ready")
    final = transport.observe_alias(selected.special_bag_alias)
    if (
        t2_user_readiness.assess(selected, policy.capability, persistent, final).state
        != "ready"
    ):
        raise NativeEnrollmentError("Linux-native alias is not ready after activation")
    return result


def _activate_replacement_for_verification(
    *,
    transport: t2_aks_transport.AKSActivationTransport,
    acm_device: t2_acm_device.ACMDevice,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    linux_boot_uuid: str,
) -> None:
    """Reactivate schema-2 authority using its persisted creation material."""
    decision, persistent, operation_id = _authorize_operation(
        transport=transport,
        mapping_set=mapping_set,
        selected=selected,
        linux_boot_uuid=linux_boot_uuid,
        operation="verify",
    )
    if (
        selected.activation_secret_path is None
        or selected.activation_secret_sha256 is None
    ):
        raise NativeEnrollmentError(
            "replacement activation material is unavailable for verification"
        )
    journal_path = ACTIVATION_ROOT / f"{operation_id}.jsonl"
    with t2_activation_bundle.activation_secret(
        Path(selected.activation_secret_path),
        selected.activation_secret_sha256,
    ) as activation_material:
        with t2_user_activation_operation.retain_ready_identity_handle(
            journal_path,
            mapping_set,
            selected,
            "verify",
            persistent,
            transport,
            authorization=decision,
            linux_boot_uuid=linux_boot_uuid,
        ) as retained_state:
            if retained_state in {"device-locked", "before-first-unlock"}:
                t2_user_activation_operation.prepare_retained_identity(
                    journal_path, selected, transport
                )
            final_policy = None
            try:
                with t2_acm_device.identity_authorized_context(
                    acm_device,
                    selected.apple_uid,
                    activation_material,
                    transport.bind_loaded_identity_secret_to_acm_context,
                    include_authorization_context=True,
                ) as proof:
                    if len(proof) != 4:
                        raise NativeEnrollmentError(
                            "replacement verification omitted its output context"
                        )
                    (
                        _initial,
                        final_policy,
                        identity_reference,
                        _output_context,
                    ) = proof
                    if retained_state in {
                        "device-locked",
                        "before-first-unlock",
                    }:
                        t2_user_activation_operation.unlock_retained_identity(
                            journal_path,
                            selected,
                            "verify",
                            persistent,
                            transport,
                            identity_reference,
                        )
                    _wipe(activation_material)
            except t2_acm_device.ACMContextCleanupError as error:
                t2_acm_device.reconcile_identity_cleanup_after_close(
                    error, acm_device
                )
            if final_policy is None or final_policy.satisfied is not True:
                raise NativeEnrollmentError(
                    "replacement verification authorization did not complete"
                )
    final = transport.observe_alias(selected.special_bag_alias)
    if (
        t2_user_readiness.assess(
            selected, "verify", persistent, final
        ).state
        != "ready"
    ):
        raise NativeEnrollmentError(
            "replacement identity is not ready after verification activation"
        )


def _activate_for_post_reboot_verification(
    *,
    transport: t2_aks_transport.AKSActivationTransport,
    acm_device: t2_acm_device.ACMDevice,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    password: bytearray,
    linux_boot_uuid: str,
) -> None:
    if mapping_set.schema_version == t2_user_mapping.LEGACY_SCHEMA_VERSION:
        activation = _activate_for_operation(
            transport=transport,
            acm_device=acm_device,
            mapping_set=mapping_set,
            selected=selected,
            password=password,
            linux_boot_uuid=linux_boot_uuid,
            operation="verify",
        )
        if activation.outcome not in {"ready", "already-ready"}:
            raise NativeEnrollmentError(
                "native keybag runtime did not revalidate"
            )
        return
    if mapping_set.schema_version != t2_user_mapping.SCHEMA_VERSION:
        raise NativeEnrollmentError(
            "native verification mapping schema is unsupported"
        )
    _activate_replacement_for_verification(
        transport=transport,
        acm_device=acm_device,
        mapping_set=mapping_set,
        selected=selected,
        linux_boot_uuid=linux_boot_uuid,
    )


def _arm_enrollment(cancellation: Event) -> None:
    if cancellation.is_set():
        raise NativeEnrollmentError("native enrollment was cancelled before capture")
    _emit("enrollment-armed")


def _feedback(transition: object) -> None:
    action = getattr(transition, "action", None)
    progress = getattr(transition, "progress_percent", None)
    if not isinstance(action, t2_enrollment_protocol.EnrollmentAction):
        raise NativeEnrollmentError("enrollment feedback has the wrong type")
    fields: dict[str, object] = {"action": action.value}
    if isinstance(progress, int):
        fields["progress_percent"] = progress
    _emit("enrollment-feedback", **fields)


def _synchronize_persisted_biolockout(
    coordinated: t2_enrollment_coordinator.EnrollmentCoordinatorResult,
    apple_user_id: int,
) -> t2_enrollment_coordinator.EnrollmentCoordinatorResult:
    """Publish the committed BioLockout head after any successful enrollment."""

    if not coordinated.persistence_ready:
        return coordinated
    committed = t2_catacomb_store.CatacombStore(
        CATACOMB_ROOT, apple_user_id
    ).read_committed_components()
    newest = t2_catacomb_codec.decode_biolockout_catacomb(
        committed["biolockout.cat"]
    ).secure_data
    rolling_store = t2_biolockout_store.BioLockoutStore(
        str(STATE_ROOT / "biolockout")
    )
    current = rolling_store.current()
    if current is None or current.payload != newest:
        rolling_store.commit(newest)
    _emit("rolling-biolockout-synchronized")
    return coordinated


def _candidate_native_identity_name(
    selected: t2_user_mapping.UserMapping,
    existing_authority: t2_user_authority.RuntimeUserAuthority | None,
    live_inventory: dict[str, object],
) -> str:
    """Choose one neutral handle from the exact prepared E0."""

    try:
        if existing_authority is None:
            current_handles: tuple[str, ...] = ()
        else:
            store = t2_catacomb_store.CatacombStore(
                CATACOMB_ROOT, selected.apple_uid
            )
            components = store.read_committed_components()
            local = t2_catacomb_codec.decode_user_catacomb(
                components[f"user_{selected.apple_uid:08x}.cat"],
                selected.apple_uid,
            )
            projection = t2_fprint_projection.project(
                t2_identity_inventory.summarize(local, live_inventory)
            )
            if not projection.complete:
                raise NativeEnrollmentError(
                    "existing fingerprint labels require migration"
                )
            current_handles = projection.finger_names
        return t2_fprint_sequence.candidate(
            selected.apple_uid, current_handles
        )
    except NativeEnrollmentError:
        raise
    except Exception as error:
        raise NativeEnrollmentError(
            "durable fingerprint handle allocation failed"
        ) from error


def _run(
    *,
    configuration: dict[str, object],
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    credential: bytearray,
    identity_name: str,
    cancellation: Event,
    existing_authority: t2_user_authority.RuntimeUserAuthority | None = None,
    on_feedback: Callable[[object], None] = _feedback,
    on_started: Callable[[], None] | None = None,
    authorization_session: object | None = None,
    authorization_authority: t2_user_authority.RuntimeUserAuthority | None = None,
) -> t2_enrollment_coordinator.EnrollmentCoordinatorResult:
    if not t2_fprint_identity.is_enrollment_request(identity_name):
        raise NativeEnrollmentError("native enrollment request syntax is invalid")
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise NativeEnrollmentError(
            "an earlier biometric mutation requires reconciliation"
        )
    linux_boot_uuid = str(uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip()))
    operation_id = str(uuid.uuid4())
    journal_path = MUTATION_ROOT / f"{operation_id}.jsonl"
    _require_private_runtime_root()
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(OPERATION_LOCK, lock_flags, 0o600)
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != 0
            or lock_info.st_mode & 0o077
        ):
            raise NativeEnrollmentError("operation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with _sleep_inhibitor() as inhibitor:
            if cancellation.is_set() or inhibitor.poll() is not None:
                raise NativeEnrollmentError("native enrollment was cancelled before preflight")
            _emit("preflight-started")
            _emit("endpoint-discovered")
            with _prepared_native_enrollment_lease(
                configuration=configuration,
                mapping_set=mapping_set,
                selected=selected,
                linux_boot_uuid=linux_boot_uuid,
                existing_authority=existing_authority,
            ) as prepared:
                (
                    lease,
                    host_inventory,
                    expected_identity_count,
                    native_binding,
                    live_inventory,
                ) = prepared
                activation_password = bytearray(credential)
                try:
                    with (
                        t2_aks_transport.AKSActivationTransport() as aks_transport,
                        t2_acm_device.ACMDevice() as acm_device,
                    ):
                        caller_authorization = None
                        if authorization_session is not None:
                            caller_authorization = t2_native_caller_authorization.collect(
                                authorization_session,
                                authorization_authority
                                or existing_authority
                                or t2_user_authority.load(selected.linux_uid),
                                operation="enroll",
                                operation_id=operation_id,
                                linux_boot_uuid=linux_boot_uuid,
                                runtime_generation=aks_transport.runtime_generation,
                            )
                        allocated_identity_name = _candidate_native_identity_name(
                            selected, existing_authority, live_inventory
                        )
                        if (
                            mapping_set.schema_version
                            == t2_user_mapping.LEGACY_SCHEMA_VERSION
                        ):
                            activation = _activate_for_operation(
                                transport=aks_transport,
                                acm_device=acm_device,
                                mapping_set=mapping_set,
                                selected=selected,
                                password=activation_password,
                                linux_boot_uuid=linux_boot_uuid,
                                operation="enroll",
                            )
                            _emit("keybag-ready", outcome=activation.outcome)
                        else:
                            (
                                activation_decision,
                                persistent,
                                activation_operation_id,
                            ) = _authorize_operation(
                                transport=aks_transport,
                                mapping_set=mapping_set,
                                selected=selected,
                                linux_boot_uuid=linux_boot_uuid,
                                operation="enroll",
                                operation_id=operation_id,
                                operation_grant=(
                                    caller_authorization.operation_grant
                                    if caller_authorization is not None
                                    else None
                                ),
                                activation_grant=(
                                    caller_authorization.activation_grant
                                    if caller_authorization is not None
                                    else None
                                ),
                            )

                        def bind_password(external_form: bytes) -> None:
                            aks_transport.bind_password_to_acm_context(
                                selected.special_bag_alias,
                                credential,
                                external_form,
                            )
                            _arm_enrollment(cancellation)

                        def finalizer(result):
                            target_lease = lease
                            fresh_context = None
                            if result.outcome == "result-witnessed":
                                # Live D218 evidence proves the completed T2
                                # identity becomes authoritative only after the
                                # enrollment connection closes. Keep the same
                                # process/ACM lifetime, but roll Bridge
                                # generation before inventory and persistence.
                                lease.close()
                                try:
                                    port = _discover_port(
                                        configuration["host"],
                                        configuration["interface"],
                                    )
                                    fresh_context = (
                                        t2_bridge_connection.BridgeConnectionLease.connect(
                                            configuration["host"],
                                            configuration["interface"],
                                            port,
                                            timeout=60,
                                        )
                                    )
                                    target_lease = fresh_context.__enter__()
                                    return t2_enrollment_finalizer.BuiltinEnrollmentFinalizer(
                                        lease=target_lease,
                                        apple_user_id=selected.apple_uid,
                                        connection_generation=(
                                            target_lease.connection_generation
                                        ),
                                        journal_path=journal_path,
                                        operation_id=operation_id,
                                        catacomb_root=CATACOMB_ROOT,
                                        mapping_generation=mapping_set.generation,
                                        identity_name=allocated_identity_name,
                                    )(result)
                                except BaseException:
                                    current = t2_enrollment_journal.read(journal_path)
                                    if (
                                        current.phase
                                        is t2_enrollment_journal.EnrollmentPhase.TERMINAL_WITNESS
                                    ):
                                        t2_enrollment_journal.append_checked(
                                            journal_path,
                                            operation_id,
                                            "ENROLL_OUTCOME_UNKNOWN",
                                            {
                                                "connection_generation": current.baseline[
                                                    "connection_generation"
                                                ],
                                                "stage": "terminal",
                                                "reason": "connection-lost",
                                                "mutation_possible": True,
                                            },
                                        )
                                    raise
                                finally:
                                    if fresh_context is not None:
                                        fresh_context.__exit__(None, None, None)
                            return t2_enrollment_finalizer.BuiltinEnrollmentFinalizer(
                                lease=target_lease,
                                apple_user_id=selected.apple_uid,
                                connection_generation=target_lease.connection_generation,
                                journal_path=journal_path,
                                operation_id=operation_id,
                                catacomb_root=CATACOMB_ROOT,
                                mapping_generation=mapping_set.generation,
                                identity_name=allocated_identity_name,
                            )(result)
                        def coordinate(authorization_scope=None):
                            coordinated = t2_enrollment_coordinator.run(
                                lease=lease,
                                acm_device=acm_device,
                                apple_user_id=selected.apple_uid,
                                host_inventory=host_inventory,
                                journal_path=journal_path,
                                operation_id=operation_id,
                                caller_linux_uid=selected.linux_uid,
                                target_linux_uid=selected.linux_uid,
                                linux_boot_uuid=linux_boot_uuid,
                                mapping_generation=mapping_set.generation,
                                backup_reference=None,
                                password_fallback_verified=True,
                                password_binder=bind_password,
                                finalizer=finalizer,
                                dispatch_allowed=lambda: not cancellation.is_set()
                                and inhibitor.poll() is None
                                and (
                                    caller_authorization is None
                                    or caller_authorization.dispatch_allowed()
                                ),
                                authorization_scope=authorization_scope,
                                linux_native_binding=native_binding,
                                cancel_requested=lambda: cancellation.is_set()
                                or inhibitor.poll() is not None,
                                on_started=(
                                    on_started
                                    if on_started is not None
                                    else lambda: _emit("enrollment-active")
                                ),
                                on_feedback=on_feedback,
                                live_inventory=live_inventory,
                            )
                            return _synchronize_persisted_biolockout(
                                coordinated, selected.apple_uid
                            )

                        if (
                            mapping_set.schema_version
                            == t2_user_mapping.LEGACY_SCHEMA_VERSION
                        ):
                            return coordinate()
                        if (
                            selected.activation_secret_path is None
                            or selected.activation_secret_sha256 is None
                        ):
                            raise NativeEnrollmentError(
                                "replacement activation material is unavailable"
                            )

                        def identity_authorization_scope(consumer):
                            consumed = None
                            final_policy = None
                            if retained_state in {
                                "device-locked",
                                "before-first-unlock",
                            }:
                                t2_user_activation_operation.prepare_retained_identity(
                                    activation_journal_path,
                                    selected,
                                    aks_transport,
                                )
                            try:
                                with t2_acm_device.identity_authorized_context(
                                    acm_device,
                                    selected.apple_uid,
                                    activation_material,
                                    aks_transport.bind_loaded_identity_secret_to_acm_context,
                                    include_authorization_context=True,
                                ) as proof:
                                    if len(proof) != 4:
                                        raise NativeEnrollmentError(
                                            "replacement authorization omitted its output context"
                                        )
                                    (
                                        _initial,
                                        final_policy,
                                        identity_reference,
                                        output_context,
                                    ) = proof
                                    if retained_state in {
                                        "device-locked",
                                        "before-first-unlock",
                                    }:
                                        t2_user_activation_operation.unlock_retained_identity(
                                            activation_journal_path,
                                            selected,
                                            "enroll",
                                            persistent,
                                            aks_transport,
                                            identity_reference,
                                        )
                                    _wipe(activation_material)
                                    _emit("keybag-ready", outcome="ready")
                                    readiness = t2_mesa_enrollment_preparation.prepare_user_for_enrollment(
                                        lease,
                                        selected.apple_uid,
                                        expected_identity_count,
                                        declare_missing_user=existing_authority is None,
                                    )
                                    _emit(
                                        "mesa-enrollment-ready",
                                        calibration_loaded=readiness.calibration_loaded,
                                        selected_user_secure=readiness.selected_user_secure,
                                        system_policy_ready=readiness.system_policy_ready,
                                        user_policy_ready=readiness.user_policy_ready,
                                    )
                                    _arm_enrollment(cancellation)
                                    consumed = consumer(output_context)
                            except t2_acm_device.ACMContextCleanupError as error:
                                if error.primary_error is not None:
                                    t2_acm_device.raise_primary_after_identity_cleanup_close(
                                        error, acm_device
                                    )
                                else:
                                    t2_acm_device.reconcile_identity_cleanup_after_close(
                                        error, acm_device
                                    )
                            if final_policy is None or consumed is None:
                                raise NativeEnrollmentError(
                                    "replacement enrollment authorization did not complete"
                                )
                            return final_policy, consumed

                        with t2_activation_bundle.activation_secret(
                            Path(selected.activation_secret_path),
                            selected.activation_secret_sha256,
                        ) as activation_material:
                            activation_journal_path = (
                                ACTIVATION_ROOT
                                / f"{activation_operation_id}.jsonl"
                            )
                            with t2_user_activation_operation.retain_ready_identity_handle(
                                activation_journal_path,
                                mapping_set,
                                selected,
                                "enroll",
                                persistent,
                                aks_transport,
                                authorization=activation_decision,
                                linux_boot_uuid=linux_boot_uuid,
                            ) as retained_state:
                                return coordinate(identity_authorization_scope)
                finally:
                    _wipe(activation_password)
    finally:
        os.close(lock_descriptor)


def _run_add_finger_preflight(
    *,
    configuration: dict[str, object],
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    existing_authority: t2_user_authority.RuntimeUserAuthority,
) -> dict[str, object]:
    """Prove the complete additional-enrollment E0 without creating a journal."""
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise NativeEnrollmentError(
            "an earlier biometric mutation requires reconciliation"
        )
    linux_boot_uuid = str(uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip()))
    _require_private_runtime_root()
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(OPERATION_LOCK, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
        ):
            raise NativeEnrollmentError("operation lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with _sleep_inhibitor() as inhibitor:
            if inhibitor.poll() is not None:
                raise NativeEnrollmentError("sleep inhibitor exited during preflight")
            with _prepared_native_enrollment_lease(
                configuration=configuration,
                mapping_set=mapping_set,
                selected=selected,
                linux_boot_uuid=linux_boot_uuid,
                existing_authority=existing_authority,
            ) as prepared:
                lease, host, count, binding, live = prepared
                if (
                    lease.connection_generation != live.get("connection_generation")
                    or not isinstance(count, int)
                    or count < 1
                    or len(host.get("identity_records", [])) != count
                    or set(binding) != {
                        "account_uuid",
                        "bag_uuid",
                        "authority_reference",
                        "authority_sha256",
                    }
                ):
                    raise NativeEnrollmentError(
                        "additional enrollment preflight did not reconcile"
                    )
                if (
                    selected.activation_secret_path is None
                    or selected.activation_secret_sha256 is None
                ):
                    raise NativeEnrollmentError(
                        "replacement activation material is unavailable"
                    )
                with (
                    t2_aks_transport.AKSActivationTransport() as aks_transport,
                    t2_acm_device.ACMDevice() as acm_device,
                ):
                    decision, persistent, operation_id = _authorize_operation(
                        transport=aks_transport,
                        mapping_set=mapping_set,
                        selected=selected,
                        linux_boot_uuid=linux_boot_uuid,
                        operation="enroll",
                    )
                    with t2_activation_bundle.activation_secret(
                        Path(selected.activation_secret_path),
                        selected.activation_secret_sha256,
                    ) as activation_material:
                        activation_journal_path = (
                            ACTIVATION_ROOT / f"{operation_id}.jsonl"
                        )
                        with t2_user_activation_operation.retain_ready_identity_handle(
                            activation_journal_path,
                            mapping_set,
                            selected,
                            "enroll",
                            persistent,
                            aks_transport,
                            authorization=decision,
                            linux_boot_uuid=linux_boot_uuid,
                        ) as retained_state:
                            if retained_state in {
                                "device-locked",
                                "before-first-unlock",
                            }:
                                t2_user_activation_operation.prepare_retained_identity(
                                    activation_journal_path,
                                    selected,
                                    aks_transport,
                                )
                            final_policy = None
                            readiness = None
                            try:
                                with t2_acm_device.identity_authorized_context(
                                    acm_device,
                                    selected.apple_uid,
                                    activation_material,
                                    aks_transport.bind_loaded_identity_secret_to_acm_context,
                                    include_authorization_context=True,
                                ) as proof:
                                    if len(proof) != 4:
                                        raise NativeEnrollmentError(
                                            "replacement preflight authorization omitted its output context"
                                        )
                                    (
                                        _initial,
                                        final_policy,
                                        identity_reference,
                                        _output_context,
                                    ) = proof
                                    if retained_state in {
                                        "device-locked",
                                        "before-first-unlock",
                                    }:
                                        t2_user_activation_operation.unlock_retained_identity(
                                            activation_journal_path,
                                            selected,
                                            "enroll",
                                            persistent,
                                            aks_transport,
                                            identity_reference,
                                        )
                                    _wipe(activation_material)
                                    readiness = t2_mesa_enrollment_preparation.prepare_user_for_enrollment(
                                        lease, selected.apple_uid, count
                                    )
                            except t2_acm_device.ACMContextCleanupError as error:
                                if error.primary_error is not None:
                                    t2_acm_device.raise_primary_after_identity_cleanup_close(
                                        error, acm_device
                                    )
                                else:
                                    t2_acm_device.reconcile_identity_cleanup_after_close(
                                        error, acm_device
                                    )
                            if (
                                final_policy is None
                                or final_policy.satisfied is not True
                                or readiness is None
                                or readiness.identity_count != count
                            ):
                                raise NativeEnrollmentError(
                                    "additional enrollment authorization preflight did not complete"
                                )
        return {
            "additional_enrollment_preflight_ready": True,
            "mesa_enrollment_preflight_ready": True,
            "fingerprint_mutation_performed": False,
            "journal_created": False,
            "identifiers_redacted": True,
        }
    finally:
        os.close(descriptor)


def _pending_post_reboot_journal(
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
) -> tuple[Path, t2_enrollment_journal.EnrollmentHistory]:
    candidates: list[tuple[Path, t2_enrollment_journal.EnrollmentHistory]] = []
    with os.scandir(MUTATION_ROOT) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".jsonl"):
                raise NativeEnrollmentError("native mutation directory is not canonical")
            path = MUTATION_ROOT / entry.name
            history = t2_enrollment_journal.read(path)
            if history.phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED:
                candidates.append((path, history))
            else:
                raise NativeEnrollmentError(
                    "native enrollment journal requires reconciliation before reuse"
                )
    if len(candidates) != 1:
        raise NativeEnrollmentError(
            "post-reboot verification requires exactly one reconciled enrollment"
        )
    path, history = candidates[0]
    baseline = history.baseline
    if (
        baseline.get("baseline_version") != 2
        or baseline.get("caller_linux_uid") != selected.linux_uid
        or baseline.get("target_linux_uid") != selected.linux_uid
        or baseline.get("apple_uid") != selected.apple_uid
        or baseline.get("account_uuid") != selected.account_uuid
        or baseline.get("bag_uuid") != selected.bag_uuid
        or baseline.get("mapping_generation") != mapping_set.generation
    ):
        raise NativeEnrollmentError("native enrollment journal binding changed")
    return path, history


def _pending_authority_publication_journal(
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    *,
    expected_operation_id: str,
) -> tuple[Path, t2_enrollment_journal.EnrollmentHistory]:
    """Select only the initial E4 journal that can still become authority."""

    entries = t2_mutation_registry.scan(MUTATION_ROOT)
    if any(entry.blocks_new_mutation for entry in entries):
        raise NativeEnrollmentError(
            "authority publication recovery found an unfinished mutation"
        )
    candidates: list[tuple[Path, t2_enrollment_journal.EnrollmentHistory]] = []
    later_mutation = False
    for path in sorted(MUTATION_ROOT.iterdir(), key=lambda item: item.name):
        records = t2_mutation_journal.read(path)
        evidence = records[0].get("evidence") if records else None
        operation_kind = (
            evidence.get("operation_kind")
            if isinstance(evidence, dict)
            else None
        )
        if operation_kind != "enroll":
            later_mutation = True
            continue
        history = t2_enrollment_journal.validate_history(records)
        if history.phase is t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED:
            candidates.append((path, history))
        elif (
            history.baseline.get("baseline_version") != 2
            or history.phase
            not in {
                t2_enrollment_journal.EnrollmentPhase.BASELINE,
                t2_enrollment_journal.EnrollmentPhase.ABORTED_BEFORE_START,
            }
        ):
            later_mutation = True
    if later_mutation or len(candidates) != 1:
        raise NativeEnrollmentError(
            "authority publication recovery is not unambiguous"
        )
    path, history = candidates[0]
    if (
        history.operation_id != expected_operation_id
        or path.name != f"{history.operation_id}.jsonl"
        or history.baseline.get("baseline_version") != 2
    ):
        raise NativeEnrollmentError(
            "authority publication recovery selected another journal"
        )
    try:
        t2_user_authority._bound_history(
            mapping_set, selected, history, selected.linux_uid
        )
    except t2_user_authority.UserAuthorityError as error:
        raise NativeEnrollmentError(
            "authority publication recovery journal binding changed"
        ) from error
    return path, history


def _run_post_reboot_publication_recovery(
    *,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    expected_operation_id: str,
) -> dict[str, object]:
    """Publish a committed E4 proof without repeating any hardware work."""

    _require_private_runtime_root()
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(OPERATION_LOCK, lock_flags, 0o600)
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != 0
            or lock_info.st_mode & 0o077
        ):
            raise NativeEnrollmentError("operation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal_path, _history = _pending_authority_publication_journal(
            mapping_set,
            selected,
            expected_operation_id=expected_operation_id,
        )
        manifest = (
            t2_user_authority.USERS_ROOT
            / str(selected.linux_uid)
            / "authority.json"
        )
        try:
            current = t2_user_authority.load(selected.linux_uid)
        except t2_user_authority.UserAuthorityError as error:
            if os.path.lexists(manifest):
                raise NativeEnrollmentError(
                    "an existing runtime authority is invalid"
                ) from error
        else:
            if (
                current.mapping_set != mapping_set
                or current.selected != selected
                or current.enrollment_journal.name != journal_path.name
            ):
                raise NativeEnrollmentError(
                    "a different runtime authority is already published"
                )
            return {
                "enrollment_post_reboot_verified": True,
                "fingerprint_mutation_performed": False,
                "identifiers_redacted": True,
                "runtime_authority_published": True,
                "authority_publication_recovered": False,
                "schema_version": 1,
            }
        try:
            authority = t2_user_authority.publish(
                selected.linux_uid, journal_path
            )
        except t2_user_authority.UserAuthorityReadbackError as error:
            raise t2_post_reboot_diagnostic.staged(
                "final-authority-readback", error
            ) from error
        except Exception as error:
            raise t2_post_reboot_diagnostic.staged(
                "authority-publication", error
            ) from error
        if (
            authority.mapping_set != mapping_set
            or authority.selected != selected
            or authority.enrollment_journal.name != journal_path.name
        ):
            error = NativeEnrollmentError(
                "recovered runtime authority changed bindings"
            )
            raise t2_post_reboot_diagnostic.staged(
                "final-authority-readback", error
            ) from error
        return {
            "enrollment_post_reboot_verified": True,
            "fingerprint_mutation_performed": False,
            "identifiers_redacted": True,
            "runtime_authority_published": True,
            "authority_publication_recovered": True,
            "schema_version": 1,
        }
    finally:
        os.close(lock_descriptor)


def _pending_observed_identity_recovery(
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
) -> tuple[Path, t2_enrollment_journal.EnrollmentHistory]:
    """Select one same-boot terminal ambiguity that can be read back safely."""
    _private(CATACOMB_ROOT, directory=True)
    _private(MUTATION_ROOT, directory=True)
    t2_mutation_registry.scan(MUTATION_ROOT)
    candidates: list[tuple[Path, t2_enrollment_journal.EnrollmentHistory]] = []
    with os.scandir(MUTATION_ROOT) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(
                ".jsonl"
            ):
                raise NativeEnrollmentError(
                    "native mutation directory is not canonical"
                )
            path = MUTATION_ROOT / entry.name
            try:
                records = t2_mutation_journal.read(path)
            except t2_mutation_journal.JournalError as error:
                raise NativeEnrollmentError(
                    "native mutation journal is invalid"
                ) from error
            if not records:
                raise NativeEnrollmentError("native mutation journal is empty")
            evidence = records[0].get("evidence")
            operation_kind = (
                evidence.get("operation_kind")
                if isinstance(evidence, dict)
                else None
            )
            if operation_kind != "enroll":
                # The shared registry owns rename/delete validation. This
                # selector must inspect only enrollment journals and must not
                # feed another operation kind to the enrollment state machine.
                continue
            history = t2_enrollment_journal.validate_history(records)
            if (
                history.phase is t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
                and history.outcome_unknown_stage == "terminal"
            ):
                candidates.append((path, history))
            elif history.phase in {
                t2_enrollment_journal.EnrollmentPhase.RECONCILED,
                t2_enrollment_journal.EnrollmentPhase.ADDITION_VERIFIED,
                t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED,
            }:
                # Additional enrollment legitimately coexists with the durable
                # journals that establish the identities in its v1 baseline.
                continue
            else:
                raise NativeEnrollmentError(
                    "native enrollment journal is not a terminal recovery candidate"
                )
    if len(candidates) != 1:
        raise NativeEnrollmentError(
            "identity recovery requires exactly one terminal outcome-unknown enrollment"
        )
    path, history = candidates[0]
    baseline = history.baseline
    linux_boot_uuid = str(uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip()))
    if (
        baseline.get("baseline_version") not in (1, 2)
        or baseline.get("linux_boot_uuid") != linux_boot_uuid
        or baseline.get("caller_linux_uid") != selected.linux_uid
        or baseline.get("target_linux_uid") != selected.linux_uid
        or baseline.get("apple_uid") != selected.apple_uid
        or baseline.get("account_uuid") != selected.account_uuid
        or baseline.get("bag_uuid") != selected.bag_uuid
        or baseline.get("mapping_generation") != mapping_set.generation
    ):
        raise NativeEnrollmentError(
            "terminal identity recovery journal binding changed"
        )
    return path, history


def _pending_outcome_unknown_reconciliation(
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
) -> tuple[Path, t2_enrollment_journal.EnrollmentHistory]:
    """Select one ambiguous enrollment for fresh, no-replay readback."""
    _private(CATACOMB_ROOT, directory=True)
    _private(MUTATION_ROOT, directory=True)
    t2_mutation_registry.scan(MUTATION_ROOT)
    candidates: list[tuple[Path, t2_enrollment_journal.EnrollmentHistory]] = []
    with os.scandir(MUTATION_ROOT) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(
                ".jsonl"
            ):
                raise NativeEnrollmentError(
                    "native mutation directory is not canonical"
                )
            path = MUTATION_ROOT / entry.name
            try:
                records = t2_mutation_journal.read(path)
            except t2_mutation_journal.JournalError as error:
                raise NativeEnrollmentError(
                    "native mutation journal is invalid"
                ) from error
            if not records:
                raise NativeEnrollmentError("native mutation journal is empty")
            evidence = records[0].get("evidence")
            operation_kind = (
                evidence.get("operation_kind")
                if isinstance(evidence, dict)
                else None
            )
            if operation_kind != "enroll":
                continue
            history = t2_enrollment_journal.validate_history(records)
            if (
                history.phase
                is t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
            ):
                candidates.append((path, history))
            elif history.phase in {
                t2_enrollment_journal.EnrollmentPhase.RECONCILED,
                t2_enrollment_journal.EnrollmentPhase.ADDITION_VERIFIED,
                t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED,
            }:
                continue
            else:
                raise NativeEnrollmentError(
                    "native enrollment journal is not a terminal recovery candidate"
                )
    if len(candidates) != 1:
        raise NativeEnrollmentError(
            "outcome reconciliation requires exactly one outcome-unknown enrollment"
        )
    path, history = candidates[0]
    baseline = history.baseline
    if (
        baseline.get("baseline_version") not in (1, 2)
        or baseline.get("caller_linux_uid") != selected.linux_uid
        or baseline.get("target_linux_uid") != selected.linux_uid
        or baseline.get("apple_uid") != selected.apple_uid
        or baseline.get("account_uuid") != selected.account_uuid
        or baseline.get("bag_uuid") != selected.bag_uuid
        or baseline.get("mapping_generation") != mapping_set.generation
    ):
        raise NativeEnrollmentError(
            "outcome reconciliation journal binding changed"
        )
    return path, history


def _run_outcome_unknown_reconciliation(
    *,
    configuration: dict[str, object],
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
) -> dict[str, object]:
    """Prove an ambiguous enrollment made no change, without replaying it."""
    journal_path, history = _pending_outcome_unknown_reconciliation(
        mapping_set, selected
    )
    _require_private_runtime_root()
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(OPERATION_LOCK, lock_flags, 0o600)
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != 0
            or lock_info.st_mode & 0o077
        ):
            raise NativeEnrollmentError("operation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with _sleep_inhibitor() as inhibitor:
            if inhibitor.poll() is not None:
                raise NativeEnrollmentError(
                    "sleep inhibitor exited during outcome reconciliation setup"
                )
            port = _discover_port(
                configuration["host"], configuration["interface"]
            )
            store = t2_catacomb_store.CatacombStore(
                CATACOMB_ROOT, selected.apple_uid
            )
            with t2_bridge_connection.BridgeConnectionLease.connect(
                configuration["host"],
                configuration["interface"],
                port,
                timeout=60,
            ) as lease:
                live = t2_bridge_inventory.collect_stable_private_inventory(
                    lease, selected.apple_uid
                )
                local_prepare_discarded = (
                    _discard_cancelled_biolockout_prepare(store, history)
                )
                host = t2_enrollment_finalizer.read_local_host_snapshot(
                    store, history.baseline
                )
                reconciled = t2_enrollment_reconciliation.append_reconciled(
                    journal_path,
                    history.operation_id,
                    host=host,
                    live=live,
                    mapping_generation=mapping_set.generation,
                )
        if (
            reconciled.phase
            is not t2_enrollment_journal.EnrollmentPhase.RECONCILED
            or reconciled.terminal_identity_uuid is not None
        ):
            raise NativeEnrollmentError(
                "outcome reconciliation did not prove an unchanged identity set"
            )
        return {
            "outcome_unknown_reconciled": True,
            "identity_count": len(live["per_user_identity_records"]),
            "fingerprint_mutation_performed": False,
            "local_prepare_discarded": local_prepare_discarded,
            "identifiers_redacted": True,
            "schema_version": 1,
        }
    finally:
        os.close(lock_descriptor)


def _discard_cancelled_biolockout_prepare(
    store: t2_catacomb_store.CatacombStore,
    history: t2_enrollment_journal.EnrollmentHistory,
) -> bool:
    """Remove the empty rollback side left by an ambiguous cancel save.

    Mesa cancellation is already terminal and identity-free at this point.
    The BioLockout save request is a read/export operation, but a lost reply
    can leave the host transaction directory open before any component bytes
    exist.  Never replay that request.  Admit only the exact cancelled,
    BioLockout-only, pre-host-stage shape and let the fresh stable inventory
    plus normal E3 classifier prove that the identity set stayed unchanged.
    """
    prepare = CATACOMB_ROOT / "prepare"
    commit = CATACOMB_ROOT / "commit"
    prepare_pending = os.path.lexists(prepare)
    commit_pending = os.path.lexists(commit)
    if not prepare_pending and not commit_pending:
        return False
    persistence = history.persistence
    exact_cancel_save = (
        history.phase is t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
        and history.terminal_identity_uuid is None
        and history.terminal_status == 66
        and persistence.phase
        is t2_enrollment_persistence_journal.PersistencePhase.OUTCOME_UNKNOWN
        and persistence.outcome_unknown_stage == "complete"
        and persistence.outcome_unknown_host_commit_possible is False
        and persistence.batch_index == 0
        and persistence.component_index == 0
        and persistence.staged_files == ()
        and len(persistence.batches) == 1
        and len(persistence.batches[0]) == 1
        and persistence.batches[0][0][0] == "biolockout.cat"
    )
    if not exact_cancel_save or not prepare_pending or commit_pending:
        raise NativeEnrollmentError(
            "outcome reconciliation found an unsupported local Catacomb transaction"
        )
    store.discard_empty_prepare()
    return True


def _run_observed_identity_recovery(
    *,
    configuration: dict[str, object],
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    identity_name: str | None,
) -> dict[str, object]:
    """Adopt one stable SEP identity and finish persistence without recapture.

    This adapts T1Bridge's fresh-identity-list postcondition and durable
    user-before-master save ordering.  T2 keeps the stricter fresh-generation
    global/per-user equality, baseline delta, BioLockout, and E3 gates.
    """
    journal_path, history = _pending_observed_identity_recovery(
        mapping_set, selected
    )
    baseline_identities = history.baseline.get("identity_records")
    if not isinstance(baseline_identities, list):
        raise NativeEnrollmentError(
            "observed identity recovery baseline is malformed"
        )
    current_handles = tuple(
        record.get("name")
        for record in baseline_identities
        if isinstance(record, dict)
    )
    if len(current_handles) != len(baseline_identities):
        raise NativeEnrollmentError(
            "observed identity recovery baseline is malformed"
        )
    try:
        current_handles = t2_fprint_identity.ordered(current_handles)
        allocated_identity_name = t2_fprint_sequence.candidate(
            selected.apple_uid, current_handles
        )
    except (
        t2_fprint_identity.FprintIdentityError,
        t2_fprint_sequence.FprintSequenceError,
    ) as error:
        raise NativeEnrollmentError(
            "observed identity recovery slot allocation failed"
        ) from error
    if identity_name is not None and identity_name != allocated_identity_name:
        raise NativeEnrollmentError(
            "observed identity recovery slot changed"
        )
    _require_private_runtime_root()
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(OPERATION_LOCK, lock_flags, 0o600)
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != 0
            or lock_info.st_mode & 0o077
        ):
            raise NativeEnrollmentError("operation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with _sleep_inhibitor() as inhibitor:
            if inhibitor.poll() is not None:
                raise NativeEnrollmentError(
                    "sleep inhibitor exited during identity recovery setup"
                )
            port = _discover_port(
                configuration["host"], configuration["interface"]
            )
            store = t2_catacomb_store.CatacombStore(
                CATACOMB_ROOT, selected.apple_uid
            )
            with t2_bridge_connection.BridgeConnectionLease.connect(
                configuration["host"],
                configuration["interface"],
                port,
                timeout=60,
            ) as lease:
                live = t2_bridge_inventory.collect_stable_private_inventory(
                    lease, selected.apple_uid
                )
                host = t2_enrollment_finalizer.read_local_host_snapshot(
                    store, history.baseline
                )
                recovery = (
                    t2_enrollment_reconciliation.classify_observed_identity_recovery(
                        history,
                        host=host,
                        live=live,
                        mapping_generation=mapping_set.generation,
                    )
                )
                recovered = t2_enrollment_journal.append_checked(
                    journal_path,
                    history.operation_id,
                    "E2_RECOVERY_IDENTITY_READBACK_OBSERVED",
                    recovery.evidence,
                )
                if (
                    recovered.phase
                    is not t2_enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY
                    or recovered.terminal_identity_uuid != recovery.identity_uuid
                    or recovered.persistence_connection_generation
                    != lease.connection_generation
                ):
                    raise NativeEnrollmentError(
                        "recovered identity was not bound to the fresh Bridge lease"
                    )
                finalizer = t2_enrollment_finalizer.BuiltinEnrollmentFinalizer(
                    lease=lease,
                    apple_user_id=selected.apple_uid,
                    connection_generation=lease.connection_generation,
                    journal_path=journal_path,
                    operation_id=history.operation_id,
                    catacomb_root=CATACOMB_ROOT,
                    mapping_generation=mapping_set.generation,
                    identity_name=allocated_identity_name,
                )
                attestation = finalizer(
                    t2_enrollment_operation.EnrollmentOperationResult(
                        "identity-observed", None, reconciliation_required=True
                    )
                )
        final_history = t2_enrollment_journal.read(journal_path)
        if (
            not attestation.persistence_ready
            or not attestation.reconciliation_complete
            or final_history.phase
            is not t2_enrollment_journal.EnrollmentPhase.RECONCILED
            or final_history.terminal_identity_uuid != recovery.identity_uuid
        ):
            raise NativeEnrollmentError(
                "observed identity recovery did not reach reconciled persistence"
            )
        # This path bypasses coordinate(), so publish the same committed
        # rolling lockout state before exposing the recovered fingerprint.
        _synchronize_persisted_biolockout(
            t2_enrollment_coordinator.EnrollmentCoordinatorResult(
                "identity-observed", True, True, True
            ),
            selected.apple_uid,
        )
        return {
            "enrollment_succeeded": True,
            "observed_identity_recovered": True,
            "fingerprint_mutation_performed": False,
            "identifiers_redacted": True,
            "persistence_ready": True,
            "reconciliation_complete": True,
            "reboot_verification_required": True,
        }
    finally:
        os.close(lock_descriptor)


def _run_post_reboot_verification(
    *,
    configuration: dict[str, object],
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    credential: bytearray,
    require_different_boot: bool = True,
) -> dict[str, object]:
    try:
        linux_boot_uuid = str(
            uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip())
        )
        journal_path, history = _pending_post_reboot_journal(
            mapping_set, selected
        )
    except Exception as error:
        raise t2_post_reboot_diagnostic.staged(
            "configuration-mapping-validation", error
        ) from error
    if (
        require_different_boot
        and linux_boot_uuid == history.baseline["linux_boot_uuid"]
    ):
        error = NativeEnrollmentError(
            "native enrollment verification requires a different Linux boot"
        )
        raise t2_post_reboot_diagnostic.staged(
            "configuration-mapping-validation", error
        ) from error
    _require_private_runtime_root()
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(OPERATION_LOCK, lock_flags, 0o600)
    try:
        lock_info = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != 0
            or lock_info.st_mode & 0o077
        ):
            raise NativeEnrollmentError("operation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with _sleep_inhibitor() as inhibitor:
            if inhibitor.poll() is not None:
                raise NativeEnrollmentError("sleep inhibitor exited during setup")
            try:
                port = _discover_port(
                    configuration["host"], configuration["interface"]
                )
                activation_password = bytearray(credential)
                try:
                    with (
                        t2_aks_transport.AKSActivationTransport() as aks_transport,
                        t2_acm_device.ACMDevice() as acm_device,
                    ):
                        _activate_for_post_reboot_verification(
                            transport=aks_transport,
                            acm_device=acm_device,
                            mapping_set=mapping_set,
                            selected=selected,
                            password=activation_password,
                            linux_boot_uuid=linux_boot_uuid,
                        )
                finally:
                    _wipe(activation_password)
            except Exception as error:
                raise t2_post_reboot_diagnostic.staged(
                    "native-activation", error
                ) from error
            try:
                store = t2_catacomb_store.CatacombStore(
                    CATACOMB_ROOT, selected.apple_uid
                )
                host = t2_enrollment_finalizer.read_local_host_snapshot(
                    store, history.baseline
                )
                with t2_bridge_connection.BridgeConnectionLease.connect(
                    configuration["host"],
                    configuration["interface"],
                    port,
                    timeout=60,
                    defer_client_version=True,
                ) as lease:
                    t2_bridge_inventory.attest_preclient_protocol(
                        lease, selected.apple_uid
                    )
                    lease.select_client_version()
                    live = t2_bridge_inventory.collect_stable_private_inventory(
                        lease, selected.apple_uid
                    )
            except Exception as error:
                raise t2_post_reboot_diagnostic.staged(
                    "inventory-collection", error
                ) from error
            try:
                append_verification = (
                    t2_enrollment_reconciliation.append_post_reboot_verified
                    if require_different_boot
                    else t2_enrollment_reconciliation.append_runtime_verified
                )
                verified = append_verification(
                    journal_path,
                    history.operation_id,
                    host=host,
                    live=live,
                    linux_boot_uuid=linux_boot_uuid,
                    mapping_generation=mapping_set.generation,
                    keybag_runtime_revalidated=True,
                )
            except Exception as error:
                raise t2_post_reboot_diagnostic.staged(
                    "journal-append", error
                ) from error
            if (
                verified.phase
                is not t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
            ):
                error = NativeEnrollmentError(
                    "native enrollment verification did not reach post-reboot authority"
                )
                raise t2_post_reboot_diagnostic.staged(
                    "journal-append", error
                ) from error
            try:
                authority = t2_user_authority.publish(
                    selected.linux_uid, journal_path
                )
            except t2_user_authority.UserAuthorityReadbackError as error:
                raise t2_post_reboot_diagnostic.staged(
                    "final-authority-readback", error
                ) from error
            except Exception as error:
                raise t2_post_reboot_diagnostic.staged(
                    "authority-publication", error
                ) from error
            if authority.enrollment_journal.name != journal_path.name:
                error = NativeEnrollmentError(
                    "runtime authority publication changed journals"
                )
                raise t2_post_reboot_diagnostic.staged(
                    "final-authority-readback", error
                ) from error
            return {
                "enrollment_runtime_verified": True,
                "enrollment_post_reboot_verified": require_different_boot,
                "fingerprint_mutation_performed": False,
                "identifiers_redacted": True,
                "runtime_authority_published": True,
                "schema_version": 1,
            }
    finally:
        os.close(lock_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credential-fd", type=int, default=-1)
    parser.add_argument("--operator-fd", type=int, default=0)
    parser.add_argument("--identity-name", default="finger-1")
    parser.add_argument("--acknowledge-one-shot-native-enrollment", action="store_true")
    parser.add_argument(
        "--acknowledge-one-shot-native-enrollment-verification", action="store_true"
    )
    parser.add_argument("--acknowledge-password-fallback-tested", action="store_true")
    parser.add_argument("--acknowledge-local-catacomb-mutation", action="store_true")
    parser.add_argument(
        "--acknowledge-observed-identity-recovery", action="store_true"
    )
    parser.add_argument("--reconcile-outcome-unknown", action="store_true")
    parser.add_argument("--recover-observed-identity", action="store_true")
    parser.add_argument("--post-reboot-verification", action="store_true")
    parser.add_argument("--add-finger", action="store_true")
    parser.add_argument("--preflight-add-finger", action="store_true")
    args = parser.parse_args()
    credential = bytearray()
    cancellation = Event()
    handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_handlers: dict[signal.Signals, object] = {}
    try:
        if os.geteuid() != 0:
            raise NativeEnrollmentError("native enrollment must run as root")
        if args.operator_fd < 0 or args.credential_fd < -1:
            raise NativeEnrollmentError("native enrollment descriptors are invalid")
        if sum(bool(value) for value in (
            args.post_reboot_verification,
            args.reconcile_outcome_unknown,
            args.recover_observed_identity,
            args.add_finger,
            args.preflight_add_finger,
        )) > 1:
            raise NativeEnrollmentError("native enrollment recovery modes conflict")
        if (
            not args.post_reboot_verification
            and not args.reconcile_outcome_unknown
            and not args.recover_observed_identity
            and not args.preflight_add_finger
            and args.credential_fd >= 0
            and args.credential_fd == args.operator_fd
        ):
            raise NativeEnrollmentError(
                "credential and operator acknowledgement descriptors must differ"
            )
        if args.recover_observed_identity:
            if not (
                args.acknowledge_observed_identity_recovery
                and args.acknowledge_local_catacomb_mutation
            ):
                raise NativeEnrollmentError(
                    "observed identity recovery acknowledgements are required"
                )
        elif args.post_reboot_verification:
            if not (
                args.acknowledge_one_shot_native_enrollment_verification
                and args.acknowledge_password_fallback_tested
            ):
                raise NativeEnrollmentError(
                    "native enrollment verification acknowledgements are required"
                )
        elif args.reconcile_outcome_unknown:
            pass
        elif not args.preflight_add_finger and not (
            args.acknowledge_one_shot_native_enrollment
            and args.acknowledge_password_fallback_tested
            and args.acknowledge_local_catacomb_mutation
        ):
            raise NativeEnrollmentError("all native enrollment acknowledgements are required")
        if (
            not args.identity_name
            or "\0" in args.identity_name
            or len(args.identity_name.encode("utf-8")) > 1024
        ):
            raise NativeEnrollmentError("identity name is invalid")
        configuration = _configuration()
        mapping_set, selected, _history = _load_provisioned_authority(
            configuration["linux_uid"], configuration["apple_uid"]
        )
        needs_legacy_credential = (
            mapping_set.schema_version == t2_user_mapping.LEGACY_SCHEMA_VERSION
            and not args.preflight_add_finger
            and not args.reconcile_outcome_unknown
            and not args.recover_observed_identity
        )
        if needs_legacy_credential and args.credential_fd < 0:
            raise NativeEnrollmentError(
                "legacy native authority requires a credential descriptor"
            )
        if args.preflight_add_finger:
            authority = t2_user_authority.load(selected.linux_uid)
            document = _run_add_finger_preflight(
                configuration=configuration,
                mapping_set=mapping_set,
                selected=selected,
                existing_authority=authority,
            )
            print(json.dumps(document, sort_keys=True))
            return 0
        if args.reconcile_outcome_unknown:
            document = _run_outcome_unknown_reconciliation(
                configuration=configuration,
                mapping_set=mapping_set,
                selected=selected,
            )
            print(json.dumps(document, sort_keys=True))
            return 0
        if args.recover_observed_identity:
            previous_handlers = {
                handled_signal: signal.signal(
                    handled_signal, lambda _signum, _frame: cancellation.set()
                )
                for handled_signal in handled
            }
            document = _run_observed_identity_recovery(
                configuration=configuration,
                mapping_set=mapping_set,
                selected=selected,
                identity_name=args.identity_name,
            )
            print(json.dumps(document, sort_keys=True))
            return 0
        credential = (
            _read_secret(args.credential_fd)
            if args.credential_fd >= 0
            else bytearray()
        )
        if args.post_reboot_verification:
            document = _run_post_reboot_verification(
                configuration=configuration,
                mapping_set=mapping_set,
                selected=selected,
                credential=credential,
            )
            print(json.dumps(document, sort_keys=True))
            return 0
        existing_authority = None
        if args.add_finger:
            existing_authority = t2_user_authority.load(selected.linux_uid)
            _private(CATACOMB_ROOT, directory=True)
            _private(MUTATION_ROOT, directory=True)
            _private(ACTIVATION_ROOT, directory=True)
        else:
            _require_fresh_enrollment_state()
        previous_handlers = {
            handled_signal: signal.signal(
                handled_signal, lambda _signum, _frame: cancellation.set()
            )
            for handled_signal in handled
        }
        result = _run(
            configuration=configuration,
            mapping_set=mapping_set,
            selected=selected,
            credential=credential,
            identity_name=args.identity_name,
            cancellation=cancellation,
            existing_authority=existing_authority,
        )
        success = (
            result.outcome == "identity-observed"
            and result.policy_satisfied
            and result.persistence_ready
            and result.reconciliation_complete
        )
        print(
            json.dumps(
                {
                    "enrollment_succeeded": success,
                    "identifiers_redacted": True,
                    "persistence_ready": result.persistence_ready,
                    "additional_fingerprint": args.add_finger,
                    "same_boot_validation_required": success and args.add_finger,
                    "reboot_verification_required": success and not args.add_finger,
                },
                sort_keys=True,
            )
        )
        return 0 if success else 1
    except (
        OSError,
        ValueError,
        NativeEnrollmentError,
        t2_acm_device.ACMDeviceError,
        t2_activation_bundle.ActivationBundleError,
        t2_aks_provisioning.AKSProvisioningError,
        t2_aks_replacement_activation_journal.AKSReplacementActivationJournalError,
        t2_aks_replacement_journal.AKSReplacementJournalError,
        t2_aks_transport.AKSActivationTransportError,
        t2_baseline.BaselineError,
        t2_biolockout_store.BioLockoutStoreError,
        t2_bridge_connection.BridgeConnectionError,
        t2_bridge_inventory.BridgeInventoryError,
        t2_catacomb_store.CatacombStoreError,
        t2_mesa_enrollment_preparation.MesaEnrollmentPreparationError,
        t2_native_state_restore.NativeStateRestoreError,
        t2_enrollment_coordinator.EnrollmentCoordinatorError,
        t2_enrollment_finalizer.EnrollmentFinalizerError,
        t2_enrollment_journal.EnrollmentJournalError,
        t2_enrollment_reconciliation.EnrollmentReconciliationError,
        t2_linux_account.LinuxAccountError,
        t2_user_activation_operation.UserActivationOperationError,
        t2_user_authority.UserAuthorityError,
        t2_user_mapping.UserMappingError,
        t2_user_policy.UserPolicyError,
        t2_user_readiness.UserReadinessError,
    ) as error:
        parser.error(str(error))
    finally:
        _wipe(credential)
        for handled_signal, previous in previous_handlers.items():
            signal.signal(handled_signal, previous)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
