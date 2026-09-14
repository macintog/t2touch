#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one bounded match against Linux-native E4 Touch ID authority."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import struct
import subprocess
import sys
import time
from threading import Event
from typing import Iterator
import uuid


SOURCE = Path(__file__).resolve().parent
MODULE_ROOT = next(
    (
        candidate
        for candidate in (SOURCE, Path("/opt/t2-touchid/src"))
        if (candidate / "t2_user_authority.py").is_file()
    ),
    SOURCE,
)
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

import t2_acm_device
import t2_activation_bundle
import t2_aks_transport
import t2_enrollment_journal
import t2_user_activation_operation
import t2_user_authority
import t2_user_policy


CONFIG = Path("/etc/t2-touchid.conf")
STATE_ROOT = Path("/var/lib/t2-touchid")
CATACOMB_ROOT = STATE_ROOT / "catacomb"
BIOLOCKOUT_ROOT = STATE_ROOT / "biolockout"
ACTIVATION_ROOT = STATE_ROOT / "activation"
MUTATION_ROOT = STATE_ROOT / "mutations"
NATIVE_MATCH_ROOT = STATE_ROOT / "native-match"
RUN_ROOT = Path("/run/t2-touchid")
OPERATION_LOCK = RUN_ROOT / "operation.lock"
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SYSTEMD_INHIBIT = Path("/usr/bin/systemd-inhibit")
CAT = Path("/usr/bin/cat")
DISCOVERY_PYTHON = Path("/opt/t2-touchid/.venv/bin/python")
DISCOVERY_TOOL = Path("/opt/t2-touchid/src/discover-biometric-port.py")
PROBE = Path("/opt/t2-touchid/src/bridge-xpc-probe.py")
FIRST_DYNAMIC_PORT = 49152
DISCOVERY_TIMEOUT_SECONDS = 45
MAX_RETAINED_RESULT_BYTES = 8 * 1024 * 1024


class NativeMatchError(RuntimeError):
    pass


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


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
        raise NativeMatchError("native match state is not private")
    return info


def _configuration() -> dict[str, object]:
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
        raise NativeMatchError("configuration has missing or duplicate values")
    if wanted["T2_TOUCHID_AUTHORITY_MODE"] != ["linux-native"]:
        raise NativeMatchError("authority mode is not exactly linux-native")
    user_name = wanted["T2_TOUCHID_USER"][0]
    try:
        linux_uid = pwd.getpwnam(user_name).pw_uid
    except KeyError as error:
        raise NativeMatchError("configured Linux user does not exist") from error
    apple_uid_text = wanted["T2_TOUCHID_MACOS_USER_ID"][0]
    sudo_uid = os.environ.get("SUDO_UID", "")
    if (
        linux_uid <= 0
        or not apple_uid_text.isdecimal()
        or not 10 <= int(apple_uid_text) < (1 << 32) - 1
        or not wanted["T2_TOUCHID_HOST"][0]
        or not wanted["T2_TOUCHID_INTERFACE"][0]
        or not sudo_uid.isdecimal()
        or int(sudo_uid) != linux_uid
    ):
        raise NativeMatchError("configured native match identity is invalid")
    return {
        "linux_uid": linux_uid,
        "apple_uid": int(apple_uid_text),
        "host": wanted["T2_TOUCHID_HOST"][0],
        "interface": wanted["T2_TOUCHID_INTERFACE"][0],
    }


def _require_runtime() -> None:
    try:
        RUN_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _private(RUN_ROOT, directory=True)
    for path in (CATACOMB_ROOT, BIOLOCKOUT_ROOT, ACTIVATION_ROOT):
        _private(path, directory=True)


def _discover_port(host: str, interface: str) -> int:
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
        raise NativeMatchError("BiometricKit endpoint discovery timed out") from error
    if completed.returncode != 0:
        raise NativeMatchError("BiometricKit endpoint discovery failed")
    try:
        value = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise NativeMatchError("BiometricKit discovery output is invalid") from error
    if not value.isdecimal() or not FIRST_DYNAMIC_PORT <= int(value) <= 65535:
        raise NativeMatchError("BiometricKit discovery output is invalid")
    return int(value)


def _inhibitor_registered(process: subprocess.Popen[bytes]) -> bool:
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
        and record.get("who") == "t2-touchid-native-match"
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
            "--who=t2-touchid-native-match",
            "--why=Linux-native Touch ID match is active",
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
            if _inhibitor_registered(process):
                break
            if process.poll() is not None:
                raise NativeMatchError("sleep inhibitor exited during setup")
            time.sleep(0.05)
        else:
            raise NativeMatchError("sleep inhibitor could not be verified")
        yield process
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=2)


def _grant(
    *,
    action: str,
    selected,
    mapping_generation: str,
    operation_id: str,
    linux_boot_uuid: str,
    runtime_generation: str,
    now: int,
) -> t2_user_policy.PolicyGrant:
    return t2_user_policy.PolicyGrant(
        authorization_id=str(uuid.uuid4()),
        action=action,
        caller_linux_uid=selected.linux_uid,
        linux_account_generation=selected.linux_account_generation,
        target_linux_uid=selected.linux_uid,
        mapping_generation=mapping_generation,
        operation_id=operation_id,
        linux_boot_uuid=linux_boot_uuid,
        runtime_generation=runtime_generation,
        issued_monotonic_ns=now,
        expires_monotonic_ns=now + 60 * 1_000_000_000,
        authorized=True,
    )


def _authorize(authority, transport, linux_boot_uuid: str):
    selected = authority.selected
    mapping_set = authority.mapping_set
    policy = t2_user_policy.OPERATION_POLICIES["verify"]
    operation_id = str(uuid.uuid4())
    now = time.monotonic_ns()
    request = t2_user_policy.OperationRequest(
        "verify",
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
    decision = t2_user_policy.authorize(
        mapping_set,
        request,
        caller,
        authority.persistent,
        transport.observe_alias(selected.special_bag_alias),
        _grant(
            action=policy.action,
            selected=selected,
            mapping_generation=mapping_set.generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=transport.runtime_generation,
            now=now,
        ),
        _grant(
            action=t2_user_policy.ACTIVATE_ACTION,
            selected=selected,
            mapping_generation=mapping_set.generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=transport.runtime_generation,
            now=now,
        ),
    )
    if decision.state not in {"authorized", "activation-authorized"}:
        raise NativeMatchError("native match activation was not authorized")
    return decision, operation_id


def _probe_command(
    configuration: dict[str, object],
    *,
    port: int,
    credential_fd: int,
    seconds: float,
    private_events: str | None,
    expect_no_match: bool = False,
    stop_on_first_verdict: bool = False,
    addition_journal: str | None = None,
    target_finger: str | None = None,
    resolve_any_finger: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(PROBE),
        "--host",
        str(configuration["host"]),
        "--interface",
        str(configuration["interface"]),
        "--port",
        str(port),
        "--timeout",
        "60",
        "--macos-user-id",
        str(configuration["apple_uid"]),
        "--native-authority-linux-uid",
        str(configuration["linux_uid"]),
        "--authorized-credential-set-fd",
        str(credential_fd),
        "--load-native-catacomb-root",
        str(CATACOMB_ROOT),
        "--biolockout-state-dir",
        str(BIOLOCKOUT_ROOT),
        "--initialize",
        "--biometric-protocol",
        "--sensor-readiness",
        "--reset-sensor",
        "--sensor-info",
        "--load-calibration",
        "--cancel-operation",
        "--bio-device-list",
        "--identity-list",
        "--service-template-sync",
        "--global-identity-list",
        "--display-on",
        "--system-awake",
        "--match-seconds",
        str(seconds),
        "--live-match-feedback",
        "--live-match-feedback-format",
        "json",
    ]
    if addition_journal is not None:
        command.extend(["--native-addition-journal", addition_journal])
    elif target_finger is not None:
        command.extend(["--match-finger-name", target_finger])
    elif resolve_any_finger:
        command.append("--resolve-any-finger-name")
    else:
        command.append("--match-all-enrolled-identities")
    if expect_no_match or stop_on_first_verdict:
        command.extend(["--stop-on-match-result", "--retry-image-quality-no-match"])
    else:
        command.append("--stop-on-match-success")
    if private_events is not None:
        command.extend(["--private-match-events-output", private_events])
    return command


def _validate_negative_result(stdout: bytes) -> None:
    try:
        public_result = json.loads(stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeMatchError("negative control result could not be validated") from error
    if not isinstance(public_result, dict):
        raise NativeMatchError("negative control result could not be validated")
    match_events = public_result.get("match_events")
    match_results = [
        event
        for event in match_events if isinstance(event, dict)
        and event.get("event_kind") == "match_result"
    ] if isinstance(match_events, list) else []
    # Quality rejections are explicitly retryable in this observation. Only
    # valid quality-only results may precede the single terminal negative.
    quality_prefix_valid = all(
        event.get("result_valid") is True
        and event.get("host_accepted_result") is True
        and event.get("no_match") is True
        and event.get("no_match_image_quality") is True
        and event.get("no_match_matcher") is False
        and event.get("matched") is False
        for event in match_results[:-1]
    )
    terminal = match_results[-1] if match_results else {}
    if (
        not quality_prefix_valid
        or terminal.get("result_valid") is not True
        or terminal.get("host_accepted_result") is not True
        or terminal.get("no_match") is not True
        or terminal.get("no_match_matcher") is not True
        or terminal.get("no_match_image_quality") is True
        or terminal.get("matched") is not False
    ):
        raise NativeMatchError(
            "negative control did not produce one exact matcher no-match"
        )


def _probe_failure_reason(stdout: bytes) -> str:
    """Project a bounded identifier-free reason from the public probe result."""
    try:
        result = json.loads(stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return "native match probe failed before a valid public result"
    if not isinstance(result, dict):
        return "native match probe failed before a valid public result"
    failure_reason = result.get("failure_reason")
    if (
        result.get("probe_failed") is True
        and result.get("identifiers_redacted") is True
        and isinstance(failure_reason, str)
        and 1 <= len(failure_reason) <= 300
    ):
        return f"native match probe failed: {failure_reason}"
    reply = result.get("match_start_reply")
    if result.get("match_rejected") is True and isinstance(reply, dict):
        status = reply.get("status")
        status_hex = reply.get("status_hex")
        if type(status) is int and isinstance(status_hex, str):
            return (
                "native match start was rejected "
                f"(status {status}, {status_hex})"
            )
        return "native match start was rejected with an invalid status"
    terminal = result.get("sensor_operation_terminal_status")
    reason = result.get("sensor_operation_end_reason")
    if type(terminal) is int and isinstance(reason, str):
        return (
            "native match sensor operation ended "
            f"(status {terminal}, reason {reason[:80]})"
        )
    return "native match probe failed after producing a public result"


def _required_identity_public_result(stdout: bytes) -> dict[str, object]:
    try:
        public_result = json.loads(stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeMatchError("new-finger result could not be validated") from error
    match_events = public_result.get("match_events") if isinstance(public_result, dict) else None
    results = [
        event for event in match_events
        if isinstance(event, dict) and event.get("event_kind") == "match_result"
    ] if isinstance(match_events, list) else []
    retry_prefix_valid = all(
        event.get("result_structure_valid") is True
        and event.get("result_valid") is True
        and event.get("host_accepted_result") is True
        and event.get("result_ignored") is False
        and event.get("no_match") is True
        and type(event.get("no_match_image_quality")) is bool
        and type(event.get("no_match_matcher")) is bool
        and (
            event.get("no_match_image_quality") is True
            or event.get("no_match_matcher") is True
        )
        and event.get("matches_enrolled_identity") is False
        and event.get("matched") is False
        for event in results[:-1]
    )
    terminal = results[-1] if results else {}
    if (
        not retry_prefix_valid
        or terminal.get("result_structure_valid") is not True
        or terminal.get("host_accepted_result") is not True
        or terminal.get("result_valid") is not True
        or terminal.get("result_ignored") is not False
        or terminal.get("no_match") is not False
        or terminal.get("matches_enrolled_identity") is not True
        or terminal.get("matched") is not True
        or terminal.get("matches_required_identity") is not True
    ):
        raise NativeMatchError("capture did not match the newly added identity")
    if not isinstance(public_result, dict):
        raise NativeMatchError("new-finger result could not be validated")
    return public_result


def _validate_required_identity_result(stdout: bytes) -> None:
    _required_identity_public_result(stdout)


def _append_addition_match_verification(
    addition_journal: Path,
    stdout: bytes,
    private_events: Path,
    linux_boot_uuid: str,
) -> t2_enrollment_journal.EnrollmentHistory:
    if addition_journal.parent != MUTATION_ROOT:
        raise NativeMatchError("addition journal path is not canonical")
    _private(addition_journal, directory=False)
    _private(private_events, directory=False)
    public_result = _required_identity_public_result(stdout)
    post_match = public_result.get("post_match_save_biolockout")
    reply = post_match.get("reply") if isinstance(post_match, dict) else None
    required_true = {
        "configured_identity_records_reconciled": public_result.get(
            "configured_identity_records_reconciled"
        ),
        "match_cleanup_valid": public_result.get("match_cleanup_valid"),
        "bridge_os_transaction_released_after_match": public_result.get(
            "bridge_os_transaction_released_after_match"
        ),
        "private_match_events_written": public_result.get(
            "private_match_events_written"
        ),
    }
    if any(value is not True for value in required_true.values()) or (
        public_result.get("termination_requested") is not False
        or not isinstance(post_match, dict)
        or post_match.get("linux_store_committed") is not True
        or not isinstance(reply, dict)
        or reply.get("valid") is not True
        or reply.get("status") != 0
    ):
        raise NativeMatchError("new-finger match cleanup evidence is incomplete")
    global_count = public_result.get("global_identity_record_count")
    template_count = public_result.get("template_sync_identity_count")
    generation = post_match.get("linux_store_generation")
    for value in (global_count, template_count, generation):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise NativeMatchError("new-finger match counters are invalid")
    history = t2_enrollment_journal.read(addition_journal)
    evidence = {
        "linux_boot_uuid": linux_boot_uuid,
        "public_result_sha256": hashlib.sha256(stdout).hexdigest(),
        "private_events_sha256": hashlib.sha256(private_events.read_bytes()).hexdigest(),
        "host_accepted_result": True,
        "matches_required_identity": True,
        "configured_identity_records_reconciled": True,
        "match_cleanup_valid": True,
        "bridge_os_transaction_released_after_match": True,
        "global_identity_record_count": global_count,
        "template_sync_identity_count": template_count,
        "biolockout_generation": generation,
    }
    try:
        return t2_enrollment_journal.append_checked(
            addition_journal,
            history.operation_id,
            "ADDITION_MATCH_VERIFIED",
            evidence,
        )
    except t2_enrollment_journal.EnrollmentJournalError as error:
        raise NativeMatchError(
            "new-finger match could not be bound to its enrollment journal"
        ) from error


def _private_events_for_saved_match(public_result: Path) -> Path:
    """Bind a retained result to its exact producer's private event file."""
    if public_result.parent != NATIVE_MATCH_ROOT:
        raise NativeMatchError("saved match result path is not canonical")
    match = re.fullmatch(r"tui-match-(\d{8}T\d{12}Z)\.json", public_result.name)
    if match is not None:
        return NATIVE_MATCH_ROOT / f"private-tui-match-events-{match.group(1)}.json"
    match = re.fullmatch(
        r"fprint-addition-match-([0-9a-f-]{36})\.json", public_result.name
    )
    if match is not None:
        try:
            token = uuid.UUID(match.group(1))
        except ValueError:
            token = None
        if token is not None and token.int != 0 and str(token) == match.group(1):
            return NATIVE_MATCH_ROOT / f"private-fprint-addition-match-events-{token}.json"
    raise NativeMatchError("saved match result path is not canonical")


def _decode_private_wire_value(value: object) -> object:
    """Restore the exact byte values emitted by probe private_json_value."""

    if isinstance(value, dict) and set(value) == {"bytes_hex", "length"}:
        encoded = value.get("bytes_hex")
        length = value.get("length")
        if (
            not isinstance(encoded, str)
            or type(length) is not int
            or length < 0
            or len(encoded) != length * 2
        ):
            raise NativeMatchError("saved private match bytes are malformed")
        try:
            decoded = bytes.fromhex(encoded)
        except ValueError as error:
            raise NativeMatchError("saved private match bytes are malformed") from error
        if len(decoded) != length:
            raise NativeMatchError("saved private match byte length changed")
        return decoded
    if isinstance(value, list):
        return [_decode_private_wire_value(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _decode_private_wire_value(item)
            for key, item in value.items()
        }
    return value


def _probe_summarizer():
    path = MODULE_ROOT / "bridge-xpc-probe.py"
    spec = importlib.util.spec_from_file_location("t2_saved_match_probe", path)
    if spec is None or spec.loader is None:
        raise NativeMatchError("saved match summarizer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summarizer = getattr(module, "summarize_event", None)
    if not callable(summarizer):
        raise NativeMatchError("saved match summarizer is unavailable")
    return summarizer


def _resummarize_saved_addition_result(
    public_result: object,
    private_document: object,
    *,
    apple_user_id: int,
    enrolled_identity_records: tuple[bytes, ...],
    required_identity_record: bytes,
    summarizer,
) -> bytes:
    """Derive the missing identity comparison from retained raw events."""

    if (
        not isinstance(public_result, dict)
        or not isinstance(private_document, dict)
        or set(private_document) != {"schema", "processed_flags", "events"}
        or private_document.get("schema") != 1
        or type(private_document.get("processed_flags")) is not int
        or not isinstance(private_document.get("events"), list)
        or type(apple_user_id) is not int
        or apple_user_id < 0
        or not enrolled_identity_records
        or any(type(record) is not bytes or len(record) != 20 for record in enrolled_identity_records)
        or type(required_identity_record) is not bytes
        or required_identity_record not in enrolled_identity_records
        or not callable(summarizer)
    ):
        raise NativeMatchError("saved addition-match evidence is malformed")
    original = public_result.get("match_events")
    if not isinstance(original, list):
        raise NativeMatchError("saved public match events are unavailable")
    events = _decode_private_wire_value(private_document["events"])
    if not isinstance(events, list) or len(events) != len(original):
        raise NativeMatchError("saved public and private event counts differ")
    recomputed = [
        summarizer(
            event,
            enrolled_identity_records,
            expected_user_id=apple_user_id,
            selected_identity_record=required_identity_record,
            required_identity_record=required_identity_record,
        )
        for event in events
    ]
    for retained, current in zip(original, recomputed, strict=True):
        if not isinstance(retained, dict):
            raise NativeMatchError("saved public match summary changed")
        expected = dict(current)
        if "matches_required_identity" not in retained:
            expected.pop("matches_required_identity", None)
        if expected != retained:
            raise NativeMatchError("saved public match summary changed")
    recovered = dict(public_result)
    recovered["match_events"] = recomputed
    encoded = json.dumps(recovered, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _required_identity_public_result(encoded)
    return encoded


def _write_recovered_result(path: Path, payload: bytes) -> None:
    if path.parent != NATIVE_MATCH_ROOT or not path.name.startswith("reconciled-"):
        raise NativeMatchError("recovered match result path is not canonical")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        _private(path, directory=False)
        if path.read_bytes() != payload:
            raise NativeMatchError("existing recovered match result differs")
        return
    complete = False
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise NativeMatchError("recovered match result write stopped")
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete and os.path.lexists(path):
            path.unlink()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _reconcile_addition_match_result(
    addition_journal: Path, public_result: Path
) -> dict[str, object]:
    private_events = _private_events_for_saved_match(public_result)
    public_info = _private(public_result, directory=False)
    _private(private_events, directory=False)
    journal_info = _private(addition_journal, directory=False)
    if public_info.st_mtime_ns < journal_info.st_mtime_ns:
        raise NativeMatchError("saved match result predates enrollment reconciliation")
    if (
        not 0 < public_info.st_size <= MAX_RETAINED_RESULT_BYTES
        or not 0 < private_events.stat().st_size <= MAX_RETAINED_RESULT_BYTES
    ):
        raise NativeMatchError("saved match evidence size is invalid")
    history = t2_enrollment_journal.read(addition_journal)
    baseline_records = history.baseline.get("identity_records")
    apple_user_id = history.baseline.get("apple_uid")
    if (
        history.phase is not t2_enrollment_journal.EnrollmentPhase.RECONCILED
        or history.terminal_identity_uuid is None
        or history.baseline.get("baseline_version") != 1
        or type(apple_user_id) is not int
        or not isinstance(baseline_records, list)
        or any(
            not isinstance(record, dict) or not isinstance(record.get("uuid"), str)
            for record in baseline_records
        )
    ):
        raise NativeMatchError("addition journal cannot bind saved match evidence")
    try:
        enrolled = tuple(
            struct.pack("<I16s", apple_user_id, uuid.UUID(record["uuid"]).bytes)
            for record in baseline_records
        ) + (
            struct.pack(
                "<I16s", apple_user_id, uuid.UUID(history.terminal_identity_uuid).bytes
            ),
        )
        retained_public = json.loads(public_result.read_bytes())
        retained_private = json.loads(private_events.read_bytes())
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise NativeMatchError("saved match evidence could not be decoded") from error
    stdout = _resummarize_saved_addition_result(
        retained_public,
        retained_private,
        apple_user_id=apple_user_id,
        enrolled_identity_records=enrolled,
        required_identity_record=enrolled[-1],
        summarizer=_probe_summarizer(),
    )
    recovered_result = NATIVE_MATCH_ROOT / f"reconciled-{public_result.name}"
    _write_recovered_result(recovered_result, stdout)
    linux_boot_uuid = str(uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip()))
    history = _append_addition_match_verification(
        addition_journal, stdout, private_events, linux_boot_uuid
    )
    return {
        "addition_match_reconciled": True,
        "phase": history.phase.value,
        "evidence_files_retained": True,
        "private_events_resummarized": True,
        "identifiers_redacted": True,
    }


def _run_probe(
    configuration: dict[str, object],
    *,
    port: int,
    credential_set: bytes,
    seconds: float,
    private_events: str | None,
    cancellation: Event,
    expect_no_match: bool = False,
    stop_on_first_verdict: bool = False,
    require_expected_result: bool = True,
    addition_journal: str | None = None,
    target_finger: str | None = None,
    resolve_any_finger: bool = False,
) -> int:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    process: subprocess.Popen[bytes] | None = None
    try:
        command = _probe_command(
            configuration,
            port=port,
            credential_fd=read_fd,
            seconds=seconds,
            private_events=private_events,
            expect_no_match=expect_no_match,
            stop_on_first_verdict=stop_on_first_verdict,
            addition_journal=addition_journal,
            target_finger=target_finger,
            resolve_any_finger=resolve_any_finger,
        )
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=None,
            pass_fds=(read_fd,),
        )
        os.close(read_fd)
        read_fd = -1
        offset = 0
        while offset < len(credential_set):
            offset += os.write(write_fd, credential_set[offset:])
        os.close(write_fd)
        write_fd = -1
        while True:
            if cancellation.is_set() and process.poll() is None:
                process.terminate()
            try:
                stdout, _stderr = process.communicate(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                continue
        if stdout:
            sys.stdout.buffer.write(stdout)
            sys.stdout.buffer.flush()
        if process.returncode != 0:
            raise NativeMatchError(_probe_failure_reason(stdout))
        if expect_no_match and require_expected_result:
            _validate_negative_result(stdout)
        if addition_journal is not None and require_expected_result:
            if private_events is None:
                raise NativeMatchError(
                    "new-finger match requires private event evidence"
                )
            _append_addition_match_verification(
                Path(addition_journal),
                stdout,
                Path(private_events),
                str(uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip())),
            )
        return process.returncode
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor >= 0:
                os.close(descriptor)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _run(args: argparse.Namespace, cancellation: Event) -> int:
    configuration = _configuration()
    authority = t2_user_authority.load(int(configuration["linux_uid"]))
    if (
        authority.origin != "linux-native-e4"
        or authority.selected.apple_uid != configuration["apple_uid"]
        or authority.selected.activation_secret_path is None
        or authority.selected.activation_secret_sha256 is None
    ):
        raise NativeMatchError("E4 schema-2 native authority is unavailable")
    _require_runtime()
    linux_boot_uuid = str(uuid.UUID(BOOT_ID.read_text(encoding="ascii").strip()))
    lock_descriptor = os.open(
        OPERATION_LOCK,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_info = os.fstat(lock_descriptor)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0 or lock_info.st_mode & 0o077:
            raise NativeMatchError("operation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with _sleep_inhibitor() as inhibitor:
            port = _discover_port(
                str(configuration["host"]), str(configuration["interface"])
            )
            with (
                t2_aks_transport.AKSActivationTransport() as transport,
                t2_acm_device.ACMDevice() as acm_device,
            ):
                decision, operation_id = _authorize(
                    authority, transport, linux_boot_uuid
                )
                selected = authority.selected
                journal_path = ACTIVATION_ROOT / f"{operation_id}.jsonl"
                with t2_activation_bundle.activation_secret(
                    Path(selected.activation_secret_path),
                    selected.activation_secret_sha256,
                ) as activation_material:
                    with t2_user_activation_operation.retain_ready_identity_handle(
                        journal_path,
                        authority.mapping_set,
                        selected,
                        "verify",
                        authority.persistent,
                        transport,
                        authorization=decision,
                        linux_boot_uuid=linux_boot_uuid,
                    ) as retained_state:
                        if retained_state in {"device-locked", "before-first-unlock"}:
                            t2_user_activation_operation.prepare_retained_identity(
                                journal_path, selected, transport
                            )
                        result = None
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
                                    raise NativeMatchError(
                                        "native match authorization omitted its output context"
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
                                        journal_path,
                                        selected,
                                        "verify",
                                        authority.persistent,
                                        transport,
                                        identity_reference,
                                    )
                                _wipe(activation_material)
                                if cancellation.is_set() or inhibitor.poll() is not None:
                                    raise NativeMatchError(
                                        "native match cancelled before sensor start"
                                    )
                                result = _run_probe(
                                    configuration,
                                    port=port,
                                    credential_set=output_context,
                                    seconds=(0.35 if args.preflight_no_finger else args.observation_seconds),
                                    private_events=args.private_match_events_output,
                                    cancellation=cancellation,
                                    expect_no_match=args.expect_no_match,
                                    stop_on_first_verdict=(
                                        args.stop_on_first_verdict
                                    ),
                                    require_expected_result=not args.preflight_no_finger,
                                    addition_journal=args.addition_journal,
                                    target_finger=args.match_finger_name,
                                    resolve_any_finger=args.resolve_any_finger_name,
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
                        if final_policy is None or not final_policy.satisfied or result is None:
                            raise NativeMatchError(
                                "native match authorization did not complete"
                            )
                        return result
    finally:
        os.close(lock_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation-seconds", type=float, default=0.0)
    parser.add_argument("--private-match-events-output")
    parser.add_argument("--preflight-no-finger", action="store_true")
    parser.add_argument("--expect-no-match", action="store_true")
    parser.add_argument("--stop-on-first-verdict", action="store_true")
    parser.add_argument("--addition-journal")
    parser.add_argument("--match-finger-name")
    parser.add_argument("--resolve-any-finger-name", action="store_true")
    parser.add_argument("--reconcile-addition-match-result")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("native match must run as root")
    if args.observation_seconds < 0:
        parser.error("--observation-seconds cannot be negative")
    if args.preflight_no_finger and args.observation_seconds != 0:
        parser.error("preflight owns its fixed no-finger ceiling")
    if args.expect_no_match and args.addition_journal is not None:
        parser.error("negative control and required-addition match are distinct modes")
    if args.stop_on_first_verdict and (
        args.expect_no_match
        or args.addition_journal is not None
        or args.preflight_no_finger
    ):
        parser.error(
            "standard first-verdict matching is a distinct observation mode"
        )
    if sum(bool(value) for value in (
        args.addition_journal,
        args.match_finger_name,
        args.resolve_any_finger_name,
    )) > 1:
        parser.error("native match identity selectors conflict")
    if args.reconcile_addition_match_result is not None:
        if (
            args.addition_journal is None
            or args.preflight_no_finger
            or args.expect_no_match
            or args.stop_on_first_verdict
            or args.match_finger_name is not None
            or args.resolve_any_finger_name
            or args.private_match_events_output is not None
            or args.observation_seconds != 0
        ):
            parser.error("saved addition-match reconciliation is a standalone mode")
        result = _reconcile_addition_match_result(
            Path(args.addition_journal),
            Path(args.reconcile_addition_match_result),
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.addition_journal is not None and args.private_match_events_output is None:
        parser.error("required-addition match needs private event evidence")
    cancellation = Event()
    child_signal = signal.getsignal(signal.SIGTERM)

    def request_cancel(_signum: int, _frame: object) -> None:
        cancellation.set()

    signal.signal(signal.SIGTERM, request_cancel)
    try:
        return _run(args, cancellation)
    finally:
        signal.signal(signal.SIGTERM, child_signal)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"t2-native-match: {error}", file=sys.stderr)
        raise SystemExit(1)
