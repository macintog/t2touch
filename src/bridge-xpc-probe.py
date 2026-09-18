#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only BridgeXPC transport probe for the Intel T2 biometric service.

The default action performs only the protocol HELO exchange.  It never sends
a BridgeXPC application message (frame type 2).
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import plistlib
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

LOCAL_SOURCE = os.path.dirname(os.path.abspath(__file__))
if LOCAL_SOURCE not in sys.path:
    sys.path.insert(0, LOCAL_SOURCE)

from t2_bridge_wire import (
    BIOMETRIC_COMMAND_HEADER,
    BIOMETRIC_COMMAND_MAGIC,
    HEADER,
    MAGIC,
    PROTOCOL_VERSION,
    TYPE_HELO,
    TYPE_MESSAGE,
    biometric_command,
    describe,
    is_biometric_nil_output,
    notify,
    receive_envelope,
    receive_exact,
    receive_frame,
    request,
    request_with_events,
    send_helo,
    send_message,
)
from t2_enrollment_protocol import (
    BRIDGE_SERVICE_STATUS,
    STATUS_PAYLOAD_HEADER,
    parse_service_event,
    validate_status_payload,
)
import t2_acm_device
import t2_aks_transport
import t2_biolockout_store
import t2_catacomb_codec
import t2_catacomb_protocol
import t2_catacomb_store
import t2_enrollment_journal
import t2_fprint_match_gate
import t2_fprint_projection
import t2_native_mutation_authority
import t2_performance
import t2_user_authority


CATACOMB_ROOT = Path("/var/lib/t2-touchid/catacomb")

MATCH_FLAG_FOR_UNLOCK = 0x0001
MATCH_FLAG_FOR_CREDENTIAL_SET = 0x0008
MATCH_FLAG_SELECTED_IDENTITIES = 0x4000


def public_failure_message(error: BaseException) -> str:
    """Return one bounded failure reason without paths or opaque identifiers."""
    if isinstance(error, OSError):
        return type(error).__name__
    message = " ".join(str(error).split())
    if not message or len(message) > 300 or "/" in message or "\\" in message:
        return type(error).__name__
    for token in message.replace("(", " ").replace(")", " ").split():
        try:
            uuid.UUID(token.strip("[]{}<>,.;:"))
        except (ValueError, AttributeError):
            continue
        return type(error).__name__
    return message


def native_match_gate_complete(args: argparse.Namespace) -> bool:
    """Accept every fail-closed native selector supported by the match gate."""
    selector = any(
        (
            args.match_all_enrolled_identities,
            args.native_addition_journal is not None,
            args.match_finger_name is not None,
            args.resolve_any_finger_name,
            args.resolve_any_identity_slot,
        )
    )
    return bool(
        args.match_seconds is not None
        and args.initialize
        and args.biometric_protocol
        and args.identity_list
        and args.service_template_sync
        and args.global_identity_list
        and selector
    )


def match_observation_should_stop(summary: dict, args: argparse.Namespace) -> bool:
    """Apply the same verdict policy to initial and subsequently read events."""
    return bool(
        (args.stop_on_match_result or args.stop_on_match_success)
        and summary.get("event_kind") == "match_result"
        and summary.get("result_valid") is True
        and (
            summary.get("matched") is True
            or (
                args.stop_on_match_result
                and summary.get("no_match") is True
                and not (
                    args.retry_image_quality_no_match
                    and summary.get("no_match_image_quality") is True
                )
            )
        )
    )


def observe_touch_to_verdict(
    summary: dict,
    timing: dict[str, float],
    *,
    observed_at: float | None = None,
) -> None:
    """Measure one capture from validated finger presence to its verdict."""
    if summary.get("status_semantics") == "finger-present":
        timing.setdefault(
            "finger_present",
            time.monotonic() if observed_at is None else observed_at,
        )
        return
    if summary.get("event_kind") != "match_result":
        return
    started = timing.pop("finger_present", None)
    if started is None:
        return
    t2_performance.emit(
        "bridge_match",
        "touch_to_verdict",
        started,
        "ok" if summary.get("result_valid") is True else "invalid",
    )


def selected_match_records(
    enrolled: tuple[bytes, ...],
    required_addition: bytes | None,
    targeted: bytes | None,
) -> tuple[bytes, ...]:
    """Select the exact authorized identity set for one match request."""
    if required_addition is not None:
        return (required_addition,)
    if targeted is not None:
        return (targeted,)
    return enrolled


def build_match_request(
    apple_user_id: int,
    base_flags: int,
    credential_set: bytes | bytearray | None,
    selected_records: tuple[bytes, ...] | None,
) -> tuple[bytes, int, int]:
    """Build Apple's fixed header and optional counted identity selection."""
    if not 0 <= apple_user_id <= 0xFFFFFFFF or not 0 <= base_flags <= 0xFFFFFFFF:
        raise ValueError("match request scalar is invalid")
    header = bytearray(68)
    flags = base_flags
    struct.pack_into("<II", header, 0, flags, apple_user_id)
    if credential_set is not None:
        credential = bytes(credential_set)
        if not 1 <= len(credential) <= 56:
            raise ValueError("credential set length is invalid")
        flags |= MATCH_FLAG_FOR_CREDENTIAL_SET
        struct.pack_into("<III", header, 0, flags, apple_user_id, len(credential))
        header[12 : 12 + len(credential)] = credential
    selected_count = 0
    payload = bytes(header)
    if selected_records is not None:
        if not selected_records or any(
            type(record) is not bytes or len(record) != 20
            for record in selected_records
        ):
            raise ValueError("selected identity records are invalid")
        selected_count = len(selected_records)
        flags |= MATCH_FLAG_SELECTED_IDENTITIES
        struct.pack_into("<I", header, 0, flags)
        payload = (
            bytes(header)
            + struct.pack("<I", selected_count)
            + b"".join(selected_records)
        )
    return payload, flags, selected_count


def release_bridge_os_transaction(
    sock: socket.socket,
    retained: bool,
    result: dict,
) -> bool:
    """Release a retained BridgeOS activity transaction exactly once."""
    if not retained:
        return False
    notify(sock, [12, False])
    result["bridge_os_transaction_released_after_match"] = True
    return False


MATCH_STATUS_FEEDBACK = {
    63: "finger-present",
    64: "finger-removed",
    66: "operation-ended",
    67: "operation-ended",
    68: "operation-ended",
    78: "capture-rejected",
    85: "capture-rejected",
    86: "capture-rejected-small-coverage",
    87: "capture-rejected",
    88: "capture-rejected",
    # Exact 24G830 BKMatchOperation does not map 91 to an operator callback;
    # it falls through to the superclass. Treat it only as internal progress,
    # never as an instruction to lift.
    91: "capture-progress",
    98: "capture-rejected",
}

# Exact 24G830 BKOperation translates these inherited terminal statuses into
# operationEndsWithReason:.  They end the sensor operation without producing a
# biometric match/no-match verdict.
MATCH_TERMINAL_STATUS_REASONS = {66: 2, 67: 3, 68: 4}


def drain_post_cancel_service_events(
    sock: socket.socket,
    events: list[object],
    *,
    idle_seconds: float = 0.5,
    maximum_events: int = 256,
) -> int:
    """Own and acknowledge callbacks that race a successful cancel reply."""
    if not 0 < idle_seconds <= 2 or not 1 <= maximum_events <= 1024:
        raise ValueError("post-cancel drain bounds are invalid")
    previous_timeout = sock.gettimeout()
    drained = 0
    try:
        sock.settimeout(idle_seconds)
        while True:
            try:
                envelope = receive_envelope(sock)
            except TimeoutError:
                return drained
            if (
                envelope[0] != 1
                or envelope[1] is not False
                or not isinstance(envelope[2], str)
                or not envelope[2]
            ):
                raise ValueError("unexpected post-cancel Bridge envelope")
            if drained >= maximum_events:
                raise ValueError("post-cancel callback drain exceeded its bound")
            events.append(envelope[3])
            send_message(sock, [1, True, envelope[2], [0]])
            drained += 1
    finally:
        sock.settimeout(previous_timeout)


def summarize_event(
    payload: object,
    enrolled_identity_records: tuple[bytes, ...] = (),
    *,
    expected_user_id: int | None = None,
    selected_identity_record: bytes | None = None,
    required_identity_record: bytes | None = None,
    all_match_gate: object | None = None,
    slot_match_gate: object | None = None,
) -> dict:
    if isinstance(payload, list) and len(payload) == 5 and payload[0] == 9:
        data = payload[2]
        summary = {
            "method": "serviceStatus",
            "bridge_status": payload[1],
            "data_length": len(data) if isinstance(data, bytes) else None,
        }
        if isinstance(data, bytes) and len(data) >= 24:
            try:
                parsed_common_event = parse_service_event(data)
            except (TypeError, ValueError):
                parsed_common_event = None
            summary["common_record_valid"] = parsed_common_event is not None
            reserved, embedded_type, version, event_timestamp = struct.unpack_from(
                "<QIIQ", data
            )
            summary.update(
                reserved_zero=reserved == 0,
                embedded_type=f"0x{embedded_type:08x}",
                version=version,
                event_timestamp_present=event_timestamp > 0,
            )
            event_data = data[24:]
            if embedded_type == 0xE3FF8001:
                summary["event_kind"] = "status"
                if len(event_data) >= 4:
                    summary["untrusted_status_code"] = struct.unpack_from(
                        "<I", event_data
                    )[0]
                status_payload_valid = False
                if (
                    parsed_common_event is not None
                    and payload[1] == BRIDGE_SERVICE_STATUS
                    and version in (1, 2)
                ):
                    try:
                        validate_status_payload(parsed_common_event)
                    except ValueError:
                        pass
                    else:
                        status_payload_valid = True
                summary["status_payload_valid"] = status_payload_valid
                if status_payload_valid:
                    status_code = parsed_common_event.ordinal
                    summary["status_code"] = status_code
                    summary["ordinal"] = status_code
                    if status_code in MATCH_STATUS_FEEDBACK:
                        summary["status_semantics"] = MATCH_STATUS_FEEDBACK[
                            status_code
                        ]
                    if status_code in MATCH_TERMINAL_STATUS_REASONS:
                        summary["operation_end_reason"] = (
                            MATCH_TERMINAL_STATUS_REASONS[status_code]
                        )
                    summary["parsed_ordinal_matches"] = True
                if len(event_data) >= 16:
                    summary["status_data_length"] = struct.unpack_from(
                        "<Q", event_data, 8
                    )[0]
            elif embedded_type == 0xE3FF8002:
                summary["event_kind"] = "match_result"
                # Match results carry the generic 16-byte status/length
                # prefix. Version 1 ends at the fixed 0xc84-byte body; version
                # 2 adds a bounded LOTL vector whose count is at body 0xc84.
                # The result identity is the first exact 20-byte record. Never
                # search the opaque body for an incidental UUID.
                structure_valid = False
                result_data = b""
                if (
                    parsed_common_event is not None
                    and payload[1] == BRIDGE_SERVICE_STATUS
                    and version in (1, 2)
                    and len(event_data) >= STATUS_PAYLOAD_HEADER.size
                ):
                    result_status, result_length = STATUS_PAYLOAD_HEADER.unpack_from(
                        event_data
                    )
                    if (
                        result_status == 0
                        and event_data[4:8] == b"\0" * 4
                        and result_length
                        == len(event_data) - STATUS_PAYLOAD_HEADER.size
                    ):
                        result_data = event_data[STATUS_PAYLOAD_HEADER.size :]
                if version == 1:
                    structure_valid = len(result_data) == 0xC84
                elif version == 2 and len(result_data) >= 0xC88:
                    lotl_count = struct.unpack_from("<I", result_data, 0xC84)[0]
                    structure_valid = len(result_data) == 0xC88 + 4 * lotl_count
                summary["result_structure_valid"] = structure_valid
                summary["host_accepted_result"] = False
                summary["result_valid"] = False
                if structure_valid:
                    signed_user_id = struct.unpack_from("<i", result_data)[0]
                    flags = struct.unpack_from("<I", result_data, 0x14)[0]
                    result_ignored = bool(flags & 0x200)
                    summary["result_ignored"] = result_ignored
                    if signed_user_id == -1:
                        no_match_nibble = flags & 0xF
                        summary["no_match"] = True
                        summary["no_match_reason"] = (
                            1
                            if no_match_nibble == 1
                            else 2 if no_match_nibble in (2, 3) else 0
                        )
                        summary["no_match_image_quality"] = no_match_nibble == 1
                        summary["no_match_matcher"] = (flags & 0x0D) == 0
                        summary["matched"] = False
                        summary["matches_enrolled_identity"] = False
                        summary["host_accepted_result"] = True
                        summary["result_valid"] = not result_ignored
                    else:
                        identity_record = result_data[:20]
                        expected_identity = (
                            expected_user_id is not None
                            and signed_user_id == expected_user_id
                            and identity_record in enrolled_identity_records
                        )
                        summary["no_match"] = False
                        summary["contains_enrolled_identity_uuid"] = expected_identity
                        summary["matches_enrolled_identity"] = expected_identity
                        summary["matched"] = expected_identity and not result_ignored
                        summary["host_accepted_result"] = expected_identity
                        summary["result_valid"] = expected_identity and not result_ignored
                        if (
                            type(selected_identity_record) is bytes
                            and len(selected_identity_record) == 20
                        ):
                            summary["matches_selected_identity"] = (
                                identity_record == selected_identity_record
                            )
                        if required_identity_record is not None:
                            summary["matches_required_identity"] = (
                                identity_record == required_identity_record
                            )
                        exact_event = identity_record[4:20] + b"\0" * (0xC70 - 16)
                        if all_match_gate is not None:
                            matched_name = (
                                t2_fprint_match_gate.resolve_all_match_event(
                                    all_match_gate, exact_event
                                )
                            )
                            summary["matched_finger_name_present"] = (
                                matched_name is not None
                            )
                            if matched_name is not None:
                                summary["matched_finger_name"] = matched_name
                        if slot_match_gate is not None:
                            matched_slot = (
                                t2_fprint_match_gate.resolve_slot_match_event(
                                    slot_match_gate, exact_event
                                )
                            )
                            summary["matched_identity_slot_present"] = (
                                matched_slot is not None
                            )
                            if matched_slot is not None:
                                summary["matched_identity_slot"] = matched_slot
            elif embedded_type == 0xE3FF8004:
                summary["event_kind"] = "statistics"
                # Exact 24G830 MesaCoreAnalytics consumes these as a packed
                # uint32 type plus one 64-bit fixed/floating value. BridgeXPC
                # prefixes the data with its common ordinal/padding/length
                # record, just as it does for a generic status. Preserve the
                # useful discriminator without publishing the raw event.
                statistics_data = b""
                if (
                    len(event_data) >= 28
                    and struct.unpack_from("<Q", event_data, 8)[0]
                    == len(event_data) - 16
                ):
                    statistics_data = event_data[16:]
                    summary["statistics_record_valid"] = True
                else:
                    summary["statistics_record_valid"] = False
                if len(statistics_data) >= 12:
                    summary["statistics_type"] = struct.unpack_from(
                        "<I", statistics_data
                    )[0]
                    summary["statistics_value_present"] = True
            elif embedded_type == 0xE3FF800A:
                # Keep live protocol diagnostics useful without emitting the
                # Apple user ID, SKS state, or opaque trailing bytes.
                summary["event_kind"] = "sks_lock_state"
                summary["event_data_length"] = len(event_data)
                if expected_user_id is not None and len(event_data) >= 4:
                    summary["user_id_matches_configured"] = (
                        struct.unpack_from("<I", event_data)[0] == expected_user_id
                    )
            else:
                summary["event_kind"] = "other"
        return summary
    return {"method": "unknown", "value_type": type(payload).__name__}


def summarize_command_reply(reply: object) -> dict:
    """Return JSON-safe details without assuming a successful command reply."""
    if not isinstance(reply, list) or not reply:
        return {"valid": False, "raw_type": type(reply).__name__}
    status = reply[0]
    summary = {"valid": isinstance(status, int), "status": status}
    if isinstance(status, int):
        summary["status_hex"] = f"0x{status & 0xffffffff:08x}"
    if len(reply) > 1:
        output = reply[1]
        summary["output_length"] = len(output) if isinstance(output, bytes) else None
        if is_biometric_nil_output(output):
            summary["output_kind"] = "nil-placeholder"
    return summary


def command_reply_failure(operation: str, stage: str, reply: object) -> str:
    """Describe a rejected command without disclosing its opaque payload."""
    summary = summarize_command_reply(reply)
    item_count = len(reply) if isinstance(reply, list) else None
    return (
        f"{operation} failed at {stage}: expected list reply with status=0; "
        f"actual_type={type(reply).__name__} item_count={item_count} "
        f"status={summary.get('status')} "
        f"status_hex={summary.get('status_hex')} "
        f"output_length={summary.get('output_length')}"
    )


def strict_identity_records(
    reply: object, events: object, record_size: int, label: str
) -> tuple[bytes, ...]:
    """Parse one event-free identity reply without exposing its records."""
    if (
        type(reply) is not list
        or len(reply) != 2
        or reply[0] != 0
        or type(reply[1]) is not bytes
        or type(events) is not list
        or events
        or type(record_size) is not int
        or record_size not in (20, 40)
        or len(reply[1]) % record_size
    ):
        raise ValueError(f"{label} identity inventory is invalid")
    return tuple(
        reply[1][offset : offset + record_size]
        for offset in range(0, len(reply[1]), record_size)
    )


def managed_user_identity_records(
    reply: object,
    events: object,
    apple_user_id: int,
    label: str,
) -> tuple[bytes, ...]:
    """Parse a managed user list, treating Mesa's nil output as empty."""
    if (
        type(reply) is list
        and len(reply) == 2
        and reply[0] == 0
        and is_biometric_nil_output(reply[1])
        and type(events) is list
        and not events
    ):
        return ()
    records = strict_identity_records(reply, events, 20, label)
    if (
        len(set(records)) != len(records)
        or any(
            struct.unpack_from("<I", record)[0] != apple_user_id
            for record in records
        )
    ):
        raise ValueError(f"{label} identity inventory is not user-scoped")
    return records


def compatibility_restore_required(
    live_records: tuple[bytes, ...], managed_records: tuple[bytes, ...]
) -> bool:
    """Require canonical restore only for an empty compatibility live set."""
    if (
        type(live_records) is not tuple
        or type(managed_records) is not tuple
        or any(
            type(record) is not bytes or len(record) != 20
            for record in live_records
        )
        or any(
            type(record) is not bytes or len(record) != 20
            for record in managed_records
        )
        or len(set(live_records)) != len(live_records)
        or len(set(managed_records)) != len(managed_records)
    ):
        raise ValueError("compatibility identity comparison is invalid")
    if live_records and set(live_records) != set(managed_records):
        raise ValueError("live compatibility identities differ from managed state")
    return not live_records and bool(managed_records)


def validate_compatibility_restore_state(
    restore_required: bool, component_states: tuple[int, ...]
) -> None:
    """Reject an attempted reload over a live SEP Catacomb component."""
    if type(restore_required) is not bool or type(component_states) is not tuple:
        raise ValueError("compatibility Catacomb state is invalid")
    if any(type(state) is not int or state < 0 for state in component_states):
        raise ValueError("compatibility Catacomb state is invalid")
    if restore_required and any(state & 2 for state in component_states):
        raise ValueError(
            "live compatibility identities are absent while a managed Catacomb "
            "component is loaded; cold bridgeOS restart required"
        )


def post_match_identity_records(
    reply: object, events: object, record_size: int, label: str
) -> tuple[bytes, ...]:
    """Validate a post-match inventory reply while retaining late callbacks.

    BridgeXPC may deliver a final acknowledged match callback after the cancel
    command has replied.  ``request_with_events`` correctly separates that
    callback from the next command reply.  It is part of the match stream, not
    evidence that the independently typed identity reply is malformed.
    Initial/repeated pre-match inventories remain strictly event-free.
    """

    if type(events) is not list:
        raise ValueError(f"{label} callback stream is invalid")
    return strict_identity_records(reply, [], record_size, label)


def write_private_json(path: str, value: object) -> None:
    """Exclusively write root-only private inventory; never overwrite state."""
    if os.geteuid() != 0:
        raise PermissionError("private inventory output requires root")
    destination = os.path.abspath(path)
    parent = os.path.dirname(destination)
    parent_info = os.stat(parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_mode & 0o077
    ):
        raise PermissionError("private inventory parent must be root-owned mode 0700")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        destination_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(destination_info.st_mode)
            or destination_info.st_uid != 0
            or destination_info.st_nlink != 1
        ):
            raise PermissionError("private inventory output is not a root-owned regular file")
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        payload += b"\n"
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)


def write_private_bytes(path: str, payload: bytes) -> None:
    """Exclusively write opaque sensor state to a root-only regular file."""
    if os.geteuid() != 0:
        raise PermissionError("private sensor-state output requires root")
    destination = os.path.abspath(path)
    parent = os.path.dirname(destination)
    parent_info = os.stat(parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_mode & 0o077
    ):
        raise PermissionError("private sensor-state parent must be root-owned mode 0700")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        destination_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(destination_info.st_mode)
            or destination_info.st_uid != 0
            or destination_info.st_nlink != 1
        ):
            raise PermissionError(
                "private sensor-state output is not a root-owned regular file"
            )
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)


def read_private_biolockout_record(path: str) -> bytes:
    """Read one root-only opaque HRLB record without publishing its contents."""
    if os.geteuid() != 0:
        raise PermissionError("private bio-lockout input requires root")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(os.path.abspath(path), flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 4 <= info.st_size <= 4096
        ):
            raise PermissionError("bio-lockout input is not a valid root-only file")
        payload = bytearray()
        while len(payload) < info.st_size:
            chunk = os.read(descriptor, info.st_size - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    record = bytes(payload)
    if len(record) != info.st_size or not record.startswith(b"HRLB"):
        raise ValueError("bio-lockout input is not an HRLB record")
    return record


def export_biolockout_record(sock: socket.socket, *, events=None) -> tuple[bytes, dict]:
    """Export current encrypted SEP lockout state without exposing its payload."""
    save_reply, save_events = biometric_command(sock, 0x4A, output_capacity=4096)
    if events is not None:
        events.extend(save_events)
    save_output = (
        save_reply[1]
        if isinstance(save_reply, list)
        and len(save_reply) > 1
        and isinstance(save_reply[1], bytes)
        else None
    )
    summary = {
        "reply": summarize_command_reply(save_reply),
        "events": [summarize_event(event) for event in save_events],
    }
    if (
        not isinstance(save_reply, list)
        or not save_reply
        or save_reply[0] != 0
        or save_output is None
        or not save_output.startswith(b"HRLB")
    ):
        raise ValueError("sensor did not return a valid bio-lockout record")
    summary.update(
        {
            "secure_data_length": len(save_output),
            "secure_data_sha256": hashlib.sha256(save_output).hexdigest(),
        }
    )
    return save_output, summary


def next_match_callback(sock, events, cursor):
    """Consume queued command callbacks before reading another envelope."""
    if cursor < len(events):
        return events[cursor], cursor + 1
    envelope = receive_envelope(sock)
    if envelope[1] is not False:
        return None, cursor
    events.append(envelope[3])
    send_message(sock, [1, True, envelope[2], [0]])
    return envelope[3], cursor + 1


def reconcile_match_lockout(events, summarize, committed_count, persist, drain,
                            *, maximum_late_results=256):
    """Persist every accepted callback, including those received in cleanup."""
    late_results = 0
    while True:
        summaries = [summarize(event) for event in events]
        accepted = [summary for summary in summaries
                    if summary.get("event_kind") == "match_result"
                    and summary.get("host_accepted_result") is True]
        committed = committed_count()
        if committed > len(accepted):
            raise RuntimeError("lockout publication exceeds accepted match results")
        if committed == len(accepted):
            return summaries
        missing = accepted[committed:]
        late_results += len(missing)
        if late_results > maximum_late_results:
            raise RuntimeError("late match results exceeded the reconciliation bound")
        prior_events = len(events)
        for summary in missing:
            persist(summary)
        if committed_count() != len(accepted):
            raise RuntimeError("accepted match lockout state was not durably published")
        if len(events) != prior_events:
            # An export can itself receive another service callback. Complete
            # another unchanged quiet-period check before publishing a verdict.
            drain()


def save_biolockout_record(sock: socket.socket, path: str) -> dict:
    """Export current lockout state to one explicitly named private file."""
    save_output, summary = export_biolockout_record(sock)
    write_private_bytes(path, save_output)
    summary["private_output_written"] = True
    return summary


def private_json_value(value: object) -> object:
    """Encode an exact private wire value without sending it to stdout."""
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex(), "length": len(value)}
    if isinstance(value, list):
        return [private_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [private_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): private_json_value(item) for key, item in value.items()
        }
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"unsupported private wire value: {type(value).__name__}")


def emit_live_match_feedback(event_summary: dict, output_format: str = "text") -> None:
    """Show privacy-safe acquisition feedback while an operator is present."""
    if output_format == "json":
        public_event = {
            "event_kind": event_summary.get("event_kind"),
        }
        for field in (
            "status_code",
            "status_semantics",
            "status_payload_valid",
            "operation_end_reason",
            "result_valid",
            "host_accepted_result",
            "matched",
            "matches_required_identity",
            "no_match",
            "no_match_reason",
            "no_match_image_quality",
            "no_match_matcher",
        ):
            if field in event_summary:
                public_event[field] = event_summary[field]
        print(
            "T2_MATCH_EVENT " + json.dumps(public_event, separators=(",", ":")),
            file=sys.stderr,
            flush=True,
        )
        return
    if event_summary.get("event_kind") == "match_result":
        print("MATCH RESULT RECEIVED", file=sys.stderr, flush=True)
        return
    if event_summary.get("event_kind") == "match_armed":
        print("MATCH ARMED — place finger", file=sys.stderr, flush=True)
        return
    semantics = event_summary.get("status_semantics")
    messages = {
        "finger-present": "FINGER DETECTED — keep steady",
        "finger-removed": "FINGER LIFTED — ready for another placement",
        "operation-ended": "SENSOR OPERATION ENDED WITHOUT A VERDICT",
        "lift-and-retry": "LIFT FINGER — then place it again",
        "capture-rejected": (
            "CAPTURE REJECTED — lift, then place the finger pad fully and steadily"
        ),
        "capture-rejected-small-coverage": (
            "CAPTURE TOO SMALL — lift, then cover more of the sensor"
        ),
        "capture-progress": "CAPTURE PROGRESS",
        "sensor-dirty": "SENSOR NEEDS CLEANING — lift finger before cleaning",
    }
    if semantics in messages:
        print(messages[semantics], file=sys.stderr, flush=True)


def reply_bytes(reply: object) -> bytes | None:
    if (
        isinstance(reply, list)
        and len(reply) > 1
        and reply[0] == 0
        and isinstance(reply[1], bytes)
    ):
        return reply[1]
    return None


def collect_full_inventory(sock: socket.socket, macos_user_id: int) -> dict:
    uid_data = struct.pack("<I", macos_user_id)
    commands = {
        "protocol": (1, b"", 4),
        "global_identities": (0x51, b"", 40 * 10),
        "maximum_capacity": (0x0F, b"", 4),
        "per_user_identities": (0x42, uid_data, 20 * 10),
        "free_capacity": (0x41, uid_data, 4),
        "catacomb_uuid": (0x38, uid_data, 16),
        "catacomb_hash": (0x3A, uid_data, 33),
        "catacomb_state": (0x3C, b"", 4096),
        "sks_lock_state": (0x27, uid_data, 4),
    }
    replies = {}
    events = {}
    for name, (command, data, capacity) in commands.items():
        replies[name], events[name] = biometric_command(
            sock, command, data=data, output_capacity=capacity
        )
        # A freshly opened BiometricKit session can acknowledge the first
        # protocol query without returning its four-byte payload.  The query
        # is read-only and idempotent, so retry only this missing reply.  All
        # other inventory fields remain single-read per snapshot.
        if name == "protocol":
            for _attempt in range(2):
                protocol_payload = reply_bytes(replies[name])
                if isinstance(protocol_payload, bytes) and len(protocol_payload) == 4:
                    break
                retry_reply, retry_events = biometric_command(
                    sock, command, data=data, output_capacity=capacity
                )
                replies[name] = retry_reply
                events[name].extend(retry_events)
    return {"replies": replies, "events": events}


def summarize_full_inventory(
    first: dict, second: dict, macos_user_id: int, connection_generation: str, helo: dict
) -> tuple[dict, dict]:
    a = first["replies"]
    b = second["replies"]
    equality = {name: a[name] == b[name] for name in a}
    protocol = reply_bytes(a["protocol"])
    global_output = reply_bytes(a["global_identities"])
    maximum_output = reply_bytes(a["maximum_capacity"])
    per_user_output = reply_bytes(a["per_user_identities"])
    free_output = reply_bytes(a["free_capacity"])
    uuid_output = reply_bytes(a["catacomb_uuid"])
    hash_output = reply_bytes(a["catacomb_hash"])
    state_output = reply_bytes(a["catacomb_state"])
    sks_output = reply_bytes(a["sks_lock_state"])

    per_user_valid = isinstance(per_user_output, bytes) and len(per_user_output) % 20 == 0
    global_valid = isinstance(global_output, bytes) and len(global_output) % 40 == 0
    per_user_records = (
        tuple(per_user_output[offset : offset + 20] for offset in range(0, len(per_user_output), 20))
        if per_user_valid
        else ()
    )
    global_records = (
        tuple(global_output[offset : offset + 40] for offset in range(0, len(global_output), 40))
        if global_valid
        else ()
    )
    configured_global = {
        record[:20]
        for record in global_records
        if struct.unpack_from("<I", record)[0] == macos_user_id
    }
    reconciled = per_user_valid and global_valid and configured_global == set(per_user_records)
    explicit_protocol_v2 = (
        isinstance(protocol, bytes)
        and len(protocol) == 4
        and struct.unpack("<I", protocol)[0] == 2
    )
    # Global identity command 0x51 exists only in protocol v2.  A successful,
    # structurally valid reply therefore attests v2 even on firmware sessions
    # that reject the standalone command-1 query with kIOReturnBadArgument.
    protocol_v2_attested = explicit_protocol_v2 or global_valid

    public = {
        "biometric_protocol_reply": summarize_command_reply(a["protocol"]),
        "identity_list_reply": summarize_command_reply(a["per_user_identities"]),
        "identity_record_bytes_valid": per_user_valid,
        "identity_record_count": len(per_user_records) if per_user_valid else None,
        "identity_user_field": (
            "prefix"
            if per_user_records
            and all(struct.unpack_from("<I", record)[0] == macos_user_id for record in per_user_records)
            else None
        ),
        "global_identity_list_reply": summarize_command_reply(a["global_identities"]),
        "global_identity_record_bytes_valid": global_valid,
        "global_identity_record_count": len(global_records) if global_valid else None,
        "configured_identity_records_reconciled": reconciled,
        "biometric_protocol_v2_attested": protocol_v2_attested,
        "biometric_protocol_attestation": (
            "command-1" if explicit_protocol_v2 else "v2-global-identity-command"
        ) if protocol_v2_attested else None,
        "identity_capacity_reply": summarize_command_reply(a["maximum_capacity"]),
        "identity_free_count_reply": summarize_command_reply(a["free_capacity"]),
        "catacomb_uuid_reply": summarize_command_reply(a["catacomb_uuid"]),
        "catacomb_hash_reply": summarize_command_reply(a["catacomb_hash"]),
        "catacomb_uuid_length_valid": isinstance(uuid_output, bytes) and len(uuid_output) == 16,
        "catacomb_hash_length_valid": isinstance(hash_output, bytes) and len(hash_output) == 33,
        "catacomb_state_reply": summarize_command_reply(a["catacomb_state"]),
        "sks_lock_state_reply": summarize_command_reply(a["sks_lock_state"]),
        "identity_inventory_repeat_equal": equality["per_user_identities"],
        "global_identity_inventory_repeat_equal": equality["global_identities"],
        "identity_capacity_repeat_equal": equality["maximum_capacity"] and equality["free_capacity"],
        "catacomb_component_repeat_equal": equality["catacomb_uuid"] and equality["catacomb_hash"],
        "catacomb_state_repeat_equal": equality["catacomb_state"],
        "sks_lock_state_repeat_equal": equality["sks_lock_state"],
        "full_snapshot_repeat_equal": all(equality.values()),
    }
    if isinstance(protocol, bytes) and len(protocol) == 4:
        public["biometric_protocol_version"] = struct.unpack("<I", protocol)[0]
    if isinstance(maximum_output, bytes) and len(maximum_output) == 4:
        public["identity_maximum_capacity"] = struct.unpack("<I", maximum_output)[0]
    if isinstance(free_output, bytes) and len(free_output) == 4:
        public["identity_free_count"] = struct.unpack("<I", free_output)[0]
    if isinstance(hash_output, bytes) and len(hash_output) == 33:
        public["catacomb_component_present"] = bool(hash_output[0])
    if isinstance(state_output, bytes) and len(state_output) in (8, 16):
        public["catacomb_state_words"] = list(
            struct.unpack("<" + "I" * (len(state_output) // 4), state_output)
        )
    if isinstance(sks_output, bytes) and len(sks_output) == 4:
        public["sks_lock_state"] = struct.unpack("<I", sks_output)[0]

    private_gate = {
        "snapshot_stable": all(equality.values()),
        "identity_lists_reconciled": reconciled,
        "protocol_v2_attested": protocol_v2_attested,
        "maximum_capacity_length": isinstance(maximum_output, bytes) and len(maximum_output) == 4,
        "free_capacity_length": isinstance(free_output, bytes) and len(free_output) == 4,
        "catacomb_uuid_length": isinstance(uuid_output, bytes) and len(uuid_output) == 16,
        "catacomb_hash_length": isinstance(hash_output, bytes) and len(hash_output) == 33,
        "catacomb_state_present": isinstance(state_output, bytes),
        "sks_lock_state_length": isinstance(sks_output, bytes) and len(sks_output) == 4,
    }
    failures = [name for name, passed in private_gate.items() if not passed]
    public["private_inventory_complete"] = not failures
    public["private_inventory_gate_failures"] = failures
    if failures:
        return public, {}
    bridge_boot_uuid = helo.get("BootSessionUUID")
    try:
        bridge_boot_uuid = str(uuid.UUID(bridge_boot_uuid))
    except (AttributeError, TypeError, ValueError):
        bridge_boot_uuid = None
    private = {
        "schema_version": 1,
        "connection_generation": connection_generation,
        "bridge_boot_uuid": bridge_boot_uuid,
        "biometric_protocol_version": 2,
        "apple_uid": macos_user_id,
        "per_user_identity_records": [
            {
                "user_id": struct.unpack_from("<I", record)[0],
                "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
            }
            for record in per_user_records
        ],
        "global_identity_records": [
            {
                "user_id": struct.unpack_from("<I", record)[0],
                "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                "group_type": struct.unpack_from("<I", record, 20)[0],
                "group_uuid": str(uuid.UUID(bytes=record[24:40])),
            }
            for record in global_records
        ],
        "maximum_capacity": struct.unpack("<I", maximum_output)[0],
        "configured_user_free_capacity": struct.unpack("<I", free_output)[0],
        "catacomb": {
            "uuid": str(uuid.UUID(bytes=uuid_output)),
            "present": bool(hash_output[0]),
            "hash": hash_output[1:].hex(),
            "global_state": state_output.hex(),
        },
        "sks_lock_state_raw": struct.unpack("<I", sks_output)[0],
        "double_collection_equal": True,
    }
    return public, private


def read_catacomb_payloads(
    archive_path: str, macos_user_id: int = 501
) -> list[tuple[str, int, bytes]]:
    """Validate a macOS v3 catacomb archive and return opaque load payloads."""
    user_name = f"user_{macos_user_id:08x}.cat"
    expected = {"master.cat": -1, user_name: macos_user_id}
    found = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name.rsplit("/", 1)[-1]
            if name not in expected:
                continue
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError(f"unsafe catacomb archive member: {member.name}")
            if name in found:
                raise ValueError(f"duplicate catacomb archive member: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"could not read catacomb archive member: {name}")
            found[name] = plistlib.loads(stream.read())

    if set(found) != set(expected):
        missing = sorted(set(expected) - set(found))
        raise ValueError(f"catacomb archive is missing: {', '.join(missing)}")

    payloads = []
    for name in ("master.cat", user_name):
        root = found[name]
        if not isinstance(root, dict):
            raise ValueError(f"{name} is not a keyed archive")
        top = root.get("$top")
        objects = root.get("$objects")
        if not isinstance(top, dict) or not isinstance(objects, list):
            raise ValueError(f"{name} has an invalid keyed-archive structure")
        if top.get("CatacombVersion") != 0x30000:
            raise ValueError(f"{name} is not a version-3 catacomb")
        if top.get("CatacombUserID") != expected[name]:
            raise ValueError(f"{name} has an unexpected user ID")
        data_uid = top.get("CatacombSecureData")
        if not isinstance(data_uid, plistlib.UID) or data_uid.data >= len(objects):
            raise ValueError(f"{name} has no secure-data object")
        data_object = objects[data_uid.data]
        data = data_object.get("NS.data") if isinstance(data_object, dict) else None
        if not isinstance(data, bytes) or len(data) < 16:
            raise ValueError(f"{name} has invalid secure data")
        if struct.unpack_from("<I", data)[0] != 0x4346544C:  # "LTFC"
            raise ValueError(f"{name} has an invalid secure-data header")
        payloads.append((name, expected[name], data))
    return payloads


def read_native_catacomb_payloads(
    root_path: str, apple_user_id: int
) -> tuple[list[tuple[str, int, bytes]], bytes]:
    """Load one validated Linux-native Catacomb generation.

    The returned master/user values are the opaque LTFC envelopes accepted by
    command 0x40.  BioLockout is returned separately for command 0x4b.  This
    adapts T1Bridge's durable restore ordering while retaining the T2 v2 store,
    component codecs, and E4 authority boundary.
    """
    root = Path(root_path)
    if not root.is_absolute():
        raise ValueError("native Catacomb root must be absolute")
    store = t2_catacomb_store.CatacombStore(root, apple_user_id)
    components = store.read_committed_components()
    user_name = f"user_{apple_user_id:08x}.cat"
    master = t2_catacomb_codec.decode_master_catacomb(
        components["master.cat"]
    )
    user = t2_catacomb_codec.decode_user_catacomb(
        components[user_name], apple_user_id
    )
    biolockout = t2_catacomb_codec.decode_biolockout_catacomb(
        components["biolockout.cat"]
    )
    return (
        [
            ("master.cat", -1, master.secure_data),
            (user_name, apple_user_id, user.secure_data),
        ],
        biolockout.secure_data,
    )


def read_native_identity_records(
    root_path: str, apple_user_id: int
) -> tuple[bytes, ...]:
    """Return the mutable fingerprint set from the committed native Catacomb.

    The E4 enrollment journal authorizes Linux-native activation, but its
    terminal fingerprint is not a permanent allowlist: later enrollments and
    selected deletions legitimately change the set.  The committed Catacomb
    is therefore the host-side fingerprint authority that must reconcile
    exactly with both live SEP inventories before matching.
    """

    root = Path(root_path)
    if not root.is_absolute():
        raise ValueError("native Catacomb root must be absolute")
    store = t2_catacomb_store.CatacombStore(root, apple_user_id)
    components = store.read_committed_components()
    user = t2_catacomb_codec.decode_user_catacomb(
        components[f"user_{apple_user_id:08x}.cat"], apple_user_id
    )
    return tuple(
        struct.pack("<I16s", identity.user_id, uuid.UUID(identity.uuid).bytes)
        for identity in user.identities
    )


def native_addition_identity_records(
    addition: t2_enrollment_journal.EnrollmentHistory,
    authority_history: t2_enrollment_journal.EnrollmentHistory,
    authority: t2_user_authority.RuntimeUserAuthority,
    apple_user_id: int,
    linux_uid: int,
) -> tuple[tuple[bytes, ...], bytes]:
    """Bind a pending addition to the complete mutable E4 identity set.

    The immutable E4 journal proves the Linux-native account authority; it is
    not a snapshot of every later fingerprint. A pending addition extends its
    current reconciled Catacomb baseline, which is separately bound to all
    prior completed mutation journals. The original fingerprint may have been
    deleted without weakening the same-boot set-equality gate.
    """

    baseline = addition.baseline
    baseline_identities = baseline.get("identity_records")
    try:
        current_authority = t2_native_mutation_authority.from_baseline(
            baseline,
            authority_history,
            authority,
            mutation_root=Path("/var/lib/t2-touchid/mutations"),
            excluded_operation_id=addition.operation_id,
        )
    except t2_native_mutation_authority.NativeMutationAuthorityError as error:
        raise ValueError(
            "native addition journal does not extend current authority"
        ) from error
    if (
        addition.phase is not t2_enrollment_journal.EnrollmentPhase.RECONCILED
        or addition.terminal_identity_uuid is None
        or baseline.get("baseline_version") != 1
        or baseline.get("caller_linux_uid") != linux_uid
        or baseline.get("target_linux_uid") != linux_uid
        or baseline.get("apple_uid") != apple_user_id
        or baseline.get("account_uuid") != authority.selected.account_uuid
        or baseline.get("bag_uuid") != authority.selected.bag_uuid
        or baseline.get("mapping_generation") != authority.mapping_set.generation
        or baseline.get("backup_references")
        != [
            {
                "reference": current_authority.reference,
                "sha256": current_authority.sha256,
            }
        ]
        or not isinstance(baseline_identities, list)
    ):
        raise ValueError("native addition journal does not extend current authority")
    baseline_uuids = tuple(record.get("uuid") for record in baseline_identities)
    if (
        any(not isinstance(value, str) for value in baseline_uuids)
        or addition.terminal_identity_uuid in baseline_uuids
    ):
        raise ValueError("native addition journal does not extend current authority")
    try:
        expected = tuple(
            struct.pack("<I16s", apple_user_id, uuid.UUID(value).bytes)
            for value in baseline_uuids
        )
        required = struct.pack(
            "<I16s", apple_user_id, uuid.UUID(addition.terminal_identity_uuid).bytes
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(
            "native addition journal does not extend current authority"
        ) from error
    return expected + (required,), required


def reconcile_native_biolockout(
    store: t2_biolockout_store.BioLockoutStore, native_payload: bytes
) -> tuple[t2_biolockout_store.BioLockoutGeneration, str]:
    """Seed E4 once without rolling a later match generation backward."""
    current = store.current()
    if current is None:
        return store.commit(native_payload), "seeded-from-e4"
    if current.payload == native_payload:
        return current, "already-e4"
    return current, "rolling-head-retained"


def load_linux_biolockout(
    sock: socket.socket,
    store: t2_biolockout_store.BioLockoutStore,
    current: t2_biolockout_store.BioLockoutGeneration,
    *,
    allow_sep_ahead_recovery: bool,
) -> tuple[t2_biolockout_store.BioLockoutGeneration, dict, dict | None]:
    """Load the durable head, recovering only from newer SEP-owned state."""

    def load(generation: t2_biolockout_store.BioLockoutGeneration) -> dict:
        reply, events = biometric_command(sock, 0x4B, data=generation.payload)
        return {
            "source": "linux-append-only-store",
            "generation": generation.sequence,
            "secure_data_length": generation.length,
            "secure_data_sha256": generation.sha256,
            "reply": summarize_command_reply(reply),
            "events": [summarize_event(event) for event in events],
        }

    summary = load(current)
    if summary["reply"].get("status") == 0:
        return current, summary, None
    if not allow_sep_ahead_recovery:
        raise ValueError("sensor rejected the current Linux bio-lockout generation")

    sep_payload, export_summary = export_biolockout_record(sock)
    if sep_payload == current.payload:
        raise ValueError(
            "sensor rejected a Linux bio-lockout generation identical to its export"
        )
    recovered = store.commit(sep_payload)
    recovered_summary = load(recovered)
    if recovered_summary["reply"].get("status") != 0:
        raise ValueError("sensor rejected its recovered bio-lockout generation")
    return (
        recovered,
        recovered_summary,
        {
            "reason": "SEP state advanced beyond durable host head",
            "previous_generation": current.sequence,
            "recovered_generation": recovered.sequence,
            "export": export_summary,
        },
    )


def read_credential_set_fd(descriptor: int) -> bytearray:
    """Read one exact external ACM form from an inherited private pipe."""
    if os.geteuid() != 0 or type(descriptor) is not int or descriptor < 3:
        raise ValueError("native credential-set descriptor is invalid")
    value = bytearray()
    try:
        while len(value) <= 16:
            block = os.read(descriptor, 17 - len(value))
            if not block:
                break
            value.extend(block)
    finally:
        os.close(descriptor)
    if len(value) != 16:
        value[:] = b"\0" * len(value)
        raise ValueError("native credential set is not exactly 16 bytes")
    return value


def read_service_catacomb_state(
    sock: socket.socket, protocol_version: int
) -> dict:
    """Read and strictly decode the Catacomb state used by service startup."""
    user_reply, user_events = biometric_command(sock, 0x3C, output_capacity=4096)
    user_output = reply_bytes(user_reply)
    try:
        user_states = t2_catacomb_protocol.parse_user_states(user_output)
    except t2_catacomb_protocol.CatacombProtocolError as error:
        summary = summarize_command_reply(user_reply)
        raise ValueError(
            "sensor returned invalid Catacomb user state: "
            f"status={summary.get('status')}, "
            f"output_length={summary.get('output_length')}, parser={error}"
        ) from error

    group_reply = None
    group_events = []
    group_states = ()
    if protocol_version >= 2:
        group_reply, group_events = biometric_command(
            sock,
            0x50,
            output_capacity=t2_catacomb_protocol.GROUP_STATE_RECORD.size * 10,
        )
        group_output = reply_bytes(group_reply)
        if (
            isinstance(group_reply, list)
            and len(group_reply) > 1
            and group_reply[0] == 0
            and is_biometric_nil_output(group_reply[1])
        ):
            group_output = b""
        try:
            group_states = t2_catacomb_protocol.parse_group_states(group_output)
        except t2_catacomb_protocol.CatacombProtocolError as error:
            summary = summarize_command_reply(group_reply)
            raise ValueError(
                "sensor returned invalid Catacomb group state: "
                f"status={summary.get('status')}, "
                f"output_length={summary.get('output_length')}, parser={error}"
            ) from error

    return {
        "user_reply": user_reply,
        "user_events": user_events,
        "user_states": user_states,
        "group_reply": group_reply,
        "group_events": group_events,
        "group_states": group_states,
    }


def read_biolockout_payload(archive_path: str) -> bytes:
    """Validate and return macOS's opaque encrypted bio-lockout record."""
    with tarfile.open(archive_path, "r:gz") as archive:
        members = [
            member
            for member in archive.getmembers()
            if member.name.rsplit("/", 1)[-1] == "biolockout.cat"
        ]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 65536:
            raise ValueError("archive must contain one regular biolockout.cat")
        stream = archive.extractfile(members[0])
        if stream is None:
            raise ValueError("could not read biolockout.cat")
        root = plistlib.loads(stream.read())
    top = root.get("$top") if isinstance(root, dict) else None
    objects = root.get("$objects") if isinstance(root, dict) else None
    if not isinstance(top, dict) or not isinstance(objects, list):
        raise ValueError("biolockout.cat has an invalid keyed archive")
    if top.get("BioLockoutRecordVersion") != 0x10000:
        raise ValueError("biolockout.cat has an unexpected version")
    data_uid = top.get("BioLockoutRecordSecureData")
    if not isinstance(data_uid, plistlib.UID) or data_uid.data >= len(objects):
        raise ValueError("biolockout.cat has no secure-data object")
    data_object = objects[data_uid.data]
    data = data_object.get("NS.data") if isinstance(data_object, dict) else None
    if not isinstance(data, bytes) or len(data) < 16 or data[:4] != b"HRLB":
        raise ValueError("biolockout.cat has invalid secure data")
    return data


def main() -> None:
    invocation_started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--macos-user-id",
        type=int,
        default=int(os.environ.get("T2_TOUCHID_MACOS_USER_ID", "501")),
        help="numeric macOS user identity to scope biometric operations",
    )
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument(
        "--port",
        type=int,
        default=(
            int(os.environ["T2_TOUCHID_PORT"])
            if "T2_TOUCHID_PORT" in os.environ
            else None
        ),
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument(
        "--service-open",
        action="store_true",
        help="send Apple's read-only getServiceOpened request after HELO",
    )
    parser.add_argument(
        "--bridge-version",
        action="store_true",
        help="send Apple's read-only getBridgeVersion request after HELO",
    )
    parser.add_argument(
        "--initialize",
        action="store_true",
        help="negotiate the BiometricKit bridge API version",
    )
    parser.add_argument(
        "--match-seconds",
        "--match-observation-seconds",
        dest="match_seconds",
        type=float,
        metavar="SECONDS",
        help=(
            "start a quality-gated match; positive SECONDS is a safety ceiling, "
            "while 0 observes until SIGTERM requests clean cancellation"
        ),
    )
    parser.add_argument(
        "--match-finger-name",
        type=lambda value: (
            value
            if t2_fprint_projection.is_finger_name(value)
            else parser.error("match finger must be a neutral numbered handle")
        ),
        help=(
            "restrict matching to one neutral fprint identity after fresh "
            "local/per-user/global reconciliation"
        ),
    )
    parser.add_argument(
        "--resolve-any-finger-name",
        action="store_true",
        help=(
            "require a complete reconciled name map and report only the "
            "neutral finger handle selected by an all-identities match"
        ),
    )
    parser.add_argument(
        "--resolve-any-identity-slot",
        action="store_true",
        help=(
            "allow noncanonical labels and report only the ephemeral current "
            "identity slot selected by an all-identities match"
        ),
    )
    parser.add_argument(
        "--match-processed-flags",
        type=lambda value: int(value, 0),
        default=MATCH_FLAG_FOR_UNLOCK,
        help="additional processed match flags (default: 1 for unlock)",
    )
    parser.add_argument(
        "--authorized-credential-set-match",
        action="store_true",
        help=(
            "bind the configured macOS password to a live ACM context and "
            "serialize its redacted external form as Apple's credential set"
        ),
    )
    parser.add_argument(
        "--authorized-credential-set-password",
        default=os.environ.get("T2_TOUCHID_MACOS_PASSWORD"),
        help="macOS test-system password used for the live ACM binding",
    )
    parser.add_argument(
        "--authorized-credential-set-fd",
        type=int,
        help=(
            "inherited private descriptor containing one exact 16-byte "
            "authorized ACM external form"
        ),
    )
    parser.add_argument(
        "--native-authority-linux-uid",
        type=int,
        help=(
            "require E4 Linux-native authority and its exact enrolled identity "
            "before match start"
        ),
    )
    parser.add_argument(
        "--compatibility-authority-linux-uid",
        type=int,
        help=(
            "require the validated Apple-control authority while restoring "
            "the canonical managed Catacomb generation"
        ),
    )
    parser.add_argument(
        "--native-addition-journal",
        help="root-private reconciled same-boot addition journal",
    )
    parser.add_argument(
        "--match-all-enrolled-identities",
        action="store_true",
        help=(
            "send the native 68-byte match request without a sensor-side "
            "identity filter; returned identities remain host-validated"
        ),
    )
    parser.add_argument(
        "--stop-on-match-result",
        action="store_true",
        help="apply one-shot policy and stop after either valid match verdict",
    )
    parser.add_argument(
        "--stop-on-match-success",
        action="store_true",
        help="mirror Apple stopOnSuccess while leaving no-match retryable",
    )
    parser.add_argument(
        "--retry-image-quality-no-match",
        action="store_true",
        help=(
            "with --stop-on-match-result, keep observing after a valid "
            "image-quality no-match"
        ),
    )
    parser.add_argument(
        "--live-match-feedback",
        action="store_true",
        help="print privacy-safe capture acceptance feedback to stderr",
    )
    parser.add_argument(
        "--live-match-feedback-format",
        choices=("text", "json"),
        default="text",
        help="format for privacy-safe live feedback (default: text)",
    )
    parser.add_argument(
        "--private-match-events-output",
        metavar="PATH",
        help="write exact match events to a new root-only file (never stdout)",
    )
    parser.add_argument(
        "--audible-match-alert",
        action="store_true",
        help="play the desktop alert immediately before starting a match",
    )
    parser.add_argument(
        "--biometric-protocol",
        action="store_true",
        help="read the sensor command protocol version (biometric command 1)",
    )
    parser.add_argument(
        "--reset-sensor",
        action="store_true",
        help="run Apple's readiness-gated sensor init with up to three reset attempts",
    )
    parser.add_argument(
        "--cancel-operation",
        action="store_true",
        help="cancel any outstanding sensor operation (biometric command 12)",
    )
    parser.add_argument(
        "--sensor-readiness",
        action="store_true",
        help="read the one-byte sensor-ready state (biometric command 0x53)",
    )
    parser.add_argument(
        "--bio-device-list",
        action="store_true",
        help="cache Apple's protocol-v2 biometric device list (command 0x52)",
    )
    parser.add_argument(
        "--sensor-info",
        action="store_true",
        help="read the 12-byte sensor information record (command 0x35)",
    )
    parser.add_argument(
        "--biometrickitd-info",
        action="store_true",
        help=(
            "read command 0x28's exact 23-byte info record and expose only "
            "Apple's template-presence and calibration-gating booleans"
        ),
    )
    parser.add_argument(
        "--calibration-info",
        action="store_true",
        help="read calibration blob metadata from bridgeOS without saving it",
    )
    parser.add_argument(
        "--load-calibration",
        action="store_true",
        help=(
            "mirror Apple's calibration gate and load bridgeOS calibration only "
            "when command 0x28 says it is required"
        ),
    )
    parser.add_argument(
        "--identity-list",
        action="store_true",
        help="query the SEP identity-record count for the configured macOS user",
    )
    parser.add_argument(
        "--service-template-sync",
        action="store_true",
        help="mirror normal service setup's all-user and Catacomb state sync queries",
    )
    parser.add_argument(
        "--global-identity-list",
        action="store_true",
        help="query protocol-v2 global SEP identity records (command 0x51)",
    )
    parser.add_argument(
        "--identity-capacity",
        action="store_true",
        help="query maximum and configured-user free identity capacity",
    )
    parser.add_argument(
        "--catacomb-component-state",
        action="store_true",
        help="query configured-user SEP Catacomb UUID/presence/hash metadata",
    )
    parser.add_argument(
        "--stability-check",
        action="store_true",
        help="repeat requested inventory queries and report exact private equality",
    )
    parser.add_argument(
        "--full-inventory",
        action="store_true",
        help="collect complete inventory snapshots A and B on one connection",
    )
    parser.add_argument(
        "--private-inventory-output",
        metavar="PATH",
        help="write raw root-only inventory to a new file (never stdout)",
    )
    parser.add_argument(
        "--catacomb-state",
        action="store_true",
        help="query SEP catacomb state metadata without returning its contents",
    )
    parser.add_argument(
        "--sks-lock-state",
        action="store_true",
        help="query the secure-key-store lock state for the configured macOS user",
    )
    parser.add_argument(
        "--load-catacomb-archive",
        metavar="PATH",
        help="validate and load encrypted macOS v3 catacomb components (command 0x40)",
    )
    parser.add_argument(
        "--load-native-catacomb-root",
        metavar="DIRECTORY",
        help=(
            "validate and load the committed Linux-native Catacomb generation "
            "for command 0x40"
        ),
    )
    parser.add_argument(
        "--load-biolockout-archive",
        metavar="PATH",
        help="restore the encrypted macOS bio-lockout record (command 0x4b)",
    )
    parser.add_argument(
        "--load-biolockout-record",
        metavar="PATH",
        help="load a root-only encrypted HRLB record previously saved by command 0x4a",
    )
    parser.add_argument(
        "--save-biolockout-output",
        metavar="PATH",
        help="save the current encrypted SEP bio-lockout record to a new root-only file",
    )
    parser.add_argument(
        "--save-biolockout-after-match-output",
        metavar="PATH",
        help="save updated encrypted SEP bio-lockout state after a valid match result",
    )
    parser.add_argument(
        "--biolockout-state-dir",
        metavar="DIRECTORY",
        help=(
            "load and append immutable Linux-owned bio-lockout generations in "
            "a root-only state directory"
        ),
    )
    parser.add_argument(
        "--display-on",
        action="store_true",
        help="mirror serviceMatchCommon's display-on notification (command 0x14)",
    )
    parser.add_argument(
        "--system-awake",
        action="store_true",
        help="mirror serviceMatchCommon's system-awake notification (command 0x57)",
    )
    parser.add_argument(
        "--catacomb-component",
        choices=("all", "master", "user"),
        default="all",
        help="select which validated catacomb component to load (default: all)",
    )
    parser.add_argument(
        "--strip-catacomb-file-header",
        action="store_true",
        help="strip the validated 32-byte LTFC file wrapper before command 0x40",
    )
    args = parser.parse_args()
    if args.match_finger_name is not None and args.match_seconds is None:
        parser.error("--match-finger-name requires --match-seconds")
    if args.resolve_any_finger_name and args.match_seconds is None:
        parser.error("--resolve-any-finger-name requires --match-seconds")
    if args.resolve_any_identity_slot and args.match_seconds is None:
        parser.error("--resolve-any-identity-slot requires --match-seconds")
    if sum(
        (
            args.match_finger_name is not None,
            args.resolve_any_finger_name,
            args.resolve_any_identity_slot,
        )
    ) > 1:
        parser.error(
            "named, resolved-name, and resolved-slot matching conflict"
        )
    if not 0 <= args.macos_user_id <= 0xFFFFFFFF:
        parser.error("--macos-user-id must fit an unsigned 32-bit integer")
    if not args.host or not args.interface:
        parser.error(
            "set --host/--interface or T2_TOUCHID_HOST/T2_TOUCHID_INTERFACE"
        )
    if args.port is None:
        parser.error("set --port or T2_TOUCHID_PORT")
    if args.biolockout_state_dir and (
        args.load_biolockout_archive or args.load_biolockout_record
    ):
        parser.error(
            "--biolockout-state-dir cannot be combined with an explicit load source"
        )
    if args.retry_image_quality_no_match and not args.stop_on_match_result:
        parser.error(
            "--retry-image-quality-no-match requires --stop-on-match-result"
        )
    if args.authorized_credential_set_match and args.match_seconds is None:
        parser.error("--authorized-credential-set-match requires --match-seconds")
    if args.authorized_credential_set_match and not (
        isinstance(args.authorized_credential_set_password, str)
        and 1 <= len(args.authorized_credential_set_password.encode()) <= 128
    ):
        parser.error(
            "--authorized-credential-set-match requires a 1..128 byte password"
        )
    if args.authorized_credential_set_match and args.authorized_credential_set_fd is not None:
        parser.error("choose one credential-set authorization source")
    if args.authorized_credential_set_fd is not None and args.match_seconds is None:
        parser.error("--authorized-credential-set-fd requires --match-seconds")
    if (
        args.native_authority_linux_uid is not None
        and args.compatibility_authority_linux_uid is not None
    ):
        parser.error("choose one managed Catacomb authority")
    managed_authority_uid = (
        args.native_authority_linux_uid
        if args.native_authority_linux_uid is not None
        else args.compatibility_authority_linux_uid
    )
    if bool(managed_authority_uid is not None) != bool(
        args.load_native_catacomb_root
    ):
        parser.error(
            "managed authority and managed Catacomb root must be supplied together"
        )
    if args.native_addition_journal is not None and args.native_authority_linux_uid is None:
        parser.error("native addition matching requires native authority")
    if args.native_authority_linux_uid is not None and args.authorized_credential_set_fd is None:
        parser.error("native authority matching requires a credential-set descriptor")
    if (
        args.native_authority_linux_uid is not None
        and not native_match_gate_complete(args)
    ):
        parser.error("native authority matching requires the complete match gate")
    if args.compatibility_authority_linux_uid is not None and not (
        args.service_template_sync and args.initialize
    ):
        parser.error(
            "compatibility authority requires initialized template synchronization"
        )
    if args.load_catacomb_archive and args.load_native_catacomb_root:
        parser.error("choose one Catacomb source")

    native_expected_identities: tuple[bytes, ...] = ()
    native_required_match_identity = None
    native_biolockout = None
    managed_expected_identities: tuple[bytes, ...] = ()
    compatibility_loaded_empty_restore = False
    if args.native_authority_linux_uid is not None:
        authority_validation_started = time.monotonic()
        if os.geteuid() != 0 or args.native_authority_linux_uid <= 0:
            parser.error("native authority matching requires a non-root target and root owner")
        if (
            os.path.realpath(args.load_native_catacomb_root)
            != "/var/lib/t2-touchid/catacomb"
        ):
            parser.error("native authority matching requires the canonical Catacomb root")
        authority = t2_user_authority.load(args.native_authority_linux_uid)
        if authority.origin != "linux-native-e4" or authority.selected.apple_uid != args.macos_user_id:
            parser.error("native match authority does not match the configured user")
        history = t2_enrollment_journal.read(authority.enrollment_journal)
        if history.terminal_identity_uuid is None:
            parser.error("native authority has no terminal enrolled identity")
        if args.native_addition_journal is not None:
            addition_path = Path(args.native_addition_journal)
            mutation_root = Path("/var/lib/t2-touchid/mutations")
            if (
                not addition_path.is_absolute()
                or addition_path.parent != mutation_root
                or addition_path.suffix != ".jsonl"
            ):
                parser.error("native addition journal is outside the canonical root")
            addition_info = addition_path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(addition_info.st_mode)
                or addition_info.st_uid != 0
                or addition_info.st_gid != 0
                or addition_info.st_nlink != 1
                or addition_info.st_mode & 0o077
            ):
                parser.error("native addition journal is not private")
            addition = t2_enrollment_journal.read(addition_path)
            try:
                native_expected_identities, native_required_match_identity = (
                    native_addition_identity_records(
                        addition,
                        history,
                        authority,
                        args.macos_user_id,
                        args.native_authority_linux_uid,
                    )
                )
            except ValueError:
                parser.error("native addition journal does not extend current authority")
        else:
            native_expected_identities = (
                struct.pack(
                    "<I16s",
                    args.macos_user_id,
                    uuid.UUID(history.terminal_identity_uuid).bytes,
                ),
            )
        managed_expected_identities = read_native_identity_records(
            args.load_native_catacomb_root, args.macos_user_id
        )
        if args.native_addition_journal is not None and (
            len(managed_expected_identities) != len(native_expected_identities)
            or set(managed_expected_identities) != set(native_expected_identities)
        ):
            parser.error(
                "native managed Catacomb differs from the pending addition"
            )
        _native_payloads, native_biolockout = read_native_catacomb_payloads(
            args.load_native_catacomb_root, args.macos_user_id
        )
        if args.match_seconds is not None:
            t2_performance.emit(
                "bridge_match",
                "authority_validation",
                authority_validation_started,
            )
    elif args.compatibility_authority_linux_uid is not None:
        if os.geteuid() != 0 or args.compatibility_authority_linux_uid <= 0:
            parser.error(
                "compatibility authority requires a non-root target and root owner"
            )
        if os.path.realpath(args.load_native_catacomb_root) != "/var/lib/t2-touchid/catacomb":
            parser.error(
                "compatibility authority requires the canonical Catacomb root"
            )
        authority = t2_user_authority.load_compatibility(
            args.compatibility_authority_linux_uid
        )
        if authority.selected.apple_uid != args.macos_user_id:
            parser.error(
                "compatibility authority does not match the configured user"
            )
        managed_store = t2_catacomb_store.CatacombStore(
            Path(args.load_native_catacomb_root), args.macos_user_id
        )
        managed_components = managed_store.read_committed_components()
        managed_user = t2_catacomb_codec.decode_user_catacomb(
            managed_components[f"user_{args.macos_user_id:08x}.cat"],
            args.macos_user_id,
        )
        managed_expected_identities = tuple(
            struct.pack("<I16s", identity.user_id, uuid.UUID(identity.uuid).bytes)
            for identity in managed_user.identities
        )
        _managed_payloads, native_biolockout = read_native_catacomb_payloads(
            args.load_native_catacomb_root, args.macos_user_id
        )
        compatibility_loaded_empty_restore = True

    termination_requested = False
    if args.match_seconds is not None:
        def request_termination(_signum: int, _frame: object) -> None:
            nonlocal termination_requested
            termination_requested = True

        signal.signal(signal.SIGTERM, request_termination)

    scope_id = socket.if_nametoindex(args.interface)
    with ExitStack() as resources, socket.socket(
        socket.AF_INET6, socket.SOCK_STREAM
    ) as sock:
        authorized_credential_set = None
        authorized_policy = None
        if args.authorized_credential_set_fd is not None:
            authorized_credential_set = read_credential_set_fd(
                args.authorized_credential_set_fd
            )

            def wipe_inherited_credential_set() -> None:
                authorized_credential_set[:] = b"\0" * len(authorized_credential_set)

            resources.callback(wipe_inherited_credential_set)
            authorized_policy = {
                "policy": 1007,
                "source": "linux-native-e4",
                "final_satisfied": True,
                "credential_set_length": len(authorized_credential_set),
                "context_identifier_redacted": True,
            }
        elif args.authorized_credential_set_match:
            acm_device = resources.enter_context(t2_acm_device.ACMDevice())
            aks_transport = resources.enter_context(
                t2_aks_transport.AKSActivationTransport()
            )
            password = bytearray(args.authorized_credential_set_password.encode())

            def wipe_match_password() -> None:
                password[:] = b"\0" * len(password)

            resources.callback(wipe_match_password)

            def bind_match_password(external_form: bytes) -> None:
                try:
                    aks_transport.bind_password_to_acm_context(
                        -args.macos_user_id, password, external_form
                    )
                finally:
                    wipe_match_password()

            initial_policy, final_policy, authorized_credential_set = (
                resources.enter_context(
                    t2_acm_device.authorized_context(
                        acm_device,
                        args.macos_user_id,
                        bind_match_password,
                    )
                )
            )
            authorized_policy = {
                "policy": 1007,
                "initial_requirement_type": initial_policy.requirement_type,
                "password_bound": True,
                "final_satisfied": final_policy.satisfied,
                "credential_set_length": len(authorized_credential_set),
                "context_identifier_redacted": True,
            }
        bridge_preparation_started = time.monotonic()
        if args.match_seconds is not None:
            t2_performance.emit(
                "bridge_match", "invocation_setup", invocation_started
            )
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port, 0, scope_id))
        frame_type, body = receive_frame(sock)
        if frame_type != TYPE_HELO:
            raise ValueError(f"expected HELO frame, received type {frame_type}")
        helo = describe(frame_type, body)
        send_helo(sock, int(helo.get("BridgeXPCVersion", 39)))
        result = {"peer_helo": helo, "sent": "HELO only"}
        operations = []
        connection_generation = str(uuid.uuid4())
        enrolled_identity_records: tuple[bytes, ...] = ()
        global_identity_records: tuple[bytes, ...] = ()
        maximum_output = None
        free_output = None
        uuid_output = None
        hash_output = None
        catacomb_state_output = None
        private_inventory = None
        private_match_events = None
        deferred_failure = None
        client_version = None
        client_version_negotiated = False
        os_transaction_retained = False
        biometrickitd_info_output = None
        biometrickitd_info_valid = False
        apple_template_list_already_in_sep = None
        apple_calibration_load_bypassed = None
        sensor_ready = None
        biolockout_store = (
            t2_biolockout_store.BioLockoutStore(args.biolockout_state_dir)
            if args.biolockout_state_dir
            else None
        )
        if biolockout_store is not None and native_biolockout is not None:
            current_biolockout, reconciliation = reconcile_native_biolockout(
                biolockout_store, native_biolockout
            )
            result["linux_biolockout_reconciliation"] = reconciliation
            result["linux_biolockout_generation"] = current_biolockout.sequence
        if args.initialize:
            version_reply = request(sock, [0])
            if (
                not isinstance(version_reply, list)
                or len(version_reply) != 2
                or version_reply[0] != 0
            ):
                raise ValueError(f"getBridgeVersion failed: {version_reply!r}")
            api_version = version_reply[1]
            result["bridge_version_reply"] = version_reply
            # Exact 24G830 completes serviceMatchCommon before negotiating
            # client API v2. Sending this request before biometric command 1
            # makes the sensor reject the protocol query with 0xe00002c2.
            client_version = min(api_version, 2)
            result["bridge_client_version"] = client_version
            operations.append("read bridge version")
        if args.full_inventory:
            if not args.initialize:
                raise ValueError("--full-inventory requires --initialize")
            first_inventory = collect_full_inventory(sock, args.macos_user_id)
            second_inventory = collect_full_inventory(sock, args.macos_user_id)
            public_inventory, private_inventory = summarize_full_inventory(
                first_inventory,
                second_inventory,
                args.macos_user_id,
                connection_generation,
                helo,
            )
            result.update(public_inventory)
            operations.append("full inventory snapshots A/B")
        if args.bridge_version:
            result["bridge_version_reply"] = request(sock, [0])
            operations.append("getBridgeVersion")
        if args.service_open:
            result["service_reply"] = request(sock, [1])
            operations.append("getServiceOpened")
        if args.biometric_protocol:
            protocol_reply, protocol_events = biometric_command(
                sock, 1, output_capacity=4
            )
            protocol_output = reply_bytes(protocol_reply)
            result["biometric_protocol_reply"] = summarize_command_reply(
                protocol_reply
            )
            if isinstance(protocol_output, bytes) and len(protocol_output) == 4:
                result["biometric_protocol_version"] = struct.unpack(
                    "<I", protocol_output
                )[0]
                result["biometric_protocol_query_accepted"] = True
            elif (
                isinstance(protocol_reply, list)
                and len(protocol_reply) == 2
                and protocol_reply[0] == -536870206
                and protocol_reply[1] == bytes(4)
            ):
                # Stable Linux-hardware divergence on this reference machine:
                # cmd1 is rejected with kIOReturnUnsupported while v2-only
                # cmds 0x51/0x52/0x53 succeed. Preserve the rejection, then
                # require one of those commands to attest v2 before matching.
                result["biometric_protocol_query_accepted"] = False
            else:
                raise ValueError("sensor returned a malformed biometric protocol")
            result["biometric_protocol_events"] = [
                summarize_event(event) for event in protocol_events
            ]
            operations.append("get biometric protocol")
        if args.biometrickitd_info or args.load_calibration:
            if not args.initialize:
                raise ValueError("command 0x28 requires --initialize")
            info_reply, info_events = biometric_command(
                sock, 0x28, output_capacity=23
            )
            result["biometrickitd_info_reply"] = summarize_command_reply(
                info_reply
            )
            biometrickitd_info_output = reply_bytes(info_reply)
            biometrickitd_info_valid = (
                isinstance(biometrickitd_info_output, bytes)
                and len(biometrickitd_info_output) == 23
            )
            result["biometrickitd_info_length_valid"] = biometrickitd_info_valid
            if not biometrickitd_info_valid:
                raise ValueError("sensor returned an invalid command 0x28 record")
            apple_template_list_already_in_sep = bool(
                biometrickitd_info_output[21]
            )
            result["apple_template_list_already_in_sep"] = (
                apple_template_list_already_in_sep
            )
            apple_calibration_load_bypassed = bool(
                biometrickitd_info_output[22]
            )
            result["apple_calibration_load_bypassed"] = (
                apple_calibration_load_bypassed
            )
            result["biometrickitd_info_events"] = [
                summarize_event(event) for event in info_events
            ]
            operations.append("get calibration-gating info")
        if args.sensor_readiness:
            readiness_reply, readiness_events = biometric_command(
                sock, 0x53, output_capacity=1
            )
            result["sensor_readiness_reply"] = summarize_command_reply(
                readiness_reply
            )
            if (
                isinstance(readiness_reply, list)
                and len(readiness_reply) > 1
                and readiness_reply[0] == 0
                and isinstance(readiness_reply[1], bytes)
                and len(readiness_reply[1]) == 1
            ):
                sensor_ready = bool(readiness_reply[1][0])
                result["sensor_ready"] = sensor_ready
            result["sensor_readiness_events"] = [
                summarize_event(event) for event in readiness_events
            ]
            if sensor_ready is None:
                raise ValueError("sensor returned an invalid readiness record")
            operations.append("get sensor readiness")
        if args.reset_sensor:
            if not args.initialize:
                raise ValueError("--reset-sensor requires --initialize")
            if args.sensor_readiness and sensor_ready is False:
                result["reset_sensor_skipped"] = True
                operations.append("skip sensor init per readiness gate")
            else:
                reset_attempts = []
                combined_reset_events = []
                reset_reply = None
                for _attempt in range(3):
                    reset_reply, reset_events = biometric_command(sock, 2, value=2)
                    combined_reset_events.extend(reset_events)
                    reset_attempts.append(summarize_command_reply(reset_reply))
                    if (
                        isinstance(reset_reply, list)
                        and bool(reset_reply)
                        and reset_reply[0] == 0
                    ):
                        break
                result["reset_sensor_reply"] = summarize_command_reply(reset_reply)
                result["reset_sensor_attempts"] = reset_attempts
                result["reset_sensor_events"] = [
                    summarize_event(event) for event in combined_reset_events
                ]
                if (
                    not isinstance(reset_reply, list)
                    or not reset_reply
                    or reset_reply[0] != 0
                ):
                    raise ValueError("sensor reset failed after three attempts")
                operations.append("readiness-gated sensor init")
        if (
            args.sensor_info
            and args.sensor_readiness
            and sensor_ready is False
        ):
            result["sensor_info_skipped"] = True
            operations.append("skip sensor info per readiness gate")
        elif args.sensor_info:
            sensor_info_reply, sensor_info_events = biometric_command(
                sock, 0x35, output_capacity=12
            )
            result["sensor_info_reply"] = summarize_command_reply(
                sensor_info_reply
            )
            if (
                isinstance(sensor_info_reply, list)
                and len(sensor_info_reply) > 1
                and sensor_info_reply[0] == 0
                and isinstance(sensor_info_reply[1], bytes)
                and len(sensor_info_reply[1]) == 12
            ):
                result["sensor_info_words"] = list(
                    struct.unpack("<III", sensor_info_reply[1])
                )
            result["sensor_info_events"] = [
                summarize_event(event) for event in sensor_info_events
            ]
            if "sensor_info_words" not in result:
                raise ValueError("sensor returned an invalid sensor-info record")
            operations.append("get sensor info")
        if args.calibration_info:
            calibration = {}
            for label, method in (("eeprom", 5), ("fdr", 11)):
                reply, events = request_with_events(sock, [method])
                entry = {"reply_type": type(reply).__name__}
                if isinstance(reply, list) and len(reply) == 1:
                    blob = reply[0]
                    if isinstance(blob, bytes):
                        entry.update(
                            length=len(blob), sha256=hashlib.sha256(blob).hexdigest()
                        )
                    elif blob is None:
                        entry["available"] = False
                entry["events"] = [summarize_event(event) for event in events]
                calibration[label] = entry
            result["calibration"] = calibration
            operations.append("read calibration metadata")
        if (
            args.load_calibration
            and args.sensor_readiness
            and sensor_ready is False
        ):
            if not args.initialize:
                raise ValueError("--load-calibration requires --initialize")
            result["load_calibration_skipped"] = True
            result["load_calibration_performed"] = False
            operations.append("skip calibration init per readiness gate")
        elif args.load_calibration:
            if not args.initialize:
                raise ValueError("--load-calibration requires --initialize")
            if not biometrickitd_info_valid:
                raise ValueError("sensor returned an invalid command 0x28 record")

            result["load_calibration_required"] = not bool(
                apple_calibration_load_bypassed
            )
            if apple_calibration_load_bypassed:
                result["load_calibration_performed"] = False
                operations.append("bypass calibration load per sensor gate")
            else:
                calibration_blob = None
                calibration_source = None
                calibration_label = None
                calibration_events = []
                for method, source, label in (
                    (11, 3, "bridgeOS FDR"),
                    (5, 2, "sensor EEPROM"),
                ):
                    calibration_reply, source_events = request_with_events(
                        sock, [method]
                    )
                    calibration_events.extend(source_events)
                    if (
                        isinstance(calibration_reply, list)
                        and len(calibration_reply) == 1
                        and isinstance(calibration_reply[0], bytes)
                        and calibration_reply[0]
                    ):
                        calibration_blob = calibration_reply[0]
                        calibration_source = source
                        calibration_label = label
                        break
                if calibration_blob is None or calibration_source is None:
                    raise ValueError("bridgeOS returned no usable calibration data")
                load_reply, load_events = biometric_command(
                    sock,
                    0x20,
                    value=calibration_source,
                    data=calibration_blob,
                )
                result["load_calibration_reply"] = summarize_command_reply(
                    load_reply
                )
                result["load_calibration_source"] = calibration_label
                result["load_calibration_length"] = len(calibration_blob)
                result["load_calibration_performed"] = True
                result["load_calibration_events"] = [
                    summarize_event(event)
                    for event in calibration_events + load_events
                ]
                operations.append("load required calibration")
        if args.cancel_operation:
            if not args.initialize:
                raise ValueError("--cancel-operation requires --initialize")
            cancel_reply, cancel_events = biometric_command(sock, 12)
            result["cancel_operation_reply"] = summarize_command_reply(
                cancel_reply
            )
            result["cancel_operation_events"] = [
                summarize_event(event) for event in cancel_events
            ]
            if (
                not isinstance(cancel_reply, list)
                or not cancel_reply
                or cancel_reply[0] != 0
            ):
                raise ValueError("sensor rejected pre-match cancellation")
            operations.append("cancel operation")
        if args.bio_device_list:
            if not args.initialize:
                raise ValueError("--bio-device-list requires --initialize")
            device_reply, device_events = biometric_command(
                sock, 0x52, output_capacity=0x108
            )
            device_output = reply_bytes(device_reply)
            device_list_valid = (
                isinstance(device_output, bytes)
                and len(device_output) <= 0x108
                and len(device_output) % 44 == 0
            )
            result["bio_device_list_reply"] = summarize_command_reply(device_reply)
            result["bio_device_list_length_valid"] = device_list_valid
            result["bio_device_count"] = (
                len(device_output) // 44 if device_list_valid else None
            )
            result["bio_device_list_events"] = [
                summarize_event(event) for event in device_events
            ]
            if not device_list_valid:
                raise ValueError("sensor returned an invalid biometric device list")
            if result.get("biometric_protocol_query_accepted") is False:
                result["biometric_protocol_version"] = 2
                result["biometric_protocol_attested_by_device_list"] = True
            operations.append("cache biometric device list")
        if args.identity_list:
            identities_reply, identities_events = biometric_command(
                sock, 0x42, data=struct.pack("<I", args.macos_user_id), output_capacity=20 * 10
            )
            result["identity_list_reply"] = summarize_command_reply(
                identities_reply
            )
            if (
                isinstance(identities_reply, list)
                and len(identities_reply) > 1
                and isinstance(identities_reply[1], bytes)
            ):
                result["identity_record_count"] = len(identities_reply[1]) // 20
                result["identity_record_bytes_valid"] = (
                    len(identities_reply[1]) % 20 == 0
                )
                if result["identity_record_bytes_valid"]:
                    enrolled_identity_records = tuple(
                        identities_reply[1][offset : offset + 20]
                        for offset in range(0, len(identities_reply[1]), 20)
                    )
                    result["identity_user_field"] = (
                        "prefix"
                        if all(
                            struct.unpack_from("<I", record)[0] == args.macos_user_id
                            for record in enrolled_identity_records
                        )
                        else "suffix"
                        if all(
                            struct.unpack_from("<I", record, 16)[0] == args.macos_user_id
                            for record in enrolled_identity_records
                        )
                        else "unknown"
                    )
            result["identity_list_events"] = [
                summarize_event(event) for event in identities_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock,
                    0x42,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=20 * 10,
                )
                result["identity_inventory_repeat_equal"] = (
                    repeated_reply == identities_reply
                )
                result["identity_list_repeat_reply"] = summarize_command_reply(
                    repeated_reply
                )
                result["identity_list_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get identity count")
        if args.service_template_sync:
            if not args.initialize:
                raise ValueError("--service-template-sync requires --initialize")
            catacomb_source_present = bool(
                args.load_catacomb_archive or args.load_native_catacomb_root
            )
            if catacomb_source_present and args.catacomb_component != "all":
                raise ValueError(
                    "service template restore requires both Catacomb components"
                )
            if catacomb_source_present and args.strip_catacomb_file_header:
                raise ValueError(
                    "service template restore requires the complete LTFC payload"
                )

            protocol_version = result.get("biometric_protocol_version", 0)
            initial_state = read_service_catacomb_state(sock, protocol_version)
            state_reply = initial_state["user_reply"]
            state_events = initial_state["user_events"]
            user_states = initial_state["user_states"]
            result["template_sync_catacomb_state_reply"] = (
                summarize_command_reply(state_reply)
            )
            result["template_sync_catacomb_state_bytes_valid"] = True
            result["template_sync_catacomb_state_count"] = len(user_states)
            result["template_sync_catacomb_state_events"] = [
                summarize_event(event) for event in state_events
            ]
            group_states = initial_state["group_states"]
            group_reply = initial_state["group_reply"]
            group_events = initial_state["group_events"]
            if protocol_version >= 2:
                result["template_sync_group_state_reply"] = (
                    summarize_command_reply(group_reply)
                )
                result["template_sync_group_state_bytes_valid"] = True
                result["template_sync_group_state_count"] = len(group_states)
                result["template_sync_group_state_events"] = [
                    summarize_event(event) for event in group_events
                ]

            if catacomb_source_present:
                if group_states:
                    raise ValueError(
                        "service template restore has no archived group components"
                    )
                source_payloads = (
                    read_catacomb_payloads(
                        args.load_catacomb_archive, args.macos_user_id
                    )
                    if args.load_catacomb_archive
                    else read_native_catacomb_payloads(
                        args.load_native_catacomb_root, args.macos_user_id
                    )[0]
                )
                payloads = {
                    user_id: (name, secure_data)
                    for name, user_id, secure_data in source_payloads
                }
                compatibility_restore_needed = False
                compatibility_live_matches = False
                if compatibility_loaded_empty_restore:
                    live_reply, live_events = biometric_command(
                        sock,
                        0x42,
                        data=struct.pack("<I", args.macos_user_id),
                        output_capacity=20 * 10,
                    )
                    live_records = managed_user_identity_records(
                        live_reply,
                        live_events,
                        args.macos_user_id,
                        "pre-restore compatibility",
                    )
                    result["compatibility_pre_restore_identity_reply"] = (
                        summarize_command_reply(live_reply)
                    )
                    result["compatibility_pre_restore_identity_count"] = len(
                        live_records
                    )
                    compatibility_restore_needed = compatibility_restore_required(
                        live_records, managed_expected_identities
                    )
                    compatibility_live_matches = not compatibility_restore_needed
                    validate_compatibility_restore_state(
                        compatibility_restore_needed,
                        tuple(record.state for record in user_states),
                    )
                load_entries = []
                master = t2_catacomb_protocol.CatacombComponent.master()
                master_states = [
                    record for record in user_states if record.component == master
                ]
                if len(master_states) != 1 or not (master_states[0].state & 1):
                    raise ValueError("SEP master Catacomb is not loadable")
                if not compatibility_live_matches and not (
                    master_states[0].state & 2
                ):
                    name, secure_data = payloads[-1]
                    load_reply, load_events = biometric_command(
                        sock, 0x40, version=1, data=secure_data
                    )
                    load_entries.append(
                        {
                            "component": name,
                            "user_id": -1,
                            "secure_data_length": len(secure_data),
                            "command_data_length": len(secure_data),
                            "reply": summarize_command_reply(load_reply),
                            "events": [
                                summarize_event(event) for event in load_events
                            ],
                        }
                    )
                    if (
                        not isinstance(load_reply, list)
                        or not load_reply
                        or load_reply[0] != 0
                    ):
                        raise ValueError(
                            command_reply_failure(
                                "load-master-catacomb",
                                "command-0x40-response",
                                load_reply,
                            )
                        )

                refreshed_state = read_service_catacomb_state(
                    sock, protocol_version
                )
                refreshed_users = refreshed_state["user_states"]
                result["template_sync_refreshed_catacomb_state_reply"] = (
                    summarize_command_reply(refreshed_state["user_reply"])
                )
                result["template_sync_refreshed_catacomb_state_count"] = len(
                    refreshed_users
                )
                result["template_sync_refreshed_catacomb_state_events"] = [
                    summarize_event(event)
                    for event in refreshed_state["user_events"]
                ]
                if protocol_version >= 2:
                    refreshed_groups = refreshed_state["group_states"]
                    result["template_sync_refreshed_group_state_reply"] = (
                        summarize_command_reply(refreshed_state["group_reply"])
                    )
                    result["template_sync_refreshed_group_state_count"] = len(
                        refreshed_groups
                    )
                    result["template_sync_refreshed_group_state_events"] = [
                        summarize_event(event)
                        for event in refreshed_state["group_events"]
                    ]
                    if refreshed_groups:
                        raise ValueError(
                            "service template restore discovered group components"
                        )

                selected = t2_catacomb_protocol.CatacombComponent.user(
                    args.macos_user_id
                )
                selected_states = [
                    record
                    for record in refreshed_users
                    if record.component == selected
                ]
                if len(selected_states) != 1 or not (selected_states[0].state & 1):
                    raise ValueError("SEP user Catacomb is not loadable")
                if not compatibility_live_matches and not (
                    selected_states[0].state & 2
                ):
                    name, secure_data = payloads[args.macos_user_id]
                    load_reply, load_events = biometric_command(
                        sock, 0x40, version=1, data=secure_data
                    )
                    load_entries.append(
                        {
                            "component": name,
                            "user_id": args.macos_user_id,
                            "secure_data_length": len(secure_data),
                            "command_data_length": len(secure_data),
                            "reply": summarize_command_reply(load_reply),
                            "events": [
                                summarize_event(event) for event in load_events
                            ],
                        }
                    )
                    if (
                        not isinstance(load_reply, list)
                        or not load_reply
                        or load_reply[0] != 0
                    ):
                        raise ValueError(
                            command_reply_failure(
                                "load-user-catacomb",
                                "command-0x40-response",
                                load_reply,
                            )
                        )
                    final_state = read_service_catacomb_state(
                        sock, protocol_version
                    )
                    final_users = final_state["user_states"]
                    final_groups = final_state["group_states"]
                    final_master = [
                        record
                        for record in final_users
                        if record.component == master
                    ]
                    final_selected = [
                        record
                        for record in final_users
                        if record.component == selected
                    ]
                    if (
                        final_groups
                        or len(final_master) != 1
                        or len(final_selected) != 1
                        or (final_master[0].state & 3) != 3
                        or (final_selected[0].state & 3) != 3
                    ):
                        raise ValueError(
                            "managed Catacomb did not load securely"
                        )
                    result["template_sync_final_catacomb_state_count"] = len(
                        final_users
                    )
                result["load_catacomb"] = load_entries
                result["load_catacomb_skipped_already_loaded"] = not load_entries

            sync_reply, sync_events = biometric_command(
                sock,
                0x42,
                data=struct.pack("<I", args.macos_user_id),
                output_capacity=20 * 10,
            )
            try:
                synced_records = managed_user_identity_records(
                    sync_reply,
                    sync_events,
                    args.macos_user_id,
                    "post-restore",
                )
                sync_valid = True
            except ValueError:
                synced_records = ()
                sync_valid = False
            result["template_sync_identity_reply"] = summarize_command_reply(
                sync_reply
            )
            result["template_sync_identity_bytes_valid"] = sync_valid
            result["template_sync_identity_count"] = (
                len(synced_records) if sync_valid else None
            )
            result["template_sync_identity_events"] = [
                summarize_event(event) for event in sync_events
            ]
            if not sync_valid:
                raise ValueError("sensor returned an invalid user template list")
            if enrolled_identity_records and synced_records != enrolled_identity_records:
                raise ValueError("post-restore identity list changed unexpectedly")
            enrolled_identity_records = synced_records
            identities_reply = sync_reply
            identities_events = sync_events
            if args.native_authority_linux_uid is not None and (
                len(enrolled_identity_records) != len(managed_expected_identities)
                or set(enrolled_identity_records) != set(managed_expected_identities)
            ):
                raise ValueError(
                    "live per-user identity does not match managed Catacomb"
                )
            if (
                args.compatibility_authority_linux_uid is not None
                and managed_expected_identities
                and (
                    len(enrolled_identity_records)
                    != len(managed_expected_identities)
                    or set(enrolled_identity_records)
                    != set(managed_expected_identities)
                )
            ):
                raise ValueError(
                    "live per-user identity does not match managed authority"
                )
            operations.append("sync service template state")
        if args.global_identity_list:
            global_reply, global_events = biometric_command(
                sock, 0x51, output_capacity=40 * 10
            )
            result["global_identity_list_reply"] = summarize_command_reply(
                global_reply
            )
            global_output = (
                global_reply[1]
                if isinstance(global_reply, list)
                and len(global_reply) > 1
                and isinstance(global_reply[1], bytes)
                else None
            )
            result["global_identity_record_bytes_valid"] = (
                isinstance(global_output, bytes) and len(global_output) % 40 == 0
            )
            if result["global_identity_record_bytes_valid"]:
                global_identity_records = tuple(
                    global_output[offset : offset + 40]
                    for offset in range(0, len(global_output), 40)
                )
                result["global_identity_record_count"] = len(
                    global_identity_records
                )
                configured_records = {
                    record[:20]
                    for record in global_identity_records
                    if struct.unpack_from("<I", record)[0] == args.macos_user_id
                }
                result["configured_identity_records_reconciled"] = (
                    bool(enrolled_identity_records)
                    and configured_records == set(enrolled_identity_records)
                ) or (not configured_records and not enrolled_identity_records)
                if (
                    args.native_authority_linux_uid is not None
                    and configured_records != set(managed_expected_identities)
                ):
                    raise ValueError(
                        "live global identity does not match managed Catacomb"
                    )
            result["global_identity_list_events"] = [
                summarize_event(event) for event in global_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock, 0x51, output_capacity=40 * 10
                )
                result["global_identity_inventory_repeat_equal"] = (
                    repeated_reply == global_reply
                )
                result["global_identity_list_repeat_reply"] = (
                    summarize_command_reply(repeated_reply)
                )
                result["global_identity_list_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get global identity inventory")
        if args.identity_capacity:
            maximum_reply, maximum_events = biometric_command(
                sock, 0x0F, output_capacity=4
            )
            free_reply, free_events = biometric_command(
                sock,
                0x41,
                data=struct.pack("<I", args.macos_user_id),
                output_capacity=4,
            )
            result["identity_capacity_reply"] = summarize_command_reply(
                maximum_reply
            )
            result["identity_free_count_reply"] = summarize_command_reply(free_reply)
            maximum_output = (
                maximum_reply[1]
                if isinstance(maximum_reply, list)
                and len(maximum_reply) > 1
                and isinstance(maximum_reply[1], bytes)
                else None
            )
            free_output = (
                free_reply[1]
                if isinstance(free_reply, list)
                and len(free_reply) > 1
                and isinstance(free_reply[1], bytes)
                else None
            )
            if isinstance(maximum_output, bytes) and len(maximum_output) == 4:
                result["identity_maximum_capacity"] = struct.unpack(
                    "<I", maximum_output
                )[0]
            if isinstance(free_output, bytes) and len(free_output) == 4:
                result["identity_free_count"] = struct.unpack("<I", free_output)[0]
            result["identity_capacity_events"] = [
                summarize_event(event) for event in maximum_events + free_events
            ]
            if args.stability_check:
                repeated_maximum, repeated_maximum_events = biometric_command(
                    sock, 0x0F, output_capacity=4
                )
                repeated_free, repeated_free_events = biometric_command(
                    sock,
                    0x41,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=4,
                )
                result["identity_capacity_repeat_equal"] = (
                    repeated_maximum == maximum_reply and repeated_free == free_reply
                )
                result["identity_capacity_repeat_events"] = [
                    summarize_event(event)
                    for event in repeated_maximum_events + repeated_free_events
                ]
            operations.append("get identity capacity")
        if args.catacomb_component_state:
            uid_data = struct.pack("<I", args.macos_user_id)
            uuid_reply, uuid_events = biometric_command(
                sock, 0x38, data=uid_data, output_capacity=16
            )
            hash_reply, hash_events = biometric_command(
                sock, 0x3A, data=uid_data, output_capacity=33
            )
            result["catacomb_uuid_reply"] = summarize_command_reply(uuid_reply)
            result["catacomb_hash_reply"] = summarize_command_reply(hash_reply)
            uuid_output = (
                uuid_reply[1]
                if isinstance(uuid_reply, list)
                and len(uuid_reply) > 1
                and isinstance(uuid_reply[1], bytes)
                else None
            )
            hash_output = (
                hash_reply[1]
                if isinstance(hash_reply, list)
                and len(hash_reply) > 1
                and isinstance(hash_reply[1], bytes)
                else None
            )
            result["catacomb_uuid_length_valid"] = (
                isinstance(uuid_output, bytes) and len(uuid_output) == 16
            )
            result["catacomb_hash_length_valid"] = (
                isinstance(hash_output, bytes) and len(hash_output) == 33
            )
            if result["catacomb_hash_length_valid"]:
                result["catacomb_component_present"] = bool(hash_output[0])
            result["catacomb_component_events"] = [
                summarize_event(event) for event in uuid_events + hash_events
            ]
            if args.stability_check:
                repeated_uuid, repeated_uuid_events = biometric_command(
                    sock, 0x38, data=uid_data, output_capacity=16
                )
                repeated_hash, repeated_hash_events = biometric_command(
                    sock, 0x3A, data=uid_data, output_capacity=33
                )
                result["catacomb_component_repeat_equal"] = (
                    repeated_uuid == uuid_reply and repeated_hash == hash_reply
                )
                result["catacomb_component_repeat_events"] = [
                    summarize_event(event)
                    for event in repeated_uuid_events + repeated_hash_events
                ]
            operations.append("get Catacomb component metadata")
        if args.catacomb_state:
            catacomb_reply, catacomb_events = biometric_command(
                sock, 0x3C, output_capacity=4096
            )
            result["catacomb_state_reply"] = summarize_command_reply(
                catacomb_reply
            )
            if (
                isinstance(catacomb_reply, list)
                and len(catacomb_reply) > 1
                and isinstance(catacomb_reply[1], bytes)
                and len(catacomb_reply[1]) in (8, 16)
            ):
                catacomb_state_output = catacomb_reply[1]
                result["catacomb_state_words"] = list(
                    struct.unpack(
                        "<" + "I" * (len(catacomb_reply[1]) // 4),
                        catacomb_reply[1],
                    )
                )
            result["catacomb_state_events"] = [
                summarize_event(event) for event in catacomb_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock, 0x3C, output_capacity=4096
                )
                result["catacomb_state_repeat_equal"] = (
                    repeated_reply == catacomb_reply
                )
                result["catacomb_state_repeat_reply"] = summarize_command_reply(
                    repeated_reply
                )
                result["catacomb_state_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get catacomb state")
        if args.sks_lock_state:
            sks_reply, sks_events = biometric_command(
                sock, 0x27, data=struct.pack("<I", args.macos_user_id), output_capacity=4
            )
            result["sks_lock_state_reply"] = summarize_command_reply(sks_reply)
            if (
                isinstance(sks_reply, list)
                and len(sks_reply) > 1
                and isinstance(sks_reply[1], bytes)
                and len(sks_reply[1]) == 4
            ):
                result["sks_lock_state"] = struct.unpack("<I", sks_reply[1])[0]
            result["sks_lock_state_events"] = [
                summarize_event(event) for event in sks_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock,
                    0x27,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=4,
                )
                result["sks_lock_state_repeat_equal"] = repeated_reply == sks_reply
                result["sks_lock_state_repeat_reply"] = summarize_command_reply(
                    repeated_reply
                )
                result["sks_lock_state_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get SKS lock state")
        if args.load_catacomb_archive and not args.service_template_sync:
            if not args.initialize:
                raise ValueError("--load-catacomb-archive requires --initialize")
            entries = []
            payloads = read_catacomb_payloads(
                args.load_catacomb_archive, args.macos_user_id
            )
            if args.catacomb_component != "all":
                selected_name = (
                    "master.cat"
                    if args.catacomb_component == "master"
                    else f"user_{args.macos_user_id:08x}.cat"
                )
                payloads = [
                    payload for payload in payloads if payload[0] == selected_name
                ]
            for name, user_id, secure_data in payloads:
                command_data = secure_data
                if args.strip_catacomb_file_header:
                    if len(command_data) < 33:
                        raise ValueError(f"{name} is too short for an LTFC wrapper")
                    magic, file_version, file_user_id = struct.unpack_from(
                        "<IIi", command_data
                    )
                    if (
                        magic != 0x4346544C
                        or file_version != 10
                        or file_user_id != user_id
                        or any(command_data[12:32])
                    ):
                        raise ValueError(f"{name} has an unexpected LTFC wrapper")
                    command_data = command_data[32:]
                load_reply, load_events = biometric_command(
                    sock, 0x40, version=1, data=command_data
                )
                entries.append(
                    {
                        "component": name,
                        "user_id": user_id,
                        "secure_data_length": len(secure_data),
                        "command_data_length": len(command_data),
                        "reply": summarize_command_reply(load_reply),
                        "events": [summarize_event(event) for event in load_events],
                    }
                )
                if not isinstance(load_reply, list) or not load_reply or load_reply[0] != 0:
                    break
            result["load_catacomb"] = entries
            operations.append("load encrypted catacomb")
        if args.load_biolockout_archive:
            if not args.initialize:
                raise ValueError("--load-biolockout-archive requires --initialize")
            biolockout_data = read_biolockout_payload(args.load_biolockout_archive)
            biolockout_reply, biolockout_events = biometric_command(
                sock, 0x4B, data=biolockout_data
            )
            result["load_biolockout"] = {
                "secure_data_length": len(biolockout_data),
                "reply": summarize_command_reply(biolockout_reply),
                "events": [
                    summarize_event(event) for event in biolockout_events
                ],
            }
            if (
                not isinstance(biolockout_reply, list)
                or not biolockout_reply
                or biolockout_reply[0] != 0
            ):
                raise ValueError("sensor rejected the bio-lockout record")
            operations.append("load encrypted bio-lockout record")
        if args.load_biolockout_record:
            if not args.initialize:
                raise ValueError("--load-biolockout-record requires --initialize")
            biolockout_data = read_private_biolockout_record(
                args.load_biolockout_record
            )
            biolockout_reply, biolockout_events = biometric_command(
                sock, 0x4B, data=biolockout_data
            )
            result["load_biolockout"] = {
                "secure_data_length": len(biolockout_data),
                "secure_data_sha256": hashlib.sha256(biolockout_data).hexdigest(),
                "reply": summarize_command_reply(biolockout_reply),
                "events": [
                    summarize_event(event) for event in biolockout_events
                ],
            }
            if (
                not isinstance(biolockout_reply, list)
                or not biolockout_reply
                or biolockout_reply[0] != 0
            ):
                raise ValueError("sensor rejected the bio-lockout record")
            operations.append("load current encrypted bio-lockout record")
        if biolockout_store is not None:
            current_biolockout = biolockout_store.current()
            if current_biolockout is None:
                result["linux_biolockout_generation"] = None
                result["linux_biolockout_load_skipped"] = "no committed generation"
            else:
                (
                    current_biolockout,
                    load_biolockout_summary,
                    recovery_summary,
                ) = load_linux_biolockout(
                    sock,
                    biolockout_store,
                    current_biolockout,
                    allow_sep_ahead_recovery=native_biolockout is not None,
                )
                result["load_biolockout"] = load_biolockout_summary
                if recovery_summary is not None:
                    result["linux_biolockout_recovery"] = recovery_summary
                result["linux_biolockout_generation"] = (
                    current_biolockout.sequence
                )
                operations.append("load current Linux bio-lockout generation")
        if args.save_biolockout_output:
            if not args.initialize:
                raise ValueError("--save-biolockout-output requires --initialize")
            result["save_biolockout"] = save_biolockout_record(
                sock, args.save_biolockout_output
            )
            operations.append("save current encrypted bio-lockout record")
        if args.display_on:
            if not args.initialize:
                raise ValueError("--display-on requires --initialize")
            display_reply, display_events = biometric_command(sock, 0x14, value=1)
            result["display_on_reply"] = summarize_command_reply(display_reply)
            result["display_on_events"] = [
                summarize_event(event) for event in display_events
            ]
            if (
                not isinstance(display_reply, list)
                or not display_reply
                or display_reply[0] != 0
            ):
                raise ValueError("sensor rejected the display-on notification")
            operations.append("display on")
        if args.system_awake:
            if not args.initialize:
                raise ValueError("--system-awake requires --initialize")
            awake_reply, awake_events = biometric_command(sock, 0x57, value=0)
            result["system_awake_reply"] = summarize_command_reply(awake_reply)
            result["system_awake_events"] = [
                summarize_event(event) for event in awake_events
            ]
            if (
                not isinstance(awake_reply, list)
                or not awake_reply
                or awake_reply[0] != 0
            ):
                raise ValueError("sensor rejected the system-awake notification")
            operations.append("system awake")
        if args.match_seconds is not None:
            t2_performance.emit(
                "bridge_match", "preparation", bridge_preparation_started
            )
            if not args.initialize:
                raise ValueError("--match-seconds requires --initialize")
            if args.biometric_protocol and result.get(
                "biometric_protocol_version"
            ) not in (1, 2, 3):
                raise ValueError("biometric protocol was not safely attested")
            if termination_requested:
                raise RuntimeError("match cancelled before sensor start")
            if not enrolled_identity_records:
                raise ValueError(
                    "--match-seconds requires a non-empty --identity-list result"
                )
            targeted_gate = None
            all_match_gate = None
            slot_match_gate = None
            selected_identity_record = None
            if (
                args.match_finger_name is not None
                or args.resolve_any_finger_name
                or args.resolve_any_identity_slot
            ):
                if not args.identity_list:
                    raise ValueError(
                        "resolved matching requires --identity-list"
                    )
                first_user_records = strict_identity_records(
                    identities_reply,
                    identities_events,
                    20,
                    "initial per-user",
                )
                store = t2_catacomb_store.CatacombStore(
                    CATACOMB_ROOT, args.macos_user_id
                )
                targeted_components = store.read_committed_components()
                local = t2_catacomb_codec.decode_user_catacomb(
                    targeted_components[f"user_{args.macos_user_id:08x}.cat"],
                    args.macos_user_id,
                )
                first_global_reply, first_global_events = biometric_command(
                    sock, 0x51, output_capacity=40 * 10
                )
                repeated_user_reply, repeated_user_events = biometric_command(
                    sock,
                    0x42,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=20 * 10,
                )
                repeated_global_reply, repeated_global_events = biometric_command(
                    sock, 0x51, output_capacity=40 * 10
                )
                first_global_records = strict_identity_records(
                    first_global_reply,
                    first_global_events,
                    40,
                    "initial global",
                )
                repeated_user_records = strict_identity_records(
                    repeated_user_reply,
                    repeated_user_events,
                    20,
                    "repeated per-user",
                )
                repeated_global_records = strict_identity_records(
                    repeated_global_reply,
                    repeated_global_events,
                    40,
                    "repeated global",
                )
                if args.match_finger_name is not None:
                    targeted_gate = t2_fprint_match_gate.prepare(
                        local,
                        targeted_components,
                        first_user_records,
                        first_global_records,
                        repeated_user_records,
                        repeated_global_records,
                        args.match_finger_name,
                    )
                    selected_identity_record = targeted_gate.identity_record
                    selected_records = (selected_identity_record,)
                    result["targeted_match_gate"] = targeted_gate.public()
                elif args.resolve_any_finger_name:
                    all_match_gate = t2_fprint_match_gate.prepare_all(
                        local,
                        targeted_components,
                        first_user_records,
                        first_global_records,
                        repeated_user_records,
                        repeated_global_records,
                    )
                    selected_records = all_match_gate.per_user_records
                    result["resolved_any_match_gate"] = all_match_gate.public()
                else:
                    slot_match_gate = t2_fprint_match_gate.prepare_slots(
                        local,
                        targeted_components,
                        first_user_records,
                        first_global_records,
                        repeated_user_records,
                        repeated_global_records,
                    )
                    selected_records = slot_match_gate.per_user_records
                    result["resolved_slot_match_gate"] = (
                        slot_match_gate.public()
                    )
            else:
                selected_records = enrolled_identity_records
            validation_identity_record = (
                native_required_match_identity or selected_identity_record
            )
            # match_init_data_v1: processed flags, macOS user ID, and 60 bytes
            # reserved for authenticated/special matching modes.
            # Apple's performMatchCommand: appends selectedIdentitiesBlob to
            # the fixed 68-byte match-options structure. The blob starts with
            # a uint32 record count, followed by the opaque 20-byte
            # identity_record_v1_t records returned by command 0x42.
            match_identity_records = None
            if not args.match_all_enrolled_identities:
                match_identity_records = selected_match_records(
                    enrolled_identity_records,
                    native_required_match_identity,
                    selected_identity_record,
                )
            (
                match_data,
                processed_flags,
                selected_identity_count,
            ) = build_match_request(
                args.macos_user_id,
                args.match_processed_flags,
                authorized_credential_set,
                match_identity_records,
            )
            result["match_request"] = {
                "data_length": len(match_data),
                "processed_flags": processed_flags,
                "selected_identity_count": selected_identity_count,
                "returned_identity_validation_required": True,
                "credential_set_authorized": authorized_credential_set is not None,
                "credential_set_length": (
                    len(authorized_credential_set)
                    if authorized_credential_set is not None
                    else 0
                ),
                "context_identifier_redacted": True,
            }
            if authorized_policy is not None:
                result["match_authorization"] = authorized_policy
            if args.audible_match_alert:
                subprocess.run(
                    [
                        "canberra-gtk-play",
                        "--id=message-new-instant",
                        "--description=Touch ID finger requested",
                    ],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            if api_version >= 3:
                # The installed activity callback retains BridgeOS while the
                # biometric operation is active. This is a no-reply Bridge
                # lifecycle message, not a sensor command.
                notify(sock, [12, True])
                os_transaction_retained = True
                result["bridge_os_transaction_retained_for_match"] = True
            match_accept_started = time.monotonic()
            try:
                match_reply, events = biometric_command(sock, 4, data=match_data)
            except Exception:
                if os_transaction_retained:
                    try:
                        os_transaction_retained = release_bridge_os_transaction(
                            sock, os_transaction_retained, result
                        )
                    except Exception:
                        result[
                            "bridge_os_transaction_released_after_match"
                        ] = False
                        os_transaction_retained = False
                raise
            t2_performance.emit(
                "bridge_match", "start_acceptance", match_accept_started
            )
            result["match_start_reply"] = summarize_command_reply(match_reply)
            match_started = (
                isinstance(match_reply, list)
                and bool(match_reply)
                and match_reply[0] == 0
            )
            if match_started:
                terminal_result_seen = False
                terminal_operation_status = None
                persistence_failure = None
                post_match_biolockout_generations = []
                touch_timing: dict[str, float] = {}
                def persist_match_result(event_summary: dict) -> None:
                    if (
                        event_summary.get("event_kind") != "match_result"
                        or event_summary.get("host_accepted_result") is not True
                        or not (
                            args.save_biolockout_after_match_output
                            or biolockout_store is not None
                        )
                    ):
                        return
                    with t2_performance.phase("bridge_match", "biolockout_export"):
                        save_output, save_summary = export_biolockout_record(sock, events=events)
                    generation = len(post_match_biolockout_generations) + 1
                    save_summary["match_result_generation"] = generation
                    if args.save_biolockout_after_match_output:
                        destination = args.save_biolockout_after_match_output
                        if generation > 1:
                            stem, extension = os.path.splitext(destination)
                            destination = (
                                f"{stem}-result-{generation:04d}{extension}"
                            )
                        write_private_bytes(destination, save_output)
                        save_summary["private_output_written"] = True
                        save_summary["private_output_path"] = destination
                    if biolockout_store is not None:
                        with t2_performance.phase("bridge_match", "biolockout_commit"):
                            committed = biolockout_store.commit(save_output)
                        save_summary["linux_store_generation"] = committed.sequence
                        save_summary["linux_store_committed"] = True
                    post_match_biolockout_generations.append(save_summary)
                    result["post_match_biolockout_generations"] = (
                        post_match_biolockout_generations
                    )
                    result["post_match_save_biolockout"] = save_summary
                    if generation == 1:
                        operations.append(
                            "save post-result encrypted bio-lockout record"
                        )

                if args.live_match_feedback:
                    emit_live_match_feedback(
                        {"event_kind": "match_armed"},
                        args.live_match_feedback_format,
                    )
                initial_events = tuple(events)
                for initial_event in initial_events:
                    observed_at = time.monotonic()
                    initial_summary = summarize_event(
                        initial_event,
                        enrolled_identity_records,
                        expected_user_id=args.macos_user_id,
                        selected_identity_record=validation_identity_record,
                        required_identity_record=native_required_match_identity,
                        all_match_gate=all_match_gate,
                        slot_match_gate=slot_match_gate,
                    )
                    observe_touch_to_verdict(
                        initial_summary, touch_timing, observed_at=observed_at
                    )
                    if args.live_match_feedback:
                        emit_live_match_feedback(
                            initial_summary, args.live_match_feedback_format
                        )
                    try:
                        persist_match_result(initial_summary)
                    except Exception as error:
                        persistence_failure = error
                        terminal_result_seen = True
                        break
                    if (
                        initial_summary.get("event_kind") == "match_result"
                        and initial_summary.get("result_valid") is False
                    ):
                        deferred_failure = (
                            "sensor match result failed structural or identity validation"
                        )
                        terminal_result_seen = True
                        break
                    if initial_summary.get("status_code") in (
                        MATCH_TERMINAL_STATUS_REASONS
                    ):
                        terminal_operation_status = initial_summary["status_code"]
                    if match_observation_should_stop(initial_summary, args):
                        terminal_result_seen = True
                # This deadline bounds operator observation only. Mesa accepts
                # or rejects each capture based on quality and emits the match
                # result independently of elapsed host time.
                deadline = (
                    None
                    if args.match_seconds == 0
                    else time.monotonic() + args.match_seconds
                )
                # Exports above can append callbacks. Leave them queued for
                # the observation loop or bounded post-cancel reconciliation.
                processed_events = len(initial_events)
                while (
                    not termination_requested
                    and not terminal_result_seen
                    and terminal_operation_status is None
                    and (deadline is None or time.monotonic() < deadline)
                ):
                    sock.settimeout(
                        0.25
                        if deadline is None
                        else min(0.25, max(0.1, deadline - time.monotonic()))
                    )
                    try:
                        callback, processed_events = next_match_callback(
                            sock, events, processed_events
                        )
                    except TimeoutError:
                        continue
                    if callback is not None:
                        observed_at = time.monotonic()
                        event_summary = summarize_event(
                            callback,
                            enrolled_identity_records,
                            expected_user_id=args.macos_user_id,
                            selected_identity_record=validation_identity_record,
                            required_identity_record=native_required_match_identity,
                            all_match_gate=all_match_gate,
                            slot_match_gate=slot_match_gate,
                        )
                        observe_touch_to_verdict(
                            event_summary, touch_timing, observed_at=observed_at
                        )
                        if args.live_match_feedback:
                            emit_live_match_feedback(
                                event_summary, args.live_match_feedback_format
                            )
                        try:
                            persist_match_result(event_summary)
                        except Exception as error:
                            persistence_failure = error
                            break
                        if (
                            event_summary.get("event_kind") == "match_result"
                            and event_summary.get("result_valid") is False
                        ):
                            deferred_failure = (
                                "sensor match result failed structural or identity validation"
                            )
                            break
                        if event_summary.get("status_code") in (
                            MATCH_TERMINAL_STATUS_REASONS
                        ):
                            terminal_operation_status = event_summary["status_code"]
                            break
                        if match_observation_should_stop(event_summary, args):
                            break
                sock.settimeout(args.timeout)
                try:
                    with t2_performance.phase("bridge_match", "cancel"):
                        cancel_reply, cancel_events = request_with_events(
                            sock, [3, 0, BIOMETRIC_COMMAND_HEADER.pack(
                                BIOMETRIC_COMMAND_MAGIC, 12, 1, 0
                            ), 0]
                        )
                except Exception as error:
                    result["match_cleanup_valid"] = False
                    if deferred_failure is None:
                        deferred_failure = f"sensor match cancellation failed: {error}"
                else:
                    events.extend(cancel_events)
                    result["cancel_reply"] = summarize_command_reply(cancel_reply)
                    result["match_cleanup_valid"] = (
                        isinstance(cancel_reply, list)
                        and bool(cancel_reply)
                        and cancel_reply[0] == 0
                    )
                    if result["match_cleanup_valid"]:
                        drain_started = time.monotonic()
                        try:
                            drained = drain_post_cancel_service_events(sock, events)
                        except Exception as error:
                            result["match_cleanup_valid"] = False
                            if deferred_failure is None:
                                deferred_failure = (
                                    "post-cancel service callback drain failed: "
                                    f"{error}"
                                )
                        else:
                            t2_performance.emit(
                                "bridge_match", "callback_drain", drain_started
                            )
                            result["post_cancel_events_drained"] = drained
                            result["post_cancel_callback_quiescent"] = True
                if not result["match_cleanup_valid"]:
                    if deferred_failure is None:
                        deferred_failure = "sensor match cancellation failed"
                if persistence_failure is not None:
                    deferred_failure = (
                        "post-result bio-lockout persistence failed: "
                        f"{persistence_failure}"
                    )
                if terminal_operation_status is not None:
                    result["sensor_operation_terminal_status"] = (
                        terminal_operation_status
                    )
                    result["sensor_operation_end_reason"] = (
                        MATCH_TERMINAL_STATUS_REASONS[terminal_operation_status]
                    )
                    if not termination_requested:
                        deferred_failure = (
                            "sensor operation ended without a biometric verdict "
                            f"(status {terminal_operation_status}, reason "
                            f"{MATCH_TERMINAL_STATUS_REASONS[terminal_operation_status]})"
                        )
                result["termination_requested"] = termination_requested
            else:
                result["match_rejected"] = True
            if os_transaction_retained:
                try:
                    os_transaction_retained = release_bridge_os_transaction(
                        sock, os_transaction_retained, result
                    )
                except Exception as error:
                    result["bridge_os_transaction_released_after_match"] = False
                    os_transaction_retained = False
                    if match_started:
                        result["match_cleanup_valid"] = False
                    if deferred_failure is None:
                        deferred_failure = (
                            "BridgeOS activity transaction release failed: "
                            f"{error}"
                        )
            reconciled_gate = targeted_gate or all_match_gate or slot_match_gate
            if reconciled_gate is not None:
                post_attestation_started = time.monotonic()
                post_user_reply, post_user_events = biometric_command(
                    sock,
                    0x42,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=20 * 10,
                )
                post_global_reply, post_global_events = biometric_command(
                    sock, 0x51, output_capacity=40 * 10
                )
                post_user_records = post_match_identity_records(
                    post_user_reply,
                    post_user_events,
                    20,
                    "post-match per-user",
                )
                post_global_records = post_match_identity_records(
                    post_global_reply,
                    post_global_events,
                    40,
                    "post-match global",
                )
                events.extend(post_user_events)
                events.extend(post_global_events)
                post_attestation = t2_fprint_match_gate.attest_unchanged(
                    reconciled_gate,
                    store.read_committed_components(),
                    post_user_records,
                    post_global_records,
                )
                result[
                    "targeted_match_post_attestation"
                    if targeted_gate is not None
                    else (
                        "resolved_any_match_post_attestation"
                        if all_match_gate is not None
                        else "resolved_slot_match_post_attestation"
                    )
                ] = post_attestation
                t2_performance.emit(
                    "bridge_match", "post_attestation", post_attestation_started
                )
            def summarize_match_event(event):
                return summarize_event(
                    event,
                    enrolled_identity_records,
                    expected_user_id=args.macos_user_id,
                    selected_identity_record=validation_identity_record,
                    required_identity_record=native_required_match_identity,
                    all_match_gate=all_match_gate,
                    slot_match_gate=slot_match_gate,
                )
            match_event_summaries = [summarize_match_event(event) for event in events]
            if (match_started and persistence_failure is None
                    and (args.save_biolockout_after_match_output or biolockout_store is not None)):
                try:
                    match_event_summaries = reconcile_match_lockout(
                        events, summarize_match_event,
                        lambda: len(post_match_biolockout_generations),
                        persist_match_result,
                        lambda: drain_post_cancel_service_events(sock, events),
                    )
                except Exception as error:
                    deferred_failure = f"late-result bio-lockout reconciliation failed: {error}"
            result["match_events"] = match_event_summaries
            if (
                args.save_biolockout_after_match_output
                or biolockout_store is not None
            ):
                if "post_match_save_biolockout" in result:
                    pass
                elif any(
                    event.get("event_kind") == "match_result"
                    and event.get("host_accepted_result") is True
                    for event in match_event_summaries
                ):
                    if deferred_failure is None:
                        deferred_failure = (
                            "host-accepted match result was not persisted before cleanup"
                        )
                else:
                    result["post_match_save_biolockout_skipped"] = (
                        "no host-accepted match result"
                    )
            private_match_events = {
                "schema": 1,
                "processed_flags": processed_flags,
                "events": private_json_value(events),
            }
            operations.append(
                "quality-gated match observation"
                + (" + cancel" if match_started else " (rejected)")
            )
        if args.initialize and not client_version_negotiated:
            result["set_client_version_reply"] = request(
                sock, [10, client_version]
            )
            client_version_negotiated = True
            operations.append("negotiate bridge client version")
            if api_version >= 3:
                notify(sock, [12, False])
                result["bridge_os_transaction_initial_sync"] = False
                operations.append("sync bridge OS transaction released")
        if operations:
            result["sent"] = "HELO + read-only " + ", ".join(operations)
        if args.private_inventory_output:
            if args.full_inventory:
                if not private_inventory:
                    failures = result.get("private_inventory_gate_failures", ["unknown"])
                    raise ValueError(
                        "refusing to write incomplete private inventory: "
                        + ", ".join(failures)
                    )
                write_private_json(args.private_inventory_output, private_inventory)
                result["private_inventory_written"] = True
                print(json.dumps(result, indent=2))
                return
            required = (
                args.initialize,
                args.biometric_protocol,
                args.identity_list,
                args.global_identity_list,
                args.identity_capacity,
                args.catacomb_component_state,
                args.catacomb_state,
                args.sks_lock_state,
                args.stability_check,
            )
            if not all(required):
                raise ValueError(
                    "private inventory requires all inventory queries and --stability-check"
                )
            equality_fields = (
                "identity_inventory_repeat_equal",
                "global_identity_inventory_repeat_equal",
                "identity_capacity_repeat_equal",
                "catacomb_component_repeat_equal",
                "catacomb_state_repeat_equal",
                "sks_lock_state_repeat_equal",
            )
            if not all(result.get(field) is True for field in equality_fields):
                raise ValueError("refusing to write unstable private inventory")
            if not (
                isinstance(maximum_output, bytes)
                and len(maximum_output) == 4
                and isinstance(free_output, bytes)
                and len(free_output) == 4
                and isinstance(uuid_output, bytes)
                and len(uuid_output) == 16
                and isinstance(hash_output, bytes)
                and len(hash_output) == 33
                and isinstance(catacomb_state_output, bytes)
            ):
                raise ValueError("refusing to write incomplete private inventory")
            bridge_boot_uuid = helo.get("BootSessionUUID")
            try:
                bridge_boot_uuid = str(uuid.UUID(bridge_boot_uuid))
            except (AttributeError, TypeError, ValueError):
                bridge_boot_uuid = None
            private = {
                "schema_version": 1,
                "connection_generation": connection_generation,
                "bridge_boot_uuid": bridge_boot_uuid,
                "biometric_protocol_version": result.get(
                    "biometric_protocol_version"
                ),
                "apple_uid": args.macos_user_id,
                "per_user_identity_records": [
                    {
                        "user_id": struct.unpack_from("<I", record)[0],
                        "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                    }
                    for record in enrolled_identity_records
                ],
                "global_identity_records": [
                    {
                        "user_id": struct.unpack_from("<I", record)[0],
                        "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                        "group_type": struct.unpack_from("<I", record, 20)[0],
                        "group_uuid": str(uuid.UUID(bytes=record[24:40])),
                    }
                    for record in global_identity_records
                ],
                "maximum_capacity": struct.unpack("<I", maximum_output)[0],
                "configured_user_free_capacity": struct.unpack("<I", free_output)[0],
                "catacomb": {
                    "uuid": str(uuid.UUID(bytes=uuid_output)),
                    "present": bool(hash_output[0]),
                    "hash": hash_output[1:].hex(),
                    "global_state": catacomb_state_output.hex(),
                },
                "sks_lock_state_raw": result.get("sks_lock_state"),
                "double_collection_equal": True,
            }
            write_private_json(args.private_inventory_output, private)
            result["private_inventory_written"] = True
        if args.private_match_events_output:
            if args.match_seconds is None or private_match_events is None:
                raise ValueError(
                    "--private-match-events-output requires --match-seconds"
                )
            write_private_json(
                args.private_match_events_output, private_match_events
            )
            result["private_match_events_written"] = True
        print(json.dumps(result, indent=2))
        if deferred_failure:
            raise RuntimeError(deferred_failure)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        reason = public_failure_message(error)
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "probe_failed": True,
                    "failure_reason": reason,
                    "identifiers_redacted": True,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        print(
            f"bridge-xpc-probe: {reason}",
            file=sys.stderr,
        )
        raise SystemExit(1)
