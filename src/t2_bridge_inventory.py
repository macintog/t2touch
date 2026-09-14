# SPDX-License-Identifier: GPL-2.0-only
"""Stable private E0 inventory over one already-owned Bridge connection."""

from __future__ import annotations

import struct
import uuid
from typing import Protocol

import t2_bridge_wire as wire
import t2_catacomb_protocol as catacomb_protocol
import t2_enrollment_protocol as enrollment_protocol


class BridgeInventoryError(RuntimeError):
    """Raised when a same-connection E0 snapshot cannot be trusted."""


class PreclientServiceEventError(BridgeInventoryError):
    """A read-only preclient query consumed an unrelated service callback."""


class InventoryServiceEventError(BridgeInventoryError):
    """A stable read-only inventory command consumed an unrelated callback."""


def require_preparation_service_events(
    events: object, apple_user_id: int | None = None
) -> None:
    """Admit exact non-mutating callbacks without using their private data.

    T1Bridge keeps callback transport separate from operation state.  T2
    adapts that boundary narrowly: SKS lock notifications remain ambient, and
    recovered no-op phase plus presence-state statuses may arrive after a
    failed operation has closed.  None can advance or select an identity;
    progress, continue, retry, terminal, result, and unknown events still fail.
    """
    if (
        apple_user_id is not None
        and (
            type(apple_user_id) is not int
            or isinstance(apple_user_id, bool)
            or not 0 <= apple_user_id <= 0xFFFFFFFF
        )
    ) or type(events) is not list:
        raise BridgeInventoryError("preparation service events are malformed")
    for value in events:
        if (
            type(value) is not list
            or len(value) != 5
            or value[0] != 9
            or value[1] != enrollment_protocol.BRIDGE_SERVICE_STATUS
            or type(value[2]) is not bytes
        ):
            raise BridgeInventoryError("preparation service event envelope is invalid")
        try:
            event = enrollment_protocol.parse_service_event(value[2])
            if event.envelope_type == enrollment_protocol.SERVICE_SKS_LOCK_STATE:
                enrollment_protocol.validate_sks_lock_state_payload(event)
                accepted = (
                    event.version == 1
                    and event.ordinal == 0
                    and len(event.payload) == 22
                )
            elif (
                event.envelope_type == enrollment_protocol.SERVICE_STATUS
                and event.version in (1, 2)
                and (
                    event.ordinal in (63, 64)
                    or any(
                        lower <= event.ordinal <= upper
                        for lower, upper in (
                            enrollment_protocol.EXACT_NOOP_PHASE_RANGES
                        )
                    )
                )
            ):
                enrollment_protocol.validate_status_payload(event)
                accepted = True
            else:
                accepted = False
        except enrollment_protocol.EnrollmentProtocolError as error:
            raise BridgeInventoryError(
                "preparation service event is malformed"
            ) from error
        if not accepted:
            raise BridgeInventoryError(
                "preparation emitted a state-changing service event"
            )


class InventoryLease(Protocol):
    connection_generation: str
    peer_boot_uuid: str | None

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]: ...

    def invalidate(self) -> None: ...


COMMANDS = (
    ("protocol", 0x01, b"", 4),
    ("global_identities", 0x51, b"", 40 * 10),
    ("maximum_capacity", 0x0F, b"", 4),
    ("per_user_identities", 0x42, None, 20 * 10),
    ("free_capacity", 0x41, None, 4),
    ("catacomb_uuid", 0x38, None, 16),
    ("catacomb_hash", 0x3A, None, 33),
    ("catacomb_state", 0x3C, b"", 4096),
    ("sks_lock_state", 0x27, None, 4),
)


def _reply_output(
    reply: object,
    name: str,
    *,
    allow_nonzero: bool = False,
    allow_nil_empty: bool = False,
) -> bytes:
    if type(reply) is not list or len(reply) != 2:
        raise BridgeInventoryError(f"{name} reply is malformed")
    status, output = reply
    if name in {"global_identities", "per_user_identities"} and status == 0:
        # bkremoted represents an Objective-C nil output with one exact fixed
        # CFString sentinel.  Identity-list commands use nil for a successful
        # empty list; no other command or string is normalized here.
        if wire.is_biometric_nil_output(output):
            output = b""
    if (
        type(status) is not int
        or isinstance(status, bool)
        or not -(2**31) <= status < 2**32
    ):
        raise BridgeInventoryError(f"{name} reply status is malformed")
    # D151 proved only that the empty global-list output was non-bytes. The
    # known fixed bkremoted sentinel is the narrow falsifiable hypothesis;
    # normalize that exact value and nothing else.
    if wire.is_biometric_nil_output(output):
        if status == 0 and allow_nil_empty:
            return b""
        raise BridgeInventoryError(f"{name} reply output is not bytes")
    if type(output) is not bytes:
        output_kind = (
            "null"
            if output is None
            else "unrecognized string"
            if type(output) is str
            else "unsupported type"
        )
        raise BridgeInventoryError(f"{name} reply output is {output_kind}")
    if status != 0 and not allow_nonzero:
        raise BridgeInventoryError(
            f"{name} reply returned status 0x{status & 0xffffffff:08x}"
        )
    return output


def _collect_once(
    lease: InventoryLease, apple_user_id: int, generation: str
) -> dict[str, tuple[int, bytes]]:
    uid = struct.pack("<I", apple_user_id)
    snapshot: dict[str, tuple[int, bytes]] = {}
    for name, command, static_data, capacity in COMMANDS:
        data = uid if static_data is None else static_data
        reply, events = lease.biometric_command(
            command,
            # These inventory codecs retain command-wrapper version 1 even
            # when command 0x51 attests biometric protocol version 2.
            version=1,
            value=0,
            data=data,
            output_capacity=capacity,
        )
        if lease.connection_generation != generation:
            raise BridgeInventoryError("Bridge generation changed during E0")
        try:
            require_preparation_service_events(events, apple_user_id)
        except BridgeInventoryError as error:
            raise BridgeInventoryError(
                f"{name} emitted an unexpected service event"
            ) from error
        output = _reply_output(
            reply,
            name,
            allow_nonzero=name in {"protocol", "catacomb_uuid", "catacomb_hash"},
        )
        status = reply[0]
        if name == "protocol" and len(output) != 4:
            for _attempt in range(2):
                retry, retry_events = lease.biometric_command(
                    command,
                    version=1,
                    value=0,
                    data=data,
                    output_capacity=capacity,
                )
                if lease.connection_generation != generation:
                    raise BridgeInventoryError("Bridge generation changed during E0")
                require_preparation_service_events(retry_events, apple_user_id)
                output = _reply_output(retry, name, allow_nonzero=True)
                status = retry[0]
                if len(output) == 4:
                    break
        snapshot[name] = (status, output)
    return snapshot


def attest_preclient_protocol(lease: InventoryLease, apple_user_id: int) -> None:
    """Issue the one exact sensor protocol query required before API selection."""
    try:
        generation = lease.connection_generation
        parsed_generation = uuid.UUID(generation)
        if str(parsed_generation) != generation:
            raise BridgeInventoryError("Bridge generation is not canonical")
    except (AttributeError, TypeError, ValueError) as error:
        raise BridgeInventoryError("Bridge generation is invalid") from error

    try:
        output = b""
        for _attempt in range(3):
            reply, events = lease.biometric_command(
                0x01,
                version=1,
                value=0,
                data=b"",
                output_capacity=4,
            )
            if lease.connection_generation != generation:
                raise BridgeInventoryError(
                    "Bridge generation changed during protocol preflight"
                )
            require_preparation_service_events(events, apple_user_id)
            output = _reply_output(reply, "protocol", allow_nonzero=True)
            if len(output) == 4:
                break
        if len(output) != 4:
            raise BridgeInventoryError("protocol preflight reply length is invalid")
    except BaseException as error:
        try:
            lease.invalidate()
        except BaseException:
            pass
        if isinstance(error, BridgeInventoryError):
            raise
        raise BridgeInventoryError("protocol preflight failed") from error


def prepare_empty_native_components(
    lease: InventoryLease, apple_user_id: int
) -> None:
    """Select the missing master and user Catacomb components before API v2.

    Exact 24G830 maps performNoCatacombCommand: to command 0x31 with one
    uint32 input and no output. Pinned T1Bridge commit 7003b8d9f791 adapts the
    master-then-user component order only; its transport and v1 workflow are
    not used here.
    """
    if (
        type(apple_user_id) is not int
        or not 0 <= apple_user_id <= 0x7FFFFFFF
    ):
        raise BridgeInventoryError("Apple user ID is outside signed component range")
    try:
        generation = lease.connection_generation
        parsed_generation = uuid.UUID(generation)
        if str(parsed_generation) != generation:
            raise BridgeInventoryError("Bridge generation is not canonical")
    except (AttributeError, TypeError, ValueError) as error:
        raise BridgeInventoryError("Bridge generation is invalid") from error

    try:
        for component in (0xFFFFFFFF, apple_user_id):
            reply, events = lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", component),
                output_capacity=0,
            )
            if lease.connection_generation != generation:
                raise BridgeInventoryError(
                    "Bridge generation changed during empty-component preparation"
                )
            if type(events) is not list or events:
                raise BridgeInventoryError(
                    "empty-component preparation emitted an unexpected service event"
                )
            if type(reply) is not list or len(reply) not in (1, 2):
                raise BridgeInventoryError(
                    "empty-component preparation reply is malformed"
                )
            status = reply[0]
            if type(status) is not int or isinstance(status, bool) or status != 0:
                raise BridgeInventoryError(
                    "empty-component preparation returned a failure status"
                )
            if len(reply) == 2:
                output = reply[1]
                if output not in (None, b"") and not wire.is_biometric_nil_output(output):
                    raise BridgeInventoryError(
                        "empty-component preparation returned unexpected output"
                    )
    except BaseException as error:
        try:
            lease.invalidate()
        except BaseException:
            pass
        if isinstance(error, BridgeInventoryError):
            raise
        raise BridgeInventoryError("empty-component preparation failed") from error


def _records(output: bytes, size: int, name: str) -> tuple[bytes, ...]:
    if len(output) % size:
        raise BridgeInventoryError(f"{name} record bytes are malformed")
    return tuple(output[offset : offset + size] for offset in range(0, len(output), size))


def collect_stable_private_inventory(
    lease: InventoryLease, apple_user_id: int
) -> dict[str, object]:
    """Collect and validate two complete snapshots without releasing the lease."""
    if type(apple_user_id) is not int or not 0 <= apple_user_id <= 0xFFFFFFFF:
        raise BridgeInventoryError("Apple user ID is outside uint32 range")
    try:
        generation = lease.connection_generation
        parsed_generation = uuid.UUID(generation)
        if str(parsed_generation) != generation:
            raise BridgeInventoryError("Bridge generation is not canonical")
    except (AttributeError, TypeError, ValueError) as error:
        raise BridgeInventoryError("Bridge generation is invalid") from error
    dispatched = False
    try:
        dispatched = True
        first = _collect_once(lease, apple_user_id, generation)
        second = _collect_once(lease, apple_user_id, generation)
        if first != second:
            raise BridgeInventoryError("E0 inventory changed between collections")

        protocol_status, protocol_output = first["protocol"]
        global_records = _records(first["global_identities"][1], 40, "global identity")
        user_records = _records(first["per_user_identities"][1], 20, "per-user identity")
        configured_global = {
            record[:20]
            for record in global_records
            if struct.unpack_from("<I", record)[0] == apple_user_id
        }
        if configured_global != set(user_records):
            raise BridgeInventoryError("global and per-user identities disagree")
        if any(struct.unpack_from("<I", record)[0] != apple_user_id for record in user_records):
            raise BridgeInventoryError("per-user inventory contains another Apple user")
        explicit_v2 = (
            protocol_status == 0
            and len(protocol_output) == 4
            and struct.unpack("<I", protocol_output)[0] == 2
        )
        if not explicit_v2:
            # Successful, structurally valid command 0x51 is protocol-v2-only.
            if first["global_identities"][0] != 0:
                raise BridgeInventoryError("biometric protocol v2 is not attested")

        maximum_output = first["maximum_capacity"][1]
        free_output = first["free_capacity"][1]
        catacomb_uuid = first["catacomb_uuid"][1]
        catacomb_hash = first["catacomb_hash"][1]
        catacomb_state = first["catacomb_state"][1]
        sks_state = first["sks_lock_state"][1]
        if len(maximum_output) != 4 or len(free_output) != 4:
            raise BridgeInventoryError("capacity reply length is invalid")
        if len(catacomb_uuid) != 16:
            raise BridgeInventoryError("Catacomb UUID reply is invalid")
        if len(catacomb_hash) != 33:
            raise BridgeInventoryError("Catacomb hash reply is invalid")
        catacomb_missing = (
            first["catacomb_uuid"][0] == 22
            and first["catacomb_hash"][0] == 22
            and not any(catacomb_uuid)
            and not any(catacomb_hash)
            and not global_records
            and not user_records
        )
        if (
            not catacomb_missing
            and (
                first["catacomb_uuid"][0] != 0
                or first["catacomb_hash"][0] != 0
            )
        ):
            raise BridgeInventoryError("Catacomb metadata status is invalid")
        if not any(catacomb_uuid) and (
            global_records or user_records or catacomb_hash[0] != 0
        ):
            raise BridgeInventoryError("Catacomb UUID reply is inconsistent")
        try:
            catacomb_states = catacomb_protocol.parse_user_states(catacomb_state)
        except catacomb_protocol.CatacombProtocolError as error:
            raise BridgeInventoryError("Catacomb state reply is invalid") from error
        master = catacomb_protocol.CatacombComponent.master()
        selected = catacomb_protocol.CatacombComponent.user(apple_user_id)
        master_count = sum(record.component == master for record in catacomb_states)
        selected_count = sum(record.component == selected for record in catacomb_states)
        expected_component_counts = master_count == 1 and selected_count == (
            0 if catacomb_missing else 1
        )
        if not expected_component_counts or (
            catacomb_missing and len(catacomb_states) != 1
        ):
            raise BridgeInventoryError(
                "Catacomb state does not contain unique master and selected-user records"
            )
        if len(sks_state) != 4:
            raise BridgeInventoryError("SKS state reply is invalid")
        maximum = struct.unpack("<I", maximum_output)[0]
        free = struct.unpack("<I", free_output)[0]
        # Command 0x0f is device maximum while 0x41 is scoped to the selected
        # user/accessory group. Live hardware confirms they are bounded but do
        # not satisfy a simple per-user used + free == device maximum equation.
        if maximum > 64 or free > maximum or len(user_records) > maximum:
            raise BridgeInventoryError("identity capacity is inconsistent")

        boot_uuid = lease.peer_boot_uuid
        if boot_uuid is not None:
            try:
                if str(uuid.UUID(boot_uuid)) != boot_uuid:
                    raise BridgeInventoryError("Bridge boot UUID is not canonical")
            except (AttributeError, TypeError, ValueError) as error:
                raise BridgeInventoryError("Bridge boot UUID is invalid") from error
        return {
            "schema_version": 1,
            "connection_generation": generation,
            "bridge_boot_uuid": boot_uuid,
            "biometric_protocol_version": 2,
            "apple_uid": apple_user_id,
            "per_user_identity_records": [
                {
                    "user_id": struct.unpack_from("<I", record)[0],
                    "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                }
                for record in user_records
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
            "maximum_capacity": maximum,
            "configured_user_free_capacity": free,
            "catacomb": {
                "uuid": str(uuid.UUID(bytes=catacomb_uuid)),
                "present": bool(catacomb_hash[0]),
                "hash": catacomb_hash[1:].hex(),
                "global_state": catacomb_state.hex(),
                "user_states": [
                    {
                        "kind": record.component.kind.value,
                        "user_id": record.component.user_id,
                        "state": record.state,
                        "needs_save": record.needs_save,
                    }
                    for record in catacomb_states
                ],
            },
            "sks_lock_state_raw": struct.unpack("<I", sks_state)[0],
            "double_collection_equal": True,
        }
    except BaseException as error:
        if dispatched:
            try:
                lease.invalidate()
            except BaseException:
                pass
        if isinstance(error, BridgeInventoryError):
            raise
        raise BridgeInventoryError("same-connection E0 collection failed") from error
