# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed Mesa readiness sequence immediately before enrollment.

This adapts the non-destructive part of T1Bridge's working enrollment path:
select the authorized user, refresh Catacomb state twice around an identity
read, and verify protected policy.  It deliberately does not rebind a user or
write policy; an unexpected live state stops before enrollment dispatch.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Protocol

import t2_bridge_inventory
import t2_bridge_wire as wire
import t2_catacomb_protocol as catacomb_protocol
import t2_enrollment_protocol as enrollment_protocol


DAEMON_INFO_SIZE = 23
IDENTITY_RECORD_SIZE = 20
MAX_COMPONENTS = 64
MAX_IDENTITIES = 64
SECURELY_LOADED_STATE_BITS = 0x03
CALIBRATION_STATUS_DETAIL_LENGTHS = {80: 0, 64: 36, 94: 0}


class MesaEnrollmentPreparationError(RuntimeError):
    """Raised when Mesa is not demonstrably ready for enrollment."""


class MesaLease(Protocol):
    connection_generation: str

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]: ...

    def bridge_request(self, payload: object) -> tuple[object, list[object]]: ...

    def invalidate(self) -> None: ...


@dataclass(frozen=True, repr=False)
class MesaEnrollmentReadiness:
    component_count: int
    identity_capacity: int
    calibration_loaded: bool
    selected_user_secure: bool
    identity_count: int
    system_policy_ready: bool
    user_policy_ready: bool

    def __repr__(self) -> str:
        return (
            "MesaEnrollmentReadiness(component_count="
            f"{self.component_count}, identity_capacity={self.identity_capacity}, "
            f"calibration_loaded={self.calibration_loaded}, "
            f"selected_user_secure={self.selected_user_secure}, "
            f"identity_count={self.identity_count}, "
            f"system_policy_ready={self.system_policy_ready}, "
            f"user_policy_ready={self.user_policy_ready})"
        )


def _require_calibration_service_events(events: object) -> None:
    """Admit only exact notifications observed during command-0x20 loading."""
    if type(events) is not list:
        raise t2_bridge_inventory.BridgeInventoryError(
            "calibration service events are malformed"
        )
    for value in events:
        if (
            type(value) is not list
            or len(value) != 5
            or value[0] != 9
            or value[1] != enrollment_protocol.BRIDGE_SERVICE_STATUS
            or type(value[2]) is not bytes
        ):
            raise t2_bridge_inventory.BridgeInventoryError(
                "calibration service event envelope is invalid"
            )
        try:
            event = enrollment_protocol.parse_service_event(value[2])
            if event.envelope_type == enrollment_protocol.SERVICE_SKS_LOCK_STATE:
                t2_bridge_inventory.require_preparation_service_events([value])
                continue
            enrollment_protocol.validate_status_payload(event)
        except (
            enrollment_protocol.EnrollmentProtocolError,
            t2_bridge_inventory.BridgeInventoryError,
        ) as error:
            raise t2_bridge_inventory.BridgeInventoryError(
                "calibration service event is malformed"
            ) from error
        expected_detail_length = CALIBRATION_STATUS_DETAIL_LENGTHS.get(event.ordinal)
        if (
            event.envelope_type != enrollment_protocol.SERVICE_STATUS
            or event.version != 1
            or expected_detail_length is None
            or len(event.payload) != (
                enrollment_protocol.STATUS_PAYLOAD_HEADER.size
                + expected_detail_length
            )
        ):
            raise t2_bridge_inventory.BridgeInventoryError(
                "calibration emitted an unsupported service event"
            )


def _command(
    lease: MesaLease,
    generation: str,
    command: int,
    data: bytes,
    output_capacity: int,
    label: str,
    *,
    value: int = 0,
    calibration_events: bool = False,
) -> bytes:
    reply, events = lease.biometric_command(
        command,
        version=1,
        value=value,
        data=data,
        output_capacity=output_capacity,
    )
    if lease.connection_generation != generation:
        raise MesaEnrollmentPreparationError(
            "Bridge generation changed during Mesa enrollment preparation"
        )
    try:
        if calibration_events:
            _require_calibration_service_events(events)
        else:
            t2_bridge_inventory.require_preparation_service_events(events)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise MesaEnrollmentPreparationError(
            f"{label} emitted an unexpected service event"
        ) from error
    if type(reply) is not list or len(reply) != 2 or reply[0] != 0:
        raise MesaEnrollmentPreparationError(f"{label} did not succeed")
    output = reply[1]
    if wire.is_biometric_nil_output(output):
        output = b""
    if type(output) is not bytes:
        raise MesaEnrollmentPreparationError(f"{label} output is malformed")
    return output


def _select_user(lease: MesaLease, generation: str, apple_user_id: int) -> None:
    output = _command(
        lease,
        generation,
        0x31,
        struct.pack("<I", apple_user_id),
        0,
        "Mesa user selection",
    )
    if output:
        raise MesaEnrollmentPreparationError(
            "Mesa user selection returned unexpected data"
        )


def _daemon_info(lease: MesaLease, generation: str) -> tuple[int, int, bool]:
    output = _command(
        lease,
        generation,
        0x28,
        b"",
        DAEMON_INFO_SIZE,
        "Mesa daemon-info read",
    )
    if len(output) != DAEMON_INFO_SIZE:
        raise MesaEnrollmentPreparationError("Mesa daemon-info length is invalid")
    component_count, identity_capacity = struct.unpack_from("<II", output)
    calibration_flag = output[22]
    if component_count > MAX_COMPONENTS:
        raise MesaEnrollmentPreparationError("Mesa component count is implausible")
    if not 1 <= identity_capacity <= MAX_IDENTITIES:
        raise MesaEnrollmentPreparationError("Mesa identity capacity is implausible")
    if calibration_flag not in (0, 1):
        raise MesaEnrollmentPreparationError(
            "Mesa calibration-loaded flag is invalid"
        )
    return component_count, identity_capacity, calibration_flag == 1


def _sensor_readiness(lease: MesaLease, generation: str) -> bool:
    output = _command(
        lease, generation, 0x53, b"", 1, "Mesa sensor-readiness read"
    )
    if len(output) != 1 or output[0] not in (0, 1):
        raise MesaEnrollmentPreparationError(
            "Mesa sensor-readiness output is invalid"
        )
    return output[0] == 1


def _reset_sensor(lease: MesaLease, generation: str) -> None:
    for _attempt in range(3):
        reply, events = lease.biometric_command(
            0x02,
            version=1,
            value=2,
            data=b"",
            output_capacity=0,
        )
        if lease.connection_generation != generation:
            raise MesaEnrollmentPreparationError(
                "Bridge generation changed during sensor reset"
            )
        try:
            t2_bridge_inventory.require_preparation_service_events(events)
        except t2_bridge_inventory.BridgeInventoryError as error:
            raise MesaEnrollmentPreparationError(
                "Mesa sensor reset returned malformed service events"
            ) from error
        if type(reply) is not list or not reply or type(reply[0]) is not int:
            raise MesaEnrollmentPreparationError("Mesa sensor reset reply is malformed")
        if reply[0] == 0:
            if len(reply) == 2:
                output = reply[1]
                if not wire.is_biometric_nil_output(output) and output not in (None, b""):
                    raise MesaEnrollmentPreparationError(
                        "Mesa sensor reset returned unexpected data"
                    )
            elif len(reply) != 1:
                raise MesaEnrollmentPreparationError(
                    "Mesa sensor reset reply is malformed"
                )
            return
    raise MesaEnrollmentPreparationError("Mesa sensor reset did not succeed")


def _calibration_blob(
    lease: MesaLease, generation: str
) -> tuple[bytes, int]:
    for method, source in ((11, 3), (5, 2)):
        reply, events = lease.bridge_request([method])
        if lease.connection_generation != generation:
            raise MesaEnrollmentPreparationError(
                "Bridge generation changed during calibration lookup"
            )
        try:
            t2_bridge_inventory.require_preparation_service_events(events)
        except t2_bridge_inventory.BridgeInventoryError as error:
            raise MesaEnrollmentPreparationError(
                "calibration lookup returned malformed service events"
            ) from error
        if type(reply) is not list or len(reply) != 1:
            raise MesaEnrollmentPreparationError(
                "calibration lookup reply is malformed"
            )
        blob = reply[0]
        if type(blob) is bytes and 0 < len(blob) <= 1024 * 1024:
            return blob, source
        if blob is not None:
            raise MesaEnrollmentPreparationError(
                "calibration lookup returned malformed data"
            )
    raise MesaEnrollmentPreparationError("no usable sensor calibration is available")


def _prepare_sensor(lease: MesaLease, generation: str) -> tuple[int, int]:
    if not _sensor_readiness(lease, generation):
        raise MesaEnrollmentPreparationError("Mesa sensor is not ready")
    _reset_sensor(lease, generation)
    sensor_info = _command(
        lease,
        generation,
        0x35,
        b"",
        12,
        "Mesa sensor-info read",
    )
    if len(sensor_info) != 12:
        raise MesaEnrollmentPreparationError("Mesa sensor-info length is invalid")
    component_count, identity_capacity, calibrated = _daemon_info(lease, generation)
    if not calibrated:
        blob, source = _calibration_blob(lease, generation)
        output = _command(
            lease,
            generation,
            0x20,
            blob,
            0,
            "Mesa calibration load",
            value=source,
            calibration_events=True,
        )
        if output:
            raise MesaEnrollmentPreparationError(
                "Mesa calibration load returned unexpected data"
            )
        after_components, after_capacity, calibrated = _daemon_info(lease, generation)
        if (
            after_components != component_count
            or after_capacity != identity_capacity
        ):
            raise MesaEnrollmentPreparationError(
                "Mesa daemon info changed during calibration"
            )
    if not calibrated:
        raise MesaEnrollmentPreparationError("Mesa calibration is not loaded")
    cancel_output = _command(
        lease,
        generation,
        0x0C,
        b"",
        0,
        "Mesa residual-operation cancellation",
    )
    if cancel_output:
        raise MesaEnrollmentPreparationError(
            "Mesa residual-operation cancellation returned unexpected data"
        )
    return component_count, identity_capacity


def _states(
    lease: MesaLease, generation: str, component_count: int
) -> tuple[catacomb_protocol.CatacombState, ...]:
    output = _command(
        lease,
        generation,
        0x3C,
        b"",
        (component_count + 1) * 8,
        "Mesa Catacomb-state read",
    )
    try:
        states = catacomb_protocol.parse_user_states(output)
    except catacomb_protocol.CatacombProtocolError as error:
        raise MesaEnrollmentPreparationError(
            "Mesa Catacomb-state output is malformed"
        ) from error
    if len(states) > component_count + 1:
        raise MesaEnrollmentPreparationError(
            "Mesa Catacomb-state count exceeds daemon capacity"
        )
    return states


def _require_secure_selected_user(
    states: tuple[catacomb_protocol.CatacombState, ...], apple_user_id: int
) -> None:
    selected = catacomb_protocol.CatacombComponent.user(apple_user_id)
    matching = [record for record in states if record.component == selected]
    if len(matching) != 1 or (
        matching[0].state & SECURELY_LOADED_STATE_BITS
    ) != SECURELY_LOADED_STATE_BITS:
        raise MesaEnrollmentPreparationError(
            "authorized Mesa user is not securely loaded"
        )


def _identities(
    lease: MesaLease, generation: str, apple_user_id: int, capacity: int
) -> int:
    output = _command(
        lease,
        generation,
        0x42,
        struct.pack("<I", apple_user_id),
        capacity * IDENTITY_RECORD_SIZE,
        "Mesa identity read",
    )
    if len(output) % IDENTITY_RECORD_SIZE:
        raise MesaEnrollmentPreparationError("Mesa identity output is malformed")
    for offset in range(0, len(output), IDENTITY_RECORD_SIZE):
        if struct.unpack_from("<I", output, offset)[0] != apple_user_id:
            raise MesaEnrollmentPreparationError(
                "Mesa returned an identity for another user"
            )
    return len(output) // IDENTITY_RECORD_SIZE


def _protected_policy(
    lease: MesaLease, generation: str, apple_user_id: int
) -> tuple[bool, bool]:
    system = _command(
        lease,
        generation,
        0x43,
        b"",
        28,
        "Mesa system protected-configuration read",
    )
    user = _command(
        lease,
        generation,
        0x2E,
        struct.pack("<I", apple_user_id),
        32,
        "Mesa user protected-configuration read",
    )
    if len(system) != 28 or len(user) != 32:
        raise MesaEnrollmentPreparationError(
            "Mesa protected-configuration length is invalid"
        )
    system_values = struct.unpack("<7i", system)
    user_values = struct.unpack("<8i", user)
    if any(value not in (-1, 0, 1) for value in system_values[3:]):
        raise MesaEnrollmentPreparationError(
            "Mesa system protected configuration is unrecognized"
        )
    if any(value not in (-1, 0, 1) for value in user_values):
        raise MesaEnrollmentPreparationError(
            "Mesa user protected configuration is unrecognized"
        )
    return system_values[3:] == (1, 1, 1, 1), user_values[:3] == (1, 1, 1)


def prepare_user_for_enrollment(
    lease: MesaLease,
    apple_user_id: int,
    expected_identity_count: int,
    *,
    declare_missing_user: bool = False,
) -> MesaEnrollmentReadiness:
    """Run the working native pre-enrollment sequence without persistent writes."""
    if (
        type(apple_user_id) is not int
        or isinstance(apple_user_id, bool)
        or not 0 <= apple_user_id <= 0x7FFFFFFF
    ) or type(expected_identity_count) is not int or not 0 <= expected_identity_count <= MAX_IDENTITIES:
        raise MesaEnrollmentPreparationError("Mesa user ID is outside signed range")
    try:
        generation = lease.connection_generation
        sensor_component_count, sensor_identity_capacity = _prepare_sensor(
            lease, generation
        )
        # T2 command 0x31 is performNoCatacombCommand:, not a generic user
        # selector. It establishes the missing component for first enrollment,
        # but issuing it for an existing user hides the loaded identity set and
        # leaves an empty save-dirty component (D206).
        if declare_missing_user:
            if expected_identity_count != 0:
                raise MesaEnrollmentPreparationError(
                    "a missing user cannot have existing identities"
                )
            _select_user(lease, generation, apple_user_id)

        component_count, identity_capacity, calibration_loaded = _daemon_info(
            lease, generation
        )
        if (
            component_count != sensor_component_count
            or identity_capacity != sensor_identity_capacity
        ):
            raise MesaEnrollmentPreparationError(
                "Mesa daemon info changed after sensor preparation"
            )
        first_states = _states(lease, generation, component_count)
        _require_secure_selected_user(first_states, apple_user_id)
        identity_count = _identities(
            lease, generation, apple_user_id, identity_capacity
        )

        second_component_count, second_capacity, second_calibrated = _daemon_info(
            lease, generation
        )
        if (
            second_component_count != component_count
            or second_capacity != identity_capacity
            or second_calibrated != calibration_loaded
        ):
            raise MesaEnrollmentPreparationError(
                "Mesa daemon info changed during enrollment preparation"
            )
        second_states = _states(lease, generation, second_component_count)
        _require_secure_selected_user(second_states, apple_user_id)
        if first_states != second_states:
            raise MesaEnrollmentPreparationError(
                "Mesa Catacomb state changed during enrollment preparation"
            )
        system_ready, user_ready = _protected_policy(
            lease, generation, apple_user_id
        )
        if not calibration_loaded:
            raise MesaEnrollmentPreparationError(
                "Mesa calibration is not loaded"
            )
        if identity_count != expected_identity_count:
            raise MesaEnrollmentPreparationError(
                "Mesa identity count changed before enrollment"
            )
        if not system_ready or not user_ready:
            raise MesaEnrollmentPreparationError(
                "Mesa Touch ID protected policy is not enabled"
            )
        return MesaEnrollmentReadiness(
            component_count=component_count,
            identity_capacity=identity_capacity,
            calibration_loaded=True,
            selected_user_secure=True,
            identity_count=identity_count,
            system_policy_ready=True,
            user_policy_ready=True,
        )
    except BaseException as error:
        try:
            lease.invalidate()
        except BaseException:
            pass
        if isinstance(error, MesaEnrollmentPreparationError):
            raise
        raise MesaEnrollmentPreparationError(
            "Mesa enrollment preparation failed"
        ) from error


def prepare_empty_user_for_enrollment(
    lease: MesaLease, apple_user_id: int
) -> MesaEnrollmentReadiness:
    """Compatibility wrapper for first Linux-native enrollment."""
    return prepare_user_for_enrollment(
        lease, apple_user_id, 0, declare_missing_user=True
    )
