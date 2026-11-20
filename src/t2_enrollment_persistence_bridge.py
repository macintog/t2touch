# SPDX-License-Identifier: GPL-2.0-only
"""Route one enrollment persistence plan across its two SEP protocols."""

from __future__ import annotations

from enum import Enum

import t2_biolockout_bridge
import t2_biolockout_protocol
import t2_catacomb_bridge
import t2_catacomb_protocol
import t2_enrollment_protocol as protocol


class EnrollmentPersistenceBridgeError(RuntimeError):
    pass


class PostCaptureLease:
    """Route known asynchronous notifications separately from save replies."""

    # Other serviceStatus readers treat the two plist trailer fields as opaque.
    # Captured-format fixtures use nulls there as well as zeroes.

    def __init__(self, lease):
        self._lease = lease

    @property
    def connection_generation(self):
        return self._lease.connection_generation

    def invalidate(self):
        self._lease.invalidate()

    @staticmethod
    def _scalar(value) -> str:
        # Never format arbitrary objects; only routing scalars are printable.
        if value is None or type(value) is int:
            return str(value)
        return f"a {type(value).__name__}"

    def _envelope_defect(self, callback) -> str | None:
        """Describe a wrapper mismatch using kinds, counts, and lengths only.

        Callback payload bytes are never formatted into the returned text.
        """
        if type(callback) is not list:
            return f"callback is {type(callback).__name__}, not a 5-item list"
        if len(callback) != 5:
            return f"callback is a {len(callback)}-item list, expected 5"
        if callback[0] != 9:
            return (
                f"callback method is {self._scalar(callback[0])}, expected 9"
            )
        if callback[1] != protocol.BRIDGE_SERVICE_STATUS:
            return (
                f"callback selector is {self._scalar(callback[1])}, expected "
                f"{protocol.BRIDGE_SERVICE_STATUS}"
            )
        data = callback[2]
        if type(data) is not bytes:
            return f"callback event data is {type(data).__name__}, expected bytes"
        low = protocol.SERVICE_HEADER.size
        high = protocol.SERVICE_HEADER.size + protocol.MAX_EVENT_PAYLOAD
        if not low <= len(data) <= high:
            return (
                f"callback event data is {len(data)} bytes, "
                f"expected {low} to {high} bytes"
            )
        return None

    def biometric_command(self, command, **kwargs):
        result = self._lease.biometric_command(command, **kwargs)
        if type(result) is not tuple or len(result) != 2:
            return result
        reply, events = result
        if type(events) is not list or not events:
            return result
        for callback in events:
            defect = self._envelope_defect(callback)
            if defect is not None:
                # The defect text names only wrapper kinds, counts, lengths,
                # and routing scalars, so it can never echo callback content.
                raise EnrollmentPersistenceBridgeError(
                    f"unexpected save callback envelope: {defect}"
                )
            try:
                event = protocol.parse_service_event(callback[2])
            except protocol.EnrollmentProtocolError as error:
                # Protocol framing messages carry no callback data.
                raise EnrollmentPersistenceBridgeError(
                    f"save callback event header is invalid: {error}"
                ) from error
            if event.envelope_type == protocol.SERVICE_STATISTICS:
                try:
                    protocol.validate_statistics_payload(event)
                except protocol.EnrollmentProtocolError as error:
                    raise EnrollmentPersistenceBridgeError(str(error)) from error
                # Telemetry has no bearing on persistence, even if repeated.
                continue
            # Phase 53 is in the recovered enrollment no-op domain. It was
            # also observed interleaved with a Catacomb confirmation reply.
            confirm_phase = (
                command == t2_catacomb_protocol.COMMAND_CONFIRM_SAVE_CATACOMB
                and event.version == 1 and event.ordinal == 53
            )
            presence = event.version in (1, 2) and event.ordinal in (63, 64)
            if (event.envelope_type != protocol.SERVICE_STATUS or
                    not (presence or confirm_phase) or
                    (confirm_phase and event.payload !=
                     protocol.STATUS_PAYLOAD_HEADER.pack(event.ordinal, 0))):
                # Report only protocol header fields, never callback data.
                raise EnrollmentPersistenceBridgeError(
                    f"save callback type={event.envelope_type:#x} "
                    f"version={event.version} ordinal={event.ordinal} "
                    f"payload_length={len(event.payload)}"
                )
            if presence:
                try:
                    protocol.validate_status_payload(event)
                except protocol.EnrollmentProtocolError as error:
                    raise EnrollmentPersistenceBridgeError(
                        "save presence callback has invalid status framing"
                    ) from error
        # The lower layer has correlated the reply by request ID. The original
        # save adapter still checks its status, shape, and generation.
        return reply, []


class RouteState(Enum):
    IDLE = "idle"
    CATACOMB = "catacomb"
    BIOLOCKOUT_PREPARED = "biolockout-prepared"
    BIOLOCKOUT_CAPTURED = "biolockout-captured"


class EnrollmentPersistenceBridgeTransport:
    """One same-generation transport for user/master then bio-lockout."""

    def __init__(self, lease, *, protocol_version: int, connection_generation: str):
        self._catacomb = t2_catacomb_bridge.CatacombBridgeTransport(
            lease,
            protocol_version=protocol_version,
            connection_generation=connection_generation,
        )
        self._biolockout = t2_biolockout_bridge.BioLockoutBridgeTransport(
            lease, connection_generation=connection_generation
        )
        self._state = RouteState.IDLE

    @property
    def state(self) -> RouteState:
        return self._state

    @staticmethod
    def _is_biolockout(descriptor: bytes) -> bool:
        return descriptor == t2_biolockout_protocol.PERSISTENCE_DESCRIPTOR

    def prepare(self, descriptor: bytes) -> tuple[int, int]:
        if self._state is not RouteState.IDLE:
            raise EnrollmentPersistenceBridgeError(
                "enrollment persistence prepare is out of order"
            )
        if self._is_biolockout(descriptor):
            self._state = RouteState.BIOLOCKOUT_PREPARED
            return 0, t2_biolockout_protocol.OUTPUT_CAPACITY
        self._state = RouteState.CATACOMB
        try:
            return self._catacomb.prepare(descriptor)
        except BaseException:
            self._state = RouteState.IDLE
            raise

    def complete(self, descriptor: bytes) -> tuple[int, bytearray]:
        if self._is_biolockout(descriptor):
            if self._state is not RouteState.BIOLOCKOUT_PREPARED:
                raise EnrollmentPersistenceBridgeError(
                    "bio-lockout capture is out of order"
                )
            output = self._biolockout.capture()
            self._state = RouteState.BIOLOCKOUT_CAPTURED
            return 0, output
        if self._state is not RouteState.CATACOMB:
            raise EnrollmentPersistenceBridgeError(
                "Catacomb complete is out of order"
            )
        return self._catacomb.complete(descriptor)

    def confirm(self, descriptor: bytes) -> int:
        if self._is_biolockout(descriptor):
            if self._state is not RouteState.BIOLOCKOUT_CAPTURED:
                raise EnrollmentPersistenceBridgeError(
                    "bio-lockout host confirmation is out of order"
                )
            self._state = RouteState.IDLE
            return 0
        if self._state is not RouteState.CATACOMB:
            raise EnrollmentPersistenceBridgeError(
                "Catacomb confirm is out of order"
            )
        status = self._catacomb.confirm(descriptor)
        self._state = RouteState.IDLE
        return status
