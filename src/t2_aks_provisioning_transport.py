# SPDX-License-Identifier: GPL-2.0-only
"""Narrow owner for one kernel-gated AKS identity provisioning sequence."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import t2_aks_identity_create as codec

if TYPE_CHECKING:
    from t2_aks_provisioning_operation import PreflightAttestation


DEVICE = Path("/dev/t2-aks")
EXCHANGE_FORMAT = "=Bb2xIIIQQ"
INFO_FORMAT = "=16sIIII"
EXCHANGE_SIZE = struct.calcsize(EXCHANGE_FORMAT)
INFO_SIZE = struct.calcsize(INFO_FORMAT)


class AKSProvisioningTransportError(RuntimeError):
    def __init__(self, message: str, *, sep_status: int | None = None) -> None:
        super().__init__(message)
        self.sep_status = sep_status


def _ioc(direction: int, kind: int, number: int, size: int) -> int:
    if not 0 <= direction < 4 or not 0 <= kind < 256 or not 0 <= number < 256:
        raise ValueError("invalid ioctl field")
    if not 0 <= size < (1 << 14):
        raise ValueError("invalid ioctl size")
    return (direction << 30) | (size << 16) | (kind << 8) | number


if EXCHANGE_SIZE != 32 or INFO_SIZE != 32:
    raise RuntimeError("unexpected AKS exchange ABI size")
T2_AKS_IOC_EXCHANGE = _ioc(3, 0xA7, 0, EXCHANGE_SIZE)
T2_AKS_IOC_GET_INFO = _ioc(2, 0xA7, 1, INFO_SIZE)

T2_AKS_INFO_F_OOL_REGISTERED = 1 << 0
T2_AKS_INFO_F_ACM_REGISTERED = 1 << 1
T2_AKS_INFO_F_VERSIONED_APP_SELECTED = 1 << 3
T2_AKS_INFO_F_PROVISIONING_ENABLED = 1 << 4
T2_AKS_INFO_F_PROVISIONING_POISONED = 1 << 5
T2_AKS_INFO_F_INVENTORY_ONLY = 1 << 6
T2_AKS_INFO_F_PASSWORD_BOUND = 1 << 7
T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE = 1 << 8
T2_AKS_INFO_F_RUNTIME_POISONED = 1 << 9
T2_AKS_INFO_F_IDENTITY_SECRET_SET = 1 << 10
T2_AKS_INFO_F_REPLACEMENT_ENABLED = 1 << 11
T2_AKS_INFO_F_REPLACEMENT_ARMED = 1 << 12
_KNOWN_INFO_FLAGS = (1 << 13) - 1
_REQUIRED_INFO_FLAGS = (
    T2_AKS_INFO_F_OOL_REGISTERED
    | T2_AKS_INFO_F_ACM_REGISTERED
    | T2_AKS_INFO_F_PROVISIONING_ENABLED
)

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.ioctl.restype = ctypes.c_int


def _address(buffer: bytearray) -> int:
    if not buffer:
        return 0
    return ctypes.addressof((ctypes.c_ubyte * len(buffer)).from_buffer(buffer))


def _zero(buffer: bytearray) -> None:
    if buffer:
        ctypes.memset(_address(buffer), 0, len(buffer))


def _ioctl_mutate(fd: int, command: int, buffer: bytearray) -> None:
    """Retain kernel output when ioctl also returns an error."""
    ctypes.set_errno(0)
    result = _LIBC.ioctl(
        ctypes.c_int(fd), ctypes.c_ulong(command), ctypes.c_void_p(_address(buffer))
    )
    if result < 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))


@dataclass(frozen=True)
class _AKSInfo:
    raw: bytes
    connection_generation: str
    flags: int
    header_version: int
    provisioning_phase: int
    stable_absence_count: int


def _parse_info(raw: bytes | bytearray) -> _AKSInfo:
    if len(raw) != INFO_SIZE:
        raise AKSProvisioningTransportError("invalid AKS registration metadata")
    generation, flags, header_version, phase, absence_count = struct.unpack(
        INFO_FORMAT, raw
    )
    parsed_generation = uuid.UUID(bytes=generation)
    if (
        parsed_generation.int == 0
        or flags & ~_KNOWN_INFO_FLAGS
        or flags & _REQUIRED_INFO_FLAGS != _REQUIRED_INFO_FLAGS
        or flags
        & (
            T2_AKS_INFO_F_PROVISIONING_POISONED
            | T2_AKS_INFO_F_INVENTORY_ONLY
            | T2_AKS_INFO_F_PASSWORD_BOUND
            | T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE
            | T2_AKS_INFO_F_RUNTIME_POISONED
            | T2_AKS_INFO_F_IDENTITY_SECRET_SET
        )
        or header_version != 2
        or phase != 0
        or absence_count > 2
    ):
        raise AKSProvisioningTransportError(
            "AKS registration is not ready for identity provisioning"
        )
    return _AKSInfo(
        bytes(raw),
        str(parsed_generation),
        flags,
        header_version,
        phase,
        absence_count,
    )


class AKSProvisioningTransport:
    """Hold the exclusive AKS descriptor from create through UUID verification."""

    def __init__(self, path: Path = DEVICE) -> None:
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = self._get_info()
            if info.stable_absence_count != 0:
                raise AKSProvisioningTransportError(
                    "new AKS owner inherited stale inventory evidence"
                )
            self.connection_generation = info.connection_generation
            self._initial_info = info.raw
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def invalidate(self) -> None:
        self.close()

    def __enter__(self) -> "AKSProvisioningTransport":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get_info(self) -> _AKSInfo:
        if self.fd < 0:
            raise AKSProvisioningTransportError("AKS provisioning transport is closed")
        raw = bytearray(INFO_SIZE)
        try:
            fcntl.ioctl(self.fd, T2_AKS_IOC_GET_INFO, raw, True)
            return _parse_info(raw)
        finally:
            _zero(raw)

    def _exchange(
        self, operation: int, request: bytearray, response_capacity: int
    ) -> bytearray:
        if self.fd < 0:
            raise AKSProvisioningTransportError("AKS provisioning transport is closed")
        if type(operation) is not int or operation not in {
            0x01,
            0x02,
            0x03,
            0x05,
            0x06,
            0x21,
            0x49,
            0x51,
        }:
            raise AKSProvisioningTransportError("operation is outside the provisioning ABI")
        if (
            not isinstance(request, bytearray)
            or not request
            or len(request) > codec.MAX_BODY_BYTES
            or not 0 <= response_capacity <= codec.MAX_BODY_BYTES
        ):
            raise AKSProvisioningTransportError("invalid AKS exchange bounds")

        response = bytearray(response_capacity)
        request_address = _address(request)
        response_address = _address(response)
        exchange = bytearray(
            struct.pack(
                EXCHANGE_FORMAT,
                operation,
                0,
                len(request),
                response_capacity,
                0,
                request_address,
                response_address,
            )
        )
        try:
            try:
                _ioctl_mutate(self.fd, T2_AKS_IOC_EXCHANGE, exchange)
            except OSError as error:
                returned = struct.unpack(EXCHANGE_FORMAT, exchange)
                detail = (
                    f"; SEP status {returned[1]}" if returned[1] else ""
                )
                raise AKSProvisioningTransportError(
                    f"AKS operation {operation:#04x} failed{detail}",
                    sep_status=returned[1] or None,
                ) from error
            (
                returned_operation,
                sep_status,
                request_length,
                returned_capacity,
                response_length,
                returned_request,
                returned_response,
            ) = struct.unpack(EXCHANGE_FORMAT, exchange)
            if (
                returned_operation != operation
                or request_length != len(request)
                or returned_capacity != response_capacity
                or returned_request != request_address
                or returned_response != response_address
            ):
                raise AKSProvisioningTransportError(
                    "kernel altered immutable AKS exchange metadata"
                )
            if sep_status:
                raise AKSProvisioningTransportError(
                    f"SEP rejected AKS operation with status {sep_status}"
                )
            if response_length > response_capacity:
                raise AKSProvisioningTransportError(
                    "kernel returned an oversized AKS response"
                )
            return bytearray(response[:response_length])
        finally:
            _zero(exchange)
            _zero(response)

    def create(self, request: bytearray) -> tuple[int, bytearray]:
        return 0, self._exchange(0x01, request, codec.MAX_BODY_BYTES)

    def export(self, request: bytearray) -> tuple[int, bytearray]:
        return 0, self._exchange(0x02, request, codec.MAX_BODY_BYTES)

    def bind_password(
        self,
        session: int,
        keybag_handle: int,
        password: bytearray,
        acm_external_form: bytes | bytearray,
    ) -> None:
        """Satisfy the live ACM context through the same exclusive AKS lease."""
        if (
            type(session) is not int
            or session != 1
            or type(keybag_handle) is not int
            or keybag_handle == 0
            or not -(1 << 31) <= keybag_handle < (1 << 31)
            or not isinstance(password, bytearray)
            or not 1 <= len(password) <= 128
            or not isinstance(acm_external_form, (bytes, bytearray))
            or len(acm_external_form) != 16
            or not any(acm_external_form)
        ):
            raise AKSProvisioningTransportError("invalid password-binding input")
        padded_password_length = (len(password) + 3) & ~3
        request = bytearray(32 + padded_password_length + 16)
        response = bytearray()
        try:
            struct.pack_into(
                "<IQiI",
                request,
                0,
                1,
                session,
                keybag_handle,
                len(password),
            )
            request[20 : 20 + len(password)] = password
            struct.pack_into("<I", request, 20 + padded_password_length, 16)
            context_offset = 24 + padded_password_length
            request[context_offset : context_offset + 16] = acm_external_form
            struct.pack_into("<Q", request, context_offset + 16, 0x200)
            response = self._exchange(0x21, request, 12)
            if len(response) != 12 or struct.unpack_from("<I", response)[0] != 1:
                raise AKSProvisioningTransportError(
                    "verify-secret returned an invalid response"
                )
        finally:
            _zero(request)
            _zero(response)

    def _observe_primary_absence(self, session: int) -> bytes:
        request = bytearray(36)
        response = bytearray()
        try:
            struct.pack_into("<Q", request, 4, session)
            struct.pack_into("<I", request, 20, 0xFFFFFFFF)
            struct.pack_into("<I", request, 28, 0xFFFFFFFF)
            try:
                response = self._exchange(0x51, request, codec.MAX_BODY_BYTES)
            except AKSProvisioningTransportError as error:
                if error.sep_status == -3:
                    return b"mailbox-status:-3"
                raise
            if response == struct.pack("<II", 0xFFFFFFFD, 0):
                return b"body-status:-3"
            raise AKSProvisioningTransportError(
                "durable primary identity is present or its reply is malformed"
            )
        finally:
            _zero(request)
            _zero(response)

    def collect_stable_empty_preflight(self, session: int) -> "PreflightAttestation":
        """Bind two exact absent-primary observations to this open lease."""
        if type(session) is not int or not 0 < session < (1 << 64):
            raise AKSProvisioningTransportError("invalid provisioning session")
        first = self._observe_primary_absence(session)
        second = self._observe_primary_absence(session)
        info = self._get_info()
        if (
            info.connection_generation != self.connection_generation
            or info.stable_absence_count != 2
        ):
            raise AKSProvisioningTransportError(
                "kernel did not attest stable empty primary inventory"
            )
        request = bytearray(36)
        try:
            struct.pack_into("<Q", request, 4, session)
            struct.pack_into("<I", request, 20, 0xFFFFFFFF)
            struct.pack_into("<I", request, 28, 0xFFFFFFFF)
            digest = hashlib.sha256(
                b"t2-aks-provisioning-preflight-v1\0"
                + self._initial_info
                + request
                + first
                + b"\0"
                + second
                + b"\0"
                + info.raw
            ).hexdigest()
        finally:
            _zero(request)
        from t2_aks_provisioning_operation import PreflightAttestation

        return PreflightAttestation(
            connection_generation=self.connection_generation,
            evidence_sha256=digest,
            xart_ready=True,
            primary_identity_absent=True,
            inventory_stable=True,
        )

    def require_identity_secret_ready(self) -> None:
        """Require command 0x28 to have armed this exact create lease."""
        if self.fd < 0:
            raise AKSProvisioningTransportError("AKS provisioning transport is closed")
        raw = bytearray(INFO_SIZE)
        try:
            fcntl.ioctl(self.fd, T2_AKS_IOC_GET_INFO, raw, True)
            generation, flags, header_version, phase, absence_count = struct.unpack(
                INFO_FORMAT, raw
            )
            if (
                str(uuid.UUID(bytes=generation)) != self.connection_generation
                or flags & ~_KNOWN_INFO_FLAGS
                or flags & _REQUIRED_INFO_FLAGS != _REQUIRED_INFO_FLAGS
                or flags & T2_AKS_INFO_F_IDENTITY_SECRET_SET == 0
                or flags
                & (
                    T2_AKS_INFO_F_PROVISIONING_POISONED
                    | T2_AKS_INFO_F_INVENTORY_ONLY
                    | T2_AKS_INFO_F_PASSWORD_BOUND
                    | T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE
                    | T2_AKS_INFO_F_RUNTIME_POISONED
                )
                or header_version != 2
                or phase != 0
                or absence_count != 2
            ):
                raise AKSProvisioningTransportError(
                    "ACM identity secret is not armed for this provisioning lease"
                )
        finally:
            _zero(raw)

    def copy_live_uuid(self, session: int, live_handle: int) -> str:
        if (
            type(session) is not int
            or not 0 < session < (1 << 64)
            or type(live_handle) is not int
            or not 0 < live_handle <= 0x7FFFFFFF
        ):
            raise AKSProvisioningTransportError("invalid live keybag owner")
        request = bytearray(struct.pack("<IQI", 0, session, live_handle))
        response = bytearray()
        try:
            response = self._exchange(0x06, request, 24)
            if len(response) != 24:
                raise AKSProvisioningTransportError(
                    "copy-keybag-UUID response has the wrong length"
                )
            status, blob_length = struct.unpack_from("<II", response)
            if status or blob_length != 16:
                raise AKSProvisioningTransportError(
                    "copy-keybag-UUID response is not a 16-byte success"
                )
            bag_uuid = uuid.UUID(bytes=bytes(response[8:24]))
            if bag_uuid.int == 0:
                raise AKSProvisioningTransportError(
                    "copy-keybag-UUID returned the zero UUID"
                )
            return str(bag_uuid)
        finally:
            _zero(request)
            _zero(response)
