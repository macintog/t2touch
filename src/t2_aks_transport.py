# SPDX-License-Identifier: GPL-2.0-only
"""Single-owner Linux AKS transport for journaled per-user activation."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import stat
import struct
import uuid
from pathlib import Path, PurePosixPath

import t2_aks_state
import t2_user_readiness


DEVICE = Path("/dev/t2-aks")
EXCHANGE_FORMAT = "=Bb2xIIIQQ"
INFO_FORMAT = "=16sIIII"
EXCHANGE_SIZE = struct.calcsize(EXCHANGE_FORMAT)
INFO_SIZE = struct.calcsize(INFO_FORMAT)
MAX_BODY_BYTES = 16_300
MAX_SAVED_KEYBAG_BYTES = 16_000
MAX_PASSWORD_BYTES = 1_023

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.ioctl.restype = ctypes.c_int


class AKSActivationTransportError(RuntimeError):
    def __init__(self, message: str, *, sep_status: int | None = None) -> None:
        super().__init__(message)
        self.sep_status = sep_status


def _ioc(direction: int, kind: int, number: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (kind << 8) | number


if EXCHANGE_SIZE != 32 or INFO_SIZE != 32:
    raise RuntimeError("unexpected AKS exchange ABI size")
T2_AKS_IOC_EXCHANGE = _ioc(3, 0xA7, 0, EXCHANGE_SIZE)
T2_AKS_IOC_GET_INFO = _ioc(2, 0xA7, 1, INFO_SIZE)

T2_AKS_INFO_F_OOL_REGISTERED = 1 << 0
T2_AKS_INFO_F_ACM_REGISTERED = 1 << 1
T2_AKS_INFO_F_XART_UUID_PUBLISHED = 1 << 2
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
_REQUIRED_INFO_FLAGS = T2_AKS_INFO_F_OOL_REGISTERED
_UNSAFE_INFO_FLAGS = (
    T2_AKS_INFO_F_PROVISIONING_POISONED
    | T2_AKS_INFO_F_INVENTORY_ONLY
    | T2_AKS_INFO_F_PASSWORD_BOUND
    | T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE
    | T2_AKS_INFO_F_RUNTIME_POISONED
    | T2_AKS_INFO_F_IDENTITY_SECRET_SET
    | T2_AKS_INFO_F_REPLACEMENT_ARMED
)


def _address(buffer: bytearray) -> int:
    if not buffer:
        return 0
    return ctypes.addressof((ctypes.c_ubyte * len(buffer)).from_buffer(buffer))


def _zero(buffer: bytearray) -> None:
    if buffer:
        ctypes.memset(_address(buffer), 0, len(buffer))


def _ioctl_mutate(fd: int, command: int, buffer: bytearray) -> None:
    """Call ioctl directly so output survives a negative syscall result.

    Python's fcntl.ioctl copies its internal staging buffer back only on
    success.  The AKS ABI intentionally returns a signed SEP status in the
    exchange structure alongside EREMOTEIO, so callers must retain the
    kernel-mutated structure on that error path.
    """
    ctypes.set_errno(0)
    result = _LIBC.ioctl(
        ctypes.c_int(fd), ctypes.c_ulong(command), ctypes.c_void_p(_address(buffer))
    )
    if result < 0:
        error_number = ctypes.get_errno() or errno.EIO
        raise OSError(error_number, os.strerror(error_number))


def _special_alias(value: object) -> bool:
    return type(value) is int and -(1 << 31) <= value <= -10


def _open_device(path: Path) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise AKSActivationTransportError("AKS device path must be absolute")
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as error:
        raise AKSActivationTransportError("AKS device cannot be opened") from error


def _get_info_fd(fd: int) -> tuple[bytes, int, int, int, int]:
    raw = bytearray(INFO_SIZE)
    try:
        fcntl.ioctl(fd, T2_AKS_IOC_GET_INFO, raw, True)
        return struct.unpack(INFO_FORMAT, raw)
    except OSError as error:
        raise AKSActivationTransportError("AKS metadata query failed") from error
    finally:
        _zero(raw)


def _policy_keybag_path(value: object) -> PurePosixPath:
    if not isinstance(value, str):
        raise AKSActivationTransportError("keybag path is outside policy")
    path = PurePosixPath(value)
    parts = path.parts
    canonical_uid = (
        len(parts) > 5
        and parts[5].isascii()
        and parts[5].isdigit()
        and 1 <= int(parts[5], 10) <= (1 << 31) - 1
        and str(int(parts[5], 10)) == parts[5]
    )
    legacy = len(parts) == 7 and parts[6] == "user.kb"
    bundled = False
    if len(parts) == 9 and parts[6] == "identities" and parts[8] == "user.kb":
        try:
            generation = uuid.UUID(parts[7])
            bundled = generation.int != 0 and str(generation) == parts[7]
        except ValueError:
            pass
    if (
        parts[:5] != ("/", "var", "lib", "t2-touchid", "users")
        or not canonical_uid
        or not (legacy or bundled)
        or str(path) != value
    ):
        raise AKSActivationTransportError("keybag path is outside policy")
    return path


class AKSActivationTransport:
    """Own one AKS descriptor and any positive handle loaded through it."""

    session = 1

    def __init__(self, path: Path = DEVICE) -> None:
        self.fd = _open_device(path)
        self._live_handle: int | None = None
        self._unload_attempted = False
        self._bound_alias: int | None = None
        self._acm_unlock_attempted = False
        try:
            (
                generation,
                info_flags,
                header_version,
                provisioning_phase,
                stable_absence_count,
            ) = self._get_info()
            parsed = uuid.UUID(bytes=generation)
            if (
                parsed.int == 0
                or info_flags & ~_KNOWN_INFO_FLAGS
                or info_flags & _REQUIRED_INFO_FLAGS != _REQUIRED_INFO_FLAGS
                or info_flags & _UNSAFE_INFO_FLAGS
                or header_version != 2
                or provisioning_phase != 0
                or stable_absence_count != 0
            ):
                raise AKSActivationTransportError(
                    "AKS registration is not ready for user activation"
                )
            self.runtime_generation = str(parsed)
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def __enter__(self) -> "AKSActivationTransport":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self.fd < 0:
            return
        failure: BaseException | None = None
        try:
            if self._live_handle is not None and not self._unload_attempted:
                self.unload_keybag(self._live_handle)
        except BaseException as error:
            failure = error
        finally:
            os.close(self.fd)
            self.fd = -1
            self._live_handle = None
            self._unload_attempted = False
            self._bound_alias = None
            self._acm_unlock_attempted = False
        if failure is not None:
            raise AKSActivationTransportError(
                "loaded keybag could not be released cleanly"
            ) from failure

    def _get_info(self) -> tuple[bytes, int, int, int, int]:
        if self.fd < 0:
            raise AKSActivationTransportError("AKS transport is closed")
        return _get_info_fd(self.fd)

    def _exchange(
        self, operation: int, request: bytearray, response_capacity: int
    ) -> bytearray:
        if self.fd < 0:
            raise AKSActivationTransportError("AKS transport is closed")
        if type(operation) is not int or operation not in {
            0x03,
            0x04,
            0x05,
            0x06,
            0x0D,
            0x18,
            0x19,
            0x21,
            0x23,
        }:
            raise AKSActivationTransportError("operation is outside activation ABI")
        if (
            not isinstance(request, bytearray)
            or not request
            or len(request) > MAX_BODY_BYTES
            or not 0 <= response_capacity <= MAX_BODY_BYTES
        ):
            raise AKSActivationTransportError("invalid AKS exchange bounds")
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
                raise AKSActivationTransportError(
                    f"AKS operation {operation:#04x} failed",
                    sep_status=returned[1] or None,
                ) from error
            returned = struct.unpack(EXCHANGE_FORMAT, exchange)
            if (
                returned[0] != operation
                or returned[1] != 0
                or returned[2] != len(request)
                or returned[3] != response_capacity
                or returned[5] != request_address
                or returned[6] != response_address
                or returned[4] > response_capacity
            ):
                raise AKSActivationTransportError("invalid kernel AKS reply metadata")
            return bytearray(response[: returned[4]])
        finally:
            _zero(exchange)
            _zero(response)

    def _bind_secret_to_acm_context(
        self,
        target_handle: int,
        secret: bytearray,
        acm_external_form: bytes | None,
        options: int,
    ) -> None:
        """Verify one exact secret and optionally authorize one ACM context."""
        _, flags, _, _, _ = self._get_info()
        if not flags & T2_AKS_INFO_F_ACM_REGISTERED:
            raise AKSActivationTransportError("AKS registration has no ACM endpoint")
        if (
            type(target_handle) is not int
            or target_handle == 0
            or not isinstance(secret, bytearray)
            or not 1 <= len(secret) <= 128
            or (
                acm_external_form is not None
                and (
                    not isinstance(acm_external_form, bytes)
                    or len(acm_external_form) != 16
                    or not any(acm_external_form)
                )
            )
            or (acm_external_form is None and options != 0x100)
            or options not in {0x100, 0x200}
        ):
            raise AKSActivationTransportError("invalid ACM password-binding input")
        padded = (len(secret) + 3) & ~3
        context = b"" if acm_external_form is None else acm_external_form
        request = bytearray(32 + padded + len(context))
        response = bytearray()
        try:
            struct.pack_into(
                "<IQiI", request, 0, 1, self.session, target_handle, len(secret)
            )
            request[20 : 20 + len(secret)] = secret
            struct.pack_into("<I", request, 20 + padded, len(context))
            context_offset = 24 + padded
            request[context_offset : context_offset + len(context)] = context
            struct.pack_into("<Q", request, context_offset + len(context), options)
            response = self._exchange(0x21, request, 12)
            if len(response) != 12 or struct.unpack_from("<I", response)[0] != 1:
                raise AKSActivationTransportError(
                    "verify-secret returned an invalid response"
                )
        finally:
            _zero(request)
            _zero(response)

    def bind_loaded_identity_secret_to_acm_context(
        self, identity_reference: bytes, authorization_context: bytes
    ) -> None:
        """Authenticate one ACM input reference into a separate live context."""
        if self._live_handle is None or self._bound_alias is None:
            raise AKSActivationTransportError(
                "loaded keybag is not owned and bound for ACM authorization"
            )
        if (
            not isinstance(identity_reference, bytes)
            or len(identity_reference) != 16
            or not any(identity_reference)
            or not isinstance(authorization_context, bytes)
            or len(authorization_context) != 16
            or not any(authorization_context)
            or identity_reference == authorization_context
        ):
            raise AKSActivationTransportError(
                "invalid ACM identity/authentication references"
            )
        mutable_identity_reference = bytearray(identity_reference)
        try:
            self._bind_secret_to_acm_context(
                self._live_handle,
                mutable_identity_reference,
                authorization_context,
                0x100,
            )
        finally:
            _zero(mutable_identity_reference)

    def verify_loaded_identity_secret(self, identity_reference: bytes) -> None:
        """Verify the loaded identity secret without producing authorization."""
        if self._live_handle is None or self._bound_alias is None:
            raise AKSActivationTransportError(
                "loaded keybag is not owned and bound for identity verification"
            )
        if (
            not isinstance(identity_reference, bytes)
            or len(identity_reference) != 16
            or not any(identity_reference)
        ):
            raise AKSActivationTransportError("invalid ACM identity reference")
        mutable_identity_reference = bytearray(identity_reference)
        try:
            self._bind_secret_to_acm_context(
                self._live_handle, mutable_identity_reference, None, 0x100
            )
        finally:
            _zero(mutable_identity_reference)

    def bind_password_to_acm_context(
        self,
        special_alias: int,
        password: bytearray,
        acm_external_form: bytes,
    ) -> None:
        """Authorize an ACM context against one exact special alias."""
        if not _special_alias(special_alias):
            raise AKSActivationTransportError("special AKS alias is invalid")
        self._bind_secret_to_acm_context(
            special_alias, password, acm_external_form, 0x200
        )

    @staticmethod
    def _read_keybag(path_text: str) -> bytearray:
        path = _policy_keybag_path(path_text)
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        value = bytearray()
        try:
            descriptor = os.open(str(path), flags)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= MAX_SAVED_KEYBAG_BYTES
            ):
                raise AKSActivationTransportError(
                    "saved keybag is not a private root-owned regular file"
                )
            while len(value) <= MAX_SAVED_KEYBAG_BYTES:
                block = os.read(
                    descriptor,
                    min(4096, MAX_SAVED_KEYBAG_BYTES + 1 - len(value)),
                )
                if not block:
                    break
                value.extend(block)
            if len(value) != info.st_size:
                raise AKSActivationTransportError("saved keybag changed during read")
            return value
        except AKSActivationTransportError:
            _zero(value)
            raise
        except OSError as error:
            _zero(value)
            raise AKSActivationTransportError("saved keybag cannot be read") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def load_keybag(self, keybag_path: str) -> int:
        if self._live_handle is not None:
            raise AKSActivationTransportError("this AKS owner already has a live handle")
        saved = self._read_keybag(keybag_path)
        padded = (len(saved) + 3) & ~3
        request = bytearray(16 + padded)
        response = bytearray()
        try:
            struct.pack_into("<IQI", request, 0, 0, self.session, len(saved))
            request[16 : 16 + len(saved)] = saved
            response = self._exchange(0x03, request, 8)
            if len(response) != 8:
                raise AKSActivationTransportError("load-keybag reply has wrong length")
            status, handle = struct.unpack("<II", response)
            if status != 0 or not 1 <= handle <= 0x7FFFFFFF:
                raise AKSActivationTransportError("load-keybag reply is invalid")
            self._live_handle = handle
            self._unload_attempted = False
            self._bound_alias = None
            self._acm_unlock_attempted = False
            return handle
        finally:
            _zero(saved)
            _zero(request)
            _zero(response)

    def unload_keybag(self, handle: int) -> int:
        if type(handle) is not int or handle != self._live_handle:
            raise AKSActivationTransportError("runtime AKS handle is not owned")
        request = bytearray(struct.pack("<IQI", 0, self.session, handle))
        response = bytearray()
        try:
            self._unload_attempted = True
            response = self._exchange(0x05, request, 4)
            if response != bytearray(4):
                raise AKSActivationTransportError("unload-keybag reply is invalid")
            self._live_handle = None
            self._unload_attempted = False
            self._bound_alias = None
            self._acm_unlock_attempted = False
            return 0
        finally:
            _zero(request)
            _zero(response)

    def _copy_uuid(self, handle: int) -> str | None:
        if not (_special_alias(handle) or handle == self._live_handle):
            raise AKSActivationTransportError("AKS UUID target is not owned")
        request = bytearray(struct.pack("<IQi", 0, self.session, handle))
        response = bytearray()
        try:
            try:
                response = self._exchange(0x06, request, 24)
            except AKSActivationTransportError as error:
                if error.sep_status == -3:
                    return None
                raise
            if response == bytearray(struct.pack("<II", 0xFFFFFFFD, 0)):
                return None
            if len(response) != 24:
                raise AKSActivationTransportError("keybag UUID reply has wrong length")
            status, length = struct.unpack_from("<II", response)
            parsed = uuid.UUID(bytes=bytes(response[8:24]))
            if status or length != 16 or parsed.int == 0:
                raise AKSActivationTransportError("keybag UUID reply is invalid")
            return str(parsed)
        finally:
            _zero(request)
            _zero(response)

    def bag_uuid(self, handle: int) -> str:
        first = self._copy_uuid(handle)
        second = self._copy_uuid(handle)
        if first is None or second is None or first != second:
            raise AKSActivationTransportError("loaded keybag UUID is unstable")
        return first

    def bind_alias(self, handle: int, special_alias: int) -> int:
        if handle != self._live_handle or not _special_alias(special_alias):
            raise AKSActivationTransportError("alias binding target is not owned")
        request = bytearray(24)
        response = bytearray()
        try:
            struct.pack_into(
                "<IQIiI", request, 0, 0, self.session, handle, special_alias, 0
            )
            response = self._exchange(0x0D, request, 4)
            if len(response) != 4:
                raise AKSActivationTransportError("alias-bind reply has wrong length")
            status = struct.unpack("<I", response)[0]
            if status == 0:
                self._bound_alias = special_alias
            return status
        finally:
            _zero(request)
            _zero(response)

    def _state_blob(self, handle: int) -> bytearray:
        if not (_special_alias(handle) or handle == self._live_handle):
            raise AKSActivationTransportError("AKS state target is not owned")
        request = bytearray(struct.pack("<IQiII", 1, self.session, handle, 0, 0))
        response = bytearray()
        try:
            response = self._exchange(0x19, request, MAX_BODY_BYTES)
            if len(response) < 12:
                raise AKSActivationTransportError("keybag-state reply is too short")
            version, length = struct.unpack_from("<II", response)
            padded = (length + 3) & ~3
            if (
                version != 1
                or not length
                or len(response) != 8 + padded
                or any(response[8 + length :])
            ):
                raise AKSActivationTransportError("keybag-state reply is invalid")
            return bytearray(response[8 : 8 + length])
        finally:
            _zero(request)
            _zero(response)

    def _state(self, handle: int) -> t2_aks_state.KeybagState:
        blob = self._state_blob(handle)
        try:
            try:
                return t2_aks_state.decode(bytes(blob))
            except t2_aks_state.AKSStateError as error:
                raise AKSActivationTransportError(
                    "keybag-state dictionary is invalid"
                ) from error
        finally:
            _zero(blob)

    def observe_alias_uuid(self, special_alias: int) -> str | None:
        """Return one stable doubled UUID result without querying state."""
        if not _special_alias(special_alias):
            raise AKSActivationTransportError("special AKS alias is invalid")
        first = self._copy_uuid(special_alias)
        second = self._copy_uuid(special_alias)
        if first != second:
            raise AKSActivationTransportError("AKS alias UUID is unstable")
        return first

    def read_alias_state_blob(self, special_alias: int) -> bytearray:
        """Return a bounded mutable state blob; the caller must wipe it."""
        if not _special_alias(special_alias):
            raise AKSActivationTransportError("special AKS alias is invalid")
        return self._state_blob(special_alias)

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence:
        if not _special_alias(special_alias):
            raise AKSActivationTransportError("special AKS alias is invalid")
        first = self._copy_uuid(special_alias)
        if first is None:
            if self._copy_uuid(special_alias) is not None:
                raise AKSActivationTransportError("AKS alias absence is unstable")
            return t2_user_readiness.AliasEvidence(False, None, None, None)
        state = self._state(special_alias)
        second = self._copy_uuid(special_alias)
        if second != first or state.handle != special_alias:
            raise AKSActivationTransportError("AKS alias observation is unstable")
        return t2_user_readiness.AliasEvidence(
            True, special_alias, first, state.lock_state, state.user_uuid
        )

    def unlock_alias(self, special_alias: int, password: memoryview) -> int:
        if not _special_alias(special_alias):
            raise AKSActivationTransportError("special AKS alias is invalid")
        if (
            not isinstance(password, memoryview)
            or password.readonly
            or password.ndim != 1
            or password.itemsize != 1
            or not password.c_contiguous
            or not 1 <= len(password) <= MAX_PASSWORD_BYTES
        ):
            raise AKSActivationTransportError(
                "password is not bounded writable contiguous byte storage"
            )
        padded = (len(password) + 3) & ~3
        request = bytearray(24 + padded)
        response = bytearray()
        try:
            struct.pack_into(
                "<IQiII", request, 0, 0, self.session, special_alias, 0, len(password)
            )
            request[24 : 24 + len(password)] = password
            response = self._exchange(0x04, request, 4)
            if len(response) != 4:
                raise AKSActivationTransportError("unlock reply has wrong length")
            return struct.unpack("<I", response)[0]
        finally:
            _zero(request)
            _zero(response)

    def unlock_alias_with_acm_context(
        self, special_alias: int, acm_external_form: bytes
    ) -> int:
        """Perform selector 0x9a's one-shot credential state transition."""
        if (
            not _special_alias(special_alias)
            or self._live_handle is None
            or self._bound_alias != special_alias
            or self._acm_unlock_attempted
            or not isinstance(acm_external_form, bytes)
            or len(acm_external_form) != 16
            or not any(acm_external_form)
        ):
            raise AKSActivationTransportError("invalid ACM alias-unlock input")
        request = bytearray(48)
        response = bytearray()
        try:
            struct.pack_into(
                "<IQiIQI",
                request,
                0,
                0,
                self.session,
                special_alias,
                0,
                0x100,
                len(acm_external_form),
            )
            request[32:48] = acm_external_form
            self._acm_unlock_attempted = True
            response = self._exchange(0x18, request, 20)
            if len(response) != 20 or struct.unpack_from("<I", response)[0] != 0:
                raise AKSActivationTransportError(
                    "ACM alias-unlock reply is invalid"
                )
            return 0
        finally:
            _zero(request)
            _zero(response)

    def resolve_alias_configuration(self, special_alias: int) -> None:
        """Resolve one alias configuration and discard its opaque contents."""
        if not _special_alias(special_alias):
            raise AKSActivationTransportError("special AKS alias is invalid")
        request = bytearray(struct.pack("<IQi", 0, self.session, special_alias))
        response = bytearray()
        try:
            response = self._exchange(0x23, request, MAX_BODY_BYTES)
            if len(response) < 12:
                raise AKSActivationTransportError(
                    "keybag configuration reply is too short"
                )
            status, length = struct.unpack_from("<II", response)
            padded = (length + 3) & ~3
            if (
                status != 0
                or not length
                or padded < length
                or len(response) != 8 + padded
                or any(response[8 + length :])
            ):
                raise AKSActivationTransportError(
                    "keybag configuration reply is invalid"
                )
        finally:
            _zero(request)
            _zero(response)
