"""Narrow userspace client for the root-only T2 ACM lifecycle ioctl."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import inspect
import os
import struct
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Callable
from typing import Iterator, TypeVar, cast

import t2_acm_protocol as protocol
import t2_performance


DEVICE = Path("/dev/t2-acm")
INFO_FORMAT = "=QII"
EXCHANGE_FORMAT = "=B3xIIIIIQQQ"
INFO_SIZE = struct.calcsize(INFO_FORMAT)
EXCHANGE_SIZE = struct.calcsize(EXCHANGE_FORMAT)


class ACMDeviceError(RuntimeError):
    pass


class ACMContextCleanupError(ACMDeviceError):
    def __init__(
        self,
        message: str,
        *,
        primary_error: BaseException | None,
        cleanup_errors: tuple[BaseException, ...],
    ) -> None:
        super().__init__(message)
        self.primary_error = primary_error
        self.cleanup_errors = cleanup_errors


T = TypeVar("T")


def _ioc(direction: int, kind: int, number: int, size: int) -> int:
    if not 0 <= direction < 4 or not 0 <= kind < 256 or not 0 <= number < 256:
        raise ValueError("invalid ioctl field")
    if not 0 <= size < (1 << 14):
        raise ValueError("invalid ioctl size")
    return (direction << 30) | (size << 16) | (kind << 8) | number


T2_ACM_IOC_EXCHANGE = _ioc(3, 0xAC, 0, EXCHANGE_SIZE)
T2_ACM_IOC_GET_INFO = _ioc(2, 0xAC, 1, INFO_SIZE)
T2_ACM_INFO_F_POISONED = 1 << 0


def _address(buffer: bytearray) -> int:
    return ctypes.addressof((ctypes.c_ubyte * len(buffer)).from_buffer(buffer))


def _zero(buffer: bytearray) -> None:
    if buffer:
        ctypes.memset(_address(buffer), 0, len(buffer))


def _signed_u32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def _registration_generation(info: bytes | bytearray) -> int:
    if len(info) != INFO_SIZE:
        raise ACMDeviceError("invalid endpoint-10 registration metadata")
    generation, capacity, flags = struct.unpack(INFO_FORMAT, info)
    if (
        generation == 0
        or capacity != 16384
        or flags & ~T2_ACM_INFO_F_POISONED
    ):
        raise ACMDeviceError("invalid endpoint-10 registration metadata")
    if flags & T2_ACM_INFO_F_POISONED:
        raise ACMDeviceError(
            "endpoint-10 has an ambiguous late reply; reboot required"
        )
    return generation


class ACMDevice:
    def __init__(self, path: Path = DEVICE) -> None:
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            self.fd = os.open(path, flags)
        except OSError as error:
            import t2_preparation_lease
            if (error.errno != errno.EBUSY or path != DEVICE
                    or not t2_preparation_lease.release_idle_owner()):
                raise
            self.fd = os.open(path, flags)
        try:
            info = bytearray(INFO_SIZE)
            fcntl.ioctl(self.fd, T2_ACM_IOC_GET_INFO, info, True)
            self.generation = _registration_generation(info)
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def require_current_generation(self) -> None:
        info = bytearray(INFO_SIZE)
        fcntl.ioctl(self.fd, T2_ACM_IOC_GET_INFO, info, True)
        if _registration_generation(info) != self.generation:
            raise ACMDeviceError("prepared ACM generation is no longer valid")

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "ACMDevice":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def exchange(self, command: bytes | bytearray, response_capacity: int) -> bytes:
        if self.fd < 0:
            raise ACMDeviceError("ACM device is closed")
        opcode = protocol.validate_command(command)
        if not 0 <= response_capacity <= 16384:
            raise ACMDeviceError("invalid response capacity")
        request = bytearray(command)
        response = bytearray(response_capacity)
        request_address = _address(request)
        response_address = _address(response) if response else 0
        exchange = bytearray(
            struct.pack(
                EXCHANGE_FORMAT,
                1,
                len(request),
                response_capacity,
                0,
                0,
                0,
                self.generation,
                request_address,
                response_address,
            )
        )
        try:
            with t2_performance.transport_phase("acm", f"op_{opcode:02x}"):
                fcntl.ioctl(self.fd, T2_ACM_IOC_EXCHANGE, exchange, True)
            (
                request_code,
                request_length,
                returned_capacity,
                response_length,
                request_info,
                response_info,
                generation,
                returned_request,
                returned_response,
            ) = struct.unpack(EXCHANGE_FORMAT, exchange)
            if (
                request_code != 1
                or request_length != len(request)
                or returned_capacity != response_capacity
                or request_info != 0
                or generation != self.generation
                or returned_request != request_address
                or returned_response != response_address
            ):
                raise ACMDeviceError("kernel altered immutable exchange metadata")
            if response_info != 0:
                raise ACMDeviceError(
                    f"SEP rejected ACM command with status {_signed_u32(response_info)}"
                )
            if response_length > response_capacity:
                raise ACMDeviceError("kernel returned an oversized ACM response")
            return bytes(response[:response_length])
        finally:
            _zero(exchange)
            _zero(response)
            _zero(request)


def lifecycle_test(device: ACMDevice, user_id: int) -> dict[str, object]:
    """Create one tracked context and guarantee a delete attempt before return."""
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=True), 21
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, True, False
    )
    parsed = None
    primary_error: BaseException | None = None
    response_shape = (
        f"length={len(response)}, "
        f"terminal_flag_boolean={response[-1] in (0, 1)}"
    )
    try:
        parsed = protocol.parse_create_response(response, tracking=True)
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"create response was invalid and cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(
            f"mandatory context cleanup failed: {cleanup_error}"
        ) from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            f"create response was invalid ({response_shape}); context was cleaned up"
        ) from primary_error
    assert parsed is not None
    return {
        "schema_version": 1,
        "create_succeeded": True,
        "tracking_response": parsed.tracking,
        "response_flag_boolean": type(parsed.response_flag) is bool,
        "delete_succeeded": True,
        "context_identifier_redacted": True,
        "mutation_reconciled": True,
    }


def policy_preflight_test(device: ACMDevice, user_id: int) -> dict[str, object]:
    """Observe policy 1007's requirement and guarantee context deletion."""
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=True), 21
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, True, False
    )
    result = None
    primary_error: BaseException | None = None
    try:
        handle = protocol.parse_create_response(response, tracking=True)
        policy_response = device.exchange(
            protocol.build_enrollment_policy_preflight(handle),
            protocol.POLICY_RESPONSE_CAPACITY,
        )
        result = protocol.parse_policy_response(policy_response)
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"policy preflight failed and mandatory cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(f"mandatory context cleanup failed: {cleanup_error}") from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            "policy preflight failed; context was cleaned up"
        ) from primary_error
    assert result is not None
    return {
        "schema_version": 1,
        "policy": 1007,
        "preflight_only": True,
        "policy_satisfied": result.satisfied,
        "requirement_present": result.requirement_present,
        "requirement_length": result.requirement_length,
        "requirement_type": result.requirement_type,
        "requirement_state": result.requirement_state,
        "requirement_flags": result.requirement_flags,
        "requirement_payload_length": result.requirement_payload_length,
        "context_identifier_redacted": True,
        "delete_succeeded": True,
        "mutation_reconciled": True,
    }


def externalize_context(device: ACMDevice, handle: protocol.ContextHandle) -> bytes:
    """Register an active context and return its exact 16-byte external form."""
    response = device.exchange(protocol.build_externalize(handle), 0)
    if response:
        raise ACMDeviceError("context externalization returned an unexpected body")
    return handle.context


def set_identity_secret(
    device: ACMDevice, handle: protocol.ContextHandle, secret: bytearray
) -> None:
    """Install request-10's transient type-5 data and wipe its command copy."""
    command = protocol.build_identity_secret(handle, secret)
    try:
        response = device.exchange(command, 0)
        if response:
            raise ACMDeviceError("identity-secret command returned an unexpected body")
    finally:
        _zero(command)


@contextmanager
def identity_secret_context(
    device: ACMDevice,
    user_id: int,
    secret: bytearray,
    *,
    tracking: bool = True,
) -> Iterator[bytes]:
    """Hold request-10's exact credential-bearing ACM context for one consumer."""
    response_capacity = 21 if tracking else 17
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=tracking), response_capacity
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, tracking, False
    )
    primary_error: BaseException | None = None
    stage = "create-response"
    try:
        handle = protocol.parse_create_response(response, tracking=tracking)
        stage = "identity-secret"
        set_identity_secret(device, handle, secret)
        stage = "context-externalization"
        external_form = externalize_context(device, handle)
        stage = "credential-bearing-consumer"
        yield external_form
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"identity provisioning failed at {stage} and mandatory context "
                f"cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(
            f"identity provisioning completed but mandatory context cleanup failed: "
            f"{cleanup_error}"
        ) from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            f"identity provisioning failed at {stage}; context was cleaned up"
        ) from primary_error


def identity_secret_lifecycle_test(
    device: ACMDevice, user_id: int, secret: bytearray, *, tracking: bool = True
) -> dict[str, object]:
    """Exercise request-10's transient secret producer with mandatory cleanup."""
    response_capacity = 21 if tracking else 17
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=tracking),
        response_capacity,
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, tracking, False
    )
    primary_error: BaseException | None = None
    stage = "create-response"
    try:
        handle = protocol.parse_create_response(response, tracking=tracking)
        stage = "identity-secret-set"
        set_identity_secret(device, handle, secret)
        stage = "context-externalization"
        externalize_context(device, handle)
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"identity-secret lifecycle failed at {stage} and mandatory "
                f"cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(
            f"identity-secret lifecycle completed but mandatory cleanup failed: "
            f"{cleanup_error}"
        ) from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            f"identity-secret lifecycle failed at {stage}; context was cleaned up"
        ) from primary_error
    return {
        "schema_version": 1,
        "context_create_tracking": tracking,
        "identity_secret_type": protocol.IDENTITY_SECRET_TYPE,
        "identity_secret_set": True,
        "context_externalized": True,
        "context_identifier_redacted": True,
        "delete_succeeded": True,
        "mutation_reconciled": True,
        "keybag_mutation_performed": False,
        "fingerprint_mutation_performed": False,
    }


@contextmanager
def identity_authorized_context(
    device: ACMDevice,
    user_id: int,
    identity_secret: bytearray,
    identity_binder: Callable[[bytes, bytes], None],
    *,
    tracking: bool = True,
    include_authorization_context: bool = False,
) -> Iterator[
    tuple[protocol.PolicyResult, protocol.PolicyResult, bytes]
    | tuple[protocol.PolicyResult, protocol.PolicyResult, bytes, bytes]
]:
    """Authorize a distinct policy target and yield the login credential."""
    response_capacity = 21 if tracking else 17
    cleanup_handles: list[protocol.ContextHandle] = []
    identity_reference = bytearray()
    initial = final = None
    primary_error: BaseException | None = None
    stage = "identity-create"
    try:
        response = device.exchange(
            protocol.build_create(user_id=user_id, tracking=tracking),
            response_capacity,
        )
        if len(response) < protocol.CONTEXT_SIZE:
            raise ACMDeviceError(
                "identity create omitted the context required for mandatory cleanup"
            )
        cleanup_handles.append(
            protocol.ContextHandle(
                response[: protocol.CONTEXT_SIZE], 0, tracking, False
            )
        )
        identity_handle = protocol.parse_create_response(
            response, tracking=tracking
        )
        stage = "identity-secret"
        set_identity_secret(device, identity_handle, identity_secret)
        stage = "identity-reference-externalization"
        identity_reference.extend(externalize_context(device, identity_handle))

        stage = "authorization-create"
        response = device.exchange(
            protocol.build_create(user_id=user_id, tracking=tracking),
            response_capacity,
        )
        if len(response) < protocol.CONTEXT_SIZE:
            raise ACMDeviceError(
                "authorization create omitted the context required for mandatory cleanup"
            )
        cleanup_handles.append(
            protocol.ContextHandle(
                response[: protocol.CONTEXT_SIZE], 0, tracking, False
            )
        )
        authorization_handle = protocol.parse_create_response(
            response, tracking=tracking
        )
        if authorization_handle.context == identity_reference:
            raise ACMDeviceError("ACM identity and authorization references collided")
        stage = "policy-preflight"
        initial = protocol.parse_policy_response(
            device.exchange(
                protocol.build_enrollment_policy(
                    authorization_handle, preflight=True
                ),
                protocol.POLICY_RESPONSE_CAPACITY,
            )
        )
        if initial.satisfied or initial.requirement_type != 1:
            raise ACMDeviceError("initial policy state is not the passcode requirement")
        stage = "authorization-context-externalization"
        authorization_context = externalize_context(device, authorization_handle)
        stage = "identity-authentication"
        identity_binder(bytes(identity_reference), authorization_context)
        stage = "policy-final"
        final = protocol.parse_policy_response(
            device.exchange(
                protocol.build_enrollment_policy(
                    authorization_handle, preflight=False
                ),
                protocol.POLICY_RESPONSE_CAPACITY,
            )
        )
        if not final.satisfied:
            raise ACMDeviceError("policy 1007 remained unsatisfied after authentication")
        stage = "authorized-consumer"
        # AKSIdentityAuthenticate uses the second context only as its
        # authorization output.  AKSIdentityLoginWithACMCred subsequently
        # receives the original LACUserCredential.password.contextRef.
        if include_authorization_context:
            yield (
                initial,
                final,
                bytes(identity_reference),
                authorization_context,
            )
        else:
            yield initial, final, bytes(identity_reference)
    except BaseException as error:
        primary_error = error
    cleanup_errors: list[BaseException] = []
    for cleanup_handle in reversed(cleanup_handles):
        try:
            delete_response = device.exchange(
                protocol.build_delete(cleanup_handle), 0
            )
            if delete_response:
                raise ACMDeviceError("delete returned an unexpected response body")
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
    _zero(identity_reference)
    if cleanup_errors:
        cause = primary_error if primary_error is not None else cleanup_errors[0]
        raise ACMContextCleanupError(
            f"identity authorization stopped at {stage}; mandatory cleanup of "
            f"{len(cleanup_errors)} context(s) failed",
            primary_error=primary_error,
            cleanup_errors=tuple(cleanup_errors),
        ) from cause
    if primary_error is not None:
        raise ACMDeviceError(
            f"identity authorization failed at {stage}; both contexts were cleaned up"
        ) from primary_error


def reconcile_identity_cleanup_after_close(
    error: ACMContextCleanupError,
    device: ACMDevice,
    *,
    device_factory: Callable[[], ACMDevice] = ACMDevice,
) -> None:
    """Accept cleanup-only failure only after bounded kernel-close proof."""
    if not isinstance(error, ACMContextCleanupError) or error.primary_error is not None:
        raise error
    device.close()
    with device_factory():
        pass


def raise_primary_after_identity_cleanup_close(
    error: ACMContextCleanupError,
    device: ACMDevice,
    *,
    device_factory: Callable[[], ACMDevice] = ACMDevice,
) -> None:
    """Prove bounded close cleanup, then preserve the consumer's failure."""
    if not isinstance(error, ACMContextCleanupError) or error.primary_error is None:
        raise error
    primary = error.primary_error
    device.close()
    with device_factory():
        pass
    raise primary


@contextmanager
def identity_verification_only_context(
    device: ACMDevice,
    user_id: int,
    identity_secret: bytearray,
    identity_binder: Callable[[bytes, bytes], None],
    *,
    tracking: bool = True,
) -> Iterator[tuple[protocol.PolicyResult, protocol.PolicyResult, bytes]]:
    """Verify one live identity input without creating an authorization target."""
    response_capacity = 21 if tracking else 17
    cleanup_handle: protocol.ContextHandle | None = None
    identity_reference = bytearray()
    primary_error: BaseException | None = None
    stage = "identity-create"
    try:
        response = device.exchange(
            protocol.build_create(user_id=user_id, tracking=tracking),
            response_capacity,
        )
        if len(response) < protocol.CONTEXT_SIZE:
            raise ACMDeviceError(
                "identity create omitted the context required for mandatory cleanup"
            )
        cleanup_handle = protocol.ContextHandle(
            response[: protocol.CONTEXT_SIZE], 0, tracking, False
        )
        identity_handle = protocol.parse_create_response(
            response, tracking=tracking
        )
        stage = "identity-secret"
        set_identity_secret(device, identity_handle, identity_secret)
        stage = "identity-reference-externalization"
        identity_reference.extend(externalize_context(device, identity_handle))
        stage = "identity-verification-only"
        identity_binder(bytes(identity_reference), b"")
        stage = "verification-complete"
        raise ACMDeviceError(
            "identity verification completed; authorization target intentionally omitted"
        )
        if False:  # pragma: no cover - context-manager generator marker
            yield None, None, b""  # type: ignore[misc]
    except BaseException as error:
        primary_error = error
    cleanup_error: BaseException | None = None
    if cleanup_handle is not None:
        try:
            delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
            if delete_response:
                raise ACMDeviceError("delete returned an unexpected response body")
        except BaseException as error:
            cleanup_error = error
    _zero(identity_reference)
    if cleanup_error is not None:
        raise ACMDeviceError(
            f"identity verification stopped at {stage}; mandatory cleanup failed"
        ) from primary_error
    if primary_error is not None:
        raise ACMDeviceError(
            f"identity verification stopped at {stage}; context was cleaned up"
        ) from primary_error


@contextmanager
def authorized_context(
    device: ACMDevice,
    user_id: int,
    password_binder: Callable[[bytes], None],
    *,
    tracking: bool = True,
    identity_secret: bytearray | None = None,
) -> Iterator[tuple[protocol.PolicyResult, protocol.PolicyResult, bytes]]:
    """Hold one password-authorized policy-1007 context for a synchronous scope.

    The optional ``identity_secret`` form is retained only for compatibility
    diagnostics. Native identity activation uses ``identity_authorized_context``
    so Apple's input and output ACM references remain distinct.
    """
    response_capacity = 21 if tracking else 17
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=tracking),
        response_capacity,
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, tracking, False
    )
    initial = final = None
    primary_error: BaseException | None = None
    stage = "create-response"
    try:
        handle = protocol.parse_create_response(response, tracking=tracking)
        stage = "policy-preflight"
        initial = protocol.parse_policy_response(
            device.exchange(
                protocol.build_enrollment_policy(handle, preflight=True),
                protocol.POLICY_RESPONSE_CAPACITY,
            )
        )
        if initial.satisfied or initial.requirement_type != 1:
            raise ACMDeviceError("initial policy state is not the passcode requirement")
        if identity_secret is not None:
            stage = "identity-secret"
            set_identity_secret(device, handle, identity_secret)
        stage = "context-externalization"
        external_form = externalize_context(device, handle)
        stage = "password-binding"
        password_binder(external_form)
        stage = "policy-final"
        final = protocol.parse_policy_response(
            device.exchange(
                protocol.build_enrollment_policy(handle, preflight=False),
                protocol.POLICY_RESPONSE_CAPACITY,
            )
        )
        if not final.satisfied:
            raise ACMDeviceError("policy 1007 remained unsatisfied after password binding")
        stage = "authorized-consumer"
        yield initial, final, external_form
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"authorized operation failed at {stage} and mandatory cleanup "
                f"failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(
            f"authorized operation completed but mandatory cleanup failed: {cleanup_error}"
        ) from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            f"authorized operation failed at {stage}; context was cleaned up"
        ) from primary_error


def with_authorized_context(
    device: ACMDevice,
    user_id: int,
    password_binder: Callable[[bytes], None],
    consumer: Callable[[bytes], T],
    *,
    tracking: bool = True,
) -> tuple[protocol.PolicyResult, protocol.PolicyResult, T]:
    """Run one trusted consumer while a fresh policy-1007 context is live."""
    missing = object()
    consumer_result: object = missing
    with authorized_context(
        device, user_id, password_binder, tracking=tracking
    ) as (initial, final, external_form):
        candidate = consumer(external_form)
        if inspect.isawaitable(candidate):
            close = getattr(candidate, "close", None)
            if callable(close):
                close()
            raise ACMDeviceError("authorized consumer must complete synchronously")
        consumer_result = candidate
    assert initial is not None and final is not None
    assert consumer_result is not missing
    return initial, final, cast(T, consumer_result)


def authorization_test(
    device: ACMDevice,
    user_id: int,
    password_binder: Callable[[bytes], None],
    *,
    tracking: bool = True,
) -> dict[str, object]:
    """Bind a password and authorize a no-mutation consumer for diagnostics."""
    initial, final, _ = with_authorized_context(
        device,
        user_id,
        password_binder,
        lambda _context: None,
        tracking=tracking,
    )
    return {
        "schema_version": 1,
        "policy": 1007,
        "initial_requirement_type": initial.requirement_type,
        "context_create_tracking": tracking,
        "password_bound": True,
        "policy_satisfied": final.satisfied,
        "context_identifier_redacted": True,
        "delete_succeeded": True,
        "mutation_reconciled": True,
        "fingerprint_mutation_performed": False,
    }
