#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""One-request systemd socket entry point for native user activation."""

from __future__ import annotations

import socket
import struct
import sys

import t2_user_activation_broker


REQUEST = struct.Struct(">4sBBH")
RESPONSE = struct.Struct(">4sBBH")
REQUEST_MAGIC = b"T2UA"
RESPONSE_MAGIC = b"T2UR"
PROTOCOL_VERSION = 1
OPERATION_VERIFY = 1
MAX_PASSWORD = 1023
MAX_PACKET = REQUEST.size + MAX_PASSWORD
STATUS_OK = 0
STATUS_UNAVAILABLE = 1
OUTCOME_READY = 1
OUTCOME_ALREADY_READY = 2


class ActivationServiceError(RuntimeError):
    pass


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _report_failure(error: BaseException) -> None:
    """Emit bounded operator evidence without request or credential bytes."""

    causes: list[str] = []
    current: BaseException | None = error
    while current is not None and len(causes) < 8:
        causes.append(type(current).__name__)
        current = current.__cause__
    print(
        "native T2 user activation unavailable: " + " <- ".join(causes),
        file=sys.stderr,
        flush=True,
    )


def _request(connection: socket.socket) -> tuple[bytearray, bytearray | None]:
    buffer = bytearray(MAX_PACKET)
    try:
        received, ancillary, flags, _address = connection.recvmsg_into(
            [buffer], socket.CMSG_SPACE(struct.calcsize("i"))
        )
        if (
            ancillary
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or received < REQUEST.size
        ):
            raise ActivationServiceError("activation request framing is invalid")
        magic, version, operation, password_length = REQUEST.unpack_from(buffer)
        if (
            magic != REQUEST_MAGIC
            or version != PROTOCOL_VERSION
            or operation != OPERATION_VERIFY
            or password_length > MAX_PASSWORD
            or received != REQUEST.size + password_length
        ):
            raise ActivationServiceError("activation request is unsupported")
        password = (
            bytearray(buffer[REQUEST.size:received]) if password_length else None
        )
        return buffer, password
    except BaseException:
        _wipe(buffer)
        raise


def serve(connection: socket.socket) -> int:
    request_buffer: bytearray | None = None
    password: bytearray | None = None
    try:
        request_buffer, password = _request(connection)
        result = t2_user_activation_broker.activate_from_protected_state(
            connection, password=password
        )
        outcome = (
            OUTCOME_ALREADY_READY
            if result.outcome == "already-ready"
            else OUTCOME_READY
        )
        response = RESPONSE.pack(
            RESPONSE_MAGIC, PROTOCOL_VERSION, STATUS_OK, outcome
        )
        connection.sendall(response)
        return 0
    except BaseException as error:
        _report_failure(error)
        try:
            connection.sendall(
                RESPONSE.pack(
                    RESPONSE_MAGIC,
                    PROTOCOL_VERSION,
                    STATUS_UNAVAILABLE,
                    0,
                )
            )
        except OSError:
            pass
        return 1
    finally:
        _wipe(password)
        _wipe(request_buffer)


def main() -> int:
    connection = socket.socket(fileno=0)
    try:
        return serve(connection)
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
