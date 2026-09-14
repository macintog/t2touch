#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Send one PAM-provided password to the native activation socket."""

from __future__ import annotations

import os
import pwd
import socket
import struct


SOCKET_PATH = "/run/t2-touchid/activation.sock"
REQUEST = struct.Struct(">4sBBH")
RESPONSE = struct.Struct(">4sBBH")
MAX_PASSWORD = 1023


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


def _password() -> tuple[bytearray, int]:
    storage = bytearray(MAX_PASSWORD + 1)
    length = 0
    try:
        while length < len(storage):
            count = os.readv(0, [memoryview(storage)[length:]])
            if count == 0:
                break
            length += count
        if length == 0 or length > MAX_PASSWORD:
            raise RuntimeError("PAM password input is outside protocol bounds")
        return storage, length
    except BaseException:
        _wipe(storage)
        raise


def _become_pam_user() -> bool:
    name = os.environ.get("PAM_USER")
    if os.environ.get("PAM_TYPE") != "auth" or not name:
        return False
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        return False
    if account.pw_uid == 0:
        return False
    if os.getuid() == 0 and os.geteuid() == 0:
        try:
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        except OSError:
            return False
    return (
        os.getuid() == account.pw_uid
        and os.geteuid() == account.pw_uid
        and os.getgid() == account.pw_gid
        and os.getegid() == account.pw_gid
    )


def main() -> int:
    storage: bytearray | None = None
    try:
        if not _become_pam_user():
            return 1
        storage, length = _password()
        header = REQUEST.pack(b"T2UA", 1, 1, length)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(180)
            connection.connect(SOCKET_PATH)
            sent = connection.sendmsg(
                [header, memoryview(storage)[:length]],
                [],
                socket.MSG_NOSIGNAL if hasattr(socket, "MSG_NOSIGNAL") else 0,
            )
            if sent != len(header) + length:
                return 1
            response = connection.recv(RESPONSE.size + 1)
        if len(response) != RESPONSE.size:
            return 1
        magic, version, status, outcome = RESPONSE.unpack(response)
        if magic != b"T2UR" or version != 1:
            return 1
        return int(status != 0 or outcome not in {1, 2})
    except (OSError, KeyError, RuntimeError, struct.error):
        return 1
    finally:
        if storage is not None:
            _wipe(storage)


if __name__ == "__main__":
    raise SystemExit(main())
