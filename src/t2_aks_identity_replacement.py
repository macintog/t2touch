# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free codecs for the D171 identity replacement primitives.

This module defines exact wire bodies only.  It does not expose operations
0x49 or 0x03 to the kernel transport and cannot dispatch either operation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


DELETE_OPERATION = 0x49
OPEN_OPERATION = 0x03
UUID_LENGTH = 16


class AKSIdentityReplacementCodecError(ValueError):
    pass


def _session(value: object) -> int:
    if type(value) is not int or not 0 < value < (1 << 64):
        raise AKSIdentityReplacementCodecError("session is not a nonzero uint64")
    return value


def _identity(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != UUID_LENGTH or not any(value):
        raise AKSIdentityReplacementCodecError(
            "identity object is not an exact nonzero 16-byte UUID"
        )
    return value


@dataclass(frozen=True)
class AKSIdentityDeleteRequest:
    session: int
    account_uuid: bytes

    def encode(self) -> bytes:
        session = _session(self.session)
        account_uuid = _identity(self.account_uuid)
        return struct.pack("<IQII", 0, session, 0, UUID_LENGTH) + account_uuid

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityDeleteRequest":
        if not isinstance(data, bytes) or len(data) != 36:
            raise AKSIdentityReplacementCodecError(
                "identity-delete request is not exactly 36 bytes"
            )
        status, session, compatibility_length, identity_length = struct.unpack_from(
            "<IQII", data
        )
        if status != 0 or compatibility_length != 0 or identity_length != UUID_LENGTH:
            raise AKSIdentityReplacementCodecError(
                "identity-delete request has unsupported fields"
            )
        return cls(_session(session), _identity(data[20:36]))


@dataclass(frozen=True)
class AKSIdentityDeleteResponse:
    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityDeleteResponse":
        if not isinstance(data, bytes) or data != bytes(4):
            raise AKSIdentityReplacementCodecError(
                "identity-delete response is not exact status-zero"
            )
        return cls()


@dataclass(frozen=True)
class AKSIdentityOpenRequest:
    session: int
    account_uuid: bytes

    def encode(self) -> bytes:
        session = _session(self.session)
        account_uuid = _identity(self.account_uuid)
        return struct.pack("<IQI", 0, session, UUID_LENGTH) + account_uuid

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityOpenRequest":
        if not isinstance(data, bytes) or len(data) != 32:
            raise AKSIdentityReplacementCodecError(
                "identity-open request is not exactly 32 bytes"
            )
        status, session, identity_length = struct.unpack_from("<IQI", data)
        if status != 0 or identity_length != UUID_LENGTH:
            raise AKSIdentityReplacementCodecError(
                "identity-open request has unsupported fields"
            )
        return cls(_session(session), _identity(data[16:32]))


@dataclass(frozen=True)
class AKSIdentityOpenResponse:
    live_handle: int

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityOpenResponse":
        if not isinstance(data, bytes) or len(data) != 8:
            raise AKSIdentityReplacementCodecError(
                "identity-open response is not exactly 8 bytes"
            )
        status, live_handle = struct.unpack("<II", data)
        if status != 0 or not 0 < live_handle <= 0x7FFFFFFF:
            raise AKSIdentityReplacementCodecError(
                "identity-open response has no positive live handle"
            )
        return cls(live_handle)
