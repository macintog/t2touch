# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free codec for the recovered AKS identity-create-v5 body.

This module deliberately contains no transport, command-line entry point, or
policy for choosing flags.  The enclosing AKS v2 header and endpoint-7
operation are supplied by the kernel transport only after a separate safety
review.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


MAX_BODY_BYTES = 0x4000 - 0x54
ENDPOINT = 7
OPERATION = 0x01
VERSION = 5
EXPORT_OPERATION = 0x02
EXPORT_VERSION = 1


class AKSIdentityCreateCodecError(ValueError):
    pass


def _uint(value: object, bits: int, field: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise AKSIdentityCreateCodecError(f"{field} is not an unsigned {bits}-bit integer")
    return value


def _int32(value: object, field: str) -> int:
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise AKSIdentityCreateCodecError(f"{field} is not a signed 32-bit integer")
    return value


def _bytes(value: object, field: str) -> bytes:
    if not isinstance(value, bytes):
        raise AKSIdentityCreateCodecError(f"{field} is not bytes")
    if len(value) > MAX_BODY_BYTES:
        raise AKSIdentityCreateCodecError(f"{field} exceeds the endpoint body limit")
    return value


def _blob(value: bytes) -> bytes:
    padding = (-len(value)) & 3
    return struct.pack("<I", len(value)) + value + bytes(padding)


def _read_blob(data: bytes, offset: int, field: str) -> tuple[bytes, int]:
    if len(data) - offset < 4:
        raise AKSIdentityCreateCodecError(f"{field} length is truncated")
    length = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    padding = (-length) & 3
    end = offset + length
    padded_end = end + padding
    if end < offset or padded_end > len(data):
        raise AKSIdentityCreateCodecError(f"{field} data is truncated")
    if data[end:padded_end] != bytes(padding):
        raise AKSIdentityCreateCodecError(f"{field} has nonzero alignment padding")
    return data[offset:end], padded_end


def _mutable_blob_bounds(
    data: bytearray, offset: int, field: str
) -> tuple[int, int, int]:
    if not isinstance(data, bytearray) or len(data) - offset < 4:
        raise AKSIdentityCreateCodecError(f"{field} length is truncated")
    length = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    end = start + length
    padded_end = end + ((-length) & 3)
    if end < start or padded_end > len(data):
        raise AKSIdentityCreateCodecError(f"{field} data is truncated")
    if any(data[end:padded_end]):
        raise AKSIdentityCreateCodecError(f"{field} has nonzero alignment padding")
    return start, end, padded_end


@dataclass(frozen=True)
class AKSIdentityCreateV5Request:
    session: int
    internal_flags: int
    effective_bag_handle: int
    item1: bytes
    item2: bytes
    account_uuid: bytes
    item3: bytes
    original_flags: int
    scalar2: int
    optional_data: bytes = b""

    def encode(self) -> bytes:
        session = _uint(self.session, 64, "session")
        internal_flags = _uint(self.internal_flags, 32, "internal flags")
        effective_handle = _int32(self.effective_bag_handle, "effective bag handle")
        original_flags = _uint(self.original_flags, 64, "original flags")
        scalar2 = _uint(self.scalar2, 64, "scalar2")
        item1 = _bytes(self.item1, "item1")
        item2 = _bytes(self.item2, "item2")
        account_uuid = _bytes(self.account_uuid, "account UUID")
        item3 = _bytes(self.item3, "item3")
        optional_data = _bytes(self.optional_data, "optional data")
        if len(account_uuid) != 16:
            raise AKSIdentityCreateCodecError("account UUID is not 16 bytes")

        encoded = b"".join(
            (
                struct.pack("<IQIi", VERSION, session, internal_flags, effective_handle),
                _blob(item1),
                _blob(item2),
                _blob(account_uuid),
                _blob(item3),
                struct.pack("<QQ", original_flags, scalar2),
                _blob(optional_data),
            )
        )
        if len(encoded) > MAX_BODY_BYTES:
            raise AKSIdentityCreateCodecError("encoded request exceeds the endpoint body limit")
        return encoded

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityCreateV5Request":
        data = _bytes(data, "request body")
        if len(data) < 24:
            raise AKSIdentityCreateCodecError("request fixed fields are truncated")
        version, session, internal_flags, effective_handle = struct.unpack_from(
            "<IQIi", data, 0
        )
        if version != VERSION:
            raise AKSIdentityCreateCodecError("unsupported identity-create version")
        offset = 20
        item1, offset = _read_blob(data, offset, "item1")
        item2, offset = _read_blob(data, offset, "item2")
        account_uuid, offset = _read_blob(data, offset, "account UUID")
        item3, offset = _read_blob(data, offset, "item3")
        if len(account_uuid) != 16:
            raise AKSIdentityCreateCodecError("account UUID is not 16 bytes")
        if len(data) - offset < 16:
            raise AKSIdentityCreateCodecError("request scalar tail is truncated")
        original_flags, scalar2 = struct.unpack_from("<QQ", data, offset)
        optional_data, offset = _read_blob(data, offset + 16, "optional data")
        if offset != len(data):
            raise AKSIdentityCreateCodecError("request has trailing bytes")
        return cls(
            session=session,
            internal_flags=internal_flags,
            effective_bag_handle=effective_handle,
            item1=item1,
            item2=item2,
            account_uuid=account_uuid,
            item3=item3,
            original_flags=original_flags,
            scalar2=scalar2,
            optional_data=optional_data,
        )


@dataclass(frozen=True)
class AKSIdentityCreateV5Response:
    live_handle: int
    kek_material: bytes

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityCreateV5Response":
        data = _bytes(data, "response body")
        if len(data) < 12:
            raise AKSIdentityCreateCodecError("response is truncated")
        version, live_handle = struct.unpack_from("<Ii", data, 0)
        if version != VERSION:
            raise AKSIdentityCreateCodecError("unsupported identity-create response version")
        kek_material, offset = _read_blob(data, 8, "KEK material")
        if offset != len(data):
            raise AKSIdentityCreateCodecError("response has trailing bytes")
        return cls(live_handle=live_handle, kek_material=kek_material)

    @classmethod
    def inspect_mutable(cls, data: bytearray) -> tuple[int, int]:
        """Validate without copying optional KEK bytes out of a wipeable buffer."""
        if not isinstance(data, bytearray) or len(data) < 12:
            raise AKSIdentityCreateCodecError("response is truncated")
        version, live_handle = struct.unpack_from("<Ii", data, 0)
        if version != VERSION:
            raise AKSIdentityCreateCodecError("unsupported identity-create response version")
        start, end, offset = _mutable_blob_bounds(data, 8, "KEK material")
        if offset != len(data):
            raise AKSIdentityCreateCodecError("response has trailing bytes")
        return live_handle, end - start


@dataclass(frozen=True)
class AKSIdentityCopyKeybagV1Request:
    session: int
    live_handle: int
    compatibility_input: bytes = b""

    def encode(self) -> bytes:
        session = _uint(self.session, 64, "export session")
        live_handle = _int32(self.live_handle, "export live handle")
        compatibility_input = _bytes(
            self.compatibility_input, "export compatibility input"
        )
        encoded = struct.pack(
            "<IQi", EXPORT_VERSION, session, live_handle
        ) + _blob(compatibility_input)
        if len(encoded) > MAX_BODY_BYTES:
            raise AKSIdentityCreateCodecError(
                "encoded export request exceeds the endpoint body limit"
            )
        return encoded

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityCopyKeybagV1Request":
        data = _bytes(data, "export request body")
        if len(data) < 20:
            raise AKSIdentityCreateCodecError("export request is truncated")
        version, session, live_handle = struct.unpack_from("<IQi", data, 0)
        if version != EXPORT_VERSION:
            raise AKSIdentityCreateCodecError(
                "unsupported identity-export version"
            )
        compatibility_input, offset = _read_blob(
            data, 16, "export compatibility input"
        )
        if offset != len(data):
            raise AKSIdentityCreateCodecError("export request has trailing bytes")
        return cls(session, live_handle, compatibility_input)


@dataclass(frozen=True)
class AKSIdentityCopyKeybagV1Response:
    saved_keybag: bytes

    @classmethod
    def decode(cls, data: bytes) -> "AKSIdentityCopyKeybagV1Response":
        data = _bytes(data, "export response body")
        if len(data) < 8:
            raise AKSIdentityCreateCodecError("export response is truncated")
        version = struct.unpack_from("<I", data, 0)[0]
        if version != EXPORT_VERSION:
            raise AKSIdentityCreateCodecError(
                "unsupported identity-export response version"
            )
        saved_keybag, offset = _read_blob(data, 4, "saved keybag")
        if not saved_keybag:
            raise AKSIdentityCreateCodecError("saved keybag is empty")
        if offset != len(data):
            raise AKSIdentityCreateCodecError("export response has trailing bytes")
        return cls(saved_keybag)

    @classmethod
    def extract_mutable(cls, data: bytearray) -> bytearray:
        """Copy the saved object once into caller-owned wipeable storage."""
        if not isinstance(data, bytearray) or len(data) < 8:
            raise AKSIdentityCreateCodecError("export response is truncated")
        version = struct.unpack_from("<I", data, 0)[0]
        if version != EXPORT_VERSION:
            raise AKSIdentityCreateCodecError(
                "unsupported identity-export response version"
            )
        start, end, offset = _mutable_blob_bounds(data, 4, "saved keybag")
        if start == end:
            raise AKSIdentityCreateCodecError("saved keybag is empty")
        if offset != len(data):
            raise AKSIdentityCreateCodecError("export response has trailing bytes")
        return bytearray(data[start:end])
