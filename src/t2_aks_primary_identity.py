# SPDX-License-Identifier: GPL-2.0-only
"""Strict privacy-conscious decoder for AKS durable-primary inventory."""

from __future__ import annotations

import uuid
from dataclasses import dataclass


MAX_DER_BYTES = 16_292


class AKSPrimaryIdentityError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class PrimaryIdentity:
    """Expose only the caller-owned account UUID; keep SEP UUIDs private."""

    account_uuid: str

    def redacted(self) -> dict[str, object]:
        return {"present": True, "identifiers_redacted": True}


def _length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise AKSPrimaryIdentityError("primary identity DER length is truncated")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise AKSPrimaryIdentityError("indefinite DER length is forbidden")
    if count > 2 or offset + count > len(data):
        raise AKSPrimaryIdentityError("primary identity DER length is invalid")
    encoded = data[offset : offset + count]
    if encoded[0] == 0:
        raise AKSPrimaryIdentityError("primary identity DER length is not minimal")
    value = int.from_bytes(encoded, "big")
    if value < 0x80:
        raise AKSPrimaryIdentityError("primary identity DER length is not minimal")
    return value, offset + count


def _tlv(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise AKSPrimaryIdentityError("primary identity DER tag is unexpected")
    length, content_offset = _length(data, offset + 1)
    end = content_offset + length
    if end > len(data):
        raise AKSPrimaryIdentityError("primary identity DER value is truncated")
    return data[content_offset:end], end


def decode(data: bytes) -> PrimaryIdentity:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_DER_BYTES:
        raise AKSPrimaryIdentityError("primary identity DER size is invalid")
    root, end = _tlv(data, 0, 0x31)
    if end != len(data):
        raise AKSPrimaryIdentityError("primary identity DER has trailing data")

    values: dict[str, bytes] = {}
    offset = 0
    while offset < len(root):
        sequence, offset = _tlv(root, offset, 0x30)
        key_content, sequence_offset = _tlv(sequence, 0, 0x0C)
        try:
            key = key_content.decode("ascii")
        except UnicodeDecodeError as error:
            raise AKSPrimaryIdentityError(
                "primary identity key is not ASCII"
            ) from error
        if key in values:
            raise AKSPrimaryIdentityError("primary identity has a duplicate key")
        value, value_end = _tlv(sequence, sequence_offset, 0x04)
        if value_end != len(sequence):
            raise AKSPrimaryIdentityError(
                "primary identity sequence has extra values"
            )
        values[key] = value

    if set(values) != {"uuid", "guid", "kid"}:
        raise AKSPrimaryIdentityError(
            "primary identity fields are incomplete or unsupported"
        )
    if any(len(value) != 16 for value in values.values()):
        raise AKSPrimaryIdentityError("primary identity value is not 16 bytes")
    parsed = [uuid.UUID(bytes=values[key]) for key in ("uuid", "guid", "kid")]
    if any(value.int == 0 for value in parsed) or len(set(parsed)) != 3:
        raise AKSPrimaryIdentityError(
            "primary identity values are zero or not distinct"
        )
    return PrimaryIdentity(str(parsed[0]))
