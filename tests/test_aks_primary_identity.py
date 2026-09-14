# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import struct
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_aks_primary_identity as primary
import t2_aks_provisioning_transport as base
import t2_aks_replacement_transport as replacement
from tests.test_aks_replacement_transport import FakeReplacement, identifier


def tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        encoded = len(content).to_bytes(2, "big").lstrip(b"\0")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + content


def primary_der(*, account: int = 1, duplicate: bool = False) -> bytes:
    fields = (("uuid", account), ("guid", 2), ("kid", 3))
    if duplicate:
        fields = (("uuid", account), ("uuid", 2), ("kid", 3))
    entries = b"".join(
        tlv(0x30, tlv(0x0C, key.encode("ascii")) + tlv(0x04, uuid.UUID(int=value).bytes))
        for key, value in fields
    )
    return tlv(0x31, entries)


class InventoryReplacement(FakeReplacement):
    def __init__(self, responses: list[object]) -> None:
        super().__init__()
        self.responses = responses

    def _exchange(
        self, operation: int, request: bytearray, response_capacity: int
    ) -> bytearray:
        self.requests.append((operation, bytes(request), response_capacity))
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, bytearray)
        return value


class AKSPrimaryIdentityTests(unittest.TestCase):
    def test_strict_dictionary_exposes_only_account_uuid(self) -> None:
        decoded = primary.decode(primary_der())
        self.assertEqual(decoded.account_uuid, identifier(1))
        self.assertEqual(decoded.redacted(), {"present": True, "identifiers_redacted": True})
        self.assertNotIn(identifier(1), repr(decoded))
        with self.assertRaises(primary.AKSPrimaryIdentityError):
            primary.decode(primary_der(duplicate=True))
        with self.assertRaises(primary.AKSPrimaryIdentityError):
            primary.decode(primary_der(account=2))

    def test_transport_classifies_body_and_mailbox_absence(self) -> None:
        device = InventoryReplacement(
            [
                bytearray(struct.pack("<II", 0xFFFFFFFD, 0)),
                base.AKSProvisioningTransportError("absent", sep_status=-3),
            ]
        )
        first = device.observe_primary(7)
        second = device.observe_primary(7)
        self.assertFalse(first.present)
        self.assertFalse(second.present)
        self.assertIsNone(first.account_uuid)
        self.assertEqual(len({first.evidence_sha256, second.evidence_sha256}), 2)
        self.assertEqual([entry[0] for entry in device.requests], [0x51, 0x51])

    def test_transport_accepts_only_exact_padded_present_envelope(self) -> None:
        document = primary_der()
        padding = bytes((4 - len(document) % 4) % 4)
        valid = bytearray(struct.pack("<II", 0, len(document)) + document + padding)
        device = InventoryReplacement([valid])
        observed = device.observe_primary(7)
        self.assertTrue(observed.present)
        self.assertEqual(observed.account_uuid, identifier(1))

        malformed = bytearray(valid)
        malformed[-1:] = b"\x01"
        if not padding:
            malformed.extend(b"\x01")
        device = InventoryReplacement([malformed])
        with self.assertRaises(base.AKSProvisioningTransportError):
            device.observe_primary(7)


if __name__ == "__main__":
    unittest.main()
