# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_aks_identity_replacement as codec


class AKSIdentityReplacementCodecTests(unittest.TestCase):
    def test_delete_round_trip_is_exact_unversioned_two_blob_body(self) -> None:
        identity = bytes(range(1, 17))
        encoded = codec.AKSIdentityDeleteRequest(7, identity).encode()
        self.assertEqual(len(encoded), 36)
        self.assertEqual(encoded[:20], struct.pack("<IQII", 0, 7, 0, 16))
        self.assertEqual(codec.AKSIdentityDeleteRequest.decode(encoded).account_uuid, identity)
        self.assertEqual(codec.AKSIdentityDeleteResponse.decode(bytes(4)), codec.AKSIdentityDeleteResponse())

    def test_delete_rejects_every_shape_relaxation(self) -> None:
        valid = bytearray(
            codec.AKSIdentityDeleteRequest(7, bytes(range(1, 17))).encode()
        )
        variants = [valid[:-1], valid + b"\0"]
        for offset in (0, 12, 16, 20):
            changed = bytearray(valid)
            changed[offset] = 0 if offset == 20 else changed[offset] + 1
            if offset == 20:
                changed[20:36] = bytes(16)
            variants.append(changed)
        zero_session = bytearray(valid)
        zero_session[4:12] = bytes(8)
        variants.append(zero_session)
        for value in variants:
            with self.subTest(value=bytes(value).hex()):
                with self.assertRaises(codec.AKSIdentityReplacementCodecError):
                    codec.AKSIdentityDeleteRequest.decode(bytes(value))
        for response in (b"", b"\0" * 3, b"\0" * 5, b"\1\0\0\0"):
            with self.assertRaises(codec.AKSIdentityReplacementCodecError):
                codec.AKSIdentityDeleteResponse.decode(response)

    def test_uuid_open_round_trip_and_positive_handle_response(self) -> None:
        identity = bytes(range(1, 17))
        encoded = codec.AKSIdentityOpenRequest(9, identity).encode()
        self.assertEqual(len(encoded), 32)
        self.assertEqual(encoded[:16], struct.pack("<IQI", 0, 9, 16))
        self.assertEqual(codec.AKSIdentityOpenRequest.decode(encoded).account_uuid, identity)
        self.assertEqual(
            codec.AKSIdentityOpenResponse.decode(struct.pack("<II", 0, 42)).live_handle,
            42,
        )
        with self.assertRaises(codec.AKSIdentityReplacementCodecError):
            codec.AKSIdentityOpenRequest(1, bytes(16)).encode()
        with self.assertRaises(codec.AKSIdentityReplacementCodecError):
            codec.AKSIdentityOpenRequest.decode(
                struct.pack("<IQI", 0, 1, 17) + bytes(range(1, 17))
            )
        for status, handle in ((1, 42), (0, 0), (0, 0x80000000)):
            with self.subTest(status=status, handle=handle):
                with self.assertRaises(codec.AKSIdentityReplacementCodecError):
                    codec.AKSIdentityOpenResponse.decode(
                        struct.pack("<II", status, handle)
                    )


if __name__ == "__main__":
    unittest.main()
