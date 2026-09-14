# SPDX-License-Identifier: GPL-2.0-only
import dataclasses
import struct
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_aks_identity_create as codec


def request(**changes):
    value = codec.AKSIdentityCreateV5Request(
        session=0x0102030405060708,
        internal_flags=0x24000,
        effective_bag_handle=-1,
        item1=b"primary",
        item2=b"two",
        account_uuid=bytes(range(16)),
        item3=b"item-three",
        original_flags=5,
        scalar2=9,
        optional_data=b"optional",
    )
    return dataclasses.replace(value, **changes)


class AKSIdentityCreateCodecTests(unittest.TestCase):
    def test_constants_name_the_wire_layer(self):
        self.assertEqual((codec.ENDPOINT, codec.OPERATION, codec.VERSION), (7, 1, 5))

    def test_round_trip_preserves_explicit_fields(self):
        value = request()
        self.assertEqual(codec.AKSIdentityCreateV5Request.decode(value.encode()), value)

    def test_encoding_uses_little_endian_fixed_prefix(self):
        encoded = request().encode()
        self.assertEqual(
            encoded[:20],
            struct.pack("<IQIi", 5, 0x0102030405060708, 0x24000, -1),
        )

    def test_blobs_have_zero_four_byte_alignment_padding(self):
        encoded = request(item1=b"x").encode()
        self.assertEqual(encoded[20:28], b"\x01\0\0\0x\0\0\0")

    def test_empty_optional_blob_is_still_length_prefixed(self):
        self.assertTrue(request(optional_data=b"").encode().endswith(bytes(4)))

    def test_rejects_uuid_with_wrong_size(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "UUID"):
            request(account_uuid=b"short").encode()

    def test_rejects_bool_as_integer(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "session"):
            request(session=True).encode()

    def test_rejects_out_of_range_handle(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "handle"):
            request(effective_bag_handle=1 << 31).encode()

    def test_rejects_oversize_request(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "endpoint body"):
            request(item1=b"x" * codec.MAX_BODY_BYTES).encode()

    def test_rejects_wrong_version(self):
        encoded = bytearray(request().encode())
        encoded[:4] = struct.pack("<I", 4)
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "version"):
            codec.AKSIdentityCreateV5Request.decode(bytes(encoded))

    def test_rejects_truncated_blob(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "truncated"):
            codec.AKSIdentityCreateV5Request.decode(request().encode()[:-1])

    def test_rejects_nonzero_blob_padding(self):
        encoded = bytearray(request(item1=b"x").encode())
        encoded[25] = 1
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "padding"):
            codec.AKSIdentityCreateV5Request.decode(bytes(encoded))

    def test_rejects_request_trailing_bytes(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "trailing"):
            codec.AKSIdentityCreateV5Request.decode(request().encode() + b"\0")

    def test_decodes_live_handle_and_kek_material(self):
        data = struct.pack("<IiI", 5, 42, 3) + b"abc\0"
        self.assertEqual(
            codec.AKSIdentityCreateV5Response.decode(data),
            codec.AKSIdentityCreateV5Response(live_handle=42, kek_material=b"abc"),
        )

    def test_rejects_malformed_response(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "truncated"):
            codec.AKSIdentityCreateV5Response.decode(struct.pack("<IiI", 5, 42, 4) + b"x")

    def test_rejects_response_trailing_bytes(self):
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "trailing"):
            codec.AKSIdentityCreateV5Response.decode(struct.pack("<IiI", 5, 42, 0) + b"x")

    def test_copy_keybag_v1_round_trip_and_saved_object(self):
        request_value = codec.AKSIdentityCopyKeybagV1Request(
            session=0x0102030405060708,
            live_handle=42,
        )
        self.assertEqual(
            codec.AKSIdentityCopyKeybagV1Request.decode(request_value.encode()),
            request_value,
        )
        response = struct.pack("<II", codec.EXPORT_VERSION, 3) + b"key\0"
        self.assertEqual(
            codec.AKSIdentityCopyKeybagV1Response.decode(response).saved_keybag,
            b"key",
        )
        with self.assertRaisesRegex(codec.AKSIdentityCreateCodecError, "empty"):
            codec.AKSIdentityCopyKeybagV1Response.decode(
                struct.pack("<II", codec.EXPORT_VERSION, 0)
            )


if __name__ == "__main__":
    unittest.main()
