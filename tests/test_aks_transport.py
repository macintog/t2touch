# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import errno
import struct
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_aks_transport as transport


class FakeAKS(transport.AKSActivationTransport):
    def __init__(self) -> None:
        self.fd = 7
        self._live_handle = None
        self._unload_attempted = False
        self._bound_alias = None
        self._acm_unlock_attempted = False
        self.runtime_generation = str(uuid.UUID(int=1))
        self.requests: list[tuple[int, bytes, int]] = []
        self.fail_unload = False

    def _get_info(self):
        return (
            uuid.UUID(int=1).bytes,
            transport.T2_AKS_INFO_F_OOL_REGISTERED
            | transport.T2_AKS_INFO_F_ACM_REGISTERED,
            2,
            0,
            0,
        )

    def _exchange(
        self, operation: int, request: bytearray, response_capacity: int
    ) -> bytearray:
        self.requests.append((operation, bytes(request), response_capacity))
        if operation == 0x03:
            return bytearray(struct.pack("<II", 0, 9))
        if operation == 0x06:
            return bytearray(struct.pack("<II", 0, 16) + uuid.UUID(int=2).bytes)
        if operation in {0x04, 0x05, 0x0D}:
            if operation == 0x05 and self.fail_unload:
                raise transport.AKSActivationTransportError("ambiguous unload")
            return bytearray(4)
        if operation == 0x18:
            return bytearray(struct.pack("<IQQ", 0, 11, 12))
        if operation == 0x21:
            return bytearray(struct.pack("<III", 1, 0, 0))
        if operation == 0x19:
            return bytearray(struct.pack("<II", 1, 3) + b"der\0")
        if operation == 0x23:
            return bytearray(struct.pack("<II", 0, 3) + b"der\0")
        raise AssertionError(f"unexpected operation {operation:#x}")


class AKSActivationTransportTests(unittest.TestCase):
    def test_present_alias_includes_account_uuid_from_state(self) -> None:
        device = object.__new__(transport.AKSActivationTransport)
        bag_uuid = str(uuid.UUID(int=2))
        account_uuid = str(uuid.UUID(int=3))
        with (
            mock.patch.object(device, "_copy_uuid", return_value=bag_uuid),
            mock.patch.object(
                device,
                "_state",
                return_value=SimpleNamespace(
                    handle=-501, lock_state=0, user_uuid=account_uuid
                ),
            ),
        ):
            observed = device.observe_alias(-501)
        self.assertTrue(observed.present)
        self.assertEqual(observed.bag_uuid, bag_uuid)
        self.assertEqual(observed.account_uuid, account_uuid)

    def test_sep_status_survives_eremoteio_and_absence_is_repeatable(self) -> None:
        device = object.__new__(transport.AKSActivationTransport)
        device.fd = 7
        device._live_handle = None
        device._unload_attempted = False
        device._bound_alias = None
        device._acm_unlock_attempted = False
        device.runtime_generation = str(uuid.UUID(int=1))
        calls = 0

        def absent(_fd: int, _command: int, exchange: bytearray) -> None:
            nonlocal calls
            calls += 1
            values = list(struct.unpack(transport.EXCHANGE_FORMAT, exchange))
            values[1] = -3
            exchange[:] = struct.pack(transport.EXCHANGE_FORMAT, *values)
            raise OSError(errno.EREMOTEIO, "synthetic SEP status")

        with mock.patch.object(transport, "_ioctl_mutate", side_effect=absent):
            observed = device.observe_alias(-501)
        self.assertEqual(calls, 2)
        self.assertFalse(observed.present)
        self.assertIsNone(observed.bag_uuid)

    def test_activation_accepts_clean_current_abi_and_rejects_unsafe_state(
        self,
    ) -> None:
        required = transport.T2_AKS_INFO_F_OOL_REGISTERED
        for flags in (
            required,
            required
            | transport.T2_AKS_INFO_F_ACM_REGISTERED
            | transport.T2_AKS_INFO_F_PROVISIONING_ENABLED
            | transport.T2_AKS_INFO_F_REPLACEMENT_ENABLED,
        ):
            with (
                mock.patch("os.open", return_value=8),
                mock.patch("os.close"),
                mock.patch.object(
                    transport.AKSActivationTransport,
                    "_get_info",
                    return_value=(uuid.UUID(int=4).bytes, flags, 2, 0, 0),
                ),
            ):
                device = transport.AKSActivationTransport()
                self.assertEqual(device.runtime_generation, str(uuid.UUID(int=4)))
                device.close()

        unsafe = (
            transport.T2_AKS_INFO_F_PROVISIONING_POISONED
            | transport.T2_AKS_INFO_F_INVENTORY_ONLY
            | transport.T2_AKS_INFO_F_PASSWORD_BOUND
            | transport.T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE
            | transport.T2_AKS_INFO_F_RUNTIME_POISONED
            | transport.T2_AKS_INFO_F_IDENTITY_SECRET_SET
            | transport.T2_AKS_INFO_F_REPLACEMENT_ARMED
        )
        unsafe_info = [
            (required | flag, 0, 0)
            for flag in (
                transport.T2_AKS_INFO_F_PROVISIONING_POISONED,
                transport.T2_AKS_INFO_F_INVENTORY_ONLY,
                transport.T2_AKS_INFO_F_PASSWORD_BOUND,
                transport.T2_AKS_INFO_F_RUNTIME_HANDLE_ACTIVE,
                transport.T2_AKS_INFO_F_RUNTIME_POISONED,
                transport.T2_AKS_INFO_F_IDENTITY_SECRET_SET,
                transport.T2_AKS_INFO_F_REPLACEMENT_ARMED,
            )
        ]
        self.assertEqual(unsafe, transport._UNSAFE_INFO_FLAGS)
        unsafe_info.extend(((required, 1, 0), (required, 0, 1)))
        for flags, phase, absence_count in unsafe_info:
            with (
                mock.patch("os.open", return_value=8),
                mock.patch("os.close"),
                mock.patch.object(
                    transport.AKSActivationTransport,
                    "_get_info",
                    return_value=(
                        uuid.UUID(int=4).bytes,
                        flags,
                        2,
                        phase,
                        absence_count,
                    ),
                ),
                self.assertRaises(transport.AKSActivationTransportError),
            ):
                transport.AKSActivationTransport()

    def test_one_owner_loads_binds_acm_unlocks_and_unloads(self) -> None:
        device = FakeAKS()
        identity_reference = b"\x5a" * 16
        context = b"\xa5" * 16
        generation = str(uuid.UUID(int=5))
        keybag_path = (
            f"/var/lib/t2-touchid/users/1000/identities/{generation}/user.kb"
        )
        self.assertEqual(
            str(transport._policy_keybag_path(keybag_path)), keybag_path
        )
        with self.assertRaises(transport.AKSActivationTransportError):
            transport._policy_keybag_path(
                "/var/lib/t2-touchid/users/1000/identities/not-a-uuid/user.kb"
            )
        with mock.patch.object(
            device, "_read_keybag", return_value=bytearray(b"saved")
        ):
            handle = device.load_keybag(keybag_path)
        self.assertEqual(handle, 9)
        self.assertEqual(device.bag_uuid(handle), str(uuid.UUID(int=2)))
        self.assertEqual(device.bind_alias(handle, -1000), 0)
        device.resolve_alias_configuration(-1000)
        device.bind_loaded_identity_secret_to_acm_context(
            identity_reference, context
        )
        self.assertEqual(
            device.unlock_alias_with_acm_context(-1000, identity_reference), 0
        )
        with self.assertRaises(transport.AKSActivationTransportError):
            device.unlock_alias_with_acm_context(-1000, identity_reference)
        device.unload_keybag(handle)
        self.assertIsNone(device._live_handle)
        self.assertEqual(
            [operation for operation, _, _ in device.requests],
            [0x03, 0x06, 0x06, 0x0D, 0x23, 0x21, 0x18, 0x05],
        )
        self.assertEqual(device.requests[0][1][16:21], b"saved")
        self.assertEqual(device.requests[3][1][16:20], struct.pack("<i", -1000))
        self.assertEqual(device.requests[4][1][12:16], struct.pack("<i", -1000))
        self.assertEqual(
            struct.unpack_from("<IQiI", device.requests[5][1]),
            (1, 1, 9, 16),
        )
        self.assertEqual(device.requests[5][1][20:36], identity_reference)
        self.assertEqual(device.requests[5][1][36:40], struct.pack("<I", 16))
        self.assertEqual(device.requests[5][1][40:56], context)
        self.assertEqual(device.requests[5][1][56:64], struct.pack("<Q", 0x100))
        self.assertEqual(device.requests[5][2], 12)
        self.assertEqual(
            struct.unpack_from("<IQiIQI", device.requests[6][1]),
            (0, 1, -1000, 0, 0x100, 16),
        )
        self.assertEqual(device.requests[6][1][32:48], identity_reference)
        self.assertEqual(device.requests[6][2], 20)

        failed = FakeAKS()
        failed._live_handle = 11
        failed.fail_unload = True
        with self.assertRaises(transport.AKSActivationTransportError):
            failed.unload_keybag(11)
        with mock.patch("os.close"):
            failed.close()
        self.assertEqual(
            [operation for operation, _, _ in failed.requests].count(0x05), 1
        )

    def test_verify_only_omits_authorization_context(self) -> None:
        device = FakeAKS()
        identity_reference = b"\x5a" * 16
        with mock.patch.object(
            device, "_read_keybag", return_value=bytearray(b"saved")
        ):
            handle = device.load_keybag("/var/lib/t2-touchid/users/1000/user.kb")
        self.assertEqual(device.bind_alias(handle, -1000), 0)
        device.verify_loaded_identity_secret(identity_reference)
        operation, request, capacity = device.requests[-1]
        self.assertEqual(operation, 0x21)
        self.assertEqual(struct.unpack_from("<IQiI", request), (1, 1, 9, 16))
        self.assertEqual(request[20:36], identity_reference)
        self.assertEqual(request[36:40], struct.pack("<I", 0))
        self.assertEqual(request[40:48], struct.pack("<Q", 0x100))
        self.assertEqual(len(request), 48)
        self.assertEqual(capacity, 12)

    def test_alias_uuid_and_state_blob_can_be_reconciled_read_only(self) -> None:
        device = FakeAKS()
        self.assertEqual(device.observe_alias_uuid(-501), str(uuid.UUID(int=2)))
        blob = device.read_alias_state_blob(-501)
        self.assertEqual(blob, bytearray(b"der"))
        self.assertEqual(
            [operation for operation, _, _ in device.requests],
            [0x06, 0x06, 0x19],
        )


if __name__ == "__main__":
    unittest.main()
