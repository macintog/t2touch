# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import struct
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_aks_provisioning_transport as base
import t2_aks_replacement_transport as replacement


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class FakeReplacement(replacement.AKSReplacementTransport):
    def __init__(self) -> None:
        self.fd = 7
        self.connection_generation = identifier(10)
        self._initial_info = struct.pack(
            base.INFO_FORMAT,
            uuid.UUID(int=10).bytes,
            base.T2_AKS_INFO_F_OOL_REGISTERED
            | base.T2_AKS_INFO_F_ACM_REGISTERED
            | base.T2_AKS_INFO_F_PROVISIONING_ENABLED
            | base.T2_AKS_INFO_F_REPLACEMENT_ENABLED,
            2,
            0,
            0,
        )
        self._replacement_phase = replacement.PHASE_NONE
        self._armed_session = None
        self._armed_old_uuid = None
        self._armed_new_uuid = None
        self._recovery_handle = None
        self._created_handle = None
        self._unload_attempted = False
        self._delete_attempted = False
        self._create_attempted = False
        self._recovery_open_attempted = False
        self.requests: list[tuple[int, bytes, int]] = []

    def _exchange(
        self, operation: int, request: bytearray, response_capacity: int
    ) -> bytearray:
        self.requests.append((operation, bytes(request), response_capacity))
        if operation == 0x49:
            return bytearray(4)
        if operation == 0x03:
            return bytearray(struct.pack("<II", 0, 42))
        if operation == 0x05:
            return bytearray(4)
        raise AssertionError(f"unexpected operation {operation:#x}")


class AKSReplacementTransportTests(unittest.TestCase):
    def test_arm_is_exact_write_only_abi_and_internal_buffer_is_wiped(self) -> None:
        device = FakeReplacement()
        captured = bytearray()

        def ioctl(_fd: int, command: int, value: bytearray, _mutate: bool) -> None:
            self.assertEqual(command, replacement.T2_AKS_IOC_ARM_REPLACEMENT)
            captured.extend(value)

        material = bytearray(range(1, 17))
        with (
            mock.patch.object(replacement.fcntl, "ioctl", side_effect=ioctl),
            mock.patch.object(replacement, "_zero", wraps=replacement._zero) as wipe,
        ):
            device.arm(
                phase=replacement.PHASE_DELETE,
                session=7,
                old_account_uuid=identifier(1),
                new_account_uuid=identifier(2),
                activation_material=material,
            )
        self.assertEqual(len(captured), 64)
        self.assertEqual(captured[32:48], bytes(range(1, 17)))
        self.assertEqual(struct.unpack_from("=QII", captured, 48), (7, 1, 0))
        self.assertEqual(material, bytearray(range(1, 17)))
        self.assertEqual(wipe.call_count, 1)

    def test_delete_and_recovery_have_only_exact_typed_operations(self) -> None:
        device = FakeReplacement()
        device._replacement_phase = replacement.PHASE_DELETE
        device._armed_session = 7
        device._armed_old_uuid = identifier(1)
        device._armed_new_uuid = identifier(2)
        device.delete_identity(7, identifier(1))
        self.assertEqual(device.requests[0][0], 0x49)
        self.assertEqual(len(device.requests[0][1]), 36)
        with self.assertRaises(base.AKSProvisioningTransportError):
            device.delete_identity(7, identifier(1))

        device._replacement_phase = replacement.PHASE_RECOVER
        handle = device.open_identity(7, identifier(2))
        self.assertEqual(handle, 42)
        self.assertEqual(device.requests[1][0], 0x03)
        self.assertEqual(len(device.requests[1][1]), 32)
        device.unload_recovered_identity(7, handle)
        self.assertEqual(device.requests[2][0], 0x05)
        self.assertIsNone(device._recovery_handle)

    def test_rearm_and_unowned_handle_paths_fail_closed(self) -> None:
        device = FakeReplacement()
        device._replacement_phase = replacement.PHASE_RECOVER
        device._armed_session = 7
        device._armed_old_uuid = identifier(1)
        device._armed_new_uuid = identifier(2)
        with self.assertRaises(base.AKSProvisioningTransportError):
            device.arm(
                phase=replacement.PHASE_CREATE,
                session=7,
                old_account_uuid=identifier(1),
                new_account_uuid=identifier(2),
                activation_material=bytearray(range(1, 17)),
            )
        with self.assertRaises(base.AKSProvisioningTransportError):
            device.unload_recovered_identity(7, 42)

        device._replacement_phase = replacement.PHASE_CREATE
        device._created_handle = 43
        device.unload_created_identity(7, 43)
        self.assertEqual(device.requests[-1][0], 0x05)
        self.assertIsNone(device._created_handle)
        with self.assertRaises(base.AKSProvisioningTransportError):
            device.unload_created_identity(7, 43)


if __name__ == "__main__":
    unittest.main()
