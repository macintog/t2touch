# SPDX-License-Identifier: GPL-2.0-only
"""Exact no-CLI userspace transport for one journal-authorized D171 phase."""

from __future__ import annotations

import fcntl
import hashlib
import struct
import uuid
from dataclasses import dataclass

import t2_aks_identity_replacement as replacement_codec
import t2_aks_identity_create as create_codec
import t2_aks_primary_identity as primary_codec
from t2_aks_provisioning_transport import (
    AKSProvisioningTransport,
    AKSProvisioningTransportError,
    INFO_FORMAT,
    T2_AKS_INFO_F_REPLACEMENT_ARMED,
    T2_AKS_INFO_F_REPLACEMENT_ENABLED,
    _ioc,
    _zero,
)


ARM_FORMAT = "=16s16s16sQII"
ARM_SIZE = struct.calcsize(ARM_FORMAT)
if ARM_SIZE != 64:
    raise RuntimeError("unexpected AKS replacement arm ABI size")
T2_AKS_IOC_ARM_REPLACEMENT = _ioc(1, 0xA7, 2, ARM_SIZE)

PHASE_NONE = 0
PHASE_DELETE = 1
PHASE_CREATE = 2
PHASE_RECOVER = 3


@dataclass(frozen=True, repr=False)
class PrimaryObservation:
    present: bool
    account_uuid: str | None
    evidence_sha256: str


def _uuid_bytes(value: str, label: str) -> bytes:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise AKSProvisioningTransportError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AKSProvisioningTransportError(f"{label} is invalid")
    return parsed.bytes


class AKSReplacementTransport(AKSProvisioningTransport):
    """Hold one exclusive descriptor across one exact replacement phase."""

    def __init__(self, *arguments: object, **keywords: object) -> None:
        self._replacement_phase = PHASE_NONE
        self._armed_session: int | None = None
        self._armed_old_uuid: str | None = None
        self._armed_new_uuid: str | None = None
        self._recovery_handle: int | None = None
        self._created_handle: int | None = None
        self._unload_attempted = False
        self._delete_attempted = False
        self._create_attempted = False
        self._recovery_open_attempted = False
        super().__init__(*arguments, **keywords)
        _, flags, _, _, _ = struct.unpack(INFO_FORMAT, self._initial_info)
        if (
            flags & T2_AKS_INFO_F_REPLACEMENT_ENABLED == 0
            or flags & T2_AKS_INFO_F_REPLACEMENT_ARMED
        ):
            self.close()
            raise AKSProvisioningTransportError(
                "AKS replacement transport is not enabled and unarmed"
            )

    def arm(
        self,
        *,
        phase: int,
        session: int,
        old_account_uuid: str,
        new_account_uuid: str,
        activation_material: bytearray | None,
    ) -> None:
        if self.fd < 0:
            raise AKSProvisioningTransportError("AKS replacement transport is closed")
        if phase not in {PHASE_DELETE, PHASE_CREATE, PHASE_RECOVER}:
            raise AKSProvisioningTransportError("replacement phase is invalid")
        if type(session) is not int or not 0 < session < (1 << 64):
            raise AKSProvisioningTransportError("replacement session is invalid")
        if self._replacement_phase not in {PHASE_NONE, PHASE_DELETE} or (
            self._replacement_phase == PHASE_DELETE and phase != PHASE_CREATE
        ):
            raise AKSProvisioningTransportError("replacement phase cannot be rearmed")
        if self._replacement_phase == PHASE_DELETE and (
            session != self._armed_session
            or old_account_uuid != self._armed_old_uuid
            or new_account_uuid != self._armed_new_uuid
            or not self._delete_attempted
        ):
            raise AKSProvisioningTransportError("replacement rearm binding changed")
        if phase == PHASE_RECOVER:
            if activation_material is not None:
                raise AKSProvisioningTransportError(
                    "recovery arm must not receive activation material"
                )
        elif (
            not isinstance(activation_material, bytearray)
            or len(activation_material) != 16
            or not any(activation_material)
        ):
            raise AKSProvisioningTransportError(
                "replacement activation material is invalid"
            )
        old_uuid = _uuid_bytes(old_account_uuid, "old account UUID")
        new_uuid = _uuid_bytes(new_account_uuid, "new account UUID")
        if old_uuid == new_uuid:
            raise AKSProvisioningTransportError("replacement account UUIDs are equal")

        arm = bytearray(ARM_SIZE)
        try:
            arm[:16] = old_uuid
            arm[16:32] = new_uuid
            if activation_material is not None:
                arm[32:48] = activation_material
            struct.pack_into("=QII", arm, 48, session, phase, 0)
            fcntl.ioctl(self.fd, T2_AKS_IOC_ARM_REPLACEMENT, arm, True)
            self._replacement_phase = phase
            self._armed_session = session
            self._armed_old_uuid = old_account_uuid
            self._armed_new_uuid = new_account_uuid
        except OSError as error:
            raise AKSProvisioningTransportError(
                "AKS replacement phase could not be armed"
            ) from error
        finally:
            _zero(arm)

    def delete_identity(self, session: int, old_account_uuid: str) -> None:
        if (
            self._replacement_phase != PHASE_DELETE
            or session != self._armed_session
            or old_account_uuid != self._armed_old_uuid
            or self._delete_attempted
        ):
            raise AKSProvisioningTransportError("identity deletion is not armed")
        request = bytearray(
            replacement_codec.AKSIdentityDeleteRequest(
                session, _uuid_bytes(old_account_uuid, "old account UUID")
            ).encode()
        )
        response = bytearray()
        try:
            self._delete_attempted = True
            response = self._exchange(0x49, request, 4)
            replacement_codec.AKSIdentityDeleteResponse.decode(bytes(response))
        finally:
            _zero(request)
            _zero(response)

    def observe_primary(self, session: int) -> PrimaryObservation:
        """Read one primary result and retain only its account UUID and digest."""

        if type(session) is not int or not 0 < session < (1 << 64):
            raise AKSProvisioningTransportError("replacement session is invalid")
        request = bytearray(36)
        response = bytearray()
        try:
            struct.pack_into("<Q", request, 4, session)
            struct.pack_into("<I", request, 20, 0xFFFFFFFF)
            struct.pack_into("<I", request, 28, 0xFFFFFFFF)
            try:
                response = self._exchange(0x51, request, primary_codec.MAX_DER_BYTES + 8)
            except AKSProvisioningTransportError as error:
                if error.sep_status != -3:
                    raise
                evidence = b"mailbox-status:-3"
                return PrimaryObservation(
                    False,
                    None,
                    hashlib.sha256(bytes(request) + evidence).hexdigest(),
                )
            if response == bytearray(struct.pack("<II", 0xFFFFFFFD, 0)):
                return PrimaryObservation(
                    False,
                    None,
                    hashlib.sha256(bytes(request) + response).hexdigest(),
                )
            if len(response) < 8:
                raise AKSProvisioningTransportError(
                    "primary identity response is truncated"
                )
            status, blob_length = struct.unpack_from("<II", response)
            padded_length = (blob_length + 3) & ~3
            if (
                status != 0
                or blob_length == 0
                or blob_length > primary_codec.MAX_DER_BYTES
                or padded_length < blob_length
                or len(response) != 8 + padded_length
                or any(response[8 + blob_length :])
            ):
                raise AKSProvisioningTransportError(
                    "primary identity response envelope is invalid"
                )
            try:
                primary = primary_codec.decode(bytes(response[8 : 8 + blob_length]))
            except primary_codec.AKSPrimaryIdentityError as error:
                raise AKSProvisioningTransportError(
                    "primary identity dictionary is invalid"
                ) from error
            return PrimaryObservation(
                True,
                primary.account_uuid,
                hashlib.sha256(bytes(request) + response).hexdigest(),
            )
        finally:
            _zero(request)
            _zero(response)

    def open_identity(self, session: int, new_account_uuid: str) -> int:
        if (
            self._replacement_phase != PHASE_RECOVER
            or session != self._armed_session
            or new_account_uuid != self._armed_new_uuid
            or self._recovery_open_attempted
        ):
            raise AKSProvisioningTransportError("identity recovery is not armed")
        if self._recovery_handle is not None:
            raise AKSProvisioningTransportError("a recovered identity is already live")
        request = bytearray(
            replacement_codec.AKSIdentityOpenRequest(
                session, _uuid_bytes(new_account_uuid, "new account UUID")
            ).encode()
        )
        response = bytearray()
        try:
            self._recovery_open_attempted = True
            response = self._exchange(0x03, request, 8)
            decoded = replacement_codec.AKSIdentityOpenResponse.decode(bytes(response))
            self._recovery_handle = decoded.live_handle
            self._unload_attempted = False
            return decoded.live_handle
        finally:
            _zero(request)
            _zero(response)

    def create(self, request: bytearray) -> tuple[int, bytearray]:
        if self._replacement_phase != PHASE_CREATE or self._create_attempted:
            raise AKSProvisioningTransportError("identity creation is not armed")
        self._create_attempted = True
        status, response = super().create(request)
        live_handle, _ = create_codec.inspect_create_response(
            response, self.create_version
        )
        self._created_handle = live_handle
        return status, response

    def unload_created_identity(self, session: int, live_handle: int) -> None:
        if (
            self._replacement_phase != PHASE_CREATE
            or session != self._armed_session
            or live_handle != self._created_handle
        ):
            raise AKSProvisioningTransportError("created live handle is not owned")
        self._unload_identity(session, live_handle)
        self._created_handle = None

    def require_no_live_handles(self) -> None:
        """Re-attest this fresh descriptor's no-handle provisioning state."""

        info = self._get_info()
        if info.connection_generation != self.connection_generation:
            raise AKSProvisioningTransportError(
                "replacement connection generation changed"
            )

    def unload_recovered_identity(self, session: int, live_handle: int) -> None:
        if session != self._armed_session or live_handle != self._recovery_handle:
            raise AKSProvisioningTransportError("recovered live handle is not owned")
        self._unload_identity(session, live_handle)
        self._recovery_handle = None

    def _unload_identity(self, session: int, live_handle: int) -> None:
        if self._unload_attempted:
            raise AKSProvisioningTransportError("identity unload was already attempted")
        request = bytearray(struct.pack("<IQI", 0, session, live_handle))
        response = bytearray()
        try:
            self._unload_attempted = True
            response = self._exchange(0x05, request, 4)
            if response != bytearray(4):
                raise AKSProvisioningTransportError(
                    "identity unload reply is invalid"
                )
            self._unload_attempted = False
        finally:
            _zero(request)
            _zero(response)

    def close(self) -> None:
        super().close()
        self._replacement_phase = PHASE_NONE
        self._armed_session = None
        self._armed_old_uuid = None
        self._armed_new_uuid = None
        self._recovery_handle = None
        self._created_handle = None
        self._unload_attempted = False
        self._delete_attempted = False
        self._create_attempted = False
        self._recovery_open_attempted = False
