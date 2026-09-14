# SPDX-License-Identifier: GPL-2.0-only
"""Dependency-injected owner for one AKS create/export/persist transaction."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

import t2_aks_identity_create as codec
import t2_aks_provisioning as provisioning
import t2_acm_device


class AKSProvisioningOperationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreflightAttestation:
    connection_generation: str
    evidence_sha256: str
    xart_ready: bool
    primary_identity_absent: bool
    inventory_stable: bool


class ProvisioningTransport(Protocol):
    connection_generation: str

    def create(self, request: bytearray) -> tuple[int, bytearray]: ...

    def export(self, request: bytearray) -> tuple[int, bytearray]: ...

    def copy_live_uuid(self, session: int, live_handle: int) -> str: ...

    def invalidate(self) -> None: ...


class IdentitySecretProvisioningTransport(ProvisioningTransport, Protocol):
    def require_identity_secret_ready(self) -> None: ...


class MappingWriter(Protocol):
    def commit(
        self,
        *,
        account_uuid: str,
        bag_uuid: str,
        keybag_sha256: str,
    ) -> str: ...

    def enable_after_reboot(
        self,
        *,
        disabled_mapping_generation: str,
        account_uuid: str,
        bag_uuid: str,
        keybag_sha256: str,
    ) -> str: ...


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _freeze(
    journal_path: Path,
    operation_id: str,
    transport: ProvisioningTransport,
    stage: str,
    cause: BaseException,
) -> None:
    try:
        provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_OUTCOME_UNKNOWN",
            {"stage": stage, "mutation_possible": True},
        )
    except BaseException:
        pass
    try:
        transport.invalidate()
    except BaseException:
        pass
    raise AKSProvisioningOperationError(
        f"AKS {stage} outcome is ambiguous; the operation must not be retried"
    ) from cause


def run_to_mapping(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    account_uuid: str,
    session: int,
    acm_external_form: bytearray,
    preflight: PreflightAttestation,
    transport: ProvisioningTransport,
    keybag_store: provisioning.SavedKeybagStore,
    mapping_writer: MappingWriter,
) -> provisioning.ProvisioningHistory:
    """Create once, export once, persist, and bind the live bag UUID."""
    if not isinstance(preflight, PreflightAttestation):
        raise AKSProvisioningOperationError("provisioning preflight is not typed")
    if transport.connection_generation != preflight.connection_generation:
        raise AKSProvisioningOperationError("preflight belongs to another connection")
    try:
        account_bytes = uuid.UUID(account_uuid).bytes
    except (AttributeError, TypeError, ValueError) as error:
        raise AKSProvisioningOperationError("account UUID is invalid") from error
    if str(uuid.UUID(bytes=account_bytes)) != account_uuid or not any(account_bytes):
        raise AKSProvisioningOperationError("account UUID is not canonical and nonzero")
    if (
        not isinstance(acm_external_form, bytearray)
        or len(acm_external_form) != 16
        or not any(acm_external_form)
    ):
        _wipe(acm_external_form)
        raise AKSProvisioningOperationError("ACM external form is invalid")

    create_request = bytearray()
    create_response = bytearray()
    export_request = bytearray()
    export_response = bytearray()
    saved_keybag = bytearray()
    try:
        create_request = bytearray(
            codec.AKSIdentityCreateV5Request(
                session=session,
                internal_flags=0x4100,
                effective_bag_handle=-1,
                item1=bytes(acm_external_form),
                item2=b"",
                account_uuid=account_bytes,
                item3=b"",
                original_flags=6,
                scalar2=0,
                optional_data=b"",
            ).encode()
        )
        create_digest = hashlib.sha256(create_request).hexdigest()
        provisioning.create(
            journal_path,
            operation_id=operation_id,
            account_uuid=account_uuid,
            linux_boot_uuid=linux_boot_uuid,
            connection_generation=preflight.connection_generation,
            preflight_sha256=preflight.evidence_sha256,
            session=session,
            request_sha256=create_digest,
            xart_ready=preflight.xart_ready,
            primary_identity_absent=preflight.primary_identity_absent,
            inventory_stable=preflight.inventory_stable,
        )
        try:
            status, create_response = transport.create(create_request)
            if type(status) is not int or status != 0:
                raise AKSProvisioningOperationError("create returned a nonzero status")
            live_handle, kek_length = (
                codec.AKSIdentityCreateV5Response.inspect_mutable(create_response)
            )
            if live_handle <= 0:
                raise AKSProvisioningOperationError("create returned an invalid handle")
            provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_CREATE_SUCCEEDED",
                {
                    "session": session,
                    "live_handle": live_handle,
                    "kek_length": kek_length,
                },
            )
        except BaseException as error:
            _freeze(journal_path, operation_id, transport, "create", error)
        finally:
            _wipe(create_request)
            _wipe(create_response)

        export_request = bytearray(
            codec.AKSIdentityCopyKeybagV1Request(
                session=session,
                live_handle=live_handle,
                compatibility_input=b"",
            ).encode()
        )
        provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_EXPORT_INTENT",
            {
                "session": session,
                "live_handle": live_handle,
                "request_sha256": hashlib.sha256(export_request).hexdigest(),
            },
        )
        try:
            status, export_response = transport.export(export_request)
            if type(status) is not int or status != 0:
                raise AKSProvisioningOperationError("export returned a nonzero status")
            saved_keybag = codec.AKSIdentityCopyKeybagV1Response.extract_mutable(
                export_response
            )
            saved_digest = hashlib.sha256(saved_keybag).hexdigest()
            saved_length = len(saved_keybag)
            provisioning.append_checked(
                journal_path,
                operation_id,
                "AKS_EXPORT_SUCCEEDED",
                {
                    "saved_keybag_sha256": saved_digest,
                    "saved_keybag_length": saved_length,
                },
            )
        except BaseException as error:
            _freeze(journal_path, operation_id, transport, "export", error)
        finally:
            _wipe(export_request)
            _wipe(export_response)

        committed_digest, committed_length = keybag_store.commit(
            saved_keybag, operation_id, saved_digest
        )
        history = provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_KEYBAG_COMMITTED",
            {
                "saved_keybag_sha256": committed_digest,
                "saved_keybag_length": committed_length,
            },
        )
        bag_uuid = transport.copy_live_uuid(session, live_handle)
        history = provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_LIVE_UUID_VERIFIED",
            {"bag_uuid": bag_uuid, "uuid_verified": True},
        )
        mapping_generation = mapping_writer.commit(
            account_uuid=account_uuid,
            bag_uuid=bag_uuid,
            keybag_sha256=committed_digest,
        )
        return provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_MAPPING_COMMITTED",
            {"mapping_generation": mapping_generation, "bag_uuid": bag_uuid},
        )
    except provisioning.AKSProvisioningError as error:
        raise AKSProvisioningOperationError(str(error)) from error
    finally:
        _wipe(acm_external_form)
        _wipe(create_request)
        _wipe(create_response)
        _wipe(export_request)
        _wipe(export_response)
        _wipe(saved_keybag)


def run_identity_secret_to_mapping(
    *,
    acm_device: t2_acm_device.ACMDevice,
    apple_user_id: int,
    identity_secret: bytearray,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    account_uuid: str,
    session: int,
    preflight: PreflightAttestation,
    transport: IdentitySecretProvisioningTransport,
    keybag_store: provisioning.SavedKeybagStore,
    mapping_writer: MappingWriter,
) -> provisioning.ProvisioningHistory:
    """Mirror request 10's credential-to-ACM producer around create/export."""

    def consume(external_form: bytes) -> provisioning.ProvisioningHistory:
        transport.require_identity_secret_ready()
        mutable_external_form = bytearray(external_form)
        return run_to_mapping(
            journal_path=journal_path,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            account_uuid=account_uuid,
            session=session,
            acm_external_form=mutable_external_form,
            preflight=preflight,
            transport=transport,
            keybag_store=keybag_store,
            mapping_writer=mapping_writer,
        )

    try:
        try:
            with t2_acm_device.identity_secret_context(
                acm_device,
                apple_user_id,
                identity_secret,
            ) as external_form:
                history = consume(external_form)
        except t2_acm_device.ACMDeviceError as error:
            if isinstance(error.__cause__, AKSProvisioningOperationError):
                raise error.__cause__ from error
            raise AKSProvisioningOperationError(
                "ACM identity-secret provisioning failed and the context was reconciled"
            ) from error
    finally:
        _wipe(identity_secret)
    return history


def verify_after_reboot(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    load_and_copy_uuid: Callable[[], str],
    mapping_writer: MappingWriter,
) -> provisioning.ProvisioningHistory:
    """Verify on another boot, then atomically enable only that exact mapping."""
    history = provisioning.read(journal_path)
    if history.operation_id != operation_id or history.phase not in {
        "mapping-committed",
        "reboot-verified",
    }:
        raise AKSProvisioningOperationError("provisioning is not awaiting reboot")
    if history.phase == "mapping-committed":
        bag_uuid = load_and_copy_uuid()
        history = provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_REBOOT_VERIFIED",
            {
                "linux_boot_uuid": linux_boot_uuid,
                "bag_uuid": bag_uuid,
                "saved_keybag_sha256": history.saved_keybag_sha256,
                "keybag_loaded": True,
                "uuid_verified": True,
            },
        )
    elif history.reboot_linux_boot_uuid != linux_boot_uuid:
        bag_uuid = load_and_copy_uuid()
        history = provisioning.append_checked(
            journal_path,
            operation_id,
            "AKS_REBOOT_REVERIFIED",
            {
                "linux_boot_uuid": linux_boot_uuid,
                "bag_uuid": bag_uuid,
                "saved_keybag_sha256": history.saved_keybag_sha256,
                "keybag_loaded": True,
                "uuid_verified": True,
            },
        )
    if (
        history.mapping_generation is None
        or history.bag_uuid is None
        or history.saved_keybag_sha256 is None
    ):
        raise AKSProvisioningOperationError("verified provisioning evidence is incomplete")
    enabled_generation = mapping_writer.enable_after_reboot(
        disabled_mapping_generation=history.mapping_generation,
        account_uuid=history.account_uuid,
        bag_uuid=history.bag_uuid,
        keybag_sha256=history.saved_keybag_sha256,
    )
    return provisioning.append_checked(
        journal_path,
        operation_id,
        "AKS_MAPPING_ENABLED",
        {
            "disabled_mapping_generation": history.mapping_generation,
            "enabled_mapping_generation": enabled_generation,
            "bag_uuid": history.bag_uuid,
            "linux_boot_uuid": linux_boot_uuid,
        },
    )


def verify_after_owner_change(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    load_and_copy_uuid: Callable[[], tuple[str, str]],
    mapping_writer: MappingWriter,
) -> provisioning.ProvisioningHistory:
    """Reload through a fresh exclusive owner and enable the exact mapping."""

    history = provisioning.read(journal_path)
    if history.operation_id != operation_id or history.phase != "mapping-committed":
        raise AKSProvisioningOperationError(
            "provisioning is not awaiting runtime verification"
        )
    loaded = load_and_copy_uuid()
    if (
        not isinstance(loaded, tuple)
        or len(loaded) != 2
        or not all(isinstance(value, str) for value in loaded)
    ):
        raise AKSProvisioningOperationError(
            "fresh owner returned invalid keybag evidence"
        )
    bag_uuid, connection_generation = loaded
    history = provisioning.append_checked(
        journal_path,
        operation_id,
        "AKS_RUNTIME_VERIFIED",
        {
            "linux_boot_uuid": linux_boot_uuid,
            "connection_generation": connection_generation,
            "bag_uuid": bag_uuid,
            "saved_keybag_sha256": history.saved_keybag_sha256,
            "keybag_loaded": True,
            "uuid_verified": True,
            "fresh_owner": True,
        },
    )
    if (
        history.mapping_generation is None
        or history.bag_uuid is None
        or history.saved_keybag_sha256 is None
    ):
        raise AKSProvisioningOperationError(
            "verified provisioning evidence is incomplete"
        )
    enabled_generation = mapping_writer.enable_after_reboot(
        disabled_mapping_generation=history.mapping_generation,
        account_uuid=history.account_uuid,
        bag_uuid=history.bag_uuid,
        keybag_sha256=history.saved_keybag_sha256,
    )
    return provisioning.append_checked(
        journal_path,
        operation_id,
        "AKS_MAPPING_ENABLED",
        {
            "disabled_mapping_generation": history.mapping_generation,
            "enabled_mapping_generation": enabled_generation,
            "bag_uuid": history.bag_uuid,
            "linux_boot_uuid": linux_boot_uuid,
        },
    )
