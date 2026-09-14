# SPDX-License-Identifier: GPL-2.0-only
"""Journal-owned coordinator for the D171 replacement transaction."""

from __future__ import annotations

import hashlib
import uuid
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol

import t2_aks_identity_create as create_codec
import t2_aks_identity_replacement as replacement_codec
import t2_aks_replacement_journal as journal
from t2_activation_bundle import ActivationBundle
from t2_aks_replacement_transport import (
    PHASE_CREATE,
    PHASE_DELETE,
    PHASE_RECOVER,
    PrimaryObservation,
)


class AKSReplacementOperationError(RuntimeError):
    pass


class ReplacementTransport(Protocol):
    connection_generation: str

    def observe_primary(self, session: int) -> PrimaryObservation: ...

    def arm(
        self,
        *,
        phase: int,
        session: int,
        old_account_uuid: str,
        new_account_uuid: str,
        activation_material: bytearray | None,
    ) -> None: ...

    def delete_identity(self, session: int, old_account_uuid: str) -> None: ...

    def create(self, request: bytearray) -> tuple[int, bytearray]: ...

    def export(self, request: bytearray) -> tuple[int, bytearray]: ...

    def open_identity(self, session: int, new_account_uuid: str) -> int: ...

    def copy_live_uuid(self, session: int, live_handle: int) -> str: ...

    def unload_created_identity(self, session: int, live_handle: int) -> None: ...

    def unload_recovered_identity(self, session: int, live_handle: int) -> None: ...

    def require_no_live_handles(self) -> None: ...

    def invalidate(self) -> None: ...


class BundleStore(Protocol):
    def stage(self, secret: bytearray) -> str: ...

    def staged_secret(self, expected_sha256: str) -> AbstractContextManager[bytearray]: ...

    def commit(
        self,
        saved_keybag: bytearray,
        *,
        expected_keybag_sha256: str,
        activation_secret_sha256: str,
        bag_uuid: str,
    ) -> ActivationBundle: ...

    def published(
        self,
        *,
        expected_keybag_sha256: str,
        activation_secret_sha256: str,
        bag_uuid: str,
        expected_keybag_length: int,
    ) -> ActivationBundle: ...


class MappingWriter(Protocol):
    def commit(
        self, *, account_uuid: str, bag_uuid: str, keybag_sha256: str
    ) -> str: ...


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _uuid(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise AKSReplacementOperationError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AKSReplacementOperationError(f"{label} is invalid")
    return value


def _stable_inventory(
    transport: ReplacementTransport,
    session: int,
) -> tuple[PrimaryObservation, PrimaryObservation]:
    first = transport.observe_primary(session)
    second = transport.observe_primary(session)
    if (
        not isinstance(first, PrimaryObservation)
        or not isinstance(second, PrimaryObservation)
        or first.present is not second.present
        or first.account_uuid != second.account_uuid
    ):
        raise AKSReplacementOperationError("primary inventory is not stable")
    return first, second


def _mark_unknown(
    *,
    journal_path: Path,
    operation_id: str,
    transport: ReplacementTransport,
    milestone: str,
    evidence: dict[str, object],
    stage: str,
    cause: BaseException,
) -> None:
    try:
        transport.invalidate()
    except BaseException:
        pass
    try:
        journal.append_checked(journal_path, operation_id, milestone, evidence)
    except BaseException:
        pass
    raise AKSReplacementOperationError(
        f"replacement {stage} outcome is ambiguous; do not retry it"
    ) from cause


def prepare_replacement(
    *,
    journal_path: Path,
    operation_id: str,
    old_account_uuid: str,
    new_account_uuid: str,
    old_bag_uuid: str,
    old_mapping_generation: str,
    linux_boot_uuid: str,
    session: int,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Select replacement or absence reprovision before creating ACM context."""

    old_account_uuid = _uuid(old_account_uuid, "old account UUID")
    new_account_uuid = _uuid(new_account_uuid, "new account UUID")
    first, second = _stable_inventory(transport, session)
    if first.present and first.account_uuid != old_account_uuid:
        raise AKSReplacementOperationError(
            "durable primary does not match the old account"
        )
    domain = (
        "t2-d171-delete-preflight-v1"
        if first.present
        else "t2-d171-absence-reprovision-preflight-v1"
    )
    preflight_digest = hashlib.sha256(
        (
            domain
            + "\0"
            + first.evidence_sha256
            + "\0"
            + second.evidence_sha256
        ).encode("ascii")
    ).hexdigest()
    if not first.present:
        return journal.create_absent_reprovision(
            journal_path,
            operation_id=operation_id,
            old_account_uuid=old_account_uuid,
            new_account_uuid=new_account_uuid,
            old_bag_uuid=old_bag_uuid,
            old_mapping_generation=old_mapping_generation,
            linux_boot_uuid=linux_boot_uuid,
            connection_generation=transport.connection_generation,
            session=session,
            preflight_digest=preflight_digest,
            primary_absent=True,
            inventory_stable=True,
        )
    return journal.create(
        journal_path,
        operation_id=operation_id,
        old_account_uuid=old_account_uuid,
        new_account_uuid=new_account_uuid,
        old_bag_uuid=old_bag_uuid,
        old_mapping_generation=old_mapping_generation,
        linux_boot_uuid=linux_boot_uuid,
        connection_generation=transport.connection_generation,
        session=session,
        preflight_digest=preflight_digest,
        old_primary_matches=True,
        inventory_stable=True,
    )


def stage_absent_and_reconcile(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    activation_material: bytearray,
    transport: ReplacementTransport,
    bundle_store: BundleStore,
) -> journal.AKSReplacementHistory:
    """Stage creation material and re-prove that no deletion is needed."""

    history = journal.read(journal_path)
    if (
        history.operation_id != operation_id
        or history.phase != "absence-prepared"
        or history.initial_linux_boot_uuid != linux_boot_uuid
        or history.initial_connection_generation != transport.connection_generation
    ):
        _wipe(activation_material)
        raise AKSReplacementOperationError(
            "absence preparation does not belong to this create owner"
        )
    try:
        activation_digest = bundle_store.stage(activation_material)
        journal.append_checked(
            journal_path,
            operation_id,
            "ACTIVATION_MATERIAL_STAGED",
            {
                "activation_material_digest": activation_digest,
                "activation_material_length": 16,
                "bundle_generation": operation_id,
                "pending_directory_synced": True,
            },
        )
        return reconcile_absence(
            journal_path=journal_path,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            transport=transport,
        )
    finally:
        _wipe(activation_material)


def stage_delete_and_reconcile(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    activation_material: bytearray,
    transport: ReplacementTransport,
    bundle_store: BundleStore,
) -> journal.AKSReplacementHistory:
    """Stage and consume material while its live ACM context remains active."""

    history = journal.read(journal_path)
    if (
        history.operation_id != operation_id
        or history.phase != "prepared"
        or history.initial_linux_boot_uuid != linux_boot_uuid
        or history.initial_connection_generation != transport.connection_generation
    ):
        _wipe(activation_material)
        raise AKSReplacementOperationError(
            "replacement preparation does not belong to this delete owner"
        )
    try:
        activation_digest = bundle_store.stage(activation_material)
        journal.append_checked(
            journal_path,
            operation_id,
            "ACTIVATION_MATERIAL_STAGED",
            {
                "activation_material_digest": activation_digest,
                "activation_material_length": 16,
                "bundle_generation": operation_id,
                "pending_directory_synced": True,
            },
        )
        with bundle_store.staged_secret(activation_digest) as durable_material:
            transport.arm(
                phase=PHASE_DELETE,
                session=history.session,
                old_account_uuid=history.old_account_uuid,
                new_account_uuid=history.new_account_uuid,
                activation_material=durable_material,
            )

        delete_request = replacement_codec.AKSIdentityDeleteRequest(
            history.session, uuid.UUID(history.old_account_uuid).bytes
        ).encode()
        journal.append_checked(
            journal_path,
            operation_id,
            "DELETE_INTENT",
            {
                "session": history.session,
                "old_account_uuid": history.old_account_uuid,
                "request_digest": hashlib.sha256(delete_request).hexdigest(),
                "single_dispatch": True,
            },
        )
        try:
            transport.delete_identity(history.session, history.old_account_uuid)
            journal.append_checked(
                journal_path,
                operation_id,
                "DELETE_SUCCEEDED",
                {
                    "session": history.session,
                    "old_account_uuid": history.old_account_uuid,
                },
            )
        except BaseException as error:
            _mark_unknown(
                journal_path=journal_path,
                operation_id=operation_id,
                transport=transport,
                milestone="DELETE_OUTCOME_UNKNOWN",
                evidence={"mutation_possible": True, "descriptor_closed": True},
                stage="delete",
                cause=error,
            )
        return reconcile_delete(
            journal_path=journal_path,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            transport=transport,
        )
    finally:
        _wipe(activation_material)


def abandon_before_delete(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Close a crashed pre-delete generation only after fresh old-primary proof."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase not in {
        "prepared",
        "activation-staged",
    }:
        raise AKSReplacementOperationError(
            "replacement is not safely abandonable before deletion"
        )
    first, second = _stable_inventory(transport, history.session)
    if not first.present or first.account_uuid != history.old_account_uuid:
        raise AKSReplacementOperationError(
            "old primary is not intact for pre-delete abandonment"
        )
    return journal.append_checked(
        journal_path,
        operation_id,
        "ABANDONED_BEFORE_DELETE",
        {
            "linux_boot_uuid": linux_boot_uuid,
            "connection_generation": transport.connection_generation,
            "first_inventory_digest": first.evidence_sha256,
            "second_inventory_digest": second.evidence_sha256,
            "old_primary_matches": True,
            "inventory_stable": True,
            "no_delete_intent": True,
        },
    )


def abandon_before_create(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Close an unstaged absence generation after fresh stable absence proof."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase != "absence-prepared":
        raise AKSReplacementOperationError(
            "absence reprovision is not safely abandonable before creation"
        )
    first, second = _stable_inventory(transport, history.session)
    if first.present:
        raise AKSReplacementOperationError(
            "durable primary appeared before pre-create abandonment"
        )
    return journal.append_checked(
        journal_path,
        operation_id,
        "ABANDONED_BEFORE_CREATE",
        {
            "linux_boot_uuid": linux_boot_uuid,
            "connection_generation": transport.connection_generation,
            "first_inventory_digest": first.evidence_sha256,
            "second_inventory_digest": second.evidence_sha256,
            "primary_absent": True,
            "inventory_stable": True,
            "no_create_intent": True,
        },
    )


def reconcile_absence(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Authorize creation by stable absence, without claiming a deletion."""

    history = journal.read(journal_path)
    if (
        history.operation_id != operation_id
        or history.phase != "absence-activation-staged"
    ):
        raise AKSReplacementOperationError(
            "absence reprovision is not awaiting reconciliation"
        )
    first, second = _stable_inventory(transport, history.session)
    if first.present:
        raise AKSReplacementOperationError(
            "absence reconciliation found a durable primary"
        )
    direct = (
        linux_boot_uuid == history.initial_linux_boot_uuid
        and transport.connection_generation
        == history.initial_connection_generation
    )
    return journal.append_checked(
        journal_path,
        operation_id,
        "ABSENCE_RECONCILED",
        {
            "linux_boot_uuid": linux_boot_uuid,
            "connection_generation": transport.connection_generation,
            "session": history.session,
            "first_inventory_digest": first.evidence_sha256,
            "second_inventory_digest": second.evidence_sha256,
            "primary_absent": True,
            "inventory_stable": True,
            "direct_observation": direct,
        },
    )


def reconfirm_absence(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Rebind a crash-left absence proof to one fresh create owner."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase != "absence-reconciled":
        raise AKSReplacementOperationError(
            "absence reprovision is not ready for reconfirmation"
        )
    first, second = _stable_inventory(transport, history.session)
    if first.present:
        raise AKSReplacementOperationError(
            "reconfirmed absence found a durable primary"
        )
    return journal.append_checked(
        journal_path,
        operation_id,
        "ABSENCE_RECONFIRMED",
        {
            "linux_boot_uuid": linux_boot_uuid,
            "connection_generation": transport.connection_generation,
            "session": history.session,
            "first_inventory_digest": first.evidence_sha256,
            "second_inventory_digest": second.evidence_sha256,
            "primary_absent": True,
            "inventory_stable": True,
        },
    )


def reconcile_delete(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Classify a known or ambiguous deletion without ever dispatching it."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase not in {
        "delete-intent",
        "delete-succeeded",
        "delete-outcome-unknown",
    }:
        raise AKSReplacementOperationError("deletion is not awaiting reconciliation")
    first, second = _stable_inventory(transport, history.session)
    common = {
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": transport.connection_generation,
        "first_inventory_digest": first.evidence_sha256,
        "second_inventory_digest": second.evidence_sha256,
        "inventory_stable": True,
    }
    if not first.present:
        return journal.append_checked(
            journal_path,
            operation_id,
            "DELETE_RECONCILED",
            {
                **common,
                "session": history.session,
                "old_account_uuid": history.old_account_uuid,
                "primary_absent": True,
                "direct_reply_observed": history.phase == "delete-succeeded",
            },
        )
    if (
        history.phase in {"delete-intent", "delete-outcome-unknown"}
        and first.account_uuid == history.old_account_uuid
    ):
        return journal.append_checked(
            journal_path,
            operation_id,
            "DELETE_NOT_APPLIED",
            {
                **common,
                "old_account_uuid": history.old_account_uuid,
                "primary_present": True,
            },
        )
    raise AKSReplacementOperationError(
        "delete reconciliation found a contradictory durable primary"
    )


def reconfirm_delete(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
) -> journal.AKSReplacementHistory:
    """Rebind a crash-left proven deletion to one fresh create owner."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase != "delete-reconciled":
        raise AKSReplacementOperationError("deletion is not ready for reconfirmation")
    first, second = _stable_inventory(transport, history.session)
    if first.present:
        raise AKSReplacementOperationError(
            "reconfirmed deletion found a durable primary"
        )
    return journal.append_checked(
        journal_path,
        operation_id,
        "DELETE_RECONFIRMED",
        {
            "linux_boot_uuid": linux_boot_uuid,
            "connection_generation": transport.connection_generation,
            "session": history.session,
            "first_inventory_digest": first.evidence_sha256,
            "second_inventory_digest": second.evidence_sha256,
            "primary_absent": True,
            "inventory_stable": True,
        },
    )


def create_export_commit(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
    bundle_store: BundleStore,
    mapping_writer: MappingWriter,
) -> journal.AKSReplacementHistory:
    """Create once, export once, publish the bundle, map disabled, and unload."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase not in {
        "delete-reconciled",
        "absence-reconciled",
    }:
        raise AKSReplacementOperationError("identity operation is not ready to create")
    if (
        history.reconciliation_linux_boot_uuid != linux_boot_uuid
        or history.reconciliation_connection_generation
        != transport.connection_generation
    ):
        raise AKSReplacementOperationError(
            "create owner differs from the reconciled absence owner"
        )
    first, _second = _stable_inventory(transport, history.session)
    if first.present:
        raise AKSReplacementOperationError("primary identity is no longer absent")

    create_request = bytearray()
    create_response = bytearray()
    try:
        assert history.activation_material_digest is not None
        with bundle_store.staged_secret(
            history.activation_material_digest
        ) as activation_material:
            create_request = bytearray(
                create_codec.AKSIdentityCreateV5Request(
                    session=history.session,
                    internal_flags=0x4100,
                    effective_bag_handle=-1,
                    item1=bytes(activation_material),
                    item2=b"",
                    account_uuid=uuid.UUID(history.new_account_uuid).bytes,
                    item3=b"",
                    original_flags=6,
                    scalar2=0,
                    optional_data=b"",
                ).encode()
            )
            transport.arm(
                phase=PHASE_CREATE,
                session=history.session,
                old_account_uuid=history.old_account_uuid,
                new_account_uuid=history.new_account_uuid,
                activation_material=activation_material,
            )
        journal.append_checked(
            journal_path,
            operation_id,
            "CREATE_INTENT",
            {
                "linux_boot_uuid": linux_boot_uuid,
                "connection_generation": transport.connection_generation,
                "session": history.session,
                "new_account_uuid": history.new_account_uuid,
                "activation_material_digest": history.activation_material_digest,
                "request_digest": hashlib.sha256(create_request).hexdigest(),
                "primary_absent": True,
                "inventory_stable": True,
                "single_dispatch": True,
            },
        )
        try:
            status, create_response = transport.create(create_request)
            if type(status) is not int or status != 0:
                raise AKSReplacementOperationError("create returned nonzero status")
            live_handle, kek_length = (
                create_codec.AKSIdentityCreateV5Response.inspect_mutable(
                    create_response
                )
            )
            history = journal.append_checked(
                journal_path,
                operation_id,
                "CREATE_SUCCEEDED",
                {
                    "session": history.session,
                    "live_handle": live_handle,
                    "kek_length": kek_length,
                },
            )
        except BaseException as error:
            _mark_unknown(
                journal_path=journal_path,
                operation_id=operation_id,
                transport=transport,
                milestone="CREATE_OUTCOME_UNKNOWN",
                evidence={"mutation_possible": True, "descriptor_closed": True},
                stage="create",
                cause=error,
            )
    finally:
        _wipe(create_request)
        _wipe(create_response)
    return _export_commit_and_release(
        journal_path=journal_path,
        operation_id=operation_id,
        transport=transport,
        bundle_store=bundle_store,
        mapping_writer=mapping_writer,
        recovered=False,
    )


def recover_create_or_export(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
    bundle_store: BundleStore,
    mapping_writer: MappingWriter,
) -> journal.AKSReplacementHistory:
    """Reopen only the intended durable UUID; never redispatch create."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase not in {
        "create-intent",
        "create-outcome-unknown",
        "identity-live",
        "export-intent",
        "export-outcome-unknown",
        "export-succeeded",
        "live-uuid-verified",
    }:
        raise AKSReplacementOperationError("replacement is not recoverable by UUID")
    prior_phase = history.phase
    first, second = _stable_inventory(transport, history.session)
    common = {
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": transport.connection_generation,
        "first_inventory_digest": first.evidence_sha256,
        "second_inventory_digest": second.evidence_sha256,
        "inventory_stable": True,
    }
    if not first.present:
        if prior_phase not in {"create-intent", "create-outcome-unknown"}:
            raise AKSReplacementOperationError(
                "previously observed identity is now absent"
            )
        return journal.append_checked(
            journal_path,
            operation_id,
            "CREATE_NOT_APPLIED",
            {
                **common,
                "new_account_uuid": history.new_account_uuid,
                "primary_absent": True,
            },
        )
    if first.account_uuid != history.new_account_uuid:
        raise AKSReplacementOperationError(
            "durable primary differs from the intended replacement"
        )
    transport.arm(
        phase=PHASE_RECOVER,
        session=history.session,
        old_account_uuid=history.old_account_uuid,
        new_account_uuid=history.new_account_uuid,
        activation_material=None,
    )
    open_request = replacement_codec.AKSIdentityOpenRequest(
        history.session, uuid.UUID(history.new_account_uuid).bytes
    ).encode()
    try:
        live_handle = transport.open_identity(
            history.session, history.new_account_uuid
        )
        bag_uuid = transport.copy_live_uuid(history.session, live_handle)
    except BaseException as error:
        try:
            transport.invalidate()
        except BaseException:
            pass
        raise AKSReplacementOperationError(
            "replacement identity recovery is unavailable; do not create"
        ) from error
    milestone = (
        "IDENTITY_RECOVERED"
        if prior_phase in {"create-intent", "create-outcome-unknown"}
        else "IDENTITY_REOPENED"
    )
    try:
        journal.append_checked(
            journal_path,
            operation_id,
            milestone,
            {
                **common,
                "session": history.session,
                "new_account_uuid": history.new_account_uuid,
                "primary_matches": True,
                "open_request_digest": hashlib.sha256(open_request).hexdigest(),
                "live_handle": live_handle,
                "bag_uuid": bag_uuid,
                "live_uuid_verified": True,
            },
        )
    except BaseException as error:
        try:
            transport.invalidate()
        except BaseException:
            pass
        raise AKSReplacementOperationError(
            "replacement recovery evidence could not be committed"
        ) from error
    return _export_commit_and_release(
        journal_path=journal_path,
        operation_id=operation_id,
        transport=transport,
        bundle_store=bundle_store,
        mapping_writer=mapping_writer,
        recovered=True,
    )


def resume_local_commit(
    *,
    journal_path: Path,
    operation_id: str,
    linux_boot_uuid: str,
    transport: ReplacementTransport,
    bundle_store: BundleStore,
    mapping_writer: MappingWriter,
) -> journal.AKSReplacementHistory:
    """Converge idempotent mapping publication and fresh-boot handle absence."""

    history = journal.read(journal_path)
    if history.operation_id != operation_id or history.phase not in {
        "bundle-committed",
        "mapping-committed",
    }:
        raise AKSReplacementOperationError("replacement has no local commit to resume")
    if (
        history.activation_material_digest is None
        or history.saved_keybag_digest is None
        or history.saved_keybag_length is None
        or history.live_bag_uuid is None
        or history.bundle_generation is None
    ):
        raise AKSReplacementOperationError("committed replacement bundle is incomplete")
    bundle = bundle_store.published(
        expected_keybag_sha256=history.saved_keybag_digest,
        activation_secret_sha256=history.activation_material_digest,
        bag_uuid=history.live_bag_uuid,
        expected_keybag_length=history.saved_keybag_length,
    )
    if bundle.generation != history.bundle_generation:
        raise AKSReplacementOperationError("replacement bundle generation differs")
    if history.phase == "bundle-committed":
        mapping_generation = mapping_writer.commit(
            account_uuid=history.new_account_uuid,
            bag_uuid=history.live_bag_uuid,
            keybag_sha256=history.saved_keybag_digest,
        )
        history = journal.append_checked(
            journal_path,
            operation_id,
            "MAPPING_COMMITTED",
            {
                "mapping_generation": mapping_generation,
                "bundle_generation": history.bundle_generation,
                "bag_uuid": history.live_bag_uuid,
                "enabled": False,
            },
        )
    else:
        mapping_generation = mapping_writer.commit(
            account_uuid=history.new_account_uuid,
            bag_uuid=history.live_bag_uuid,
            keybag_sha256=history.saved_keybag_digest,
        )
        if mapping_generation != history.mapping_generation:
            raise AKSReplacementOperationError(
                "committed replacement mapping generation differs"
            )
    first, second = _stable_inventory(transport, history.session)
    if first.present and first.account_uuid != history.new_account_uuid:
        raise AKSReplacementOperationError(
            "durable primary differs from the committed replacement"
        )
    transport.require_no_live_handles()
    common = {
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": transport.connection_generation,
        "session": history.session,
        "new_account_uuid": history.new_account_uuid,
        "first_inventory_digest": first.evidence_sha256,
        "second_inventory_digest": second.evidence_sha256,
        "inventory_stable": True,
        "no_live_holders": True,
    }
    if first.present:
        return journal.append_checked(
            journal_path,
            operation_id,
            "HANDLE_RECONCILED_ABSENT",
            {**common, "primary_matches": True},
        )
    return journal.append_checked(
        journal_path,
        operation_id,
        "HANDLE_RECONCILED_PRIMARY_ABSENT",
        {
            **common,
            "primary_absent": True,
            "bundle_verified": True,
            "mapping_verified": True,
        },
    )


def _export_commit_and_release(
    *,
    journal_path: Path,
    operation_id: str,
    transport: ReplacementTransport,
    bundle_store: BundleStore,
    mapping_writer: MappingWriter,
    recovered: bool,
) -> journal.AKSReplacementHistory:
    history = journal.read(journal_path)
    if history.phase != "identity-live" or history.live_handle is None:
        raise AKSReplacementOperationError("replacement identity is not live")
    export_request = bytearray(
        create_codec.AKSIdentityCopyKeybagV1Request(
            session=history.session,
            live_handle=history.live_handle,
            compatibility_input=b"",
        ).encode()
    )
    export_response = bytearray()
    saved_keybag = bytearray()
    try:
        journal.append_checked(
            journal_path,
            operation_id,
            "EXPORT_INTENT",
            {
                "session": history.session,
                "live_handle": history.live_handle,
                "request_digest": hashlib.sha256(export_request).hexdigest(),
            },
        )
        try:
            status, export_response = transport.export(export_request)
            if type(status) is not int or status != 0:
                raise AKSReplacementOperationError("export returned nonzero status")
            saved_keybag = (
                create_codec.AKSIdentityCopyKeybagV1Response.extract_mutable(
                    export_response
                )
            )
            saved_digest = hashlib.sha256(saved_keybag).hexdigest()
            history = journal.append_checked(
                journal_path,
                operation_id,
                "EXPORT_SUCCEEDED",
                {
                    "saved_keybag_digest": saved_digest,
                    "saved_keybag_length": len(saved_keybag),
                },
            )
        except BaseException as error:
            _mark_unknown(
                journal_path=journal_path,
                operation_id=operation_id,
                transport=transport,
                milestone="EXPORT_OUTCOME_UNKNOWN",
                evidence={"descriptor_closed": True},
                stage="export",
                cause=error,
            )
        bag_uuid = transport.copy_live_uuid(history.session, history.live_handle)
        history = journal.append_checked(
            journal_path,
            operation_id,
            "LIVE_UUID_VERIFIED",
            {
                "session": history.session,
                "live_handle": history.live_handle,
                "bag_uuid": bag_uuid,
                "uuid_verified": True,
            },
        )
        assert history.activation_material_digest is not None
        bundle = bundle_store.commit(
            saved_keybag,
            expected_keybag_sha256=saved_digest,
            activation_secret_sha256=history.activation_material_digest,
            bag_uuid=bag_uuid,
        )
        history = journal.append_checked(
            journal_path,
            operation_id,
            "BUNDLE_COMMITTED",
            {
                "bundle_generation": bundle.generation,
                "activation_material_digest": bundle.activation_secret_sha256,
                "saved_keybag_digest": bundle.keybag_sha256,
                "saved_keybag_length": bundle.keybag_length,
                "manifest_digest": bundle.manifest_sha256,
                "artifacts_verified": True,
                "publication_reconciled": False,
            },
        )
        mapping_generation = mapping_writer.commit(
            account_uuid=history.new_account_uuid,
            bag_uuid=bag_uuid,
            keybag_sha256=bundle.keybag_sha256,
        )
        history = journal.append_checked(
            journal_path,
            operation_id,
            "MAPPING_COMMITTED",
            {
                "mapping_generation": mapping_generation,
                "bundle_generation": bundle.generation,
                "bag_uuid": bag_uuid,
                "enabled": False,
            },
        )
        try:
            if recovered:
                transport.unload_recovered_identity(
                    history.session, history.live_handle
                )
            else:
                transport.unload_created_identity(history.session, history.live_handle)
        except BaseException as error:
            try:
                transport.invalidate()
            except BaseException:
                pass
            raise AKSReplacementOperationError(
                "identity unload is ambiguous; reconcile on a fresh boot"
            ) from error
        return journal.append_checked(
            journal_path,
            operation_id,
            "HANDLE_UNLOADED",
            {
                "session": history.session,
                "live_handle": history.live_handle,
                "unload_succeeded": True,
            },
        )
    except AKSReplacementOperationError:
        try:
            transport.invalidate()
        except BaseException:
            pass
        raise
    except BaseException as error:
        try:
            transport.invalidate()
        except BaseException:
            pass
        raise AKSReplacementOperationError(
            "replacement local completion stopped; resume from the journal"
        ) from error
    finally:
        _wipe(export_request)
        _wipe(export_response)
        _wipe(saved_keybag)
