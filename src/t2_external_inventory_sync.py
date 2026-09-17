# SPDX-License-Identifier: GPL-2.0-only
"""Persist an authorized user's live inventory after another owner changed it.

The caller holds the operation lock and a validated native identity/ACM lease.
No enroll, delete, load, rename, or account-adoption command is issued. Only the
current user's opaque Catacomb is saved, with host presentation metadata rebuilt
from independently agreeing per-user/global inventories. Interrupted saves block
further mutation and retain both the journal and the original component backup.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import uuid

import t2_catacomb_bridge as bridge
import t2_catacomb_codec as codec
import t2_catacomb_protocol as protocol
import t2_catacomb_store as stores
import t2_external_delete_reconcile as backup_store
import t2_fprint_identity as names
import t2_identity_inventory as inventory
import t2_mutation_journal as journal

KIND = 'reconcile-external-inventory'
STEPS = ('EXTERNAL_INVENTORY_INTENT', 'EXTERNAL_INVENTORY_USER_SAVED',
         'EXTERNAL_INVENTORY_USER_CONFIRM_INTENT', 'EXTERNAL_INVENTORY_MASTER_EXPORT_INTENT',
         'EXTERNAL_INVENTORY_HOST_COMMIT_INTENT', 'EXTERNAL_INVENTORY_HOST_COMMITTED',
         'EXTERNAL_INVENTORY_RECONCILED')


class ExternalInventoryError(RuntimeError):
    pass


def live_pairs(
    live: dict,
    apple_uid: int,
    *,
    clean: bool = False,
    allow_empty: bool = False,
) -> set:
    if (not isinstance(live, dict) or live.get('double_collection_equal') is not True
            or live.get('biometric_protocol_version') != 2
            or live.get('apple_uid') != apple_uid):
        raise ExternalInventoryError('external inventory is not stable and user-bound')
    pairs = inventory._live_pairs(live.get('per_user_identity_records'), apple_uid)
    if pairs != inventory._configured_global_pairs(live.get('global_identity_records'), apple_uid):
        raise ExternalInventoryError('external per-user and global inventories disagree')
    if not 0 <= len(pairs) <= names.MAX_ENROLLED_IDENTITIES or (
        not pairs and not allow_empty
    ):
        raise ExternalInventoryError('external inventory has unsupported capacity')
    cat = live.get('catacomb')
    if not isinstance(cat, dict):
        raise ExternalInventoryError('external inventory has no loaded Catacomb')
    journal.require_uuid(cat.get('uuid'), 'Catacomb UUID')
    journal.require_sha256(cat.get('hash'), 'Catacomb hash')
    states = cat.get('user_states')
    if not isinstance(states, list) or len(states) != 2:
        raise ExternalInventoryError('external inventory has unexpected components')
    found = set()
    for item in states:
        if not isinstance(item, dict) or set(item) != {'kind', 'user_id', 'state', 'needs_save'}:
            raise ExternalInventoryError('external component state is malformed')
        key = (item['kind'], item['user_id'])
        if (key not in {('master', 0xFFFFFFFF), ('user', apple_uid)} or key in found
                or type(item['state']) is not int or item['state'] not in ((3,) if clean else (3, 7))
                or item['needs_save'] is not (item['state'] == 7)):
            raise ExternalInventoryError('external component is not securely loaded')
        found.add(key)
    if not pairs:
        if (
            cat.get('present') is not False
            or cat.get('uuid') != str(uuid.UUID(int=0))
            or cat.get('hash') != '0' * 64
            or found != {('master', 0xFFFFFFFF), ('user', apple_uid)}
        ):
            raise ExternalInventoryError(
                'empty external inventory has no exact Catacomb authority'
            )
    elif cat.get('present') is not True:
        raise ExternalInventoryError('external inventory has no loaded Catacomb')
    return pairs


def plan(
    local: codec.UserCatacomb, live: dict, *, allow_empty: bool = False
) -> bytes:
    pairs = live_pairs(live, local.expected_user_id, allow_empty=allow_empty)
    result = local
    for identity in local.identities:
        if (identity.user_id, identity.uuid) not in pairs:
            result = codec.decode_user_catacomb(result.plan_delete(identity.uuid), local.expected_user_id)
    # Names belong to this installation's presentation, not to template origin.
    occupied = {item.name for item in result.identities}
    if any(not names.is_handle(name) for name in occupied) or len(occupied) != len(result.identities):
        raise ExternalInventoryError('surviving fingerprint handles are ambiguous')
    known = {(item.user_id, item.uuid) for item in result.identities}
    for _, identity_uuid in sorted(pairs - known):
        handle = next((names.handle(n) for n in range(1, names.MAX_ENROLLED_IDENTITIES + 1)
                       if names.handle(n) not in occupied), None)
        if handle is None:
            raise ExternalInventoryError('no fingerprint handle remains')
        entity = next(n for n in range(1, 256) if n not in {item.entity for item in result.identities})
        result = codec.decode_user_catacomb(result.add(identity_uuid=identity_uuid, entity=entity, name=handle), local.expected_user_id)
        occupied.add(handle)
    if pairs:
        inventory.summarize(result, live)
    elif result.identities:
        raise ExternalInventoryError(
            'empty external inventory did not produce an empty local plan'
        )
    return result.replace_secure_data(result.secure_data)


def validate_history(records: list[dict]) -> str:
    meaningful = [r for r in records if r.get('milestone') != 'TORN_TAIL_TRUNCATED']
    if not meaningful or len(meaningful) > len(STEPS):
        raise ExternalInventoryError('external inventory journal length is invalid')
    if meaningful[-1].get('milestone') == 'EXTERNAL_INVENTORY_ABORTED_BEFORE_DISPATCH':
        if (len(meaningful) != 2 or validate_history(meaningful[:1]) != 'pending'
                or meaningful[-1].get('operation_id') != meaningful[0].get('operation_id')
                or meaningful[-1].get('evidence') != {'hardware_dispatched': False, 'host_unchanged': True}):
            raise ExternalInventoryError('external inventory abort proof is invalid')
        return 'complete'
    operation_id = meaningful[0].get('operation_id')
    journal.require_uuid(operation_id, 'operation ID')
    baseline = meaningful[0].get('evidence')
    required = {'operation_kind', 'mapping_generation', 'apple_uid', 'connection_generation',
                'backup_reference', 'backup_snapshot_sha256', 'identity_snapshot_sha256', 'catacomb_uuid'}
    if not isinstance(baseline, dict) or set(baseline) != required or baseline['operation_kind'] != KIND:
        raise ExternalInventoryError('external inventory baseline is invalid')
    if type(baseline['apple_uid']) is not int or not 10 <= baseline['apple_uid'] < 0xFFFFFFFF:
        raise ExternalInventoryError('external inventory user is invalid')
    for key in ('mapping_generation', 'backup_snapshot_sha256', 'identity_snapshot_sha256'):
        journal.require_sha256(baseline[key], key)
    for key in ('connection_generation', 'backup_reference', 'catacomb_uuid'):
        journal.require_uuid(baseline[key], key)
    for index, record in enumerate(meaningful):
        if record.get('milestone') != STEPS[index] or record.get('operation_id') != operation_id:
            raise ExternalInventoryError('external inventory journal order is invalid')
        if index:
            evidence = record.get('evidence')
            if not isinstance(evidence, dict) or set(evidence) != {'component_sha256', 'identity_snapshot_sha256'}:
                raise ExternalInventoryError('external inventory milestone is invalid')
            journal.require_sha256(evidence['component_sha256'], 'component hash')
            if evidence['identity_snapshot_sha256'] != baseline['identity_snapshot_sha256']:
                raise ExternalInventoryError('external inventory identity binding changed')
    if len(meaningful) >= 3 and meaningful[1]['evidence'] != meaningful[2]['evidence']:
        raise ExternalInventoryError('external user confirmation binding changed')
    if len(meaningful) >= 4 and meaningful[2]['evidence'] != meaningful[3]['evidence']:
        raise ExternalInventoryError('external master export binding changed')
    if len(meaningful) >= 6 and meaningful[4]['evidence'] != meaningful[5]['evidence']:
        raise ExternalInventoryError('external host commit binding changed')
    if len(meaningful) == 7 and meaningful[5]['evidence'] != meaningful[6]['evidence']:
        raise ExternalInventoryError('external readback binding changed')
    return 'complete' if len(meaningful) == len(STEPS) else 'pending'


def abort_undispatched(*, mutation_root: Path, store_root: Path, backup_root: Path,
                       apple_uid: int, mapping_generation: str) -> None:
    """Close only an intent that stopped before creation of its dispatch guard.

    The prepare directory is durably created before the first save command and
    never removed before HOST_COMMITTED. Its absence plus the original byte-exact
    backup proves an intent-only operation did not cross that boundary.
    """
    if os.path.lexists(store_root / 'prepare') or os.path.lexists(store_root / 'commit'):
        return
    for path in mutation_root.glob('*.jsonl'):
        records = journal.read(path)
        if not records or records[0].get('evidence', {}).get('operation_kind') != KIND:
            continue
        phase = validate_history(records)
        meaningful = [r for r in records if r['milestone'] != 'TORN_TAIL_TRUNCATED']
        if phase != 'pending' or len(meaningful) != 1:
            continue
        baseline = meaningful[0]['evidence']
        if baseline['apple_uid'] != apple_uid or baseline['mapping_generation'] != mapping_generation:
            raise ExternalInventoryError('undispatched inventory authority changed')
        original = stores.CatacombStore(backup_root / baseline['backup_reference'], apple_uid).read_committed_components()
        snapshot = hashlib.sha256(journal.canonical([
            {'name': name, 'sha256': hashlib.sha256(data).hexdigest()}
            for name, data in sorted(original.items())])).hexdigest()
        if (snapshot != baseline['backup_snapshot_sha256']
                or stores.CatacombStore(store_root, apple_uid).read_committed_components() != original):
            raise ExternalInventoryError('undispatched inventory backup differs')
        journal.append(path, meaningful[0]['operation_id'], 'EXTERNAL_INVENTORY_ABORTED_BEFORE_DISPATCH',
                       {'hardware_dispatched': False, 'host_unchanged': True},
                       expected_record_count=len(records), expected_previous_hash=records[-1]['record_hash'])
        validate_history(journal.read(path))


def reconcile(*, local, live, store, lease, mapping_generation, backup_root: Path,
              mutation_root: Path, collect, allow_empty: bool = False,
              operation_id: str | None = None) -> dict:
    """Save a changed inventory under an already-authorized native lease."""
    pairs = live_pairs(
        live, local.expected_user_id, allow_empty=allow_empty
    )
    encoded_plan = plan(local, live, allow_empty=allow_empty)
    proposed = codec.decode_user_catacomb(encoded_plan, local.expected_user_id)
    components = store.read_committed_components()
    user_name = f'user_{local.expected_user_id:08x}.cat'
    if codec.decode_user_catacomb(components[user_name], local.expected_user_id).identities != local.identities:
        raise ExternalInventoryError('local inventory changed before reconciliation')
    # Reject races before the first save request; the hardware has other owners.
    fresh = collect(lease, local.expected_user_id)
    if (
        live_pairs(
            fresh, local.expected_user_id, allow_empty=allow_empty
        ) != pairs
        or fresh['catacomb'] != live['catacomb']
    ):
        raise ExternalInventoryError('external inventory changed before persistence')
    if operation_id is None:
        operation_id = str(uuid.uuid4())
    else:
        try:
            parsed_operation_id = uuid.UUID(operation_id)
        except (AttributeError, TypeError, ValueError) as error:
            raise ExternalInventoryError(
                'external inventory operation ID is invalid'
            ) from error
        if str(parsed_operation_id) != operation_id:
            raise ExternalInventoryError(
                'external inventory operation ID is invalid'
            )
    backup = backup_store.create_backup(backup_root, operation_id, components)
    identity_hash = hashlib.sha256(journal.canonical(sorted(pairs))).hexdigest()
    path = mutation_root / f'{operation_id}.jsonl'
    journal.append(path, operation_id, STEPS[0], {
        'operation_kind': KIND, 'mapping_generation': mapping_generation,
        'apple_uid': local.expected_user_id, 'connection_generation': lease.connection_generation,
        'backup_reference': backup.reference, 'backup_snapshot_sha256': backup.snapshot_sha256,
        'identity_snapshot_sha256': identity_hash, 'catacomb_uuid': live['catacomb']['uuid'],
    }, exclusive=True)
    validate_history(journal.read(path))

    def record(step, digest):
        records = journal.read(path)
        validate_history(records)
        journal.append(path, operation_id, step, {
            'component_sha256': digest, 'identity_snapshot_sha256': identity_hash,
        }, expected_record_count=len(records), expected_previous_hash=records[-1]['record_hash'])
        validate_history(journal.read(path))

    transport = bridge.CatacombBridgeTransport(lease, protocol_version=2,
                                              connection_generation=lease.connection_generation)
    staged = {}
    blobs = []
    try:
        store.begin_stage({user_name, 'master.cat'})
        user_descriptor = protocol.CatacombComponent.user(local.expected_user_id).descriptor
        master_descriptor = protocol.CatacombComponent.master().descriptor
        _, size = transport.prepare(user_descriptor)
        _, blob = transport.complete(user_descriptor)
        blobs.append(blob)
        if len(blob) != size:
            raise ExternalInventoryError('external user export length changed')
        staged[user_name] = store.stage_component(user_name, proposed.replace_secure_data(bytes(blob)), {user_name, 'master.cat'})
        record(STEPS[1], staged[user_name])
        record(STEPS[2], staged[user_name])
        transport.confirm(user_descriptor)
        record(STEPS[3], staged[user_name])
        _, size = transport.prepare(master_descriptor)
        _, blob = transport.complete(master_descriptor)
        blobs.append(blob)
        if len(blob) != size:
            raise ExternalInventoryError('external master export length changed')
        master = codec.decode_master_catacomb(components['master.cat'])
        staged['master.cat'] = store.stage_component(
            'master.cat',
            master.encode(
                secure_data=bytes(blob),
                enrollment_count=len(pairs),
            ),
            {user_name, 'master.cat'},
        )
        digest = hashlib.sha256(journal.canonical(staged)).hexdigest()
        # A race after export cannot authorize publishing the wrong templates.
        fresh = collect(lease, local.expected_user_id)
        if (
            live_pairs(
                fresh, local.expected_user_id, allow_empty=allow_empty
            ) != pairs
            or fresh['catacomb']['uuid'] != live['catacomb']['uuid']
        ):
            raise ExternalInventoryError('external inventory changed during persistence')
        record(STEPS[4], digest)
        store.cross_commit_boundary(staged)
        record(STEPS[5], digest)
        transport.confirm(master_descriptor)
        saved = codec.decode_user_catacomb(store.read_committed_components()[user_name], local.expected_user_id)
        fresh = collect(lease, local.expected_user_id)
        if (
            live_pairs(
                fresh,
                local.expected_user_id,
                clean=True,
                allow_empty=allow_empty,
            ) != pairs
            or fresh['catacomb']['uuid'] != live['catacomb']['uuid']
        ):
            raise ExternalInventoryError('external inventory changed after persistence')
        inventory.summarize(saved, fresh)
        record(STEPS[6], digest)
        return {'schema_version': 1, 'external_inventory_reconciled': True,
                'external_deletion_reconciliation_needed': False,
                'identity_count': len(pairs), 'backup_created': True,
                'local_catacomb_mutated': True, 'sep_mutation_performed': True,
                'fingerprint_mutation_performed': False, 'identifiers_redacted': True}
    finally:
        for blob in blobs:
            blob[:] = b'\0' * len(blob)
