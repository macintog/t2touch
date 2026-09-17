# SPDX-License-Identifier: GPL-2.0-only
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import t2_external_inventory_sync as sync
import t2_catacomb_codec as codec
import t2_catacomb_store as stores
import t2_mutation_journal as journal
import t2_mutation_registry as registry
from tests.test_catacomb_codec import fixture, master_fixture, biolockout_fixture
from tests.test_identity_inventory import live_for


def inventory(local, dirty=True):
    live = live_for(local)
    live['catacomb'].update(uuid=str(uuid.UUID(int=99)), hash='a' * 64,
        user_states=[{'kind': 'master', 'user_id': 0xFFFFFFFF, 'state': 3, 'needs_save': False},
                     {'kind': 'user', 'user_id': 501, 'state': 7 if dirty else 3, 'needs_save': dirty}])
    return live


def empty_inventory(*, dirty=True):
    empty = codec.decode_user_catacomb(fixture(), 501)
    empty = codec.decode_user_catacomb(
        empty.clear_after_stable_sep_empty(sep_empty_attested=True), 501
    )
    live = live_for(empty)
    live['catacomb'].update(
        present=False,
        uuid=str(uuid.UUID(int=0)),
        hash='0' * 64,
        user_states=[
            {
                'kind': 'master', 'user_id': 0xFFFFFFFF,
                'state': 3, 'needs_save': False,
            },
            {
                'kind': 'user', 'user_id': 501,
                'state': 7 if dirty else 3, 'needs_save': dirty,
            },
        ],
    )
    return live


class ExternalInventoryTests(unittest.TestCase):
    def setUp(self):
        value = codec.decode_user_catacomb(fixture(), 501)
        self.local = codec.decode_user_catacomb(value.rename(value.identities[0].uuid, 'finger-1'), 501)
        empty = codec.decode_user_catacomb(self.local.plan_delete(self.local.identities[0].uuid), 501)
        self.external = codec.decode_user_catacomb(empty.add(identity_uuid=str(uuid.UUID(int=5)), entity=1, name='macOS fingerprint'), 501)
        self.live = inventory(self.external)

    def test_replacement_preserves_authority_and_adopts_live_uuid(self):
        result = codec.decode_user_catacomb(sync.plan(self.local, self.live), 501)
        self.assertEqual([(i.uuid, i.name) for i in result.identities], [(str(uuid.UUID(int=5)), 'finger-1')])
        self.assertEqual(result.account_uuid, self.local.account_uuid)
        self.assertEqual(result.keybag_uuid, self.local.keybag_uuid)
        self.assertEqual(result.secure_data, self.local.secure_data)

    def test_addition_keeps_surviving_handles(self):
        external = codec.decode_user_catacomb(self.local.add(identity_uuid=str(uuid.UUID(int=5)), entity=1, name='another OS'), 501)
        result = codec.decode_user_catacomb(sync.plan(self.local, inventory(external)), 501)
        self.assertEqual(result.identities[0], self.local.identities[0])
        self.assertEqual(result.identities[1].name, 'finger-2')

    def test_explicit_empty_reprovision_clears_local_identity(self):
        live = empty_inventory()
        result = codec.decode_user_catacomb(
            sync.plan(self.local, live, allow_empty=True), 501
        )
        self.assertEqual(result.identities, ())
        self.assertEqual(result.account_uuid, self.local.account_uuid)
        self.assertEqual(result.keybag_uuid, self.local.keybag_uuid)
        with self.assertRaises(sync.ExternalInventoryError):
            sync.plan(self.local, live)

    def test_explicit_empty_reprovision_persists_zero_count_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('store', 'backups', 'mutations'):
                (root / name).mkdir(mode=0o700)
            original = {
                'user_000001f5.cat': self.local.replace_secure_data(
                    self.local.secure_data
                ),
                'master.cat': master_fixture(),
                'biolockout.cat': biolockout_fixture(),
            }
            for name, data in original.items():
                path = root / 'store' / name
                path.write_bytes(data)
                path.chmod(0o600)
            store = stores.CatacombStore(root / 'store', 501)
            lease = SimpleNamespace(connection_generation=str(uuid.UUID(int=42)))
            user_blob = b'LTFC' + b'u' * 28
            master_blob = b'LTFC' + b'm' * 28
            transport = mock.Mock()
            transport.prepare.side_effect = [
                (0, len(user_blob)), (0, len(master_blob)),
            ]
            transport.complete.side_effect = [
                (0, bytearray(user_blob)), (0, bytearray(master_blob)),
            ]
            live = empty_inventory()
            collect = mock.Mock(
                side_effect=[
                    copy.deepcopy(live),
                    copy.deepcopy(live),
                    empty_inventory(dirty=False),
                ]
            )
            with mock.patch.object(
                sync.bridge, 'CatacombBridgeTransport', return_value=transport
            ):
                result = sync.reconcile(
                    local=self.local,
                    live=live,
                    store=store,
                    lease=lease,
                    mapping_generation='b' * 64,
                    backup_root=root / 'backups',
                    mutation_root=root / 'mutations',
                    collect=collect,
                    allow_empty=True,
                )
            components = store.read_committed_components()
            saved_user = codec.decode_user_catacomb(
                components['user_000001f5.cat'], 501
            )
            saved_master = codec.decode_master_catacomb(components['master.cat'])
            self.assertEqual(saved_user.identities, ())
            self.assertEqual(saved_user.secure_data, user_blob)
            self.assertEqual(saved_master.enrollment_count, 0)
            self.assertEqual(saved_master.secure_data, master_blob)
            self.assertEqual(result['identity_count'], 0)
            self.assertFalse(registry.blocks_new_mutation(root / 'mutations'))

    def test_rejects_unstable_wrong_user_group_and_unloaded_state(self):
        changes = [lambda x: x.update(double_collection_equal=False),
                   lambda x: x.update(apple_uid=502),
                   lambda x: x['global_identity_records'][0].update(group_uuid=str(uuid.UUID(int=1))),
                   lambda x: x['global_identity_records'].clear(),
                   lambda x: x['catacomb']['user_states'][1].update(state=1, needs_save=False),
                   lambda x: x['catacomb']['user_states'][1].update(needs_save=False),
                   lambda x: x['catacomb'].update(present=False)]
        for change in changes:
            with self.subTest(change=change):
                live = copy.deepcopy(self.live)
                change(live)
                with self.assertRaises((sync.ExternalInventoryError, sync.inventory.IdentityInventoryError)):
                    sync.plan(self.local, live)

    def exercise(
        self, *, fail_confirm=False, race_at=None, fail_record=None,
        stale_master_count=None,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('store', 'backups', 'mutations'):
                (root / name).mkdir(mode=0o700)
            master_bytes = master_fixture()
            if stale_master_count is not None:
                master_bytes = codec.decode_master_catacomb(master_bytes).encode(
                    enrollment_count=stale_master_count
                )
            original = {'user_000001f5.cat': self.local.replace_secure_data(self.local.secure_data),
                        'master.cat': master_bytes, 'biolockout.cat': biolockout_fixture()}
            for name, data in original.items():
                path = root / 'store' / name
                path.write_bytes(data)
                path.chmod(0o600)
            store = stores.CatacombStore(root / 'store', 501)
            lease = SimpleNamespace(connection_generation=str(uuid.UUID(int=42)))
            master_blob = codec.decode_master_catacomb(original['master.cat']).secure_data
            user_blob = b'LTFC' + b'n' * 28
            transport = mock.Mock()
            transport.prepare.side_effect = [(0, len(user_blob)), (0, len(master_blob))]
            transport.complete.side_effect = [(0, bytearray(user_blob)), (0, bytearray(master_blob))]
            if fail_confirm:
                transport.confirm.side_effect = RuntimeError('lost confirmation')
            observations = [copy.deepcopy(self.live), copy.deepcopy(self.live), inventory(self.external, dirty=False)]
            if race_at is not None:
                observations[race_at] = inventory(self.local, dirty=False)
            collect = mock.Mock(side_effect=observations)
            original_append = journal.append
            def append(*args, **kwargs):
                if args[2] == fail_record:
                    raise OSError('disk full')
                return original_append(*args, **kwargs)
            with mock.patch.object(sync.bridge, 'CatacombBridgeTransport', return_value=transport), mock.patch.object(journal, 'append', side_effect=append):
                kwargs = dict(local=self.local, live=self.live, store=store, lease=lease,
                              mapping_generation='b' * 64, backup_root=root / 'backups',
                              mutation_root=root / 'mutations', collect=collect)
                if fail_confirm or race_at is not None or fail_record is not None:
                    with self.assertRaises((RuntimeError, OSError)):
                        sync.reconcile(**kwargs)
                    if race_at == 0 or fail_record == sync.STEPS[0]:
                        transport.prepare.assert_not_called()
                        self.assertFalse(registry.blocks_new_mutation(root / 'mutations'))
                    else:
                        self.assertTrue(registry.blocks_new_mutation(root / 'mutations'))
                    if fail_record == sync.STEPS[2]:
                        transport.confirm.assert_not_called()
                    return
                result = sync.reconcile(**kwargs)
            self.assertFalse(result['fingerprint_mutation_performed'])
            self.assertTrue(result['external_inventory_reconciled'])
            saved = codec.decode_user_catacomb(store.read_committed_components()['user_000001f5.cat'], 501)
            saved_master = codec.decode_master_catacomb(
                store.read_committed_components()['master.cat']
            )
            self.assertEqual(saved.identities[0].uuid, self.external.identities[0].uuid)
            self.assertEqual(saved.secure_data, user_blob)
            self.assertEqual(saved_master.enrollment_count, len(self.external.identities))
            self.assertEqual(transport.confirm.call_count, 2)
            self.assertFalse(registry.blocks_new_mutation(root / 'mutations'))
            backup = next((root / 'backups').iterdir())
            self.assertEqual((backup / 'user_000001f5.cat').read_bytes(), original['user_000001f5.cat'])
            records = journal.read(next((root / 'mutations').iterdir()))
            for count in range(1, len(records)):
                self.assertEqual(sync.validate_history(records[:count]), 'pending')
            altered = copy.deepcopy(records)
            altered[-1]['evidence']['identity_snapshot_sha256'] = 'c' * 64
            with self.assertRaises(sync.ExternalInventoryError):
                sync.validate_history(altered)

    def test_replacement_normalizes_stale_master_enrollment_count(self):
        self.exercise(stale_master_count=3)

    def test_intent_only_abort_requires_unchanged_backup_and_no_prepare(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('store', 'backups', 'mutations'):
                (root / name).mkdir(mode=0o700)
            components = {'user_000001f5.cat': self.local.replace_secure_data(self.local.secure_data),
                          'master.cat': master_fixture(), 'biolockout.cat': biolockout_fixture()}
            for name, data in components.items():
                path = root / 'store' / name
                path.write_bytes(data)
                path.chmod(0o600)
            operation_id = str(uuid.uuid4())
            backup = sync.backup_store.create_backup(root / 'backups', operation_id, components)
            path = root / 'mutations' / f'{operation_id}.jsonl'
            journal.append(path, operation_id, sync.STEPS[0], {
                'operation_kind': sync.KIND, 'mapping_generation': 'b' * 64, 'apple_uid': 501,
                'connection_generation': str(uuid.UUID(int=42)), 'backup_reference': backup.reference,
                'backup_snapshot_sha256': backup.snapshot_sha256, 'identity_snapshot_sha256': 'a' * 64,
                'catacomb_uuid': str(uuid.UUID(int=99)),
            }, exclusive=True)
            args = dict(mutation_root=root / 'mutations', store_root=root / 'store',
                        backup_root=root / 'backups', apple_uid=501, mapping_generation='b' * 64)
            prepare = root / 'store' / 'prepare'
            prepare.mkdir(mode=0o700)
            sync.abort_undispatched(**args)
            self.assertTrue(registry.blocks_new_mutation(root / 'mutations'))
            prepare.rmdir()
            changed = root / 'store' / 'user_000001f5.cat'
            changed.write_bytes(self.external.replace_secure_data(self.external.secure_data))
            with self.assertRaises(sync.ExternalInventoryError):
                sync.abort_undispatched(**args)
            changed.write_bytes(components[changed.name])
            sync.abort_undispatched(**args)
            self.assertFalse(registry.blocks_new_mutation(root / 'mutations'))
            self.assertEqual(journal.read(path)[-1]['milestone'], 'EXTERNAL_INVENTORY_ABORTED_BEFORE_DISPATCH')

    def test_real_store_and_journal_transaction(self):
        self.exercise()

    def test_lost_confirmation_blocks_retry_and_retains_backup(self):
        self.exercise(fail_confirm=True)

    def test_inventory_races_never_publish_success(self):
        for index in range(3):
            with self.subTest(index=index):
                self.exercise(race_at=index)

    def test_journal_failure_prevents_next_dispatch(self):
        for step in sync.STEPS:
            with self.subTest(step=step):
                self.exercise(fail_record=step)


if __name__ == '__main__':
    unittest.main()
