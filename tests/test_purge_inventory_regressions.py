# SPDX-License-Identifier: GPL-2.0-only
"""Out-of-process mutation visibility and typed empty-inventory handling."""

import asyncio
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from dbus_next import Message, MessageType
from dbus_next.aio import MessageBus

from tests.test_t2_fprintd import MODULE, make_device

SPEC = importlib.util.spec_from_file_location(
    "product_inventory", Path(__file__).parents[1] / "src/t2-touchid-list.py"
)
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)


class MutationVisibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.catacomb = root / "catacomb"
        self.mutations = root / "mutations"
        self.catacomb.mkdir(mode=0o700)
        self.mutations.mkdir(mode=0o700)
        self.component = self.catacomb / "user_000001f5.cat"
        # Synthetic neutral presentation, not a biometric payload.
        self.component.write_text("finger-1,finger-2,finger-3")
        self.component.chmod(0o600)
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        self.backend = backend
        backend.catacomb_root = self.catacomb
        backend.inventory_projection = None
        backend.inventory_authority_token = None
        backend.inventory_state_token = None
        backend.inventory_generation = 0
        backend.operation_lock = asyncio.Lock()
        backend.inventory_task = None
        backend.runtime_authority = mock.Mock(return_value=SimpleNamespace(
            origin=MODULE.NATIVE_AUTHORITY,
            mapping_set=SimpleNamespace(generation="mapping-a"),
            selected=SimpleNamespace(
                linux_account_generation="account-a", keybag_sha256="keybag-a",
                apple_uid=501, account_uuid="account-a", bag_uuid="bag-a",
            ),
        ))

        async def collect(_authority):
            text = self.component.read_text()
            fingers = tuple(text.split(",")) if text else ()
            return MODULE.t2_fprint_runtime.RuntimeProjection(fingers, len(fingers), True)

        backend._collect_runtime_projection = mock.AsyncMock(side_effect=collect)
        # Model the installed root-owned state while allowing unprivileged CI.
        original_stat = Path.stat

        def root_owned_stat(path, **kwargs):
            info = original_stat(path, **kwargs)
            return SimpleNamespace(**{
                name: 0 if name == "st_uid" else getattr(info, name)
                for name in ("st_uid", "st_mode", "st_dev", "st_ino", "st_size",
                             "st_mtime_ns", "st_ctime_ns")
            })

        patch = mock.patch.object(Path, "stat", root_owned_stat)
        patch.start()
        self.addCleanup(patch.stop)

    def replace_component(self, text):
        staged = self.catacomb / "replacement.cat"
        staged.write_text(text)
        staged.chmod(0o600)
        os.replace(staged, self.component)

    async def test_purge_then_count_and_list_refresh_without_authority_change(self):
        self.assertEqual(await self.backend.list_fingers(), ("finger-1", "finger-2", "finger-3"))
        self.assertEqual(len(await self.backend.list_fingers()), 3)
        self.backend._collect_runtime_projection.assert_awaited_once()
        authority_token = self.backend.inventory_authority_token
        # A separate authorized helper commits deletion, without calling the
        # daemon's invalidate_inventory method or changing account authority.
        self.replace_component("")
        self.assertEqual(len(await self.backend.list_fingers()), 0)
        self.assertEqual(await self.backend.list_fingers(), ())
        self.assertEqual(self.backend.inventory_authority_token, authority_token)
        self.assertEqual(self.backend._collect_runtime_projection.await_count, 2)

    async def test_out_of_process_enrollment_and_rename_refresh_warm_inventory(self):
        await self.backend.list_fingers()
        self.replace_component("finger-1,finger-2,finger-3,finger-4")
        self.assertEqual(len(await self.backend.list_fingers()), 4)
        self.replace_component("finger-1,finger-2,finger-3,finger-5")
        self.assertEqual((await self.backend.list_fingers())[-1], "finger-5")
        self.assertEqual(self.backend._collect_runtime_projection.await_count, 3)

    async def test_journal_append_invalidates_even_without_persistence(self):
        journal = self.mutations / "mutation.jsonl"
        journal.write_text("intent\n")
        journal.chmod(0o600)
        await self.backend.list_fingers()
        with journal.open("a") as stream:
            stream.write("outcome-unknown\n")
        self.backend._collect_runtime_projection.side_effect = RuntimeError("recovery required")
        with self.assertRaisesRegex(RuntimeError, "recovery required"):
            await self.backend.list_fingers()
        self.assertEqual(self.backend._collect_runtime_projection.await_count, 2)

    async def test_incomplete_transaction_cannot_reuse_cached_inventory(self):
        await self.backend.list_fingers()
        (self.catacomb / "prepare").mkdir(mode=0o700)
        self.backend._collect_runtime_projection.side_effect = RuntimeError("incomplete transaction")
        with self.assertRaisesRegex(RuntimeError, "incomplete transaction"):
            await self.backend.list_fingers()

    async def test_state_changed_during_collection_is_not_cached(self):
        original = self.backend._collect_runtime_projection.side_effect

        async def mutate_during_collection(authority):
            projection = await original(authority)
            self.replace_component("")
            return projection

        self.backend._collect_runtime_projection.side_effect = mutate_during_collection
        self.assertEqual(len(await self.backend.list_fingers()), 3)
        self.assertIsNone(self.backend.inventory_projection)
        self.backend._collect_runtime_projection.side_effect = original
        self.assertEqual(await self.backend.list_fingers(), ())

    async def test_missing_or_unsafe_state_disables_cache_reuse(self):
        await self.backend.list_fingers()
        self.component.unlink()
        self.component.symlink_to(self.mutations)
        self.assertIsNone(self.backend._inventory_state_token(self.backend.runtime_authority()))
        self.backend._collect_runtime_projection.side_effect = RuntimeError("unsafe state")
        with self.assertRaisesRegex(RuntimeError, "unsafe state"):
            await self.backend.list_fingers()

    @unittest.skipUnless(shutil.which("dbus-daemon"), "private D-Bus daemon unavailable")
    async def test_helper_reads_post_purge_empty_state_over_real_dbus_without_callback_error(self):
        daemon = await asyncio.create_subprocess_exec(
            "dbus-daemon", "--session", "--nofork", "--print-address=1",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        service = None
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        callback_errors = []
        loop.set_exception_handler(lambda _loop, context: callback_errors.append(context))
        try:
            address = (await asyncio.wait_for(daemon.stdout.readline(), 3)).decode().strip()
            service = await MODULE.SenderAwareMessageBus(bus_address=address).connect()
            service.export("/net/reactivated/Fprint/Device/0", make_device(self.backend, identity_bus=service))
            await service.request_name("net.reactivated.Fprint")

            def factory(**_kwargs):
                return MessageBus(bus_address=address)

            before = await INVENTORY.collect(MODULE.LINUX_USER, bus_factory=factory)
            self.assertEqual(before["data"], [["finger-1", "finger-2", "finger-3"]])
            self.replace_component("")
            after = await INVENTORY.collect(MODULE.LINUX_USER, bus_factory=factory)
            self.assertEqual(after, {"type": "as", "data": [[]]})
            await asyncio.sleep(0)
            self.assertEqual(callback_errors, [])
        finally:
            if service is not None:
                service.disconnect()
                await service.wait_for_disconnect()
                service._stream.close()
                service._sock.close()
            if daemon.returncode is None:
                daemon.terminate()
            await daemon.communicate()
            loop.set_exception_handler(previous_handler)


class TypedInventoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_connection_cleans_up_without_returning_empty_inventory(self):
        bus = mock.Mock(unique_name=None)
        bus.connect = mock.AsyncMock(side_effect=RuntimeError("private transport detail"))
        bus.call = mock.AsyncMock()
        with self.assertRaisesRegex(RuntimeError, "private transport detail"):
            await INVENTORY.collect("mapped", bus_factory=mock.Mock(return_value=bus))
        bus.call.assert_not_awaited()
        bus.disconnect.assert_called_once()
        bus._finalize.assert_called_once()
        bus._stream.close.assert_called_once()
        bus._sock.close.assert_called_once()

    async def call_reply(self, reply):
        bus = mock.Mock()
        bus.connect = mock.AsyncMock()
        bus.call = mock.AsyncMock(return_value=reply)
        bus.wait_for_disconnect = mock.AsyncMock()
        factory = mock.Mock(return_value=bus)
        try:
            return await INVENTORY.collect("mapped", bus_factory=factory)
        finally:
            bus.disconnect.assert_called_once()
            bus._stream.close.assert_called_once()
            bus._sock.close.assert_called_once()
            request = bus.call.call_args.args[0]
            self.assertEqual(request.member, "ListEnrolledFingers")
            self.assertEqual(request.body, ["mapped"])

    async def test_only_typed_no_prints_error_becomes_empty_inventory(self):
        reply = Message(message_type=MessageType.ERROR, reply_serial=1,
                        error_name="net.reactivated.Fprint.Error.NoEnrolledPrints",
                        signature="s", body=["localized diagnostic"])
        self.assertEqual(await self.call_reply(reply), {"type": "as", "data": [[]]})

    async def test_service_and_permission_errors_remain_failures_even_with_empty_text(self):
        for name in ("net.reactivated.Fprint.Error.Internal",
                     "net.reactivated.Fprint.Error.PermissionDenied",
                     "org.freedesktop.DBus.Error.ServiceUnknown"):
            with self.subTest(name=name):
                reply = Message(message_type=MessageType.ERROR, reply_serial=1,
                                error_name=name, signature="s", body=["no fingerprints are enrolled"])
                with self.assertRaises(INVENTORY.InventoryError):
                    await self.call_reply(reply)

    async def test_inventory_reply_must_have_the_expected_signature(self):
        reply = Message(message_type=MessageType.METHOD_RETURN, reply_serial=1,
                        signature="as", body=[["finger-3", "finger-1"]])
        self.assertEqual(await self.call_reply(reply), {"type": "as", "data": [["finger-3", "finger-1"]]})
        malformed = Message(message_type=MessageType.METHOD_RETURN, reply_serial=1,
                            signature="s", body=["finger-1"])
        with self.assertRaises(INVENTORY.InventoryError):
            await self.call_reply(malformed)
