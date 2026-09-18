# SPDX-License-Identifier: GPL-2.0-only
"""A bounded import-only spare must never acquire the active request's state."""

import asyncio
import importlib.util
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "t2_fprintd_spare", Path(__file__).resolve().parents[1] / "src/t2-fprintd.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RESULT = {"schema_version": 1, "selector": "all", "verdict": "verify-no-match", "finger_name": None}


class Worker:
    def __init__(self, *, ready=True):
        self.pid = None  # Never signal a real process in this deterministic fixture.
        self.returncode = None
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.requests = []
        self.dispatched = asyncio.Event()
        self.exited = asyncio.Event()
        self.stdin = Mock()
        self.stdin.write.side_effect = self.write
        self.stdin.drain = AsyncMock()
        if ready:
            self.ready()

    def ready(self):
        self.stdout.feed_data(b'{"schema_version":1,"ready":true}\n')

    def write(self, value):
        self.requests.append(json.loads(value))
        self.dispatched.set()

    def finish(self):
        request_id = self.requests[-1]["request_id"]
        self.stdout.feed_data(json.dumps({
            "schema_version": 1, "request_id": request_id, "ok": True, "result": RESULT,
        }).encode() + b"\n")
        self.stderr.feed_data(f"T2_WORKER_BOUNDARY {request_id}\n".encode())

    def terminate(self):
        self.finish()

    def kill(self):
        if self.returncode is None:
            self.returncode = -9
            self.stdout.feed_eof()
            self.stderr.feed_eof()
            self.exited.set()

    async def wait(self):
        await self.exited.wait()
        return self.returncode


class NativeSpareTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        b = self.backend
        b.system_sleeping = False
        b.native_worker = None
        b.native_worker_stderr_task = None
        b.native_worker_feedback = None
        b.native_worker_boundary_event = None
        b.native_worker_cue_sent = False
        b.process = b.process_owner = None
        b.project_dir = Path("/unused")
        b.linux_uid = 1000
        b.match_seconds = 0
        b.schedule_feedback = Mock()
        b.operation_lock = asyncio.Lock()
        self.workers = []
        self.spawned = asyncio.Queue()
        self.delay_ready = False

        async def spawn(*_args, **_kwargs):
            worker = Worker(ready=not self.delay_ready)
            self.workers.append(worker)
            self.spawned.put_nowait(worker)
            return worker

        self.spawner = patch.object(MODULE.asyncio, "create_subprocess_exec", side_effect=spawn)
        self.spawner.start()

    async def asyncTearDown(self):
        self.backend.system_sleeping = True
        await self.backend._quiesce_hardware_for_sleep()
        self.spawner.stop()
        self.assertTrue(all(w.returncode is not None for w in self.workers))

    async def spawned_worker(self):
        return await asyncio.wait_for(self.spawned.get(), 1)

    async def finish_warmup(self):
        task = getattr(self.backend, "native_worker_warm_task", None)
        if task is not None:
            await asyncio.wait_for(asyncio.shield(task), 1)

    async def test_startup_preparation_waits_for_inventory_owner(self):
        entered, released = asyncio.Event(), asyncio.Event()
        async def projection():
            self.assertTrue(self.backend.operation_lock.locked())
            entered.set()
            await released.wait()
        async def prepare():
            self.assertTrue(released.is_set())
            self.assertTrue(self.backend.operation_lock.locked())
        self.backend.runtime_authority = Mock(return_value=SimpleNamespace(origin=MODULE.NATIVE_AUTHORITY))
        self.backend.runtime_projection = projection
        with patch.object(self.backend, "_ensure_native_worker", side_effect=prepare) as worker:
            warming = asyncio.create_task(self.backend.warm_runtime())
            await entered.wait()
            worker.assert_not_called()
            released.set()
            await asyncio.wait_for(warming, 1)
            worker.assert_awaited_once()

    async def test_failed_inventory_does_not_prevent_independent_preparation(self):
        self.backend.runtime_authority = Mock(return_value=SimpleNamespace(origin=MODULE.NATIVE_AUTHORITY))
        self.backend.runtime_projection = AsyncMock(side_effect=RuntimeError("unavailable"))
        with patch.object(self.backend, "_ensure_native_worker", new_callable=AsyncMock) as worker:
            await self.backend.warm_runtime()
            worker.assert_awaited_once()

    async def test_spare_imports_overlap_active_request_and_serves_next_request_once(self):
        first = asyncio.create_task(self.backend._run_native_match())
        active = await self.spawned_worker()
        spare = await self.spawned_worker()
        await self.backend.native_spare_warm_task
        self.assertFalse(first.done())
        self.assertEqual(len(active.requests), 1)
        self.assertEqual(spare.requests, [])
        self.assertIs(self.backend.native_worker, active)
        for _ in range(3):
            self.backend._schedule_native_spare()
        self.assertEqual(len(self.workers), 2)
        active.finish()
        self.assertEqual(await asyncio.wait_for(first, 1), RESULT)
        await self.finish_warmup()
        self.assertIs(self.backend.native_worker, spare)

        second = asyncio.create_task(self.backend._run_native_match())
        next_spare = await self.spawned_worker()
        self.assertIs(self.backend.native_worker, spare)
        self.assertEqual(len(spare.requests), 1)
        self.assertEqual(next_spare.requests, [])
        spare.finish()
        self.assertEqual(await asyncio.wait_for(second, 1), RESULT)
        await self.finish_warmup()
        self.assertEqual([len(w.requests) for w in self.workers], [1, 1, 0])

    async def test_spare_feedback_boundary_and_eof_cannot_complete_active_request(self):
        active = await self.backend._ensure_native_worker()
        self.backend.native_worker_expected_boundary = 1
        self.backend.native_worker_boundary_event = asyncio.Event()
        self.backend.native_worker_feedback = Mock()
        self.backend._schedule_native_spare()
        await self.backend.native_spare_warm_task
        spare = self.backend.native_spare_worker
        spare.stderr.feed_data(b'T2_WORKER_BOUNDARY 1\nT2_MATCH_EVENT {"event_kind":"match_armed"}\n')
        spare.stderr.feed_eof()
        await self.backend.native_spare_stderr_task
        self.assertFalse(self.backend.native_worker_boundary_event.is_set())
        self.backend.native_worker_feedback.assert_not_called()
        self.backend.schedule_feedback.assert_not_called()
        self.assertIs(self.backend.native_worker, active)

    async def test_promotion_waits_for_spare_ready_handshake(self):
        self.delay_ready = True
        self.backend._schedule_native_spare()
        spare = await self.spawned_worker()
        ensure = asyncio.create_task(self.backend._ensure_native_worker())
        await asyncio.sleep(0)
        self.assertFalse(ensure.done())
        self.assertIsNone(self.backend.native_worker)
        spare.ready()
        self.assertIs(await asyncio.wait_for(ensure, 1), spare)
        self.assertEqual(spare.requests, [])

    async def test_sleep_drains_both_slots_even_during_spare_import(self):
        active = await self.backend._ensure_native_worker()
        self.delay_ready = True
        self.backend._schedule_native_spare()
        await self.spawned_worker()  # The initial active worker.
        spare = await self.spawned_worker()
        self.backend.system_sleeping = True
        await asyncio.wait_for(self.backend._quiesce_hardware_for_sleep(), 1)
        self.assertIsNotNone(active.returncode)
        self.assertIsNotNone(spare.returncode)
        self.assertIsNone(self.backend.native_worker)
        self.assertIsNone(self.backend.native_spare_worker)
        self.backend._schedule_native_spare()
        self.assertEqual(len(self.workers), 2)

    async def test_bad_spare_ready_is_reaped_and_next_request_can_start_fresh(self):
        self.delay_ready = True
        self.backend._schedule_native_spare()
        spare = await self.spawned_worker()
        spare.stdout.feed_data(b'{"ready":true}\n')
        with self.assertRaises(RuntimeError):
            await self.backend.native_spare_warm_task
        self.assertIsNotNone(spare.returncode)
        self.assertIsNone(self.backend.native_spare_worker)
        self.delay_ready = False
        replacement = await self.backend._ensure_native_worker()
        self.assertIsNot(replacement, spare)
        self.assertEqual(replacement.requests, [])

    async def test_boolean_protocol_version_cannot_promote_worker(self):
        self.delay_ready = True
        warming = asyncio.create_task(self.backend._ensure_native_worker())
        worker = await self.spawned_worker()
        worker.stdout.feed_data(b'{"schema_version":true,"ready":true}\n')
        with self.assertRaises(RuntimeError):
            await warming
        self.assertIsNotNone(worker.returncode)

    async def test_cancellation_retains_only_an_unconsumed_spare(self):
        request = asyncio.create_task(self.backend._run_native_match())
        active = await self.spawned_worker()
        spare = await self.spawned_worker()
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(request, 1)
        await self.finish_warmup()
        self.assertIsNotNone(active.returncode)
        self.assertIs(self.backend.native_worker, spare)
        self.assertEqual(spare.requests, [])

    async def test_prepared_worker_serves_repeated_requests_without_spare(self):
        active = await self.backend._ensure_native_worker()
        active.t2_retains_identity = True
        active.stdin.close.side_effect = active.kill
        for _ in range(2):
            active.dispatched.clear()
            request = asyncio.create_task(self.backend._run_native_match())
            await asyncio.wait_for(active.dispatched.wait(), 1)
            active.finish()
            self.assertEqual(await asyncio.wait_for(request, 1), RESULT)
            self.assertIs(self.backend.native_worker, active)
        self.assertEqual(len(self.workers), 1)
        self.assertEqual(len(active.requests), 2)

    async def test_prepared_worker_survives_only_valid_drained_cancellation(self):
        active = await self.backend._ensure_native_worker()
        active.t2_retains_identity = True
        active.stdin.close.side_effect = active.kill
        def cancelled():
            request_id = active.requests[-1]["request_id"]
            active.stdout.feed_data(json.dumps({"schema_version": 1,
                "request_id": request_id, "ok": True, "cancelled": True}).encode()+b"\n")
            active.stderr.feed_data(f"T2_WORKER_BOUNDARY {request_id}\n".encode())
        active.terminate = cancelled
        request = asyncio.create_task(self.backend._run_native_match())
        await asyncio.wait_for(active.dispatched.wait(), 1)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(request, 1)
        self.assertIs(self.backend.native_worker, active)
        self.assertEqual(len(self.workers), 1)

    async def test_bad_prepared_terminal_is_reaped_before_next_request(self):
        active = await self.backend._ensure_native_worker()
        active.t2_retains_identity = True
        active.stdin.close.side_effect = active.kill
        request = asyncio.create_task(self.backend._run_native_match())
        await asyncio.wait_for(active.dispatched.wait(), 1)
        active.stdout.feed_data(b'{"schema_version":1,"request_id":1,"ok":true,"result":{}}\n')
        active.stderr.feed_data(b'T2_WORKER_BOUNDARY 1\n')
        with self.assertRaises(RuntimeError):
            await asyncio.wait_for(request, 1)
        self.assertIsNotNone(active.returncode)
