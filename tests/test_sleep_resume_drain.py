#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Resume-during-quiesce must not SIGKILL a worker warmed after aborting sleep."""

from __future__ import annotations

import asyncio
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import AsyncMock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/t2-fprintd.py"
SPEC = importlib.util.spec_from_file_location("t2_fprintd_sleep_resume", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class SleepResumeDrainTests(unittest.IsolatedAsyncioTestCase):
    def backend(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.system_sleeping = False
        backend.sleep_generation = 0
        backend.inventory_generation = 0
        backend.inventory_projection = None
        backend.inventory_authority_token = None
        backend.inventory_state_token = None
        backend.inventory_task = None
        backend.runtime_warm_task = None
        backend.native_worker_warm_task = None
        backend.native_worker_sleep_task = None
        backend.native_worker_start_lock = asyncio.Lock()
        backend.operation_lock = asyncio.Lock()
        backend.process_owner = None
        return backend

    async def test_resume_before_quiesce_drain_does_not_kill_warmed_worker(self):
        backend = self.backend()
        old_worker = object()
        new_worker = object()
        backend.native_worker = old_worker
        discarded = []
        started = asyncio.Event()
        hold = asyncio.Event()

        async def blocking_inventory():
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await hold.wait()
                raise

        async def discard(process):
            discarded.append(process)
            if backend.native_worker is process:
                backend.native_worker = None

        async def warm():
            backend.native_worker = new_worker

        backend.inventory_task = asyncio.create_task(blocking_inventory())
        await asyncio.wait_for(started.wait(), 1)
        backend._discard_native_worker = discard
        backend.warm_runtime = warm
        inventory = backend.inventory_task

        try:
            backend.system_sleep_changed(True)
            sleep_task = backend.native_worker_sleep_task
            self.assertIsNotNone(sleep_task)
            await asyncio.sleep(0)
            backend.system_sleep_changed(False)
            await asyncio.sleep(0)
            hold.set()
            await asyncio.wait_for(sleep_task, 1)
            warm_task = backend.runtime_warm_task
            if warm_task is not None:
                await asyncio.wait_for(warm_task, 1)

            self.assertNotIn(new_worker, discarded)
            self.assertIs(backend.native_worker, new_worker)
        finally:
            if inventory is not None and not inventory.done():
                inventory.cancel()
                await asyncio.gather(inventory, return_exceptions=True)

    async def test_quiesce_bails_when_resume_already_happened(self):
        backend = self.backend()
        backend.native_worker = object()
        backend._discard_native_worker = AsyncMock()
        backend.system_sleeping = False
        backend.sleep_generation = 3
        await backend._quiesce_hardware_for_sleep()
        backend._discard_native_worker.assert_not_awaited()

    def test_completed_claim_grace_is_at_least_two_seconds(self):
        self.assertGreaterEqual(MODULE.COMPLETED_CLAIM_SECONDS, 2.0)

    def test_unbounded_match_seconds_are_capped(self):
        backend = self.backend()
        backend.match_seconds = 0
        self.assertEqual(backend._observation_seconds(), MODULE.MAX_MATCH_SECONDS)
        backend.match_seconds = 10_000
        self.assertEqual(backend._observation_seconds(), MODULE.MAX_MATCH_SECONDS)
        backend.match_seconds = 15
        self.assertEqual(backend._observation_seconds(), 15.0)


if __name__ == "__main__":
    unittest.main()
