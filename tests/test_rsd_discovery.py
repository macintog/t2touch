# SPDX-License-Identifier: GPL-2.0-only
"""Offline checks for fast discovery without trusting stale routing hints."""

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import t2_rsd as rsd


class FakeConnection:
    peers = {}
    opened = []
    closed = []

    def __init__(self, address):
        self.port = address[1]
        self.opened.append(self.port)

    async def connect(self):
        pass

    async def send_device_handshake(self):
        pass

    async def receive_response(self):
        peer = self.peers[self.port]
        if isinstance(peer, Exception):
            raise peer
        return peer

    async def close(self):
        self.closed.append(self.port)


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeConnection.opened = []
        FakeConnection.closed = []
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.hint = Path(self.directory.name) / "rsd-endpoint.json"
        self.enterContext(patch.object(rsd, "RSD_HINT", self.hint))
        self.enterContext(patch(
            "pymobiledevice3.remote.remotexpc.RemoteXPCConnection", FakeConnection
        ))
        self.enterContext(patch.object(rsd.socket, "if_nametoindex", return_value=1))

    async def test_cached_endpoint_reads_fresh_record_without_scanning(self):
        rsd._save_hint("host", "iface", 50000)
        first = {"Services": {"service": {"Port": 50010}}}
        second = {"Services": {"service": {"Port": 50011}}}
        with patch.object(rsd, "_probe_port", new_callable=AsyncMock) as scan:
            for peer in (first, second):
                FakeConnection.peers = {50000: peer}
                _, observed = await rsd.discover_peer("host", "iface", 0.2, 3)
                self.assertIs(observed, peer)
            scan.assert_not_called()
        self.assertEqual(FakeConnection.opened, [50000, 50000])
        self.assertEqual(FakeConnection.closed, [50000, 50000])
        self.assertIsNone(rsd._load_hint("other-host", "iface"))
        self.assertIsNone(rsd._load_hint("host", "other-interface"))
        self.hint.chmod(0o644)
        self.assertIsNone(rsd._load_hint("host", "iface"))

    async def test_stale_hint_scans_until_valid_peer_and_cancels_slow_ports(self):
        rsd._save_hint("host", "iface", 50000)
        fresh = {"Services": {"service": {"Port": 50012}}}
        FakeConnection.peers = {
            50000: OSError("stale endpoint"),
            50001: {"Services": {}},
            50002: fresh,
        }
        slow_started = asyncio.Event()
        slow_cancelled = asyncio.Event()

        async def probe(_host, port, _scope, _semaphore, _timeout):
            if port < 50003:
                if port == 50002:
                    await slow_started.wait()
                return port
            slow_started.set()
            try:
                await asyncio.Future()
            finally:
                slow_cancelled.set()

        with (
            patch.object(rsd, "FIRST_DYNAMIC_PORT", 50000),
            patch.object(rsd, "LAST_DYNAMIC_PORT", 50010),
            patch.object(rsd, "_probe_port", side_effect=probe),
        ):
            _, observed = await asyncio.wait_for(
                rsd.discover_peer("host", "iface", 0.2, 3), 1
            )
        self.assertIs(observed, fresh)
        self.assertTrue(slow_cancelled.is_set())
        self.assertEqual(sorted(FakeConnection.opened), [50000, 50001, 50002])
        self.assertCountEqual(FakeConnection.closed, FakeConnection.opened)
        self.assertEqual(rsd._load_hint("host", "iface"), 50002)

    async def test_cancelled_discovery_drains_all_probe_workers(self):
        started = asyncio.Event()
        active = 0

        async def probe(*_args):
            nonlocal active
            active += 1
            started.set()
            try:
                await asyncio.Future()
            finally:
                active -= 1

        with patch.object(rsd, "_probe_port", side_effect=probe):
            discovery = asyncio.create_task(rsd.discover_peer("host", "iface", 0.2, 3))
            await asyncio.wait_for(started.wait(), 1)
            discovery.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await discovery
        self.assertEqual(active, 0)
        self.assertFalse(self.hint.exists())


if __name__ == "__main__":
    unittest.main()
