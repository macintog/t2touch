# SPDX-License-Identifier: GPL-2.0-only
"""Exercise departure subscription on a private bus, without T2 hardware."""

import argparse
import asyncio
import importlib.util
from pathlib import Path
import shutil
import unittest
from unittest import mock

from dbus_next.aio import MessageBus


SOURCE = Path(__file__).resolve().parents[1] / "src/t2-fprintd.py"
SPEC = importlib.util.spec_from_file_location("fprint_bus_integration", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@unittest.skipUnless(shutil.which("dbus-daemon"), "private D-Bus daemon unavailable")
class DepartureIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_main_subscribes_and_receives_client_departure(self):
        daemon = await asyncio.create_subprocess_exec(
            "dbus-daemon", "--session", "--nofork", "--print-address=1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        service = client = task = None
        try:
            address = (await asyncio.wait_for(daemon.stdout.readline(), 3)).decode().strip()
            self.assertTrue(address)
            ready = asyncio.Event()
            departed = asyncio.get_running_loop().create_future()

            class ServiceBus(MODULE.SenderAwareMessageBus):
                async def request_name(self, name, *args, **kwargs):
                    result = await super().request_name(name, *args, **kwargs)
                    ready.set()
                    return result

            service = ServiceBus(bus_address=address)
            class Device(MODULE.FprintDevice):
                async def sender_departed(self, sender):
                    if not departed.done():
                        departed.set_result(sender)

            with (
                mock.patch.object(MODULE, "T2Backend", return_value=object()),
                mock.patch.object(MODULE, "SenderAwareMessageBus", return_value=service),
                mock.patch.object(MODULE, "FprintDevice", Device),
            ):
                task = asyncio.create_task(MODULE.main_async(argparse.Namespace(
                    match_seconds=0, enable_native_enrollment=False,
                    enable_native_deletion=False,
                )))
                await asyncio.wait_for(ready.wait(), 3)
                client = await MessageBus(bus_address=address).connect()
                name = client.unique_name
                client.disconnect()
                await client.wait_for_disconnect()
                self.assertEqual(await asyncio.wait_for(departed, 3), name)
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            for bus in (client, service):
                if bus is not None:
                    bus.disconnect()
                    await bus.wait_for_disconnect()
                    # dbus-next 0.2.3 disconnects the transport but leaves its
                    # socket and file wrapper open; close both test resources.
                    bus._stream.close()
                    bus._sock.close()
            if daemon.returncode is None:
                daemon.terminate()
            await daemon.communicate()
