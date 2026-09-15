# SPDX-License-Identifier: GPL-2.0-only
"""Exercise departure subscription on a private bus, without T2 hardware."""

import argparse
import asyncio
import importlib.util
from pathlib import Path
import shutil
import unittest
from unittest import mock

from dbus_next import Message, MessageType
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
        service = client = login1 = task = None
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

            backend = mock.Mock()
            backend.warm_runtime = mock.AsyncMock()
            backend.system_sleeping = True
            def schedule_warm():
                return asyncio.create_task(backend.warm_runtime())
            backend._schedule_runtime_warm.side_effect = schedule_warm
            sleep_seen = asyncio.Event()
            def sleep_changed(sleeping):
                backend.system_sleeping = sleeping
                if sleeping:
                    sleep_seen.set()
            backend.system_sleep_changed.side_effect = sleep_changed

            login1 = await MessageBus(bus_address=address).connect()
            await login1.request_name("org.freedesktop.login1")
            class Login1Manager(MODULE.ServiceInterface):
                def __init__(self):
                    super().__init__("org.freedesktop.login1.Manager")

                @MODULE.dbus_property(access=MODULE.PropertyAccess.READ)
                def PreparingForSleep(self) -> "b":
                    return False

            login1.export("/org/freedesktop/login1", Login1Manager())

            with (
                mock.patch.object(MODULE, "T2Backend", return_value=backend),
                mock.patch.object(MODULE, "SenderAwareMessageBus", return_value=service),
                mock.patch.object(MODULE, "FprintDevice", Device),
            ):
                task = asyncio.create_task(MODULE.main_async(argparse.Namespace(
                    match_seconds=0, enable_native_enrollment=False,
                    enable_native_deletion=False,
                )))
                await asyncio.wait_for(ready.wait(), 3)
                backend.system_sleep_changed.assert_called_once_with(False)
                backend.system_sleep_changed.reset_mock()
                await login1.send(
                    Message(
                        message_type=MessageType.SIGNAL,
                        path="/org/freedesktop/login1",
                        interface="org.freedesktop.login1.Manager",
                        member="PrepareForSleep",
                        signature="b",
                        body=[True],
                    )
                )
                await asyncio.wait_for(sleep_seen.wait(), 3)
                backend.system_sleep_changed.assert_called_once_with(True)
                client = await MessageBus(bus_address=address).connect()
                name = client.unique_name
                client.disconnect()
                await client.wait_for_disconnect()
                self.assertEqual(await asyncio.wait_for(departed, 3), name)
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            for bus in (client, service, login1):
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
