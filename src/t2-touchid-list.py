#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read fprintd inventory with typed errors for the unprivileged product CLI."""

import argparse
import asyncio
import json
import sys

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus


class InventoryError(RuntimeError):
    pass


def inventory_reply(reply) -> dict[str, object]:
    if (
        reply.message_type == MessageType.ERROR
        and reply.error_name == "net.reactivated.Fprint.Error.NoEnrolledPrints"
    ):
        # This is the upstream fprintd representation of an empty inventory.
        data = [[]]
    elif reply.message_type == MessageType.METHOD_RETURN and reply.signature == "as":
        data = reply.body
    else:
        raise InventoryError("unable to list enrolled fingerprints")
    return {"type": "as", "data": data}


async def collect(user: str, *, bus_factory=MessageBus) -> dict[str, object]:
    bus = bus_factory(bus_type=BusType.SYSTEM)
    try:
        await asyncio.wait_for(bus.connect(), 3)
        reply = await asyncio.wait_for(bus.call(Message(
            destination="net.reactivated.Fprint",
            path="/net/reactivated/Fprint/Device/0",
            interface="net.reactivated.Fprint.Device",
            member="ListEnrolledFingers",
            signature="s",
            body=[user],
        )), 15)
        return inventory_reply(reply)
    finally:
        bus.disconnect()
        try:
            if bus.unique_name is not None:
                await asyncio.wait_for(bus.wait_for_disconnect(), 1)
        finally:
            # Remove loop registrations before releasing a reusable descriptor,
            # including when authentication/connection never completed.
            # dbus-next 0.2.3 leaves these resources open after disconnect.
            bus._finalize()
            bus._stream.close()
            bus._sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("user")
    args = parser.parse_args()
    try:
        document = asyncio.run(collect(args.user))
    except Exception:
        # D-Bus diagnostics may contain private account or identity details.
        print("t2touch: unable to list enrolled fingerprints", file=sys.stderr)
        return 1
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
