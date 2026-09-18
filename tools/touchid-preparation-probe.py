#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Measure fprintd preparation through the truthful finger-needed boundary."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pwd
import statistics
import sys
import time

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus


BUS_NAME = "net.reactivated.Fprint"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
DEVICE_INTERFACE = "net.reactivated.Fprint.Device"


async def call(bus, member: str, signature: str = "", body=None):
    reply = await bus.call(
        Message(
            destination=BUS_NAME,
            path=DEVICE_PATH,
            interface=DEVICE_INTERFACE,
            member=member,
            signature=signature,
            body=[] if body is None else body,
        )
    )
    if reply.message_type == MessageType.ERROR:
        raise RuntimeError(f"{member} failed: {reply.error_name}")
    if reply.message_type != MessageType.METHOD_RETURN:
        raise RuntimeError(f"{member} returned an invalid D-Bus reply")
    return reply.body


async def run(
    iterations: int,
    ready_timeout: float,
    idle_seconds: float,
    *,
    list_first: bool,
    wait_for_result: bool = False,
) -> dict:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    ready_event: asyncio.Event | None = None
    result_event: asyncio.Event | None = None
    observations: dict = {}

    def signal_handler(message):
        nonlocal ready_event
        if (
            message.message_type == MessageType.SIGNAL
            and message.path == DEVICE_PATH
            and message.interface == "org.freedesktop.DBus.Properties"
            and message.member == "PropertiesChanged"
            and len(message.body) == 3
            and message.body[0] == DEVICE_INTERFACE
            and isinstance(message.body[1], dict)
        ):
            value = message.body[1].get("finger-needed")
            if value is not None and value.value is True and ready_event is not None:
                observations.setdefault("armed", time.monotonic())
                ready_event.set()
            present = message.body[1].get("finger-present")
            if present is not None and present.value is True and ready_event is not None:
                observations.setdefault("finger_present", time.monotonic())
        if (
            message.message_type == MessageType.SIGNAL
            and message.path == DEVICE_PATH
            and message.interface == DEVICE_INTERFACE
            and message.member == "VerifyStatus"
            and len(message.body) == 2
            and message.body[1] is True
            and result_event is not None
        ):
            observations["public_status"] = time.monotonic()
            observations["verdict"] = message.body[0]
            result_event.set()
        return False

    bus.add_message_handler(signal_handler)
    match = await bus.call(
        Message(
            destination="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="AddMatch",
            signature="s",
            body=[
                "type='signal',path='/net/reactivated/Fprint/Device/0',"
                "sender='net.reactivated.Fprint'"
            ],
        )
    )
    if match.message_type != MessageType.METHOD_RETURN:
        raise RuntimeError("could not subscribe to fprintd readiness")

    username = pwd.getpwuid(os.getuid()).pw_name
    samples = []
    for index in range(iterations):
        if index and idle_seconds:
            await asyncio.sleep(idle_seconds)
        total_started = time.monotonic()
        sample = {"run": index + 1}
        if list_first:
            list_started = time.monotonic()
            await call(bus, "ListEnrolledFingers", "s", [username])
            listed = time.monotonic()
            sample["list_seconds"] = round(listed - list_started, 6)
        else:
            listed = time.monotonic()
        await call(bus, "Claim", "s", [username])
        claimed = time.monotonic()
        ready_event = asyncio.Event()
        result_event = asyncio.Event()
        observations = {}
        start_started = time.monotonic()
        await call(bus, "VerifyStart", "s", ["any"])
        start_returned = time.monotonic()
        try:
            await asyncio.wait_for(ready_event.wait(), ready_timeout)
            armed = observations["armed"]
            if wait_for_result:
                print(f"Attempt {index + 1}: reader ready; touch the sensor.", file=sys.stderr, flush=True)
                await asyncio.wait_for(result_event.wait(), ready_timeout)
                sample["verdict"] = observations["verdict"]
                sample["armed_to_public_status_seconds"] = round(
                    observations["public_status"] - armed, 6
                )
                if "finger_present" in observations:
                    sample["host_touch_to_public_status_seconds"] = round(
                        observations["public_status"] - observations["finger_present"], 6
                    )
        finally:
            cleanup_started = time.monotonic()
            try:
                await call(bus, "VerifyStop")
            finally:
                await call(bus, "Release")
            cleaned = time.monotonic()
            ready_event = None
            result_event = None
        sample.update(
            {
                "claim_seconds": round(claimed - listed, 6),
                "verify_start_return_seconds": round(
                    start_returned - start_started, 6
                ),
                "start_to_armed_seconds": round(armed - start_started, 6),
                "total_to_armed_seconds": round(armed - total_started, 6),
                "cleanup_seconds": round(cleaned - cleanup_started, 6),
            }
        )
        samples.append(sample)
    fields = tuple(key for key in samples[0] if key.endswith("_seconds"))
    return {
        "schema_version": 1,
        "iterations": iterations,
        "idle_seconds": idle_seconds,
        "sequence": "list-then-verify" if list_first else "direct-verify",
        "samples": samples,
        "medians": {
            field: round(statistics.median(sample[field] for sample in samples if field in sample), 6)
            for field in fields
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--ready-timeout", type=float, default=15.0)
    parser.add_argument("--idle-seconds", type=float, default=0.0)
    parser.add_argument("--wait-for-result", action="store_true",
                        help="wait for a physical touch and terminal verdict before cleanup")
    parser.add_argument(
        "--direct-verify",
        action="store_true",
        help="measure Claim and VerifyStart without a preceding inventory call",
    )
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100:
        parser.error("--iterations must be between 1 and 100")
    if not 0 < args.ready_timeout <= 120:
        parser.error("--ready-timeout must be between 0 and 120 seconds")
    if not 0 <= args.idle_seconds <= 86400:
        parser.error("--idle-seconds must be between 0 and 86400 seconds")
    print(
        json.dumps(
            asyncio.run(
                run(
                    args.iterations,
                    args.ready_timeout,
                    args.idle_seconds,
                    list_first=not args.direct_verify,
                    wait_for_result=args.wait_for_result,
                )
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
