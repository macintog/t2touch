#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Summarize the T2's read-only MobileStorage device inventory.

The request is limited to ``CopyDevices``. Raw device nodes, mount paths,
image paths, signatures, and the complete bridgeOS response are never printed.
"""

import argparse
import asyncio
import json
import os
import re
import sys
from collections import Counter
from typing import Any

from t2_rsd import discover_peer, service_port


STORAGE_SERVICE = "com.apple.mobile.storage_mounter_proxy.bridge"
UPDATE_SERVICE = "com.apple.bridgeOSUpdated"
COMMAND = "CopyDevices"
SAFE_TEXT_FIELDS = ("DeviceType", "FilesystemType")
SAFE_BOOL_FIELDS = (
    "IsMounted",
    "IsReadOnly",
    "SupportsContentProtection",
)
DEVICE_NODE = re.compile(r"^(?:/dev/)?disk[0-9]+(?P<partitions>(?:s[0-9]+)*)$")


async def _request(
    scoped_host: str,
    port: int,
    request: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    connection = RemoteXPCConnection((scoped_host, port))
    try:
        await asyncio.wait_for(connection.connect(), timeout)
        response = await asyncio.wait_for(
            connection.send_receive_request(request), timeout
        )
    finally:
        await connection.close()
    if not isinstance(response, dict):
        raise RuntimeError("bridgeOS returned a non-dictionary response")
    return response


async def _current_build(
    scoped_host: str, peer: dict[str, Any], timeout: float
) -> str:
    response = await _request(
        scoped_host,
        service_port(peer, UPDATE_SERVICE),
        {"Command": "QueryUpdateState"},
        timeout,
    )
    if response.get("Response") != "QueryUpdateState":
        raise RuntimeError("bridgeOS returned an unexpected update-state response")
    results = response.get("Results")
    build = results.get("CurrentOSBuildVersion") if isinstance(results, dict) else None
    if not isinstance(build, str) or not build:
        raise RuntimeError("bridgeOS update-state response has no build version")
    return build


def _node_shape(value: Any) -> str:
    if not isinstance(value, str):
        return "absent"
    match = DEVICE_NODE.fullmatch(value)
    if match is None:
        return "other"
    partitions = match.group("partitions")
    if not partitions:
        return "whole-disk"
    return f"partition-depth-{partitions.count('s')}"


def summarize(build: str, response: dict[str, Any]) -> dict[str, Any]:
    if response.get("Status") != "Complete":
        error = response.get("Error")
        suffix = f" ({error})" if isinstance(error, str) else ""
        raise RuntimeError(f"CopyDevices did not complete{suffix}")
    entries = response.get("EntryList")
    if not isinstance(entries, list) or not all(
        isinstance(entry, dict) for entry in entries
    ):
        raise RuntimeError("CopyDevices response has no dictionary EntryList")

    device_types: Counter[str] = Counter()
    filesystems: Counter[str] = Counter()
    node_shapes: Counter[str] = Counter()
    safe_entries: list[dict[str, Any]] = []
    for entry in entries:
        selected: dict[str, Any] = {}
        for field in SAFE_TEXT_FIELDS:
            value = entry.get(field)
            if isinstance(value, str):
                selected[field] = value
        for field in SAFE_BOOL_FIELDS:
            value = entry.get(field)
            if isinstance(value, bool):
                selected[field] = value
        selected["DeviceNodeShape"] = _node_shape(entry.get("DeviceNode"))
        safe_entries.append(selected)
        device_types.update([selected.get("DeviceType", "unspecified")])
        filesystems.update([selected.get("FilesystemType", "unspecified")])
        node_shapes.update([selected["DeviceNodeShape"]])

    return {
        "BridgeOSBuild": build,
        "Command": COMMAND,
        "EntryCount": len(entries),
        "DeviceTypes": dict(sorted(device_types.items())),
        "FilesystemTypes": dict(sorted(filesystems.items())),
        "DeviceNodeShapes": dict(sorted(node_shapes.items())),
        "Entries": safe_entries,
        "Redaction": "device nodes, paths, signatures, and raw response omitted",
    }


async def inventory(args: argparse.Namespace) -> dict[str, Any]:
    scoped_host, peer = await discover_peer(
        args.host, args.interface, args.probe_timeout, args.concurrency
    )
    build = await _current_build(scoped_host, peer, args.request_timeout)
    if build != args.expected_build:
        raise RuntimeError(
            f"refusing inventory: expected build {args.expected_build}, got {build}"
        )
    response = await _request(
        scoped_host,
        service_port(peer, STORAGE_SERVICE),
        {"Command": COMMAND},
        args.request_timeout,
    )
    return summarize(build, response)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument("--expected-build", required=True)
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument("--concurrency", type=int, default=512)
    args = parser.parse_args()
    if not args.host or not args.interface:
        parser.error(
            "set --host/--interface or T2_TOUCHID_HOST/T2_TOUCHID_INTERFACE"
        )
    if not 1 <= args.concurrency <= 2048:
        parser.error("--concurrency must be between 1 and 2048")
    if args.probe_timeout <= 0 or args.request_timeout <= 0:
        parser.error("timeouts must be positive")

    try:
        result = asyncio.run(inventory(args))
    except (OSError, RuntimeError, asyncio.TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
