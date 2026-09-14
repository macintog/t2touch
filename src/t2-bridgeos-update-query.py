#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read the bridgeOS update state over the T2 link without mutating it."""

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from t2_rsd import discover_peer, service_port


SERVICE_NAME = "com.apple.bridgeOSUpdated"
COMMAND = "QueryUpdateState"
PUBLIC_FIELDS = (
    "CurrentOSBuildVersion",
    "UpdateState",
    "UpdateOperation",
    "UpdateOperationResult",
    "PreviousUpdateState",
    "PreviousUpdateDate",
    "PreviousRestoreDate",
)


def public_results(results: dict[str, Any]) -> dict[str, Any]:
    """Select only non-identifying state fields in a stable order."""

    return {key: results[key] for key in PUBLIC_FIELDS if key in results}


async def query(args: argparse.Namespace) -> dict[str, Any]:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    scoped_host, peer = await discover_peer(
        args.host, args.interface, args.probe_timeout, args.concurrency
    )
    port = service_port(peer, SERVICE_NAME)
    connection = RemoteXPCConnection((scoped_host, port))
    try:
        await asyncio.wait_for(connection.connect(), args.request_timeout)
        response = await asyncio.wait_for(
            connection.send_receive_request({"Command": COMMAND}),
            args.request_timeout,
        )
    finally:
        await connection.close()

    if response.get("Response") != COMMAND:
        raise RuntimeError("bridgeOS returned an unexpected response")
    results = response.get("Results")
    if not isinstance(results, dict):
        raise RuntimeError("bridgeOS update-state response has no Results")
    selected = public_results(results)
    if "CurrentOSBuildVersion" not in selected:
        raise RuntimeError("bridgeOS update-state response has no build version")
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument("--concurrency", type=int, default=512)
    parser.add_argument("--json", action="store_true")
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
        results = asyncio.run(query(args))
    except (OSError, RuntimeError, asyncio.TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

    if args.json:
        print(json.dumps(results, default=str, sort_keys=True))
    else:
        for key, value in results.items():
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
