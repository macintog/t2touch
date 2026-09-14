#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Discover the T2 BiometricKit BridgeXPC port through RemoteXPC.

Run this with the repository virtual environment, which installs
``pymobiledevice3``. Only the service port is printed; device identifiers from
the RemoteXPC peer record are never emitted.
"""

import argparse
import asyncio
import os
import sys

from t2_rsd import discover_peer, service_port

RSD_SERVICE = "com.apple.eos.BiometricKit"


async def main_async(args: argparse.Namespace) -> None:
    _scoped_host, peer = await discover_peer(
        args.host, args.interface, args.probe_timeout, args.concurrency
    )
    if args.list_services:
        for name in sorted(peer["Services"]):
            print(name)
        return
    print(service_port(peer, RSD_SERVICE))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--concurrency", type=int, default=512)
    parser.add_argument(
        "--list-services",
        action="store_true",
        help="print advertised service names without ports or device identifiers",
    )
    args = parser.parse_args()
    if not args.host or not args.interface:
        parser.error(
            "set --host/--interface or T2_TOUCHID_HOST/T2_TOUCHID_INTERFACE"
        )
    if not 1 <= args.concurrency <= 2048:
        parser.error("--concurrency must be between 1 and 2048")
    try:
        asyncio.run(main_async(args))
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
