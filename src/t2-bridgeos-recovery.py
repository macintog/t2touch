#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Enter T2 iBoot recovery through the advertised restoreserviced endpoint.

Without ``--execute`` this performs only a build/service preflight. Execution
changes the T2 one-shot boot policy and causes restoreserviced to reboot the T2
about three seconds after replying. It does not start a restore or revive.
"""

import argparse
import asyncio
import os
import subprocess
import sys
from typing import Any

from t2_rsd import discover_peer, service_port


RESTORE_SERVICE = "com.apple.RestoreRemoteServices.restoreserviced"
UPDATE_SERVICE = "com.apple.bridgeOSUpdated"


class TransitionOutcomeAmbiguous(RuntimeError):
    """The mutating request was sent but no authoritative reply arrived."""


async def _current_build(
    scoped_host: str, peer: dict[str, Any], timeout: float
) -> str:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    port = service_port(peer, UPDATE_SERVICE)
    connection = RemoteXPCConnection((scoped_host, port))
    try:
        await asyncio.wait_for(connection.connect(), timeout)
        response = await asyncio.wait_for(
            connection.send_receive_request({"Command": "QueryUpdateState"}),
            timeout,
        )
    finally:
        await connection.close()
    if not isinstance(response, dict) or response.get("Response") != "QueryUpdateState":
        raise RuntimeError("bridgeOS returned an unexpected update-state response")
    results = response.get("Results")
    if not isinstance(results, dict):
        raise RuntimeError("bridgeOS update-state response has no Results")
    build = results.get("CurrentOSBuildVersion")
    if not isinstance(build, str) or not build:
        raise RuntimeError("bridgeOS update-state response has no build version")
    return build


async def run(args: argparse.Namespace) -> None:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    scoped_host, peer = await discover_peer(
        args.host, args.interface, args.probe_timeout, args.concurrency
    )
    restore_port = service_port(peer, RESTORE_SERVICE)
    build = await _current_build(scoped_host, peer, args.request_timeout)
    if build != args.expected_build:
        raise RuntimeError(
            f"refusing recovery: expected build {args.expected_build}, got {build}"
        )

    print(f"bridgeOS build: {build}")
    print(f"restore service: advertised (dynamic port {restore_port})")
    if not args.execute:
        print("action: preflight only; T2 boot policy was not changed")
        return

    observer = subprocess.run(
        ["systemctl", "is-active", "--quiet", args.observer_unit],
        check=False,
    )
    if observer.returncode != 0:
        raise RuntimeError(
            f"refusing recovery: observer unit {args.observer_unit} is not active"
        )

    connection = RemoteXPCConnection((scoped_host, restore_port))
    try:
        await asyncio.wait_for(connection.connect(), args.request_timeout)
        try:
            response = await asyncio.wait_for(
                connection.send_receive_request({"command": "recovery"}),
                args.transition_timeout,
            )
        except asyncio.TimeoutError as error:
            raise TransitionOutcomeAmbiguous(
                "recovery request timed out after it was sent; do not retry; "
                "use the independent USB observer as the authority"
            ) from error
    finally:
        await connection.close()

    if not isinstance(response, dict) or response.get("result") != "success":
        raise RuntimeError("restoreserviced did not confirm recovery")
    print("action: restoreserviced confirmed one-shot recovery; T2 reboot pending")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument("--expected-build", required=True)
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument("--transition-timeout", type=float, default=30.0)
    parser.add_argument("--concurrency", type=int, default=512)
    parser.add_argument(
        "--observer-unit",
        default="t2-recovery-usb-observer.service",
        help="active systemd unit independently observing recovery USB",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="set one-shot recovery policy and reboot the T2",
    )
    args = parser.parse_args()
    if not args.host or not args.interface:
        parser.error(
            "set --host/--interface or T2_TOUCHID_HOST/T2_TOUCHID_INTERFACE"
        )
    if not 1 <= args.concurrency <= 2048:
        parser.error("--concurrency must be between 1 and 2048")
    if (
        args.probe_timeout <= 0
        or args.request_timeout <= 0
        or args.transition_timeout <= 0
    ):
        parser.error("timeouts must be positive")

    try:
        asyncio.run(run(args))
    except TransitionOutcomeAmbiguous as error:
        print(f"outcome-ambiguous: {error}", file=sys.stderr)
        raise SystemExit(3)
    except (OSError, RuntimeError, asyncio.TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
