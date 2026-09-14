#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Request one normal bridgeOS reboot through restoreserviced.

This path sends only lowercase ``{"command": "reboot"}``.  It neither enters
recovery nor changes one-shot boot policy.  A root-private write-ahead journal,
an active independent observer, and an already armed host reboot are mandatory
because the T2 transition invalidates the live Linux transport generation.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, TextIO

from t2_rsd import discover_peer, service_port


RESTORE_SERVICE = "com.apple.RestoreRemoteServices.restoreserviced"
UPDATE_SERVICE = "com.apple.bridgeOSUpdated"


class TransitionOutcomeAmbiguous(RuntimeError):
    """The mutating request was sent but no authoritative reply arrived."""


def _open_journal(path: Path) -> TextIO:
    if not path.is_absolute():
        raise RuntimeError("journal path must be absolute")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)


def _append(journal: TextIO, event: str, **fields: Any) -> None:
    record = {
        "event": event,
        "host_boot_id": Path("/proc/sys/kernel/random/boot_id")
        .read_text(encoding="ascii")
        .strip(),
        "monotonic_ns": time.monotonic_ns(),
        **fields,
    }
    journal.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    journal.flush()
    os.fsync(journal.fileno())


def _require_active(unit: str, purpose: str) -> None:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{purpose} unit {unit} is not active")


async def _current_build(
    scoped_host: str, peer: dict[str, Any], timeout: float
) -> str:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    connection = RemoteXPCConnection(
        (scoped_host, service_port(peer, UPDATE_SERVICE))
    )
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
            f"refusing reboot: expected build {args.expected_build}, got {build}"
        )

    print(f"bridgeOS build: {build}", flush=True)
    print("restore service: advertised", flush=True)
    if not args.execute:
        print("action: preflight only; no reboot request was sent")
        return

    if os.geteuid() != 0:
        raise RuntimeError("execution requires root for the protected journal")
    _require_active(args.observer_unit, "independent observer")
    _require_active(args.host_reboot_unit, "armed host reboot")

    with _open_journal(Path(args.journal)) as journal:
        _append(
            journal,
            "BRIDGEOS_NORMAL_REBOOT_INTENT",
            expected_build=args.expected_build,
            request={"command": "reboot"},
            retry_permitted=False,
        )
        connection = RemoteXPCConnection((scoped_host, restore_port))
        dispatched = False
        try:
            try:
                await asyncio.wait_for(connection.connect(), args.request_timeout)
            except Exception as error:
                _append(
                    journal,
                    "BRIDGEOS_NORMAL_REBOOT_CONNECTION_FAILED",
                    retry_permitted=False,
                )
                raise RuntimeError(
                    "restoreserviced connection failed before dispatch; "
                    "no reboot request was sent"
                ) from error
            try:
                _append(
                    journal,
                    "BRIDGEOS_NORMAL_REBOOT_DISPATCH",
                    retry_permitted=False,
                )
                dispatched = True
                response = await asyncio.wait_for(
                    connection.send_receive_request({"command": "reboot"}),
                    args.transition_timeout,
                )
            except Exception as error:
                _append(
                    journal,
                    "BRIDGEOS_NORMAL_REBOOT_AMBIGUOUS",
                    retry_permitted=False,
                )
                raise TransitionOutcomeAmbiguous(
                    "normal reboot request failed after dispatch; do not retry; "
                    "the armed host reboot and observer are authoritative"
                ) from error
        finally:
            try:
                await connection.close()
            except Exception:
                if not dispatched:
                    raise

        if not isinstance(response, dict) or response.get("result") != "success":
            _append(
                journal,
                "BRIDGEOS_NORMAL_REBOOT_UNEXPECTED_REPLY",
                retry_permitted=False,
            )
            raise TransitionOutcomeAmbiguous(
                "restoreserviced returned an unexpected reply after dispatch; "
                "do not retry"
            )
        _append(
            journal,
            "BRIDGEOS_NORMAL_REBOOT_CONFIRMED",
            result="success",
            retry_permitted=False,
        )
    print("action: restoreserviced confirmed normal T2 reboot; host reboot remains armed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument("--expected-build", required=True)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--observer-unit", required=True)
    parser.add_argument("--host-reboot-unit", required=True)
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument("--transition-timeout", type=float, default=15.0)
    parser.add_argument("--concurrency", type=int, default=512)
    parser.add_argument("--execute", action="store_true")
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
