#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Persist identifier-free USB and carrier transitions during a T2 reboot."""

import argparse
import json
import os
from pathlib import Path
import signal
import time


APPLE_VENDOR = "05ac"
BOOTED_T2_PRODUCT = "8233"


def booted_t2_present() -> bool:
    for vendor_path in Path("/sys/bus/usb/devices").glob("*/idVendor"):
        try:
            if vendor_path.read_text(encoding="ascii").strip().lower() != APPLE_VENDOR:
                continue
            product = vendor_path.with_name("idProduct").read_text(
                encoding="ascii"
            )
            if product.strip().lower() == BOOTED_T2_PRODUCT:
                return True
        except (FileNotFoundError, OSError):
            continue
    return False


def carrier(interface: str) -> str:
    try:
        return Path(f"/sys/class/net/{interface}/carrier").read_text(
            encoding="ascii"
        ).strip()
    except (FileNotFoundError, OSError):
        return "absent"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--duration", type=float, default=45.0)
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    output = Path(args.output)
    if not output.is_absolute():
        parser.error("--output must be absolute")
    if args.duration <= 0 or args.interval <= 0:
        parser.error("duration and interval must be positive")

    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    stop = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    started = time.monotonic()
    prior: tuple[bool, str] | None = None
    with os.fdopen(descriptor, "w", encoding="utf-8", buffering=1) as stream:
        while not stop and time.monotonic() - started <= args.duration:
            state = (booted_t2_present(), carrier(args.interface))
            if state != prior:
                record = {
                    "booted_t2_present": state[0],
                    "carrier": state[1],
                    "host_boot_id": Path("/proc/sys/kernel/random/boot_id")
                    .read_text(encoding="ascii")
                    .strip(),
                    "monotonic_ns": time.monotonic_ns(),
                }
                stream.write(
                    json.dumps(record, sort_keys=True, separators=(",", ":"))
                    + "\n"
                )
                stream.flush()
                os.fsync(stream.fileno())
                prior = state
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
