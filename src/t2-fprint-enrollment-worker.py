#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private systemd transient-service entry point for native enrollment."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import t2_fprint_worker


def _exception_classes(error: BaseException) -> str:
    names: list[str] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(names) < 6:
        seen.add(id(current))
        name = type(current).__name__
        names.append(name if name.isidentifier() else "Exception")
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else None
    return ">".join(names)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True, type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        print("t2-fprint-enrollment-worker must run as root", file=sys.stderr)
        return 2
    try:
        with t2_fprint_worker.connect_endpoint(arguments.endpoint) as connection:
            t2_fprint_worker.serve_once(connection)
    except Exception as error:
        stage = getattr(error, "stage", "outside-request")
        if not isinstance(stage, str) or not stage.replace("-", "").isalpha():
            stage = "outside-request"
        print(
            "t2-fprint-enrollment-worker: enrollment stopped "
            f"stage={stage} classes={_exception_classes(error)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
