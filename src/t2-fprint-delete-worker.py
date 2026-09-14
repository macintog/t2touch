#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private transient-service entry point for one native fprint deletion."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import t2_fprint_delete_worker


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True, type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        print("t2-fprint-delete-worker must run as root", file=sys.stderr)
        return 2
    try:
        with t2_fprint_delete_worker.connect_endpoint(
            arguments.endpoint
        ) as connection:
            t2_fprint_delete_worker.serve_once(connection)
    except Exception as error:
        print(json.dumps(t2_fprint_delete_worker.failure_diagnostic(error),
                         sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
