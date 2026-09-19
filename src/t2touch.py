#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compatibility spelling; all behavior lives in the shared desktop client."""
import sys
from pathlib import Path

source = Path(__file__).resolve().parent
if not (source / "t2_touchid_cli.py").is_file():
    source = Path("/opt/t2-touchid/src")
sys.path.insert(0, str(source))
from t2_touchid_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
