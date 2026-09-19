#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fixed entry point for the installed desktop command launchers."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from t2_touchid_cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[2:], command=sys.argv[1]))
