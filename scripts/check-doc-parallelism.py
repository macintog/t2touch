#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require the shared t2touch research bundle to be byte-identical."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


RESEARCH_ROOT = Path("docs/research")


def files_below(root: Path) -> dict[Path, Path]:
    return {
        path.relative_to(root): path
        for path in root.rglob("*")
        if path.is_file() and path.name != ".DS_Store"
    }


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "compare docs/research with the corresponding t2touch or "
            "t2touch-mini checkout"
        )
    )
    parser.add_argument(
        "--other",
        type=Path,
        help="counterpart repository root (defaults to the adjacent checkout)",
    )
    args = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    counterpart_name = "t2touch" if repository.name == "t2touch-mini" else "t2touch-mini"
    counterpart = (args.other or repository.parent / counterpart_name).resolve()
    local_root = repository / RESEARCH_ROOT
    other_root = counterpart / RESEARCH_ROOT
    if not local_root.is_dir() or not other_root.is_dir():
        parser.error(f"both research roots must exist: {local_root}, {other_root}")

    local_files = files_below(local_root)
    other_files = files_below(other_root)
    failures = []
    for relative in sorted(local_files.keys() | other_files.keys()):
        if relative not in local_files:
            failures.append(f"missing locally: {relative}")
        elif relative not in other_files:
            failures.append(f"missing from counterpart: {relative}")
        elif digest(local_files[relative]) != digest(other_files[relative]):
            failures.append(f"content differs: {relative}")

    if failures:
        print("Research documentation parallelism: FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Research documentation parallelism: PASS ({len(local_files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
