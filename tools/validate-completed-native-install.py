#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate durable proof that Linux-native setup previously completed."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import t2_user_mapping  # noqa: E402


def _native_enrollment_module():
    path = ROOT / "src/t2-native-enroll.py"
    specification = importlib.util.spec_from_file_location(
        "t2_completed_install_authority", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("native authority validator is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _private_root_directory(path: Path) -> bool:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and info.st_gid == 0
        and not info.st_mode & 0o077
    )


def validate(state_root: Path) -> bool:
    if os.geteuid() != 0 or not state_root.is_absolute():
        return False
    if not _private_root_directory(state_root):
        return False
    try:
        mappings = t2_user_mapping.load(state_root / "users.json")
        if len(mappings.mappings) != 1 or not mappings.mappings[0].enabled:
            return False
        selected = mappings.mappings[0]
        native = _native_enrollment_module()
        native.STATE_ROOT = state_root
        native.MAPPING = state_root / "users.json"
        native.PROVISIONING_JOURNAL = state_root / "native-provisioning.jsonl"
        native.REPLACEMENT_JOURNAL = state_root / "native-replacement.jsonl"
        native.REPLACEMENT_ACTIVATION_JOURNAL = (
            state_root / "native-replacement-activation.jsonl"
        )
        validated, validated_selected, _history = native._load_provisioned_authority(
            selected.linux_uid, selected.apple_uid
        )
    except (OSError, RuntimeError, t2_user_mapping.UserMappingError, ValueError):
        return False
    return (
        validated.generation == mappings.generation
        and validated_selected == selected
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/t2-touchid")
    )
    args = parser.parse_args()
    raise SystemExit(0 if validate(args.state_root) else 1)


if __name__ == "__main__":
    main()
