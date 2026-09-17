#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed admission checks for legacy prepared transport updates."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_completed_native_install",
    ROOT / "tools/validate-completed-native-install.py",
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class CompletedNativeInstallTests(unittest.TestCase):
    def validate(self, *, generation="a" * 64,
                 validated_generation="a" * 64, enabled=True,
                 selected_matches=True):
        mapping = SimpleNamespace(
            enabled=enabled,
            linux_uid=1000,
            apple_uid=501,
        )
        mappings = SimpleNamespace(
            generation=generation,
            mappings=(mapping,),
        )
        validated_mapping = mapping if selected_matches else SimpleNamespace()
        native = SimpleNamespace(
            _load_provisioned_authority=mock.Mock(
                return_value=(
                    SimpleNamespace(generation=validated_generation),
                    validated_mapping,
                    SimpleNamespace(),
                )
            )
        )
        with (
            mock.patch.object(VALIDATOR.os, "geteuid", return_value=0),
            mock.patch.object(VALIDATOR, "_private_root_directory", return_value=True),
            mock.patch.object(VALIDATOR.t2_user_mapping, "load", return_value=mappings),
            mock.patch.object(VALIDATOR, "_native_enrollment_module", return_value=native),
        ):
            return VALIDATOR.validate(Path("/var/lib/t2-touchid"))

    def test_accepts_only_completed_enabled_consistent_authority(self):
        self.assertTrue(self.validate())
        self.assertFalse(self.validate(validated_generation="b" * 64))
        self.assertFalse(self.validate(enabled=False))
        self.assertFalse(self.validate(selected_matches=False))

    def test_requires_root_and_an_absolute_private_state_root(self):
        with mock.patch.object(VALIDATOR.os, "geteuid", return_value=1000):
            self.assertFalse(VALIDATOR.validate(Path("/var/lib/t2-touchid")))
        with mock.patch.object(VALIDATOR.os, "geteuid", return_value=0):
            self.assertFalse(VALIDATOR.validate(Path("relative")))

    def test_accepts_private_btrfs_directory_with_one_link(self):
        info = SimpleNamespace(st_mode=0o040700, st_uid=0, st_gid=0, st_nlink=1)
        with mock.patch.object(Path, "stat", return_value=info):
            self.assertTrue(
                VALIDATOR._private_root_directory(Path("/var/lib/t2-touchid"))
            )


if __name__ == "__main__":
    unittest.main()
