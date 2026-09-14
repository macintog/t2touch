#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import os
import pwd
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import t2_keybag_loader as loader


class KeybagLoaderTests(unittest.TestCase):
    def test_resolve_uses_validated_authority_keybag(self) -> None:
        selected = SimpleNamespace(
            keybag_path="/var/lib/t2-touchid/users/1000/user.kb"
        )
        with (
            mock.patch.object(os, "geteuid", return_value=0),
            mock.patch.object(loader, "_configuration", return_value="tester"),
            mock.patch.object(
                pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_uid=1000),
            ),
            mock.patch.object(
                loader.t2_user_authority,
                "load_compatibility",
                return_value=SimpleNamespace(selected=selected),
            ) as load,
        ):
            result = loader.resolve()
        self.assertEqual(result, Path(selected.keybag_path))
        load.assert_called_once_with(1000)


if __name__ == "__main__":
    unittest.main()
