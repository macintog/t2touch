# SPDX-License-Identifier: GPL-2.0-only
"""Product command routing without hardware or system mutation."""

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2touch


class T2TouchCLITests(unittest.TestCase):
    def test_root_only_configuration_uses_the_calling_account(self):
        with (
            mock.patch.object(Path, "read_text", side_effect=PermissionError),
            mock.patch.object(t2touch.os, "geteuid", return_value=1000),
            mock.patch.object(
                t2touch.pwd,
                "getpwuid",
                return_value=SimpleNamespace(pw_name="mapped"),
            ),
        ):
            self.assertEqual(t2touch.configured_user(), "mapped")

    def test_delete_uses_standard_fprintd_for_one_numbered_slot(self):
        completed = SimpleNamespace(returncode=0)
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(
                t2touch.subprocess, "run", return_value=completed
            ) as run,
        ):
            self.assertEqual(t2touch.delete("mapped", "finger-5"), 0)
            run.assert_called_once_with(
                ["/usr/bin/fprintd-delete", "mapped", "-f", "finger-5"],
                check=False,
            )
            with self.assertRaisesRegex(t2touch.T2TouchError, "Finger N"):
                t2touch.delete("mapped", "right-index-finger")


if __name__ == "__main__":
    unittest.main()
