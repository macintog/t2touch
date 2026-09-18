# SPDX-License-Identifier: GPL-2.0-only
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "retire_sleep", Path(__file__).resolve().parents[1] / "tools/retire-sleep-policy.py"
)
RETIRE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETIRE)


class RetireSleepPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "90-t2-touchid-s2idle.conf"
        self.backup = self.path.with_name(self.path.name + ".t2touch-retired")
        self.output = io.StringIO()

    def retire(self):
        with contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output):
            RETIRE.retire(self.path)

    def test_exact_policy_archived_and_repeated_migration_safe(self):
        self.path.write_bytes(RETIRE.LEGACY)
        self.retire()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.backup.read_bytes(), RETIRE.LEGACY)
        self.assertIn("may select deep", self.output.getvalue())
        self.retire()
        # An older installer may recreate the exact file after migration.
        self.path.write_bytes(RETIRE.LEGACY)
        self.retire()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.backup.read_bytes(), RETIRE.LEGACY)

    def test_modified_file_is_preserved(self):
        changed = RETIRE.LEGACY + b"# operator change\n"
        self.path.write_bytes(changed)
        self.retire()
        self.assertEqual(self.path.read_bytes(), changed)
        self.assertFalse(self.backup.exists())
        self.assertIn("WARNING", self.output.getvalue())

    def test_symlink_including_dangling_link_is_preserved(self):
        target = self.path.parent / "operator.conf"
        self.path.symlink_to(target)
        self.retire()
        self.assertTrue(self.path.is_symlink())
        target.write_bytes(RETIRE.LEGACY)
        self.retire()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_bytes(), RETIRE.LEGACY)

    def test_hardlink_and_unexpected_owner_are_preserved(self):
        self.path.write_bytes(RETIRE.LEGACY)
        other = self.path.parent / "other"
        os.link(self.path, other)
        self.retire()
        self.assertTrue(self.path.exists())
        other.unlink()
        with mock.patch.object(RETIRE.os, "geteuid", return_value=os.geteuid() + 1):
            self.retire()
        self.assertTrue(self.path.exists())

    def test_conflicting_backup_or_backup_symlink_is_preserved(self):
        self.path.write_bytes(RETIRE.LEGACY)
        self.backup.write_text("operator backup")
        self.retire()
        self.assertEqual(self.backup.read_text(), "operator backup")
        self.assertTrue(self.path.exists())
        self.backup.unlink()
        self.backup.symlink_to(self.path)
        self.retire()
        self.assertTrue(self.path.exists())
        self.assertTrue(self.backup.is_symlink())

    def test_failed_archive_does_not_remove_policy(self):
        self.path.write_bytes(RETIRE.LEGACY)
        with mock.patch.object(RETIRE.os, "link", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                self.retire()
        self.assertEqual(self.path.read_bytes(), RETIRE.LEGACY)

    def test_interrupted_archive_completes_on_retry(self):
        self.path.write_bytes(RETIRE.LEGACY)
        with mock.patch.object(Path, "unlink", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                self.retire()
        self.assertEqual(self.path.stat().st_nlink, 2)
        self.assertEqual(self.path.stat().st_ino, self.backup.stat().st_ino)
        self.retire()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.backup.read_bytes(), RETIRE.LEGACY)
        self.assertEqual(self.backup.stat().st_nlink, 1)

    def test_interrupted_archive_with_extra_link_is_preserved(self):
        self.path.write_bytes(RETIRE.LEGACY)
        os.link(self.path, self.backup)
        other = self.path.parent / "operator-link"
        os.link(self.path, other)
        self.retire()
        self.assertTrue(self.path.exists())
        self.assertEqual(other.read_bytes(), RETIRE.LEGACY)
        self.assertIn("WARNING", self.output.getvalue())

    def test_interrupted_archive_modified_before_retry_is_preserved(self):
        self.path.write_bytes(RETIRE.LEGACY)
        os.link(self.path, self.backup)
        changed = RETIRE.LEGACY + b"# operator change after interruption\n"
        self.path.write_bytes(changed)
        self.retire()
        self.assertEqual(self.path.read_bytes(), changed)
        self.assertEqual(self.backup.read_bytes(), changed)
        self.assertIn("WARNING", self.output.getvalue())
