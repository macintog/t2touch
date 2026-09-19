# SPDX-License-Identifier: GPL-2.0-only
"""Retirement preserves unknown files and survives an interrupted archive."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "retire_path_tools", Path(__file__).parents[1] / "tools/retire-path-tools.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RetirePathToolsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / "sbin"
        self.prefix.mkdir()
        self.archive = self.root / "retired"
        self.content = b"#!/bin/sh\n# known historical tool\n"
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.tools = {"t2-old": {"sha256": {self.digest: {}}}}
        self.path = self.prefix / "t2-old"
        self.path.write_bytes(self.content)
        # Production checks all ancestors. Tests trust only the temporary root
        # supplied by the fixture, while retaining the real checks beneath it.
        original = MODULE.safe_directory
        def checked(path, owner, *, create=False):
            if path == self.root:
                return
            return original(path, owner, create=create)
        patcher = mock.patch.object(MODULE, "safe_directory", side_effect=checked)
        patcher.start()
        self.addCleanup(patcher.stop)

    def retire(self, apply=True):
        return MODULE.retire(self.prefix, self.archive, self.tools,
                             apply=apply, owner=os.getuid())

    def test_only_recognized_bytes_are_archived_and_audit_is_read_only(self):
        self.assertEqual(self.retire(False)[0]["status"], "would-archive")
        self.assertTrue(self.path.exists())
        self.assertFalse(self.archive.exists())
        unrelated = self.prefix / "t2-other"
        unrelated.write_bytes(self.content)
        result = self.retire()
        self.assertEqual(result[0]["status"], "archived")
        self.assertFalse(self.path.exists())
        self.assertEqual(Path(result[0]["archive"]).read_bytes(), self.content)
        self.assertTrue(unrelated.exists())
        self.assertEqual(self.retire(), [])

    def test_unknown_modified_symlink_and_hardlink_files_are_preserved(self):
        self.path.write_bytes(b"local edit")
        self.assertEqual(self.retire()[0]["status"], "preserved-unrecognized-content")
        self.assertEqual(self.path.read_bytes(), b"local edit")
        self.path.unlink()
        target = self.root / "target"
        target.write_bytes(self.content)
        self.path.symlink_to(target)
        self.assertEqual(self.retire()[0]["status"], "preserved-ownership-conflict")
        self.assertTrue(self.path.is_symlink())
        self.path.unlink()
        os.link(target, self.path)
        self.assertEqual(self.retire()[0]["status"], "preserved-ownership-conflict")
        self.assertTrue(self.path.exists())

    def test_interrupted_archive_never_deletes_original_or_overwrites_evidence(self):
        generation = self.archive / self.digest
        generation.mkdir(parents=True)
        retained = generation / self.path.name
        retained.write_bytes(b"interrupted partial copy")
        with self.assertRaisesRegex(RuntimeError, "archive differs"):
            self.retire()
        self.assertEqual(self.path.read_bytes(), self.content)
        self.assertEqual(retained.read_bytes(), b"interrupted partial copy")
        retained.write_bytes(self.content)
        self.assertEqual(self.retire()[0]["status"], "archived")
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
