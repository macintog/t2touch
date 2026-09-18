#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real-file regression tests for bounded BioLockout publication work."""

from concurrent.futures import ThreadPoolExecutor
import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

import t2_biolockout_store as store_module


class BioLockoutPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = store_module.BioLockoutStore(str(self.root))
        # Production requires root ownership. For ordinary non-root test runs,
        # change only the returned ownership field for our own temporary files;
        # real type, mode, link-count, length and read/write checks stay active.
        if os.geteuid() != 0:
            real_fstat = os.fstat

            def test_owner(descriptor):
                values = list(real_fstat(descriptor))
                values[4] = 0
                return os.stat_result(values)

            owner_patch = patch.object(store_module.os, "fstat", side_effect=test_owner)
            owner_patch.start()
            self.addCleanup(owner_patch.stop)

    @staticmethod
    def payload(value):
        return b"HRLB" + bytes([value]) * 20

    def test_commit_scans_history_once_regardless_of_history_size(self):
        for sequence in range(1, 2001):
            # Historical payloads are never needed to choose the next sequence.
            (self.root / f"generation-{sequence:020d}.hrlb").touch(mode=0o600)
        real_listdir = os.listdir
        with patch.object(store_module.os, "listdir", wraps=real_listdir) as listing:
            committed = self.store.commit(self.payload(1))
        self.assertEqual(listing.call_count, 1)
        self.assertEqual(committed.sequence, 2001)
        self.assertEqual(self.store.current(), committed)
        self.assertEqual(len(list(self.root.iterdir())), 2002)

    def test_publication_keeps_all_four_durability_flushes_and_order(self):
        operations = []
        real_fsync, real_rename = os.fsync, os.rename

        def synced(descriptor):
            kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
            operations.append(("fsync", kind))
            return real_fsync(descriptor)

        def renamed(source, destination, **kwargs):
            operations.append(("publish", Path(destination).suffix))
            return real_rename(source, destination, **kwargs)

        with (
            patch.object(store_module.os, "fsync", side_effect=synced),
            patch.object(store_module.os, "rename", side_effect=renamed),
        ):
            first = self.store.commit(self.payload(1))
        self.assertEqual(operations, [
            ("fsync", "file"), ("publish", ".hrlb"), ("fsync", "directory"),
            ("fsync", "file"), ("publish", ".json"), ("fsync", "directory"),
        ])
        second = self.store.commit(self.payload(2))
        self.assertEqual(second.sequence, first.sequence + 1)
        self.assertEqual(self.store.current(), second)
        self.assertEqual(len(list(self.root.iterdir())), 4)
        for path in self.root.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_names_include_dangling_symlinks(self):
        occupied = self.root / "occupied"
        occupied.symlink_to("absent")
        descriptor = self.store._open_root()
        try:
            self.assertTrue(self.store._name_exists(descriptor, "occupied"))
            self.assertFalse(self.store._name_exists(descriptor, "absent"))
        finally:
            os.close(descriptor)

    def test_unknown_lookup_error_does_not_mean_absent(self):
        with patch.object(store_module.os, "stat", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                self.store._name_exists(-1, "test")

    def test_blob_collision_after_scan_does_not_overwrite(self):
        original_write = self.store._write_private_file
        target = self.root / "generation-00000000000000000001.hrlb"

        def write_then_conflict(directory, name, payload):
            original_write(directory, name, payload)
            if name.endswith(".hrlb"):
                target.write_bytes(b"untouched")

        with patch.object(self.store, "_write_private_file", side_effect=write_then_conflict):
            with self.assertRaisesRegex(store_module.BioLockoutStoreError, "collision"):
                self.store.commit(self.payload(1))
        self.assertEqual(target.read_bytes(), b"untouched")
        self.assertFalse(any(p.name.startswith(".pending-") for p in self.root.iterdir()))

    def test_concurrent_commit_cannot_select_the_same_generation(self):
        first_writing = threading.Event()
        release_first = threading.Event()
        second_at_lock = threading.Event()
        real_flock = fcntl.flock
        original_write = self.store._write_private_file
        second_store = store_module.BioLockoutStore(str(self.root))
        second_thread = []

        def traced_flock(descriptor, operation):
            if second_thread and threading.get_ident() == second_thread[0]:
                second_at_lock.set()
            return real_flock(descriptor, operation)

        def pause_first(directory, name, payload):
            if name.endswith(".hrlb"):
                first_writing.set()
                if not release_first.wait(3):
                    raise AssertionError("test writer was not released")
            original_write(directory, name, payload)

        def second_commit():
            second_thread.append(threading.get_ident())
            return second_store.commit(self.payload(2))

        with (
            patch.object(store_module.fcntl, "flock", side_effect=traced_flock),
            patch.object(self.store, "_write_private_file", side_effect=pause_first),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(self.store.commit, self.payload(1))
            second = None
            try:
                self.assertTrue(first_writing.wait(2))
                second = executor.submit(second_commit)
                self.assertTrue(second_at_lock.wait(2))
                self.assertFalse(second.done())
            finally:
                release_first.set()
            first_generation = first.result(timeout=3)
            second_generation = second.result(timeout=3)
        self.assertEqual((first_generation.sequence, second_generation.sequence), (1, 2))
        self.assertEqual(self.store.current(), second_generation)
        self.assertEqual((self.root / "generation-00000000000000000001.hrlb").read_bytes(),
                         self.payload(1))

    def test_cleanup_failure_always_closes_descriptor_and_unlocks(self):
        descriptor = self.store._open_root()
        with (
            patch.object(self.store, "_open_root", return_value=descriptor),
            patch.object(self.store, "_write_private_file", side_effect=OSError("write failed")),
            patch.object(store_module.os, "unlink", side_effect=OSError("cleanup failed")),
        ):
            with self.assertRaisesRegex(OSError, "cleanup failed"):
                self.store.commit(self.payload(1))
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptor)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        replacement = self.store._open_root()
        try:
            fcntl.flock(replacement, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(replacement)

    def test_failure_before_manifest_keeps_previous_generation_and_skips_orphan(self):
        first = self.store.commit(self.payload(1))
        real_write = self.store._write_private_file

        def reject_manifest(directory, name, payload):
            if name.endswith(".json"):
                raise OSError("test manifest failure")
            return real_write(directory, name, payload)

        with patch.object(self.store, "_write_private_file", side_effect=reject_manifest):
            with self.assertRaises(OSError):
                self.store.commit(self.payload(2))
        self.assertEqual(self.store.current(), first)
        third = self.store.commit(self.payload(3))
        self.assertEqual(third.sequence, 3)
        self.assertEqual(self.store.current(), third)

    def test_corrupt_latest_generation_never_rolls_back(self):
        self.store.commit(self.payload(1))
        last = self.store.commit(self.payload(2))
        manifest = self.root / f"generation-{last.sequence:020d}.json"
        content = json.loads(manifest.read_text())
        content["sha256"] = "0" * 64
        manifest.write_text(json.dumps(content))
        with self.assertRaises(store_module.BioLockoutStoreError):
            self.store.current()


if __name__ == "__main__":
    unittest.main()
