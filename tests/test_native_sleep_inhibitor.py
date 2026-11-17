# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
spec = importlib.util.spec_from_file_location("native_inhibitor_test", SOURCE / "t2-native-enroll.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeSleepInhibitorTests(unittest.TestCase):
    def setUp(self):
        self.check = native._sleep_inhibitor_is_registered
        self.process = SimpleNamespace(pid=4242, poll=mock.Mock(return_value=None))
        self.row = ["sleep", "t2-touchid-native-enrollment", "fixture", "block", 0, 4242]

    def registered(self, rows=None, *, document=None, status=0):
        if document is None:
            document = {"type": "a(ssssuu)", "data": [rows if rows is not None else [self.row]]}
        result = subprocess.CompletedProcess([], status, stdout=json.dumps(document).encode())
        with mock.patch.object(native.subprocess, "run", return_value=result) as run:
            answer = self.check(self.process)
        if self.process.poll.return_value is None:
            self.assertEqual(run.call_args.args[0][-1], "ListInhibitors")
            self.assertNotIn("--list", run.call_args.args[0])
        return answer

    def test_own_live_block_inhibitor_is_registered(self):
        self.assertTrue(self.registered())

    def test_other_inhibitor_is_not_authority(self):
        for index, value in [(0, "shutdown"), (1, "other"), (3, "delay"), (5, 4243)]:
            row = list(self.row)
            row[index] = value
            with self.subTest(index=index): self.assertFalse(self.registered([row]))

    def test_dead_process_rejected_without_query(self):
        self.process.poll.return_value = 1
        self.assertFalse(self.registered())

    def test_process_exits_during_query(self):
        self.process.poll.side_effect = [None, 1]
        self.assertFalse(self.registered())

    def test_failed_query_rejected(self):
        self.assertFalse(self.registered(status=1))

    def test_invalid_json_rejected(self):
        with mock.patch.object(native.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"bad")):
            self.assertFalse(self.check(self.process))

    def test_malformed_signature_or_container_rejected(self):
        for d in [[], {}, {"type": "a(ssssuu)", "data": []},
                  {"type": "a(ssssuu)", "data": [[] , []]},
                  {"type": "s", "data": [[self.row]]}]:
            with self.subTest(document=d): self.assertFalse(self.registered(document=d))

    def test_malformed_rows_rejected(self):
        for row in [[], {}, self.row[:-1], self.row + [1], self.row[:5] + [True],
                    self.row[:4] + [-1, 4242]]:
            with self.subTest(row=row): self.assertFalse(self.registered([row]))


class ManagementSleepInhibitorTests(NativeSleepInhibitorTests):
    def setUp(self):
        super().setUp()
        spec = importlib.util.spec_from_file_location("management_inhibitor_test", SOURCE / "t2-touchid-manage.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.check = module._sleep_inhibitor_registered
        self.row[1] = "t2-touchid-management"


if __name__ == "__main__":
    unittest.main()
