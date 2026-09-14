# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

from dataclasses import replace
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_fprint_deletion_runtime as runtime


class FprintDeletionRuntimeTests(unittest.TestCase):
    def test_exact_reconciled_completion_is_accepted(self):
        value = runtime.DeletionCompletion(
            "finger-2", True, True, False, True
        )
        self.assertEqual(value.finger_name, "finger-2")
        self.assertTrue(value.reconciled)

    def test_invalid_name_or_incomplete_proof_is_rejected(self):
        valid = runtime.DeletionCompletion(
            "finger-2", True, True, False, True
        )
        candidates = (
            ("any", True, True, False, True),
            ("finger-2", False, True, False, True),
            ("finger-2", True, False, False, True),
            ("finger-2", True, True, True, True),
            ("finger-2", True, True, False, False),
            ("finger-2", 1, True, False, True),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                runtime.FprintDeletionRuntimeError
            ):
                runtime.DeletionCompletion(*candidate)
        with self.assertRaises(runtime.FprintDeletionRuntimeError):
            replace(valid, post_reboot_pending=True)


if __name__ == "__main__":
    unittest.main()
