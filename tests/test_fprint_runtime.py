# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_fprint_runtime as runtime


def projection(names=(), *, count=2, complete=False):
    return {
        "schema_version": 1,
        "finger_names": list(names),
        "reconciled_identity_count": count,
        "unassigned_identity_count": 0 if complete else count,
        "duplicate_finger_name_count": 0,
        "complete": complete,
        "finger_names_are_presentation_metadata": True,
        "identifiers_redacted": True,
    }


class FprintRuntimeTests(unittest.TestCase):
    def test_incomplete_projection_invents_no_compatibility_identity(self):
        view = runtime.parse_projection(projection())
        self.assertEqual(view.listed_fingers, ())
        with self.assertRaises(runtime.FprintRuntimeError):
            runtime.resolve_match(view, "finger-1")

    def test_complete_projection_lists_names_but_authenticates_against_all(self):
        view = runtime.parse_projection(
            projection(
                ("finger-1", "finger-2"),
                count=2,
                complete=True,
            )
        )
        self.assertEqual(
            view.listed_fingers,
            ("finger-1", "finger-2"),
        )
        request = runtime.resolve_match(view, "finger-1")
        self.assertTrue(request.match_all)
        self.assertIsNone(request.target_finger)

    def test_any_matches_all_but_is_never_a_private_target(self):
        view = runtime.parse_projection(
            projection(("finger-1",), count=1, complete=True)
        )
        request = runtime.resolve_match(view, "any")
        self.assertTrue(request.match_all)
        self.assertIsNone(request.target_finger)

    def test_duplicate_labels_are_validly_incomplete_and_never_listed(self):
        value = projection()
        value["unassigned_identity_count"] = 0
        value["duplicate_finger_name_count"] = 1
        view = runtime.parse_projection(value)
        self.assertFalse(view.complete)
        self.assertEqual(view.listed_fingers, ())

    def test_unenrolled_name_and_empty_inventory_fail(self):
        complete = runtime.parse_projection(
            projection(("finger-1",), count=1, complete=True)
        )
        empty = runtime.parse_projection(
            projection((), count=0, complete=True)
        )
        for view, requested in (
            (complete, "finger-2"),
            (empty, "any"),
            (empty, "finger-1"),
        ):
            with self.subTest(), self.assertRaises(runtime.FprintRuntimeError):
                runtime.resolve_match(view, requested)

    def test_malformed_or_incoherent_projection_fails(self):
        cases = []
        for key, value in (
            ("schema_version", 2),
            ("finger_names", ["any"]),
            ("reconciled_identity_count", True),
            ("identifiers_redacted", False),
            ("finger_names_are_presentation_metadata", False),
        ):
            candidate = projection()
            candidate[key] = value
            cases.append(candidate)
        partial = projection(("finger-1",))
        partial["unassigned_identity_count"] = 1
        cases.append(partial)
        wrong_order = projection(
            ("finger-2", "finger-1"),
            count=2,
            complete=True,
        )
        cases.append(wrong_order)
        extra = projection()
        extra["private_uuid"] = "forbidden"
        cases.append(extra)
        for candidate in cases:
            with self.subTest(), self.assertRaises(runtime.FprintRuntimeError):
                runtime.parse_projection(candidate)


if __name__ == "__main__":
    unittest.main()
