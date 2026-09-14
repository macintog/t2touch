# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_fprint_projection as projection


def inventory(names):
    return {
        "schema_version": 1,
        "identity_count": len(names),
        "identities": [
            {"slot": slot, "name": name, "live": True}
            for slot, name in enumerate(names, 1)
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "finger_names_are_presentation_metadata": True,
        "identifiers_redacted": True,
    }


class FprintProjectionTests(unittest.TestCase):
    def test_complete_projection_uses_neutral_numeric_order(self):
        result = projection.project(
            inventory(["finger-2", "finger-1"])
        )
        self.assertTrue(result.complete)
        self.assertEqual(
            result.finger_names,
            ("finger-1", "finger-2"),
        )
        self.assertEqual(result.reconciled_identity_count, 2)
        self.assertEqual(result.unassigned_identity_count, 0)
        self.assertEqual(result.duplicate_finger_name_count, 0)

    def test_unknown_or_duplicate_label_never_produces_partial_listing(self):
        cases = (
            (["Finger 1", "finger-1"], 1, 0),
            (["finger-1", "finger-1"], 0, 1),
            (["right-index-finger", "Linux enrolled finger"], 2, 0),
        )
        for names, unassigned, duplicates in cases:
            with self.subTest(names=names):
                result = projection.project(inventory(names))
                self.assertFalse(result.complete)
                self.assertEqual(result.finger_names, ())
                self.assertEqual(result.unassigned_identity_count, unassigned)
                self.assertEqual(
                    result.duplicate_finger_name_count, duplicates
                )

    def test_projection_is_identifier_free_and_labels_are_not_authority(self):
        result = projection.project(inventory(["finger-1"]))
        rendered = json.dumps(result.public(), sort_keys=True)
        self.assertIn("finger_names_are_presentation_metadata", rendered)
        for forbidden in (
            "apple_uid",
            "linux_uid",
            "identity_uuid",
            "bag_uuid",
            "keybag",
            '"entity":',
        ):
            self.assertNotIn(forbidden, rendered)

    def test_malformed_or_nonreconciled_inventory_is_rejected(self):
        values = (None, inventory([]), inventory(["finger-1"]))
        values[1]["identity_count"] = 1
        values[2]["local_live_reconciled"] = False
        for value in values:
            with self.subTest(value=value), self.assertRaises(
                projection.FprintProjectionError
            ):
                projection.project(value)

    def test_neutral_handles_are_five_stable_slots_and_exclude_anatomy(self):
        self.assertEqual(
            projection.FINGER_NAMES,
            tuple(f"finger-{value}" for value in range(1, 6)),
        )
        self.assertTrue(projection.is_finger_name("finger-5"))
        self.assertFalse(projection.is_finger_name("finger-6"))
        self.assertFalse(projection.is_finger_name("finger-01"))
        self.assertFalse(projection.is_finger_name("right-index-finger"))
        self.assertFalse(projection.is_finger_name("any"))


if __name__ == "__main__":
    unittest.main()
