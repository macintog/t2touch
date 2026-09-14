#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_bridgeos_manifest as bridgeos


def identity(
    product: str,
    target: str,
    target_type: str,
    board: str,
    chip: str,
    sep_path: str,
) -> dict[str, object]:
    return {
        "Ap,ProductType": product,
        "Ap,Target": target,
        "Ap,TargetType": target_type,
        "ApBoardID": board,
        "ApChipID": chip,
        "Manifest": {"SEP": {"Info": {"Path": sep_path}}},
    }


def manifest(*identities: dict[str, object]) -> dict[str, object]:
    return {
        "ProductVersion": "10.6",
        "ProductBuildVersion": "23P6068",
        "BuildIdentities": list(identities),
    }


J152F = identity(
    "iBridge2,14",
    "J152fAP",
    "j152f",
    "0x3a",
    "0x8012",
    "Firmware/all_flash/sep-firmware.j152f.RELEASE.im4p",
)


class BridgeOSManifestTests(unittest.TestCase):
    def test_parses_reference_identity_without_model_allowlist(self):
        parsed = bridgeos.parse_build_manifest(manifest(J152F))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].product_type, "iBridge2,14")
        self.assertEqual(parsed[0].board_id, "0x3A")
        self.assertEqual(parsed[0].bridge_generation, "2")

    def test_collapses_identical_restore_and_update_identities(self):
        parsed = bridgeos.parse_build_manifest(manifest(J152F, dict(J152F)))
        self.assertEqual(len(parsed), 1)

    def test_parser_is_generation_neutral(self):
        hypothetical_t1 = identity(
            "iBridge1,1", "J42dAP", "j42d", "0x01", "0x7000",
            "Firmware/sep-firmware.j42d.RELEASE.im4p",
        )
        parsed = bridgeos.parse_build_manifest(manifest(hypothetical_t1))
        self.assertEqual(parsed[0].bridge_generation, "1")

    def test_exact_selectors_do_not_fall_back_to_another_board(self):
        other = identity(
            "iBridge2,1", "J137AP", "j137", "0x0A", "0x8012",
            "Firmware/all_flash/sep-firmware.j137.RELEASE.im4p",
        )
        parsed = bridgeos.parse_build_manifest(manifest(J152F, other))
        selected = bridgeos.select_identities(
            parsed, product_type="iBridge2,14", target_type="j152f", board_id="0x3a"
        )
        self.assertEqual(selected, (parsed[1],))
        with self.assertRaisesRegex(bridgeos.ManifestError, "no firmware identity"):
            bridgeos.select_identities(parsed, product_type="iBridge2,99")

    def test_conflicting_duplicate_is_rejected(self):
        conflict = dict(J152F)
        conflict["Manifest"] = {"SEP": {"Info": {"Path": "wrong.im4p"}}}
        with self.assertRaisesRegex(bridgeos.ManifestError, "conflicting duplicate"):
            bridgeos.parse_build_manifest(manifest(J152F, conflict))

    def test_missing_sep_is_rejected(self):
        broken = dict(J152F)
        broken["Manifest"] = {}
        with self.assertRaisesRegex(bridgeos.ManifestError, "SEP component"):
            bridgeos.parse_build_manifest(manifest(broken))

    def test_invalid_bridge_product_is_rejected(self):
        broken = dict(J152F)
        broken["Ap,ProductType"] = "MacBookPro16,1"
        with self.assertRaisesRegex(bridgeos.ManifestError, "bridge product"):
            bridgeos.parse_build_manifest(manifest(broken))

    def test_public_output_contains_no_manifest_private_data(self):
        value = bridgeos.parse_build_manifest(manifest(J152F))[0].public_dict()
        self.assertEqual(value["build_version"], "23P6068")
        self.assertEqual(value["sep_path"], J152F["Manifest"]["SEP"]["Info"]["Path"])
        self.assertEqual(set(value), {
            "product_type", "target", "target_type", "board_id", "chip_id",
            "product_version", "build_version", "sep_path", "bridge_generation",
        })


if __name__ == "__main__":
    unittest.main()
