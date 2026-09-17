#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class L9ExposureTests(unittest.TestCase):
    def test_account_generation_is_hmac_or_omitted(self):
        source = (ROOT / "src/t2_polkit_grant.py").read_text(encoding="utf-8")
        self.assertIn("def _account_generation_detail", source)
        self.assertIn("polkit-detail.key", source)
        self.assertIn("hmac.new", source)

    def test_broker_prints_exception_class_names_only(self):
        source = (ROOT / "src/t2-user-activation-broker.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("causes.append(type(current).__name__)", source)
        self.assertNotIn("message[:240]", source)


if __name__ == "__main__":
    unittest.main()
