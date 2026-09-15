# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'src'))
import t2_aks_provisioning_transport as transport


class CreateVersionTests(unittest.TestCase):
    def test_loaded_module_selects_version(self):
        owner = object.__new__(transport.AKSProvisioningTransport)
        for version in (4, 5):
            with patch.object(Path, 'read_text', return_value=f'{version}\n'):
                self.assertEqual(owner.create_version, version)

    def test_only_missing_parameter_uses_legacy_version(self):
        owner = object.__new__(transport.AKSProvisioningTransport)
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError):
            self.assertEqual(owner.create_version, 5)
        with patch.object(Path, 'read_text', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                _ = owner.create_version
        for invalid in ('', '3\n', '6\n', '4 5\n', '04\n'):
            with patch.object(Path, 'read_text', return_value=invalid):
                with self.assertRaises(transport.AKSProvisioningTransportError):
                    _ = owner.create_version
