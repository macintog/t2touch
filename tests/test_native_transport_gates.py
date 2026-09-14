#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free transport gate derivation from native lifecycle state."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
import sys

sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_native_transport_gates", SOURCE / "t2-native-transport-gates.py"
)
GATES = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GATES)


class NativeTransportGateTests(unittest.TestCase):
    def test_lifecycle_gate_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = root / "users.json"
            provisioning = root / "native-provisioning.jsonl"
            replacement = root / "native-replacement.jsonl"
            selected = SimpleNamespace(enabled=False)
            mapping_set = SimpleNamespace(
                schema_version=GATES.t2_user_mapping.LEGACY_SCHEMA_VERSION,
                mappings=(selected,),
            )
            provision_state = SimpleNamespace(phase="mapping-committed")
            replacement_state = SimpleNamespace(phase="mapping-committed")
            common = (
                mock.patch.object(GATES, "MAPPING", mapping),
                mock.patch.object(GATES, "PROVISIONING_JOURNAL", provisioning),
                mock.patch.object(GATES, "REPLACEMENT_JOURNAL", replacement),
                mock.patch.object(
                    GATES.t2_user_mapping, "load", return_value=mapping_set
                ),
                mock.patch.object(
                    GATES.t2_aks_provisioning, "read", return_value=provision_state
                ),
                mock.patch.object(
                    GATES.t2_aks_replacement_journal,
                    "read",
                    return_value=replacement_state,
                ),
            )
            with common[0], common[1], common[2], common[3], common[4], common[5]:
                self.assertEqual(GATES.required_gates(), (True, True))
                mapping.touch(mode=0o600)
                provisioning.touch(mode=0o600)
                self.assertEqual(GATES.required_gates(), (False, True))
                mapping_set.schema_version = GATES.t2_user_mapping.SCHEMA_VERSION
                provision_state.phase = "mapping-enabled"
                replacement.touch(mode=0o600)
                self.assertEqual(GATES.required_gates(), (False, True))
                replacement_state.phase = "complete"
                self.assertEqual(GATES.required_gates(), (False, False))
                selected.enabled = True
                self.assertEqual(GATES.required_gates(), (False, False))
                replacement_state.phase = "mapping-committed"
                with self.assertRaisesRegex(
                    GATES.NativeTransportGateError, "enabled native authority"
                ):
                    GATES.required_gates()

    def test_loader_uses_typed_gate_resolver(self):
        loader = (SOURCE / "t2-sep-transport-load.sh").read_text(encoding="utf-8")
        self.assertIn("t2-native-transport-gates.py", loader)
        self.assertNotIn('grep -Eq \'"schema_version"', loader)


if __name__ == "__main__":
    unittest.main()
