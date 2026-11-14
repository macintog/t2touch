# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "src/t2-touchid-inventory.py"
SPEC = importlib.util.spec_from_file_location("t2_touchid_inventory", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def reply(status=0):
    return {"valid": True, "status": status}


def stable_probe(identity_count=2):
    return {
        "biometric_protocol_reply": reply(),
        "biometric_protocol_version": 2,
        "biometric_protocol_v2_attested": True,
        "identity_list_reply": reply(),
        "identity_record_count": identity_count,
        "identity_record_bytes_valid": True,
        "identity_user_field": "prefix" if identity_count else None,
        "identity_inventory_repeat_equal": True,
        "global_identity_list_reply": reply(),
        "global_identity_record_bytes_valid": True,
        "global_identity_record_count": identity_count,
        "configured_identity_records_reconciled": True,
        "global_identity_inventory_repeat_equal": True,
        "identity_capacity_reply": reply(),
        "identity_free_count_reply": reply(),
        "identity_maximum_capacity": 5,
        "identity_free_count": 5 - identity_count,
        "identity_capacity_repeat_equal": True,
        "catacomb_uuid_reply": reply(),
        "catacomb_hash_reply": reply(),
        "catacomb_uuid_length_valid": True,
        "catacomb_hash_length_valid": True,
        "catacomb_component_present": bool(identity_count),
        "catacomb_component_repeat_equal": True,
        "catacomb_state_repeat_equal": True,
        "sks_lock_state_repeat_equal": True,
        "full_snapshot_repeat_equal": True,
    }


def preclient_probe(**overrides):
    value = {
        "schema_version": 1,
        "mode": "preclient-inventory",
        "diagnostic_contract": "pre-authority-v1",
        "state": "absent-baseline",
        "biometric_protocol_version": 2,
        "biometric_protocol_attestation": "v2-global-identity-command",
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "maximum_identity_capacity": 5,
        "configured_user_free_capacity": 5,
        "catacomb_uuid_present": False,
        "catacomb_component_present": False,
        "catacomb_master_state": 1,
        "selected_user_component_present": False,
        "catacomb_state_word_count": 2,
        "sks_lock_state_raw": 21,
        "double_collection_equal": True,
        "authority": "unknown",
        "mutation_performed": False,
        "identifiers_redacted": True,
    }
    value.update(overrides)
    return value


class InventoryTests(unittest.TestCase):
    def test_summarizes_without_biometric_identifiers(self):
        probe = stable_probe()
        probe.update(
            {
                "catacomb_state_reply": reply(),
                "catacomb_state_words": [1, 2, 3, 4],
                "sks_lock_state_reply": reply(),
                "sks_lock_state": 0,
                "private_uuid_that_must_not_escape": "secret",
            }
        )
        result = MODULE.summarize_probe(probe, 501)
        self.assertEqual(result["sep_identity_count"], 2)
        self.assertTrue(result["identifiers_redacted"])
        self.assertNotIn("private_uuid_that_must_not_escape", result)

    def test_rejects_malformed_identity_records(self):
        with self.assertRaises(MODULE.InventoryError):
            probe = stable_probe(1)
            probe["identity_record_bytes_valid"] = False
            MODULE.summarize_probe(probe, 501)

    def test_empty_inventory_does_not_require_layout_discriminator(self):
        result = MODULE.summarize_probe(stable_probe(0), 501)
        self.assertEqual(result["sep_identity_count"], 0)

    def test_rejects_inventory_that_changes_between_collections(self):
        with self.assertRaises(MODULE.InventoryError):
            probe = stable_probe(1)
            probe["identity_inventory_repeat_equal"] = False
            MODULE.summarize_probe(probe, 501)

    def test_preclient_absent_baseline_is_reported(self):
        result = MODULE.summarize_preclient_probe(preclient_probe())
        self.assertEqual(result["state"], "absent-baseline")
        self.assertEqual(result["mode"], "preclient-inventory")
        self.assertEqual(result["diagnostic_contract"], "pre-authority-v1")
        self.assertEqual(result["per_user_identity_count"], 0)
        self.assertFalse(result["catacomb_uuid_present"])
        self.assertEqual(result["authority"], "unknown")
        self.assertIs(result["mutation_performed"], False)

    def test_preclient_requires_unknown_authority(self):
        with self.assertRaisesRegex(MODULE.InventoryError, "claims authority"):
            MODULE.summarize_preclient_probe(
                preclient_probe(authority="linux-native")
            )

    def test_preclient_rejects_mutation(self):
        with self.assertRaisesRegex(MODULE.InventoryError, "mutation"):
            MODULE.summarize_preclient_probe(
                preclient_probe(mutation_performed=True)
            )

    def test_preclient_rejects_live_absent_baseline(self):
        with self.assertRaisesRegex(MODULE.InventoryError, "live state"):
            MODULE.summarize_preclient_probe(
                preclient_probe(per_user_identity_count=1)
            )

    def test_preclient_present_state_is_reported(self):
        result = MODULE.summarize_preclient_probe(
            preclient_probe(
                state="present",
                per_user_identity_count=1,
                global_identity_count=1,
                configured_user_free_capacity=4,
                catacomb_uuid_present=True,
                catacomb_component_present=True,
                selected_user_component_present=True,
            )
        )
        self.assertEqual(result["state"], "present")
        self.assertEqual(result["per_user_identity_count"], 1)
        self.assertTrue(result["catacomb_component_present"])

    def test_preclient_rejects_unknown_state(self):
        with self.assertRaisesRegex(MODULE.InventoryError, "state is unknown"):
            MODULE.summarize_preclient_probe(preclient_probe(state="unknown"))


if __name__ == "__main__":
    unittest.main()
