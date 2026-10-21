# SPDX-License-Identifier: GPL-2.0-only
import hashlib
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import t2_user_authority as authority
import t2_user_mapping as mapping
import t2_apple_control_discriminator as keybag
import t2_apple_control_alias_discriminator as alias
import t2_apple_control_alias_reconciliation as reconciliation
import t2_apple_control_alias_unlock as unlock


class CompatibilityAuthorityTests(unittest.TestCase):
    def test_both_authority_shapes_preserve_exact_generation(self):
        evidence = keybag.OracleEvidence("import", "a" * 64, 1000, 501,
                                        "bag", "/private/user.kb", "b" * 64)
        disabled = mapping.UserMapping(1000, "c" * 64, 501, "account", "bag",
                                       evidence.keybag_path, evidence.keybag_sha256,
                                       "disabled", frozenset(), False)
        matched = alias.MatchedKeybagProof("keybag", "boot1", "runtime1")
        bind = reconciliation.AmbiguousBindProof("bind", "boot2", "runtime2")
        reconciled = reconciliation.ReconciledAliasProof(
            "reconciliation", "boot3", "runtime3", "d" * 64
        )
        bound = alias.BoundAliasProof("bind", "boot2", "runtime2")
        unlocked = unlock.AliasUnlockProof("unlock", "boot4", "runtime4")
        for clean in (False, True):
            with (
                self.subTest(clean=clean),
                tempfile.TemporaryDirectory() as root,
                mock.patch.object(authority.os, "geteuid", return_value=0),
                mock.patch.object(keybag, "read_oracle_import", return_value=evidence),
                mock.patch.object(alias, "read_matched_keybag_proof", return_value=matched),
                mock.patch.object(reconciliation, "read_ambiguous_bind_proof",
                    return_value=bind, side_effect=(
                        reconciliation.AppleControlAliasReconciliationError("no retry")
                        if clean else None)),
                mock.patch.object(reconciliation, "read_reconciled_alias_proof", return_value=reconciled),
                mock.patch.object(alias, "read_bound_alias_proof", return_value=bound),
                mock.patch.object(unlock, "read_completed_unlock_proof", return_value=unlocked) as read_unlock,
                mock.patch.object(mapping, "load", return_value=mapping.UserMappingSet("a" * 64, (disabled,))),
            ):
                result = authority.load_compatibility(1000, state_root=Path(root))
                self.assertIs(read_unlock.call_args.args[2], bound if clean else reconciled)
                binding = dict(schema_version=1, origin=keybag.ORIGIN,
                    disabled_mapping_generation=evidence.mapping_generation,
                    import_operation_id="import", keybag_operation_id="keybag",
                    bind_operation_id="bind", unlock_operation_id="unlock")
                if not clean:
                    binding.update(reconciliation_operation_id="reconciliation",
                                   state_blob_sha256="d" * 64)
                expected = hashlib.sha256(json.dumps(
                    binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode("ascii")).hexdigest()
                self.assertEqual(result.mapping_set.generation, expected)
                self.assertTrue(result.selected.enabled)
                self.assertFalse(disabled.enabled)
                with mock.patch.object(keybag, "read_oracle_import", return_value=replace(
                    evidence, rename_mapping_generation=expected
                )):
                    self.assertEqual(authority.load_compatibility(
                        1000, state_root=Path(root)
                    ).mapping_set.generation, expected)
                with mock.patch.object(keybag, "read_oracle_import", return_value=replace(
                    evidence, rename_mapping_generation="0" * 64
                )):
                    with self.assertRaisesRegex(authority.UserAuthorityError, "another authority"):
                        authority.load_compatibility(1000, state_root=Path(root))
