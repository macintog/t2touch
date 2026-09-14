# SPDX-License-Identifier: GPL-2.0-only
"""Exercise startup routing with an actual interrupted deletion journal."""
import json
import ast
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests import test_identity_delete_operation as fixtures
import t2_native_post_reboot_reconciler as native
import t2_post_reboot_reconciler as common


class NativeDeleteStartupRecoveryTests(unittest.TestCase):
    def test_delete_failure_keeps_cause_types_without_private_messages(self):
        inner = OSError("private biometric payload")
        outer = RuntimeError("private account identity")
        outer.__cause__ = inner
        inner.__context__ = outer
        # Compile the pure diagnostic directly so this hardware-free test does
        # not need the worker's Linux/D-Bus runtime dependencies.
        source = Path(__file__).parents[1] / "src/t2_fprint_delete_worker.py"
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == "failure_diagnostic")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
        diagnostic = namespace["failure_diagnostic"](outer)
        self.assertEqual(diagnostic["exception_chain"], ["RuntimeError", "OSError"])
        self.assertTrue(diagnostic["identifiers_redacted"])
        self.assertNotIn("private", json.dumps(diagnostic))

    def interrupted_delete(self, root):
        fixture = fixtures.IdentityDeleteOperationTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.test_transport_failure_is_durable_outcome_unknown()
        fixture.path.rename(root / f"{fixture.operation_id}.jsonl")

    def test_interrupted_delete_routes_to_recovery_without_replaying_delete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.interrupted_delete(root)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            runner = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps({
                "schema_version": 1, "identifiers_redacted": True,
                "delete_recovery_succeeded": True,
                "post_reboot_verification_required": False,
            })))
            with (
                mock.patch.object(native, "MUTATION_ROOT", root),
                mock.patch.object(common, "MUTATION_ROOT", root),
                mock.patch.object(native, "ROOT_UID", os.geteuid()),
            ):
                result = native.run(management_runner=runner)
            self.assertTrue(result.journal_updated)
            self.assertEqual(result.state, "delete-recovered")
            self.assertEqual(runner.call_args.args[0][-2:], [
                "recover-delete", "--acknowledge-interrupted-delete-recovery"])
            self.assertEqual(runner.call_args.kwargs["env"]["SUDO_UID"], "1000")
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_multiple_interrupted_deletes_do_not_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.interrupted_delete(root)
            self.interrupted_delete(root)
            runner = mock.Mock()
            with (
                mock.patch.object(native, "MUTATION_ROOT", root),
                mock.patch.object(common, "MUTATION_ROOT", root),
                mock.patch.object(native, "ROOT_UID", os.geteuid()),
            ):
                with self.assertRaises(RuntimeError):
                    native.run(management_runner=runner)
            runner.assert_not_called()
