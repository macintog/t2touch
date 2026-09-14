#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the real native launcher/parser boundary without device access."""

from contextlib import redirect_stderr
import ast
import builtins
import inspect
from io import StringIO
from pathlib import Path
import symtable
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_native_match import BRIDGE_PROBE, NATIVE_MATCH


class AuthorityBoundaryReached(Exception):
    """Stop after argument validation, before reading protected state."""


class NativeMatchCLIContractTests(unittest.TestCase):
    def test_probe_runtime_names_and_local_calls_are_defined(self):
        """Catch the observed late NameError and unsupported event keyword."""
        source = Path(BRIDGE_PROBE.__file__).read_text()
        tree = ast.parse(source)
        table = symtable.symtable(source, BRIDGE_PROBE.__file__, "exec")
        known = set(vars(BRIDGE_PROBE)) | set(vars(builtins))

        def check_globals(scope):
            for symbol in scope.get_symbols():
                if symbol.is_referenced() and symbol.is_global():
                    self.assertIn(
                        symbol.get_name(), known,
                        f"{scope.get_name()} reads an undefined global",
                    )
            for child in scope.get_children():
                check_globals(child)

        main_scope = next(c for c in table.get_children() if c.get_name() == "main")
        check_globals(main_scope)
        local_functions = {
            node.name for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Name)
                or node.func.id not in local_functions
                or any(isinstance(arg, ast.Starred) for arg in node.args)
                or any(keyword.arg is None for keyword in node.keywords)
            ):
                continue
            with self.subTest(function=node.func.id, line=node.lineno):
                inspect.signature(getattr(BRIDGE_PROBE, node.func.id)).bind(
                    *[None for _ in node.args],
                    **{keyword.arg: None for keyword in node.keywords},
                )

    def test_match_stop_policy_keeps_quality_retry_and_finishes_success(self):
        """Positive matching must finish on success; quality is not a negative."""
        quality = {
            "event_kind": "match_result", "result_valid": True,
            "no_match": True, "no_match_image_quality": True,
        }
        negative = {**quality, "no_match_image_quality": False}
        success = {
            "event_kind": "match_result", "result_valid": True, "matched": True,
        }
        cases = (
            (True, False, True, quality, False),
            (True, False, True, negative, True),
            (True, False, False, quality, True),
            (False, True, False, negative, False),
            (False, True, False, success, True),
            (False, False, False, success, False),
        )
        for stop_result, stop_success, retry_quality, event, expected in cases:
            with self.subTest(
                stop_result=stop_result, stop_success=stop_success,
                retry_quality=retry_quality, event=event,
            ):
                args = SimpleNamespace(
                    stop_on_match_result=stop_result,
                    stop_on_match_success=stop_success,
                    retry_image_quality_no_match=retry_quality,
                )
                self.assertIs(
                    BRIDGE_PROBE.match_observation_should_stop(event, args), expected,
                )

    def test_generated_selectors_pass_real_parser_and_require_inventory(self):
        configuration = {
            "host": "host",
            "interface": "interface",
            "apple_uid": 501,
            "linux_uid": 1000,
        }
        selectors = (
            {},
            {"target_finger": "finger-1"},
            {"resolve_any_finger": True},
            {"addition_journal": "/not-read/addition.jsonl"},
        )
        for selector in selectors:
            command = NATIVE_MATCH._probe_command(
                configuration,
                port=50000,
                credential_fd=9,
                seconds=0.35,
                private_events=None,
                **selector,
            )
            for include_inventory in (True, False):
                argv = command[1:]
                if not include_inventory:
                    argv = [arg for arg in argv if arg != "--identity-list"]
                with (
                    self.subTest(
                        selector=selector, include_inventory=include_inventory
                    ),
                    patch.object(BRIDGE_PROBE.sys, "argv", argv),
                    patch.object(BRIDGE_PROBE.os, "geteuid", return_value=0),
                    patch.object(
                        BRIDGE_PROBE.t2_user_authority,
                        "load",
                        side_effect=AuthorityBoundaryReached,
                    ) as authority,
                    patch.object(
                        BRIDGE_PROBE.socket,
                        "socket",
                        side_effect=AssertionError("unexpected socket access"),
                    ) as socket_factory,
                    redirect_stderr(StringIO()) as stderr,
                ):
                    if include_inventory:
                        with self.assertRaises(AuthorityBoundaryReached):
                            BRIDGE_PROBE.main()
                        authority.assert_called_once_with(1000)
                    else:
                        with self.assertRaises(SystemExit) as stopped:
                            BRIDGE_PROBE.main()
                        self.assertEqual(stopped.exception.code, 2)
                        self.assertIn("complete match gate", stderr.getvalue())
                        authority.assert_not_called()
                    socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
