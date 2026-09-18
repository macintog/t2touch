# SPDX-License-Identifier: GPL-2.0-only
"""Startup prepares a capability without running an unsolicited match."""

from contextlib import ExitStack, nullcontext
import importlib.util
import io
from pathlib import Path
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "native_preparation", Path(__file__).resolve().parents[1] / "src/t2-native-match.py"
)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class NativePreparationTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        def replace(owner, name, **kwargs):
            return stack.enter_context(patch.object(owner, name, **kwargs))
        configuration = {"linux_uid": 1000, "apple_uid": 501, "host": "test", "interface": "test"}
        authority = SimpleNamespace(origin="linux-native-e4", mapping_set=Mock(), persistent=Mock(),
            selected=SimpleNamespace(apple_uid=501, activation_secret_path="test", activation_secret_sha256="test"))
        replace(native, "_configuration", return_value=configuration)
        replace(native.t2_user_authority, "load", return_value=authority)
        replace(native, "_require_runtime")
        replace(native, "BOOT_ID", new=Mock(read_text=Mock(return_value="00000000-0000-0000-0000-000000000001")))
        replace(native.os, "open", return_value=42)
        replace(native.os, "close")
        replace(native.os, "fstat", return_value=SimpleNamespace(st_mode=0o100600, st_uid=0))
        replace(native.fcntl, "flock")
        replace(native, "_sleep_inhibitor", side_effect=lambda: nullcontext(43))
        self.inhibitor = replace(native, "_sleep_inhibitor_is_active", return_value=True)
        replace(native, "_discover_port", return_value=1234)
        replace(native, "_authorize", return_value=(Mock(), "operation"))
        self.secret = bytearray(b"activation-secret")
        replace(native.t2_activation_bundle, "activation_secret", side_effect=lambda *a: nullcontext(self.secret))
        self.prepare = replace(native.t2_user_activation_operation, "prepare_retained_identity")
        self.unlock = replace(native.t2_user_activation_operation, "unlock_retained_identity")
        self.probe = replace(native, "_run_probe", return_value=0)
        self.session = Mock()
        self.session.open.side_effect = lambda *a: nullcontext(Mock())
        self.session.open_acm.side_effect = lambda: nullcontext(Mock())
        self.session.retain.side_effect = lambda *a, **k: nullcontext("device-locked")
        self.session.authorize.side_effect = lambda *a, **k: nullcontext((None, SimpleNamespace(satisfied=True), b"i" * 16, b"o" * 16))
        self.args = native._worker_arguments({"schema_version": 1, "request_id": 1,
            "observation_seconds": 0, "match_finger_name": None, "resolve_any_finger_name": True})

    def test_startup_prepares_and_unlocks_but_never_arms_sensor(self):
        self.assertEqual(native._run(self.args, Event(), prepared_identity=self.session, prepare_only=True), 0)
        self.prepare.assert_called_once()
        self.unlock.assert_called_once()
        self.probe.assert_not_called()
        self.assertEqual(self.secret, bytearray(len(self.secret)))

    def test_real_request_still_dispatches_fresh_match(self):
        native._run(self.args, Event(), prepared_identity=self.session)
        self.probe.assert_called_once()

    def test_failed_inhibitor_cannot_report_successful_preparation(self):
        self.inhibitor.return_value = False
        with self.assertRaises(native.NativeMatchError):
            native._run(self.args, Event(), prepared_identity=self.session, prepare_only=True)
        self.probe.assert_not_called()

    def test_preparation_requires_an_explicit_owned_session(self):
        with self.assertRaises(native.NativeMatchError):
            native._run(self.args, Event(), prepare_only=True)
        self.prepare.assert_not_called()


class PreparationRenewalTests(unittest.TestCase):
    def test_expired_reused_capability_gets_one_fresh_preparation(self):
        expired = native.t2_prepared_identity.PreparedAuthorizationExpired("expired")
        with patch.object(native, "_run", side_effect=[expired, 0]) as run:
            self.assertEqual(native._run_prepared_match(Mock(), Event(), io.BytesIO(), Mock(), Mock()), 0)
            self.assertEqual(run.call_count, 2)

    def test_renewal_never_retries_ambiguous_or_cancelled_work(self):
        expired = native.t2_prepared_identity.PreparedAuthorizationExpired("expired")
        cancelled = Event()
        cancelled.set()
        for stop, captured, error in ((cancelled, io.BytesIO(), expired),
                                     (Event(), io.BytesIO(b"output"), expired),
                                     (Event(), io.BytesIO(), RuntimeError("revoked caller"))):
            with self.subTest(error=error), patch.object(native, "_run", side_effect=error) as run:
                with self.assertRaises(RuntimeError):
                    native._run_prepared_match(Mock(), stop, captured, Mock(), Mock())
                run.assert_called_once()

    def test_repeated_expiry_is_bounded(self):
        with patch.object(native, "_run", side_effect=native.t2_prepared_identity.PreparedAuthorizationExpired("expired")) as run:
            with self.assertRaises(RuntimeError):
                native._run_prepared_match(Mock(), Event(), io.BytesIO(), Mock(), Mock())
            self.assertEqual(run.call_count, 2)
