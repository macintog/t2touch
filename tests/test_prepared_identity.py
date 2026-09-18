# SPDX-License-Identifier: GPL-2.0-only
"""A retained keybag must never retain a caller's authorization."""

from contextlib import contextmanager, ExitStack
import errno
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_prepared_identity as module
import t2_aks_transport as transport_module


class PreparedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.calls = []
        self.transport = Mock(runtime_generation="generation")
        self.factory = self.stack.enter_context(patch.object(
            module.t2_aks_transport, "AKSActivationTransport", return_value=self.transport
        ))
        self.assess = self.stack.enter_context(patch.object(
            module.t2_user_readiness, "assess", return_value=SimpleNamespace(state="ready")
        ))
        self.require = self.stack.enter_context(patch.object(
            module.t2_user_policy, "require_bound_authority"
        ))

        @contextmanager
        def retain(*args, **kwargs):
            self.calls.append("load")
            try:
                yield "ready"
            finally:
                self.calls.append("release")
        self.stack.enter_context(patch.object(
            module.activation, "retain_ready_identity_handle", side_effect=retain
        ))
        self.authority = SimpleNamespace(mapping_set="mapping", persistent="persistent",
                                         selected=SimpleNamespace(special_bag_alias=-501))
        self.session = module.PreparedIdentity()
        self.addCleanup(self.session.close)

    def run_request(self, grant="fresh-grant", configuration=None):
        a = self.authority
        with self.session.open(a, configuration or {"user": 1000}, "boot") as transport:
            with self.session.retain(Path("journal"), a.mapping_set, a.selected, "verify",
                                     a.persistent, transport, authorization=grant,
                                     linux_boot_uuid="boot") as state:
                self.assertEqual(state, "ready")

    def test_reuse_keeps_keybag_but_requires_new_bound_authority(self):
        self.run_request("first")
        self.run_request("second")
        self.assertEqual(self.calls, ["load"])
        self.factory.assert_called_once()
        self.transport.require_current_generation.assert_called_once()
        self.assertEqual(self.require.call_args.args[0], "second")
        self.assertFalse(self.require.call_args.kwargs["activation"])
        self.session.close()
        self.assertEqual(self.calls, ["load", "release"])
        self.transport.close.assert_called_once()

    def test_configuration_change_releases_before_reopening(self):
        self.run_request()
        self.run_request(configuration={"user": 1001})
        self.assertEqual(self.calls, ["load", "release", "load"])
        self.assertEqual(self.factory.call_count, 2)

    def test_changed_generation_fails_and_closes(self):
        self.run_request()
        self.transport.require_current_generation.side_effect = RuntimeError("changed")
        with self.assertRaises(RuntimeError):
            self.run_request()
        self.assertIsNone(self.session.transport)

    def test_revoked_request_authority_cannot_use_retained_keybag(self):
        self.run_request()
        self.require.side_effect = RuntimeError("revoked")
        with self.assertRaises(RuntimeError):
            self.run_request()
        self.assertEqual(self.calls, ["load", "release"])

    def test_locked_alias_is_not_silently_reactivated(self):
        self.run_request()
        self.assess.return_value = SimpleNamespace(state="device-locked")
        with self.assertRaises(RuntimeError):
            self.run_request()
        self.assertIsNone(self.session.transport)

    def test_repeated_close_releases_once(self):
        self.run_request()
        self.session.close()
        self.session.close()
        self.assertEqual(self.calls, ["load", "release"])

    def test_cleanup_error_still_closes_descriptor(self):
        self.run_request()
        self.session.retention = Mock()
        self.session.retention.__exit__ = Mock(side_effect=RuntimeError("unload"))
        with self.assertRaises(RuntimeError):
            self.session.close()
        self.transport.close.assert_called_once()
        self.assertIsNone(self.session.transport)

    def install_authorization(self):
        device = Mock()
        self.stack.enter_context(patch.object(module.t2_acm_device, "ACMDevice", return_value=device))
        self.policy = self.stack.enter_context(patch.object(
            module.t2_acm_device.protocol, "parse_policy_response",
            return_value=SimpleNamespace(satisfied=True),
        ))
        @contextmanager
        def authorize(*args, **kwargs):
            self.calls.append("authorize")
            try:
                yield "initial", "old-policy", b"i" * 16, b"o" * 16
            finally:
                self.calls.append("deauthorize")
        self.stack.enter_context(patch.object(
            module.t2_acm_device, "identity_authorized_context", side_effect=authorize,
        ))
        return device

    def authorized_request(self):
        a = self.authority
        with self.session.open(a, {"user": 1000}, "boot"):
            with self.session.open_acm() as device:
                with self.session.authorize(device, 501, bytearray(b"secret"), Mock(),
                                            include_authorization_context=True) as proof:
                    self.assertIs(proof[1], self.policy.return_value)

    def test_capability_reused_but_sep_policy_evaluated_on_every_request(self):
        device = self.install_authorization()
        self.authorized_request()
        self.authorized_request()
        self.assertEqual(self.calls, ["authorize"])
        self.assertEqual(device.exchange.call_count, 2)
        device.require_current_generation.assert_called_once()
        self.session.close()
        self.assertEqual(self.calls, ["authorize", "deauthorize"])
        device.close.assert_called_once()

    def test_policy_revocation_discards_entire_prepared_session(self):
        device = self.install_authorization()
        self.authorized_request()
        self.policy.return_value = SimpleNamespace(satisfied=False)
        with self.assertRaisesRegex(RuntimeError, "no longer satisfied"):
            self.authorized_request()
        self.assertIsNone(self.session.authorization)
        self.assertIsNone(self.session.transport)
        device.close.assert_called_once()

    def test_changed_acm_generation_discards_capability(self):
        device = self.install_authorization()
        self.authorized_request()
        device.require_current_generation.side_effect = RuntimeError("generation changed")
        with self.assertRaisesRegex(RuntimeError, "generation changed"):
            self.authorized_request()
        self.assertEqual(self.calls, ["authorize", "deauthorize"])
        self.assertIsNone(self.session.proof)

    def test_acm_cleanup_failure_still_releases_keybag_and_descriptors(self):
        device = self.install_authorization()
        self.run_request()
        self.authorized_request()
        self.session.authorization = Mock()
        self.session.authorization.__exit__ = Mock(side_effect=RuntimeError("cleanup failed"))
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            self.session.close()
        self.assertIn("release", self.calls)
        device.close.assert_called_once()
        self.transport.close.assert_called_once()


class BusyTransportTests(unittest.TestCase):
    def test_only_busy_owned_device_asks_for_release_then_retries_once(self):
        with patch.object(transport_module.os, "open", side_effect=[OSError(errno.EBUSY, "busy"), 41]) as opened, \
                patch("t2_preparation_lease.release_idle_owner", return_value=True) as release:
            self.assertEqual(transport_module._open_device(transport_module.DEVICE), 41)
        release.assert_called_once()
        self.assertEqual(opened.call_count, 2)

    def test_denied_open_does_not_request_release(self):
        with patch.object(transport_module.os, "open", side_effect=PermissionError(errno.EACCES, "denied")), \
                patch("t2_preparation_lease.release_idle_owner") as release:
            with self.assertRaises(transport_module.AKSActivationTransportError):
                transport_module._open_device(transport_module.DEVICE)
        release.assert_not_called()
