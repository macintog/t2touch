# SPDX-License-Identifier: GPL-2.0-only
"""Privilege, account, selector and reconciliation contracts for product delete."""
import importlib.util
import os
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("product_delete", ROOT / "src/t2-touchid-delete.py")
DELETE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DELETE)


class ProductDeleteTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"PKEXEC_UID": "1000", "SUDO_UID": "999"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.root = patch.object(DELETE.os, "geteuid", return_value=0)
        self.root.start()
        self.addCleanup(self.root.stop)
        self.events = []
        @contextmanager
        def lock():
            self.events.append("lock")
            try:
                yield
            finally:
                self.events.append("unlock")
        @contextmanager
        def inhibit():
            self.events.append("inhibit")
            yield
        def configuration():
            self.assertEqual(os.environ["SUDO_UID"], "1000")
            self.events.append("config")
            return {"linux_uid": 1000, "authority_mode": "linux-native"}
        def remove(config, *, finger_name):
            self.assertEqual(finger_name, "finger-2")
            self.assertEqual(self.events, ["config", "lock", "inhibit"])
            return {"delete_succeeded": True}
        self.manager = SimpleNamespace(runtime_configuration=configuration,
            operation_lock=lock, sleep_inhibitor=inhibit, run_delete=Mock(side_effect=remove))
        self.factory = Mock(return_value=self.manager)

    def test_authorized_single_finger_reuses_locked_manager_and_restores_environment(self):
        DELETE.delete("finger-2", manager_factory=self.factory)
        self.assertEqual(self.events, ["config", "lock", "inhibit", "unlock"])
        self.assertEqual(os.environ["SUDO_UID"], "999")
        self.manager.run_delete.assert_called_once_with(
            {"linux_uid": 1000, "authority_mode": "linux-native"}, finger_name="finger-2")

    def test_nonroot_cannot_forge_pkexec_authorization(self):
        with patch.object(DELETE.os, "geteuid", return_value=1000):
            with self.assertRaises(DELETE.DeleteError):
                DELETE.delete("finger-2", manager_factory=self.factory)
        self.factory.assert_not_called()

    def test_invalid_authenticated_uids_and_selectors_never_open_manager(self):
        for uid in ("", "0", "-1", "01000", "4294967295", "1000\n"):
            with self.subTest(uid=uid), patch.dict(os.environ, {"PKEXEC_UID": uid}):
                with self.assertRaises(DELETE.DeleteError):
                    DELETE.delete("finger-2", manager_factory=self.factory)
        for finger in ("any", "finger-0", "finger-6", "finger-2\n", "--slot=1"):
            with self.subTest(finger=finger), self.assertRaises(DELETE.DeleteError):
                DELETE.delete(finger, manager_factory=self.factory)
        self.factory.assert_not_called()

    def test_other_account_and_compatibility_mode_cannot_take_lock(self):
        for config in ({"linux_uid": 1001, "authority_mode": "linux-native"},
                       {"linux_uid": 1000, "authority_mode": "macos-control-oracle"}):
            self.manager.runtime_configuration = lambda: config
            with self.assertRaises(DELETE.DeleteError):
                DELETE.delete("finger-2", manager_factory=self.factory)
            self.assertEqual(self.events, [])
            self.assertEqual(os.environ["SUDO_UID"], "999")
        self.manager.run_delete.assert_not_called()

    def test_incomplete_result_and_operation_failure_do_not_report_success(self):
        for result in ({}, {"delete_succeeded": False}, {"delete_succeeded": 1}, None):
            self.manager.run_delete.side_effect = None
            self.manager.run_delete.return_value = result
            with self.assertRaises(DELETE.DeleteError):
                DELETE.delete("finger-2", manager_factory=self.factory)
            self.assertEqual(self.events[-1], "unlock")
        self.manager.run_delete.side_effect = RuntimeError("journal blocked")
        with self.assertRaises(RuntimeError):
            DELETE.delete("finger-2", manager_factory=self.factory)
        self.assertEqual(self.events[-1], "unlock")
        self.assertEqual(os.environ["SUDO_UID"], "999")

    def test_policy_binds_only_installed_helper_and_requires_fresh_self_auth(self):
        root = ET.parse(ROOT / "polkit/org.t2linux.touchid.policy").getroot()
        action = root.find("action[@id='org.t2linux.touchid.identity-management']")
        self.assertEqual(action.findtext("defaults/allow_active"), "auth_self")
        self.assertEqual(action.findtext("defaults/allow_any"), "no")
        self.assertEqual(action.findtext("defaults/allow_inactive"), "no")
        self.assertEqual(action.findtext("annotate[@key='org.freedesktop.policykit.exec.path']"),
                         "/usr/local/sbin/t2-touchid-delete")
        self.assertIsNone(action.find("annotate[@key='org.freedesktop.policykit.exec.allow_gui']"))


if __name__ == "__main__":
    unittest.main()
