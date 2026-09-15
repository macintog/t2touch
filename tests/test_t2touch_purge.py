# SPDX-License-Identifier: GPL-2.0-only
"""Authorization and lock ordering for the product purge helper."""

from contextlib import contextmanager
from contextlib import redirect_stdout
import io
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "product_purge", ROOT / "src/t2-touchid-purge.py"
)
PURGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PURGE)


class ProductPurgeTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ, {"PKEXEC_UID": "1000", "SUDO_UID": "999"}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.root = patch.object(PURGE.os, "geteuid", return_value=0)
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

        def remove_all(config, *, resume):
            self.assertEqual(self.events, ["config", "lock", "inhibit"])
            return {
                "purge_succeeded": True,
                "deleted_count": 3,
                "identity_count": 0,
            }

        self.manager = SimpleNamespace(
            runtime_configuration=configuration,
            operation_lock=lock,
            sleep_inhibitor=inhibit,
            run_delete_batch=Mock(side_effect=remove_all),
        )
        self.factory = Mock(return_value=self.manager)

    def test_authorized_purge_holds_one_lock_and_restores_environment(self):
        result = PURGE.purge(resume=True, manager_factory=self.factory)
        self.assertEqual(result["deleted_count"], 3)
        self.assertEqual(self.events, ["config", "lock", "inhibit", "unlock"])
        self.manager.run_delete_batch.assert_called_once_with(
            {"linux_uid": 1000, "authority_mode": "linux-native"}, resume=True
        )
        self.assertEqual(os.environ["SUDO_UID"], "999")

    def test_forged_or_wrong_account_never_starts_batch(self):
        with patch.object(PURGE.os, "geteuid", return_value=1000):
            with self.assertRaises(PURGE.PurgeError):
                PURGE.purge(manager_factory=self.factory)
        self.factory.assert_not_called()
        self.manager.runtime_configuration = lambda: {
            "linux_uid": 1001,
            "authority_mode": "linux-native",
        }
        with self.assertRaises(PURGE.PurgeError):
            PURGE.purge(manager_factory=self.factory)
        self.manager.run_delete_batch.assert_not_called()

    def test_failure_returns_only_redacted_batch_progress(self):
        self.manager.run_delete_batch.side_effect = RuntimeError("private identity")
        self.manager.delete_batch_progress = Mock(
            return_value={
                "completed_count": 1,
                "total_count": 3,
                "remaining_count": 2,
                "identifiers_redacted": True,
            }
        )
        with self.assertRaises(PURGE.PurgeError) as raised:
            PURGE.purge(manager_factory=self.factory)
        self.assertEqual(raised.exception.progress["completed_count"], 1)
        self.assertNotIn("private identity", str(raised.exception))
        self.assertEqual(os.environ["SUDO_UID"], "999")

    def test_success_requires_a_valid_deleted_count_and_empty_final_inventory(self):
        for changes in ({"deleted_count": True}, {"deleted_count": -1},
                        {"deleted_count": 6}, {"identity_count": 1},
                        {"identity_count": False}):
            with self.subTest(changes=changes):
                self.manager.run_delete_batch.side_effect = None
                self.manager.run_delete_batch.return_value = {
                    "purge_succeeded": True, "deleted_count": 3, "identity_count": 0,
                    **changes,
                }
                with self.assertRaisesRegex(PURGE.PurgeError, "did not reconcile"):
                    PURGE.purge(manager_factory=self.factory)

    def test_terminal_reports_confirmed_empty_inventory_and_zero_noop(self):
        for count, expected in (
            (3, "Deleted 3 fingerprints. No fingerprints remain enrolled.\n"),
            (1, "Deleted 1 fingerprint. No fingerprints remain enrolled.\n"),
            (0, "No fingerprints enrolled; nothing to delete.\n"),
        ):
            with (
                self.subTest(count=count),
                patch.object(PURGE.sys, "argv", ["t2-touchid-purge"]),
                patch.object(PURGE.signal, "signal"),
                patch.object(PURGE, "purge", return_value={"deleted_count": count}),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(PURGE.main(), 0)
                self.assertEqual(output.getvalue(), expected)

    def test_policy_uses_a_distinct_fresh_authorized_helper(self):
        root = ET.parse(ROOT / "polkit/org.t2linux.touchid.policy").getroot()
        action = root.find("action[@id='org.t2linux.touchid.purge']")
        self.assertEqual(action.findtext("defaults/allow_active"), "auth_self")
        self.assertEqual(action.findtext("defaults/allow_any"), "no")
        self.assertEqual(
            action.findtext(
                "annotate[@key='org.freedesktop.policykit.exec.path']"
            ),
            "/usr/local/sbin/t2-touchid-purge",
        )

    def test_install_and_uninstall_own_the_purge_helper(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("t2-touchid-purge.sh", install)
        self.assertIn("/usr/local/sbin/t2-touchid-purge", install)
        self.assertIn("t2-touchid-purge", uninstall)


if __name__ == "__main__":
    unittest.main()
