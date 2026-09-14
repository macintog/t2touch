# SPDX-License-Identifier: GPL-2.0-only

"""Exact construction contract for the reference-machine reboot transport."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "reboot_cycle",
    Path(__file__).resolve().parents[1] / "tools/reboot-cycle.py",
)
cycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cycle)


class RebootCycleTests(unittest.TestCase):
    def test_exact_single_timer_command_is_bounded_and_nonblocking_only_at_transport(self):
        self.assertEqual(
            cycle.systemd_run_command("D164"),
            (
                "/usr/bin/systemd-run",
                "--unit=t2-touchid-d164-delayed-reboot",
                "--on-active=8s",
                "--timer-property=AccuracySec=100ms",
                "/usr/bin/systemctl",
                "reboot",
            ),
        )
        with self.assertRaisesRegex(cycle.CycleError, "checkpoint"):
            cycle.systemd_run_command("latest")

    def test_post_boot_evidence_requires_exactly_one_attributed_request(self):
        self.assertEqual(
            cycle.reboot_journal_command("11111111-2222-3333-4444-555555555555"),
            (
                "journalctl",
                "-b",
                "11111111222233334444555555555555",
                "-o",
                "cat",
                "--no-pager",
                "-u",
                "systemd-logind.service",
            ),
        )
        with self.assertRaisesRegex(cycle.CycleError, "boot ID"):
            cycle.reboot_journal_command("-1")
        unit = "t2-touchid-d164-delayed-reboot"
        request = f"reboot requested from client PID 7 (unit {unit}.service)"
        unrelated = "reboot requested from client PID 8 (unit another.service)"
        self.assertEqual(cycle.reboot_request_count(request, unit), 1)
        self.assertEqual(cycle.reboot_request_count(unrelated, unit), 0)
        self.assertEqual(cycle.reboot_request_count(f"{request}\n{request}", unit), 2)

    def test_changed_head_requires_verified_remote_and_attested_ancestry(self):
        old = "a" * 40
        new = "b" * 40
        completed = mock.Mock(returncode=0)
        with mock.patch.object(cycle, "current_git", return_value=("branch", new)):
            with self.assertRaisesRegex(cycle.CycleError, "Git state"):
                cycle.require_post_reboot_git("branch", old, None)
            with mock.patch.object(cycle, "run", return_value=completed) as run:
                self.assertTrue(cycle.require_post_reboot_git("branch", old, new))
                self.assertIn("--is-ancestor", run.call_args.args)
            completed.returncode = 1
            with mock.patch.object(cycle, "run", return_value=completed):
                with self.assertRaisesRegex(cycle.CycleError, "descendant"):
                    cycle.require_post_reboot_git("branch", old, new)


if __name__ == "__main__":
    unittest.main()
