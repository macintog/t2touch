# SPDX-License-Identifier: GPL-2.0-only
"""Product command routing without hardware or system mutation."""

from pathlib import Path
from types import SimpleNamespace
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import sys
import unittest
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2touch


class T2TouchCLITests(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(t2touch.os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_root_only_configuration_uses_the_calling_account(self):
        with (
            mock.patch.object(Path, "read_text", side_effect=PermissionError),
            mock.patch.object(t2touch.os, "geteuid", return_value=1000),
            mock.patch.object(
                t2touch.pwd,
                "getpwuid",
                return_value=SimpleNamespace(pw_name="mapped"),
            ),
        ):
            self.assertEqual(t2touch.configured_user(), "mapped")

    def test_delete_authenticates_before_starting_one_numbered_deletion(self):
        completed = SimpleNamespace(returncode=0, stderr="")
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(
                t2touch.subprocess, "run", return_value=completed
            ) as run,
        ):
            self.assertEqual(t2touch.delete("mapped", "finger-5"), 0)
            run.assert_called_once_with(
                ["/usr/bin/pkexec", "/usr/local/sbin/t2-touchid-delete", "finger-5"],
                check=False,
                text=True,
                stderr=t2touch.subprocess.PIPE,
            )
            with self.assertRaisesRegex(t2touch.T2TouchError, "Finger N"):
                t2touch.delete("mapped", "right-index-finger")
            self.assertEqual(t2touch.delete("mapped", "2"), 0)
            self.assertEqual(t2touch.delete("mapped", "Finger 5"), 0)
            self.assertEqual(run.call_args_list[-2].args[0][2], "finger-2")
            self.assertEqual(run.call_args_list[-1].args[0][2], "finger-5")

    def test_cancelled_authorization_returns_without_a_deletion_fallback(self):
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(t2touch.subprocess, "run",
                              return_value=SimpleNamespace(returncode=126)) as run,
        ):
            self.assertEqual(t2touch.delete("mapped", "finger-2"), 126)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][0], "/usr/bin/pkexec")

    def test_inventory_uses_system_bus_and_returns_ordered_neutral_handles(self):
        completed = SimpleNamespace(
            returncode=0,
            stdout='{"type":"as","data":[["finger-5","finger-2"]]}\n',
        )
        with (
            mock.patch.object(t2touch, "require_current_user") as current,
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(
                t2touch.subprocess, "run", return_value=completed
            ) as run,
        ):
            self.assertEqual(
                t2touch.enrolled_fingers("mapped"), ("finger-2", "finger-5")
            )
        current.assert_called_once_with("mapped")
        self.assertEqual(run.call_args.args[0], [
            "/opt/t2-touchid/.venv/bin/python", "-I",
            "/opt/t2-touchid/src/t2-touchid-list.py", "mapped",
        ])
        self.assertEqual(run.call_args.kwargs["stderr"], t2touch.subprocess.DEVNULL)

    def test_inventory_rejects_malformed_or_failed_service_replies(self):
        malformed = (
            "not-json",
            '{}',
            '{"type":"as","data":[["right-index-finger"]]}',
            '{"type":"as","data":[["finger-1","finger-1"]]}',
            '{"type":"as","data":[["finger-1","finger-2","finger-3","finger-4","finger-5","finger-6"]]}',
        )
        for output in malformed:
            with self.subTest(output=output), self.assertRaisesRegex(
                t2touch.T2TouchError, "malformed inventory"
            ):
                t2touch._parse_finger_reply(output)
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(
                t2touch.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=1, stdout="private detail"),
            ),
            self.assertRaisesRegex(t2touch.T2TouchError, "unable to list"),
        ):
            t2touch.enrolled_fingers("mapped")

    def test_status_json_and_count_use_the_same_redacted_inventory(self):
        fingers = ("finger-1", "finger-4")
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(t2touch, "enrolled_fingers", return_value=fingers),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(t2touch.status("mapped", json_output=True), 0)
            document = json.loads(output.getvalue())
            self.assertTrue(document["service_ready"])
            self.assertEqual(document["fingerprint_count"], 2)
            self.assertEqual(
                document["fingerprints"],
                [
                    {"handle": "finger-1", "label": "Finger 1"},
                    {"handle": "finger-4", "label": "Finger 4"},
                ],
            )
            self.assertTrue(document["identifiers_redacted"])
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(t2touch.count_fingerprints("mapped"), 0)
            self.assertEqual(output.getvalue(), "2\n")

    def test_empty_inventory_is_successful_for_all_product_views(self):
        with (
            mock.patch.object(t2touch, "configured_user", return_value="mapped"),
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(t2touch.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout='{"type":"as","data":[[]]}',
            )),
        ):
            for command, expected in (
                (["count"], "0\n"),
                (["list"], "No fingerprints enrolled.\n"),
                (["status"], "Touch ID service: ready\nEnrolled fingerprints: 0\n"),
            ):
                with self.subTest(command=command), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(t2touch.main(command), 0)
                    self.assertEqual(output.getvalue(), expected)
            for command in (["list", "--json"], ["status", "--json"]):
                with self.subTest(command=command), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(t2touch.main(command), 0)
                    document = json.loads(output.getvalue())
                    self.assertEqual(document["fingerprint_count"], 0)
                    self.assertEqual(document["fingerprints"], [])
                    if command[0] == "status":
                        self.assertTrue(document["service_ready"])

    def test_ssh_deletion_is_rejected_before_confirmation_or_authorization(self):
        for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
            for command in (["purge"], ["purge", "--yes"], ["purge", "--resume"],
                            ["delete", "finger-1"]):
                with (
                    self.subTest(name=name, command=command),
                    mock.patch.dict(t2touch.os.environ, {name: "remote-session"}),
                    mock.patch.object(t2touch, "configured_user", return_value="mapped"),
                    mock.patch.object(t2touch, "require_current_user"),
                    mock.patch.object(t2touch.subprocess, "run") as run,
                    redirect_stdout(io.StringIO()) as output,
                    redirect_stderr(io.StringIO()) as errors,
                ):
                    self.assertEqual(t2touch.main(command), 1)
                    self.assertEqual(output.getvalue(), "")
                    self.assertIn("active local desktop session", errors.getvalue())
                    self.assertIn("outside SSH", errors.getvalue())
                    run.assert_not_called()

    def test_authorization_results_are_distinct_from_helper_failure(self):
        for code, diagnostic in ((126, "authorization cancelled"), (127, "authorization denied")):
            with (
                self.subTest(code=code),
                mock.patch.object(t2touch.subprocess, "run", return_value=SimpleNamespace(
                    returncode=code, stderr="This incident has been reported.\n",
                )),
                redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(t2touch.authorized_mutation(["/usr/bin/pkexec"]), code)
                self.assertIn(diagnostic, errors.getvalue())
                self.assertIn("deletion did not start", errors.getvalue())
                self.assertNotIn("incident", errors.getvalue())
        progress = "t2touch: purge incomplete; 1 of 3 deletions completed; resume\n"
        with (
            mock.patch.object(t2touch.subprocess, "run", return_value=SimpleNamespace(
                returncode=1, stderr=progress,
            )),
            redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(t2touch.authorized_mutation(["/usr/bin/pkexec"]), 1)
            self.assertEqual(errors.getvalue(), progress)

    def test_purge_requires_confirmation_then_uses_one_fresh_authorization(self):
        class TerminalInput(io.StringIO):
            def isatty(self):
                return True

        completed = SimpleNamespace(returncode=0, stderr="")
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(
                t2touch.subprocess, "run", return_value=completed
            ) as run,
        ):
            output = io.StringIO()
            self.assertEqual(
                t2touch.purge(
                    "mapped",
                    input_stream=TerminalInput("yes\n"),
                    output_stream=output,
                ),
                0,
            )
            run.assert_called_once_with(
                ["/usr/bin/pkexec", "/usr/local/sbin/t2-touchid-purge"],
                check=False,
                text=True,
                stderr=t2touch.subprocess.PIPE,
            )
            self.assertIn("cannot be undone", output.getvalue())

    def test_purge_cancel_and_noninteractive_use_never_mutate(self):
        class TerminalInput(io.StringIO):
            def isatty(self):
                return True

        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=True),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(t2touch.subprocess, "run") as run,
        ):
            self.assertEqual(
                t2touch.purge(
                    "mapped",
                    input_stream=TerminalInput("no\n"),
                    output_stream=io.StringIO(),
                ),
                2,
            )
            with self.assertRaisesRegex(t2touch.T2TouchError, "--yes"):
                t2touch.purge("mapped", input_stream=io.StringIO("yes\n"))
            run.assert_not_called()

    def test_resume_is_explicit_and_does_not_repeat_the_confirmation(self):
        with (
            mock.patch.object(t2touch, "require_current_user"),
            mock.patch.object(t2touch, "service_ready", return_value=False),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(
                t2touch.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stderr=""),
            ) as run,
        ):
            self.assertEqual(
                t2touch.purge("mapped", resume=True, input_stream=io.StringIO()), 0
            )
            run.assert_called_once_with(
                [
                    "/usr/bin/pkexec",
                    "/usr/local/sbin/t2-touchid-purge",
                    "--resume",
                ],
                check=False,
                text=True,
                stderr=t2touch.subprocess.PIPE,
            )


if __name__ == "__main__":
    unittest.main()
