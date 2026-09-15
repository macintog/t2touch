#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free first-run routing for Linux-owned AKS state."""

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
import sys

sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_native_first_run", SOURCE / "t2-native-first-run.py"
)
FIRST_RUN = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(FIRST_RUN)


class NativeFirstRunTests(unittest.TestCase):
    def test_authority_failure_is_bounded_without_a_traceback(self):
        class NativeEnrollmentError(RuntimeError):
            pass

        native = SimpleNamespace(
            NativeEnrollmentError=NativeEnrollmentError,
            _load_provisioned_authority=mock.Mock(
                side_effect=NativeEnrollmentError("account generation changed")
            ),
        )
        with self.assertRaisesRegex(
            FIRST_RUN.NativeFirstRunError, "account generation changed"
        ):
            FIRST_RUN._validate_provisioned_authority(native, 1000, 501)

    def test_owner_surfaces_only_bounded_printable_parser_error(self):
        completed = SimpleNamespace(
            returncode=2,
            stdout=b"",
            stderr=(
                b"usage: t2-native-replace.py resume\n"
                b"t2-native-replace.py: error: replacement transport is not enabled\n"
            ),
        )
        with self.assertRaisesRegex(
            FIRST_RUN.NativeFirstRunError,
            "replacement transport is not enabled",
        ):
            FIRST_RUN._owner(["ignored"], runner=lambda *_args, **_kwargs: completed)

        completed.stderr = (
            b"child: error: identity provisioning failed at "
            b"credential-bearing-consumer; context was cleaned up\n"
        )
        with self.assertRaisesRegex(
            FIRST_RUN.NativeFirstRunError, "credential-bearing-consumer; context was cleaned up"
        ):
            FIRST_RUN._owner(["ignored"], runner=lambda *_args, **_kwargs: completed)

        completed.stderr = b"child: error: unsafe\x00detail\n"
        with self.assertRaisesRegex(
            FIRST_RUN.NativeFirstRunError, "^native first-run owner stopped$"
        ):
            FIRST_RUN._owner(["ignored"], runner=lambda *_args, **_kwargs: completed)

    def test_reserved_fallback_is_not_accepted_as_identity_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            credential_root = Path(directory)
            credential = credential_root / "t2-touchid-password"
            credential.write_bytes(FIRST_RUN.CREDENTIAL_SENTINEL)
            credential.chmod(0o600)
            with mock.patch.object(FIRST_RUN, "ROOT_UID", os.geteuid()), mock.patch.dict(
                os.environ, {"CREDENTIALS_DIRECTORY": str(credential_root)}
            ):
                with self.assertRaisesRegex(
                    FIRST_RUN.NativeFirstRunError, "credential is unavailable"
                ):
                    FIRST_RUN._credential_path()

    def test_owner_failure_is_reported_without_fabricating_a_boot_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = root / "users.json"
            journal = root / "native-provisioning.jsonl"
            mapping.touch(mode=0o600)
            journal.touch(mode=0o600)
            mapped = SimpleNamespace(linux_uid=1000)
            legacy_mapping = SimpleNamespace(
                schema_version=FIRST_RUN.t2_user_mapping.LEGACY_SCHEMA_VERSION,
                mappings=(mapped,),
            )
            with (
                mock.patch.object(FIRST_RUN, "MAPPING", mapping),
                mock.patch.object(FIRST_RUN, "JOURNAL", journal),
                mock.patch.object(
                    FIRST_RUN, "REPLACEMENT_JOURNAL", root / "replacement.jsonl"
                ),
                mock.patch.object(
                    FIRST_RUN, "ACTIVATION_JOURNAL", root / "activation.jsonl"
                ),
                mock.patch.object(FIRST_RUN, "ROOT_UID", os.geteuid()),
                mock.patch.dict(
                    os.environ, {"T2_TOUCHID_AUTHORITY_MODE": "linux-native"}
                ),
                mock.patch.object(
                    FIRST_RUN.t2_aks_provisioning,
                    "read",
                    return_value=SimpleNamespace(phase="mapping-enabled"),
                ),
                mock.patch.object(
                    FIRST_RUN.t2_user_mapping,
                    "load",
                    return_value=legacy_mapping,
                ),
                mock.patch.object(
                    FIRST_RUN, "_native_enrollment_module", return_value=mock.Mock()
                ),
                mock.patch.object(
                    FIRST_RUN,
                    "_credential_owner",
                    side_effect=FIRST_RUN.NativeFirstRunError(
                        "native first-run owner stopped"
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    FIRST_RUN.NativeFirstRunError,
                    "native first-run owner stopped",
                ):
                    FIRST_RUN.run()

    def test_blank_authority_reaches_ready_in_one_running_system(self):
        """Catch any reintroduction of a staged reboot return in product setup."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = root / "users.json"
            journal = root / "native-provisioning.jsonl"
            replacement_journal = root / "native-replacement.jsonl"
            activation_journal = root / "native-replacement-activation.jsonl"
            credential_root = root / "credentials"
            credential_root.mkdir(mode=0o700)
            credential = credential_root / "t2-touchid-password"
            credential.write_bytes(b"synthetic\n")
            credential.chmod(0o600)
            mapped = SimpleNamespace(linux_uid=1000)
            state = {
                "provisioning": "new",
                "mapping_schema": FIRST_RUN.t2_user_mapping.LEGACY_SCHEMA_VERSION,
                "replacement": "new",
                "activation": "new",
            }
            commands = []

            def runner(command, **_arguments):
                commands.append(command)
                program = Path(command[1]).name
                if program == "t2-native-provision.py":
                    mapping.touch(mode=0o600)
                    journal.touch(mode=0o600)
                    state["provisioning"] = "mapping-committed"
                    document = {
                        "identifiers_redacted": True,
                        "native_identity_created": True,
                        "mapping_enabled": False,
                        "fresh_owner_activation_required": True,
                        "reboot_verification_required": False,
                    }
                elif program == "t2-native-provision-verify.py":
                    state["provisioning"] = "mapping-enabled"
                    document = {
                        "identifiers_redacted": True,
                        "mapping_enabled": True,
                        "runtime_keybag_verified": True,
                    }
                elif program == "t2-native-replace.py":
                    replacement_journal.touch(mode=0o600)
                    state["replacement"] = "complete"
                    state["mapping_schema"] = FIRST_RUN.t2_user_mapping.SCHEMA_VERSION
                    document = {
                        "identifiers_redacted": True,
                        "phase": "complete",
                        "replacement_complete": True,
                        "mapping_enabled": False,
                        "fresh_owner_activation_required": True,
                        "different_boot_activation_required": False,
                    }
                elif program == "t2-native-replace-activate.py":
                    activation_journal.touch(mode=0o600)
                    state["activation"] = "complete"
                    document = {
                        "identifiers_redacted": True,
                        "phase": "complete",
                        "independent_activation_proved": True,
                        "mapping_enabled": True,
                        "fingerprint_mutation_performed": False,
                    }
                else:
                    raise AssertionError(program)
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(document).encode(),
                    stderr=b"",
                )

            native = mock.Mock()
            native._configuration.return_value = {
                "linux_uid": 1000,
                "apple_uid": 501,
            }

            def load_mapping(_path):
                return SimpleNamespace(
                    schema_version=state["mapping_schema"],
                    mappings=(mapped,),
                )

            common = (
                mock.patch.object(FIRST_RUN, "MAPPING", mapping),
                mock.patch.object(FIRST_RUN, "JOURNAL", journal),
                mock.patch.object(
                    FIRST_RUN, "REPLACEMENT_JOURNAL", replacement_journal
                ),
                mock.patch.object(
                    FIRST_RUN, "ACTIVATION_JOURNAL", activation_journal
                ),
                mock.patch.object(FIRST_RUN, "ROOT_UID", os.geteuid()),
                mock.patch.dict(
                    os.environ,
                    {
                        "T2_TOUCHID_AUTHORITY_MODE": "linux-native",
                        "CREDENTIALS_DIRECTORY": str(credential_root),
                    },
                ),
                mock.patch.object(
                    FIRST_RUN.t2_aks_provisioning,
                    "read",
                    side_effect=lambda _path: SimpleNamespace(
                        phase=state["provisioning"]
                    ),
                ),
                mock.patch.object(
                    FIRST_RUN.t2_user_mapping,
                    "load",
                    side_effect=load_mapping,
                ),
                mock.patch.object(
                    FIRST_RUN.t2_aks_replacement_journal,
                    "read",
                    side_effect=lambda _path: SimpleNamespace(
                        phase=state["replacement"]
                    ),
                ),
                mock.patch.object(
                    FIRST_RUN.t2_aks_replacement_activation_journal,
                    "read",
                    side_effect=lambda _path: SimpleNamespace(
                        phase=state["activation"]
                    ),
                ),
                mock.patch.object(
                    FIRST_RUN, "_native_enrollment_module", return_value=native
                ),
            )
            with (
                common[0],
                common[1],
                common[2],
                common[3],
                common[4],
                common[5],
                common[6],
                common[7],
                common[8],
                common[9],
                common[10],
            ):
                result = FIRST_RUN.run(runner=runner)
                ready_again = FIRST_RUN.run(runner=runner)

            self.assertEqual(result, ("mapping-ready", True))
            self.assertEqual(ready_again, ("mapping-ready", False))
            self.assertEqual(
                [Path(command[1]).name for command in commands],
                [
                    "t2-native-provision.py",
                    "t2-native-provision-verify.py",
                    "t2-native-replace.py",
                    "t2-native-replace-activate.py",
                ],
            )
            self.assertIn("--acknowledge-fresh-owner-activation", commands[1])
            self.assertIn(
                "--acknowledge-one-shot-replacement-activation", commands[3]
            )
            native._require_fresh_enrollment_state.assert_called_once_with()
            self.assertEqual(native._load_provisioned_authority.call_count, 2)


if __name__ == "__main__":
    unittest.main()
