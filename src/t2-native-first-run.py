#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Complete Linux-native identity creation and activation for product setup."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from collections.abc import Callable

import t2_aks_provisioning
import t2_aks_replacement_activation_journal
import t2_aks_replacement_journal
import t2_user_mapping


STATE_ROOT = Path("/var/lib/t2-touchid")
MAPPING = STATE_ROOT / "users.json"
JOURNAL = STATE_ROOT / "native-provisioning.jsonl"
REPLACEMENT_JOURNAL = STATE_ROOT / "native-replacement.jsonl"
ACTIVATION_JOURNAL = STATE_ROOT / "native-replacement-activation.jsonl"
SOURCE_ROOT = Path(__file__).resolve().parent
ROOT_UID = 0
CREDENTIAL_SENTINEL = b"native-first-run-credential-unavailable"


class NativeFirstRunError(RuntimeError):
    pass


def _owner_failure_detail(completed: object) -> str | None:
    raw = getattr(completed, "stderr", None)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096:
        return None
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return None
    if not lines or ": error: " not in lines[-1]:
        return None
    detail = lines[-1].rsplit(": error: ", 1)[1]
    if not 0 < len(detail) <= 240 or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9 ._:/()#,+='-]*", detail
    ) is None:
        return None
    return detail


def _owner(
    arguments: list[str],
    *,
    runner: Callable[..., object] = subprocess.run,
    pass_fds: tuple[int, ...] = (),
) -> dict[str, object]:
    completed = runner(
        [sys.executable, *arguments],
        env={**os.environ, "T2_TOUCHID_FIRST_RUN_OWNER": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
        pass_fds=pass_fds,
    )
    if getattr(completed, "returncode", None) != 0:
        detail = _owner_failure_detail(completed)
        suffix = f": {detail}" if detail is not None else ""
        raise NativeFirstRunError(f"native first-run owner stopped{suffix}")
    try:
        document = json.loads(getattr(completed, "stdout", None))
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeFirstRunError(
            "native first-run owner returned malformed output"
        ) from error
    if not isinstance(document, dict) or document.get("identifiers_redacted") is not True:
        raise NativeFirstRunError(
            "native first-run owner returned malformed output"
        )
    return document


def _native_enrollment_module():
    path = SOURCE_ROOT / "t2-native-enroll.py"
    specification = importlib.util.spec_from_file_location(
        "t2_native_first_run_authority", path
    )
    if specification is None or specification.loader is None:
        raise NativeFirstRunError("native authority validator is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _credential_path() -> Path:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory or not Path(directory).is_absolute():
        raise NativeFirstRunError("native first-run credential is unavailable")
    path = Path(directory) / "t2-touchid-password"
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise NativeFirstRunError(
            "native first-run credential is unavailable"
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 0 < info.st_size <= 130
    ):
        raise NativeFirstRunError("native first-run credential is unsafe")
    if info.st_size == len(CREDENTIAL_SENTINEL):
        try:
            with path.open("rb") as credential:
                unavailable = credential.read(len(CREDENTIAL_SENTINEL) + 1)
        except OSError as error:
            raise NativeFirstRunError(
                "native first-run credential is unavailable"
            ) from error
        if unavailable == CREDENTIAL_SENTINEL:
            raise NativeFirstRunError("native first-run credential is unavailable")
    return path


def _credential_owner(
    arguments: list[str],
    *,
    runner: Callable[..., object],
) -> dict[str, object]:
    credential_path = _credential_path()
    descriptor = os.open(credential_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return _owner(
            [*arguments, "--credential-fd", str(descriptor)],
            runner=runner,
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)


def run(*, runner: Callable[..., object] = subprocess.run) -> tuple[str, bool]:
    mode = os.environ.get("T2_TOUCHID_AUTHORITY_MODE")
    if mode == "macos-control-oracle":
        return "compatibility-authority", False
    if mode != "linux-native":
        raise NativeFirstRunError("native first-run authority mode is invalid")
    if os.geteuid() != ROOT_UID:
        raise NativeFirstRunError("native first-run setup requires root")

    state_changed = False
    mapping_present = os.path.lexists(MAPPING)
    journal_present = os.path.lexists(JOURNAL)
    if not mapping_present and not journal_present:
        document = _credential_owner(
            [
                str(SOURCE_ROOT / "t2-native-provision.py"),
                "--acknowledge-one-shot-native-identity-create",
            ],
            runner=runner,
        )
        if (
            document.get("native_identity_created") is not True
            or document.get("mapping_enabled") is not False
            or document.get("fresh_owner_activation_required") is not True
            or document.get("reboot_verification_required") is not False
        ):
            raise NativeFirstRunError(
                "native identity creation did not reach runtime activation"
            )
        state_changed = True
        mapping_present = True
        journal_present = True
    if not mapping_present or not journal_present:
        raise NativeFirstRunError("native first-run state is incomplete")

    try:
        history = t2_aks_provisioning.read(JOURNAL)
    except t2_aks_provisioning.AKSProvisioningError as error:
        raise NativeFirstRunError("native provisioning history is invalid") from error
    if history.phase in {"mapping-committed", "reboot-verified"}:
        verification_option = (
            "--acknowledge-fresh-owner-activation"
            if history.phase == "mapping-committed"
            else "--acknowledge-one-shot-native-provisioning-verification"
        )
        document = _owner(
            [
                str(SOURCE_ROOT / "t2-native-provision-verify.py"),
                verification_option,
            ],
            runner=runner,
        )
        if (
            document.get("mapping_enabled") is not True
            or document.get("runtime_keybag_verified") is not True
        ):
            raise NativeFirstRunError(
                "native provisioning verification did not enable the mapping"
            )
        try:
            history = t2_aks_provisioning.read(JOURNAL)
        except t2_aks_provisioning.AKSProvisioningError as error:
            raise NativeFirstRunError(
                "native provisioning verification did not publish valid history"
            ) from error
        state_changed = True
    if history.phase != "mapping-enabled":
        raise NativeFirstRunError("native provisioning requires reconciliation")

    try:
        mapping_set = t2_user_mapping.load(MAPPING)
    except t2_user_mapping.UserMappingError as error:
        raise NativeFirstRunError("native mapping is invalid") from error
    if len(mapping_set.mappings) != 1:
        raise NativeFirstRunError("native mapping is not single-user")
    trusted_linux_uid = mapping_set.mappings[0].linux_uid
    if mapping_set.schema_version == t2_user_mapping.LEGACY_SCHEMA_VERSION:
        native = _native_enrollment_module()
        try:
            native._require_fresh_enrollment_state()
        except RuntimeError as error:
            raise NativeFirstRunError(
                "legacy native authority is not a blank first-run state"
            ) from error
        if os.path.lexists(ACTIVATION_JOURNAL):
            raise NativeFirstRunError(
                "native activation exists before its schema-2 mapping"
            )
        if os.path.lexists(REPLACEMENT_JOURNAL):
            try:
                replacement = t2_aks_replacement_journal.read(
                    REPLACEMENT_JOURNAL
                )
            except t2_aks_replacement_journal.AKSReplacementJournalError as error:
                raise NativeFirstRunError(
                    "native activation-bundle history is invalid"
                ) from error
            if replacement.phase == "complete":
                raise NativeFirstRunError(
                    "native activation bundle and mapping disagree"
                )
            document = _owner(
                [
                    str(SOURCE_ROOT / "t2-native-replace.py"),
                    "resume",
                    "--acknowledge-native-identity-replacement-recovery",
                ],
                runner=runner,
            )
        else:
            document = _credential_owner(
                [
                    str(SOURCE_ROOT / "t2-native-replace.py"),
                    "start",
                    "--acknowledge-one-shot-native-identity-replacement",
                ],
                runner=runner,
            )
        if (
            document.get("phase") != "complete"
            or document.get("replacement_complete") is not True
            or document.get("mapping_enabled") is not False
            or document.get("fresh_owner_activation_required") is not True
            or document.get("different_boot_activation_required") is not False
        ):
            raise NativeFirstRunError(
                "native activation-bundle creation requires reconciliation"
            )
        state_changed = True
        try:
            mapping_set = t2_user_mapping.load(MAPPING)
        except t2_user_mapping.UserMappingError as error:
            raise NativeFirstRunError("native mapping is invalid") from error
    if mapping_set.schema_version != t2_user_mapping.SCHEMA_VERSION:
        raise NativeFirstRunError("native mapping schema is unsupported")
    try:
        replacement = t2_aks_replacement_journal.read(REPLACEMENT_JOURNAL)
    except t2_aks_replacement_journal.AKSReplacementJournalError as error:
        raise NativeFirstRunError(
            "native activation-bundle history is invalid"
        ) from error
    if replacement.phase == "mapping-committed":
        document = _owner(
            [
                str(SOURCE_ROOT / "t2-native-replace.py"),
                "resume",
                "--acknowledge-native-identity-replacement-recovery",
            ],
            runner=runner,
        )
        if (
            document.get("phase") != "complete"
            or document.get("replacement_complete") is not True
            or document.get("mapping_enabled") is not False
            or document.get("fresh_owner_activation_required") is not True
            or document.get("different_boot_activation_required") is not False
        ):
            raise NativeFirstRunError(
                "native activation-bundle recovery requires reconciliation"
            )
        state_changed = True
    if replacement.phase != "complete":
        raise NativeFirstRunError("native activation bundle is incomplete")

    if os.path.lexists(ACTIVATION_JOURNAL):
        try:
            activation = t2_aks_replacement_activation_journal.read(
                ACTIVATION_JOURNAL
            )
        except (
            t2_aks_replacement_activation_journal.AKSReplacementActivationJournalError
        ) as error:
            raise NativeFirstRunError("native activation history is invalid") from error
        activation_action = "ready" if activation.phase == "complete" else "resume"
    else:
        activation_action = "start"
    activation_changed = activation_action != "ready"
    if activation_changed:
        arguments = [
            str(SOURCE_ROOT / "t2-native-replace-activate.py"),
            activation_action,
            (
                "--acknowledge-one-shot-replacement-activation"
                if activation_action == "start"
                else "--acknowledge-replacement-activation-recovery"
            ),
        ]
        document = _owner(arguments, runner=runner)
        if (
            document.get("phase") != "complete"
            or document.get("independent_activation_proved") is not True
            or document.get("mapping_enabled") is not True
            or document.get("fingerprint_mutation_performed") is not False
        ):
            raise NativeFirstRunError(
                "native activation did not reach its independent proof"
            )
        state_changed = True

    try:
        mapping_set = t2_user_mapping.load(MAPPING)
    except t2_user_mapping.UserMappingError as error:
        raise NativeFirstRunError("native activated mapping is invalid") from error
    if (
        mapping_set.schema_version != t2_user_mapping.SCHEMA_VERSION
        or len(mapping_set.mappings) != 1
        or mapping_set.mappings[0].linux_uid != trusted_linux_uid
    ):
        raise NativeFirstRunError("native activated mapping changed authority")
    native = _native_enrollment_module()
    configuration = native._configuration(
        trusted_linux_uid=trusted_linux_uid
    )
    native._load_provisioned_authority(
        trusted_linux_uid, configuration["apple_uid"]
    )
    return "mapping-ready", state_changed or activation_changed


def main() -> int:
    try:
        state, changed = run()
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "state": state,
                    "state_changed": changed,
                    "identifiers_redacted": True,
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, NativeFirstRunError) as error:
        print(
            f"t2-native-first-run: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
