#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import unittest
import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "t2_native_pam_ready", ROOT / "src/t2_native_pam_ready.py"
)
NATIVE_READY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(NATIVE_READY)


class PamAssetTests(unittest.TestCase):
    def test_installer_manages_both_omarchy_lock_stacks(self):
        installer = (ROOT / "tools/install-pam.sh").read_text()

        self.assertIn("install_one omarchy-lock-password", installer)
        self.assertIn("install_one omarchy-lock-fingerprint", installer)
        self.assertIn("install_system_auth_hook", installer)
        self.assertIn("system-auth.original", installer)
        self.assertIn("pam_faillock\\.so[[:space:]]+authfail", installer)
        self.assertIn("pam_faillock\\.so[[:space:]]+authsucc", installer)
        self.assertIn("authfail_line != unix_line + 1", installer)
        self.assertIn("$1.installed", installer)
        self.assertIn("mv -f -- \"$tmp\" \"$target\"", installer)
        self.assertIn("T2TOUCH_FORCE_PAM", installer)
        self.assertIn("--force", installer)
        self.assertIn("refuse_unfamiliar_first_install", installer)
        self.assertIn("pam/upstream/", installer)

    def test_rollback_restores_or_removes_every_managed_stack(self):
        rollback = (ROOT / "tools/rollback-pam.sh").read_text()

        self.assertIn(
            "for name in sudo polkit-1 omarchy-lock-password "
            "omarchy-lock-fingerprint",
            rollback,
        )
        self.assertIn("system-auth.original", rollback)
        self.assertIn("removed == 2", rollback)
        self.assertIn("$backup_dir/$name.absent", rollback)
        self.assertIn('rm -f -- "$target"', rollback)
        self.assertIn('rm -f -- "$backup" "$absent" "$installed"', rollback)
        self.assertIn("Refusing to overwrite changed PAM stack", rollback)

    def test_unprivileged_omarchy_password_stack_includes_system_auth(self):
        password_stack = (ROOT / "pam/omarchy-lock-password").read_text()

        self.assertNotIn("t2-pam-unlock", password_stack)
        self.assertNotIn("pam_fprintd.so", password_stack)
        self.assertIn("include                     system-auth", password_stack)
        self.assertIn("omarchy-lock-fingerprint", password_stack.splitlines()[2])

    def test_first_install_fingerprints_cover_stock_arch_and_omarchy(self):
        upstream = ROOT / "pam/upstream"
        for name in (
            "sudo.arch",
            "sudo.arch-systemd-session",
            "polkit-1.arch",
            "omarchy-lock-password.omarchy",
            "omarchy-lock-password.omarchy-no-spdx",
            "omarchy-lock-fingerprint.omarchy",
        ):
            self.assertTrue((upstream / name).is_file(), name)
        current_sudo = (upstream / "sudo.arch-systemd-session").read_text()
        self.assertIn("pam_systemd.so class=none", current_sudo)
        current_lock = (
            upstream / "omarchy-lock-password.omarchy-no-spdx"
        ).read_text()
        self.assertIn("pam_faillock.so authsucc", current_lock)
        fingerprint = (ROOT / "pam/omarchy-lock-fingerprint").read_text()
        self.assertIn("pam_fprintd.so", fingerprint)
        self.assertNotIn("sufficient", fingerprint)

    def test_sudo_skips_fingerprint_until_keybags_are_ready(self):
        sudo_stack = (ROOT / "pam/sudo").read_text()

        self.assertIn("[success=4 default=ignore]", sudo_stack)
        self.assertIn("[success=ignore default=3]", sudo_stack)
        self.assertIn("t2-pam-fingerprint-ready", sudo_stack)
        self.assertNotIn("t2-pam-unlock", sudo_stack)

    def test_native_e4_readiness_does_not_require_compatibility_markers(self):
        selected = SimpleNamespace(linux_uid=1000)
        authority = SimpleNamespace(
            origin="linux-native-e4",
            selected=selected,
            mapping_set=SimpleNamespace(
                resolve=lambda linux_uid, capability: (
                    selected
                    if (linux_uid, capability) == (1000, "verify")
                    else None
                )
            ),
        )
        NATIVE_READY.require_native_readiness(
            1000,
            authority_loader=lambda _uid: authority,
            mutation_scanner=lambda _root: (
                SimpleNamespace(blocks_new_mutation=False),
            ),
        )

        helper = (ROOT / "src/t2-pam-fingerprint-ready.sh").read_text()
        self.assertIn("T2_TOUCHID_AUTHORITY_MODE", helper)
        self.assertIn("t2_native_pam_ready.py", helper)
        self.assertIn("keybags-unlocked", helper)

    def test_pam_unlock_prompts_separately_without_shell_storage(self):
        helper = (ROOT / "src/t2-pam-unlock.sh").read_text()

        self.assertIn('unlock-keybags "$session"', helper)
        self.assertIn("t2-pam-fingerprint-ready", helper)
        self.assertNotIn("read -r password", helper)
        self.assertNotIn("printf '%s\\n'", helper)
        installer = (ROOT / "tools/install-pam.sh").read_text()
        self.assertIn(
            "local hook='auth optional pam_exec.so quiet seteuid ", installer
        )

    def test_sudo_prompt_warns_against_early_password_input(self):
        prompt = (ROOT / "src/t2-pam-fingerprint-prompt.c").read_text()

        self.assertNotIn("◎", prompt)
        self.assertIn("Preparing the fingerprint sensor", prompt)
        self.assertIn("hear the ready cue", prompt)
        self.assertNotIn("Touch the fingerprint sensor now", prompt)
        self.assertIn("Do not type your password until", prompt)

    def test_action_marker_wraps_only_the_live_fingerprint_request(self):
        source = (ROOT / "src/pam_t2touch_action_prompt.c").read_text()

        self.assertIn("◎ Place your finger on the fingerprint reader", source)
        self.assertIn('strcmp(rewritten[index].msg, action_prompt) == 0', source)
        self.assertIn("pam_set_item(pamh, PAM_CONV, &context->upstream)", source)
        self.assertIn("live->conv == marked_conversation", source)
        for name in ("sudo", "polkit-1", "omarchy-lock-fingerprint"):
            stack = (ROOT / "pam" / name).read_text()
            marker = stack.index("pam_t2touch_action_prompt.so")
            fingerprint = stack.index("pam_fprintd.so")
            self.assertLess(marker, fingerprint)

    def test_every_successful_unlock_path_publishes_readiness(self):
        for name in (
            "t2-keybag-unlock.sh",
            "t2-pam-unlock.sh",
            "t2-credential-unlock.sh",
        ):
            source = (ROOT / "src" / name).read_text()
            self.assertIn("keybags-unlocked", source)
            self.assertIn("install -o root -g root -m 0600", source)
            normalized = source.upper()
            self.assertIn('CMP -S -- "$SNAPSHOT" "$STATE_FILE"', normalized)
            self.assertIn('MV -F -- "$SNAPSHOT" "$READY_FILE"', normalized)

        loader = (ROOT / "src/t2-keybag-load.sh").read_text()
        self.assertIn('rm -f -- "$READY_FILE"', loader)

    def test_manual_unlock_refreshes_only_an_active_fprintd(self):
        helper = (ROOT / "src/t2-keybag-unlock.sh").read_text()

        self.assertIn("systemctl try-restart --no-block fprintd.service", helper)
        self.assertIn("systemd-ask-password", helper)
        self.assertIn("unlock-keybags-stdin", helper)
        self.assertNotIn('read -r password', helper)

    def test_interactive_unlock_service_is_bounded_and_hardened(self):
        service = (ROOT / "systemd/system/t2-interactive-unlock.service").read_text()
        fprintd = (ROOT / "systemd/system/fprintd.service").read_text()

        self.assertIn("Requires=t2-keybag-load.service", service)
        self.assertIn("ConditionPathExists=!/etc/credstore.encrypted/", service)
        self.assertIn("TimeoutStartSec=150", service)
        self.assertIn("LimitCORE=0", service)
        self.assertIn("LimitMEMLOCK=65536", service)
        self.assertIn("ReadWritePaths=/run/t2-touchid", service)
        self.assertIn("DevicePolicy=closed", service)
        self.assertIn("DeviceAllow=/dev/t2-aks rw", service)
        self.assertNotIn("t2-interactive-unlock.service", fprintd)
        self.assertNotIn("t2-interactive-unlock.service", fprintd.split("After=", 1)[1])
        install = (ROOT / "install.sh").read_text()
        self.assertNotIn("enable t2-interactive-unlock.service", install)
        self.assertIn("disable --now t2-interactive-unlock.service", install)
        self.assertIn("t2-interactive-unlock", (ROOT / "uninstall.sh").read_text())

    def test_first_install_requires_force_for_unfamiliar_stacks(self):
        installer = (ROOT / "tools/install-pam.sh").read_text()
        self.assertIn("refuse_unfamiliar_first_install", installer)
        self.assertIn("T2TOUCH_FORCE_PAM", installer)
        self.assertIn("--force", installer)
        self.assertTrue((ROOT / "pam/upstream/sudo.arch").is_file())
        self.assertIn("include                     system-auth", (ROOT / "pam/omarchy-lock-password").read_text())

    def test_reference_polkit_rule_is_an_example(self):
        self.assertFalse((ROOT / "tools/49-t2-touchid-reference-user.rules").exists())
        example = ROOT / "tools/49-t2-touchid-reference-user.rules.example"
        self.assertTrue(example.is_file())
        self.assertIn("polkit.Result.YES", example.read_text())

    def test_doctor_warns_about_yes_mutation_rules(self):
        doctor = (ROOT / "src/t2-touchid-doctor.py").read_text()
        self.assertIn("polkit.Result.YES", doctor)
        self.assertIn("enroll/identity-management", doctor)

    def test_pam_prompt_restores_the_original_conversation(self):
        source = (ROOT / "src/pam_t2touch_action_prompt.c").read_text()
        self.assertIn("pam_set_item(pamh, PAM_CONV, &context->upstream)", source)


if __name__ == "__main__":
    unittest.main()
