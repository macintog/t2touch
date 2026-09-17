#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free checks for installer portability assumptions."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def test_kernel_gate_precedes_product_writes(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertLess(
            installer.index("require_t2_hardware || exit $?"),
            installer.index("check_applesmc_prerequisite"),
        )
        self.assertLess(
            installer.index("check_applesmc_prerequisite"),
            installer.index("target_dir=/opt/t2-touchid"),
        )
        self.assertLess(
            installer.index("prepare_transport_update"),
            installer.index("target_dir=/opt/t2-touchid"),
        )

    def test_upgrade_exception_requires_health_or_validated_recovery(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")

        self.assertIn("if (( live_transport_matches && healthy_installed_chain ))", installer)
        self.assertIn("stat -c '%u:%g:%a:%h' /etc/t2-touchid.conf", installer)
        for unit in (
            "t2-bridge-network.service",
            "t2-biometric-port-refresh.service",
            "t2-sep-transport.service",
            "t2-native-first-run.service",
            "t2-biometric-ready.service",
            "fprintd.service",
        ):
            self.assertIn(unit, installer)
        self.assertIn(
            "active_installed_upgrade || validated_recovery_upgrade || "
            "prepared_installed_upgrade || legacy_prepared_upgrade",
            installer,
        )
        self.assertIn(
            'python3 "$source_dir/tools/validate-completed-native-install.py"',
            installer,
        )
        self.assertIn("prepared_transport_update_matches", installer)
        self.assertIn("validate-completed-native-install.py", installer)

    def test_dbus_policy_directory_is_created_before_policy_write(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        directory = (
            "install -d -o root -g root -m 0755 /etc/dbus-1/system.d"
        )
        policy = "cat >/etc/dbus-1/system.d/99-t2-touchid-fprint.conf"

        self.assertIn(directory, installer)
        self.assertIn(policy, installer)
        self.assertLess(installer.index(directory), installer.index(policy))

    def test_optional_network_recovery_is_installed_and_uninstalled(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        helper = "t2-bridge-network-ready"
        unit = "t2-bridge-network-ready@.service"

        self.assertIn(helper, installer)
        self.assertIn(helper, uninstaller)
        self.assertIn(unit, uninstaller)
        self.assertNotIn("systemctl enable t2-bridge-network-ready", installer)

    def test_installer_enables_common_product_chain_by_default(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")

        self.assertIn(
            "systemctl enable t2-bridge-network.service "
            "t2-sep-transport.service "
            "t2-biometric-port-refresh.service t2-biometric-ready.service "
            "fprintd.service",
            installer,
        )
        self.assertIn(
            "if [[ $authority_mode == macos-control-oracle ]]; then",
            installer,
        )
        self.assertIn(
            "systemctl enable t2-keybag-load.service "
            "t2-credential-unlock.service",
            installer,
        )
        self.assertIn(
            "systemctl disable --now t2-keybag-load.service "
            "t2-credential-unlock.service",
            installer,
        )
        self.assertIn("systemctl stop fprintd.service", installer)
        self.assertIn("live_transport_matches", installer)
        self.assertIn(
            '"$source_dir/modprobe.d/t2-sep-transport-autoload.conf"',
            installer,
        )
        self.assertNotIn("t2-user-activation@.service", installer)
        self.assertNotIn("t2-user-activation.socket", installer)
        self.assertTrue(
            (ROOT / "systemd/research/t2-user-activation.socket").is_file()
        )
        self.assertFalse(
            (ROOT / "systemd/system/t2-user-activation.socket").exists()
        )
        self.assertNotIn(
            "\n  /usr/local/sbin/t2-sep-transport-unload\n", installer
        )

    def test_fprintd_and_oneshots_use_worker_style_hardening(self):
        fprintd = (ROOT / "systemd/system/fprintd.service").read_text(
            encoding="utf-8"
        )
        for required in (
            "CapabilityBoundingSet=",
            "RestrictNamespaces=true",
            "LockPersonality=true",
            "SystemCallArchitectures=native",
            "ProtectProc=default",
            "DevicePolicy=closed",
        ):
            self.assertIn(required, fprintd)
        self.assertNotIn("ProtectProc=invisible", fprintd)
        capabilities = next(
            line.split("=", 1)[1].split()
            for line in fprintd.splitlines()
            if line.startswith("CapabilityBoundingSet=")
        )
        self.assertNotIn("CAP_KILL", capabilities)
        self.assertNotIn("CAP_SYS_PTRACE", capabilities)
        self.assertNotIn("RestrictSUIDSGID=", fprintd)
        for unit in (
            "t2-keybag-load.service",
            "t2-sep-transport.service",
            "t2-biometric-port-refresh.service",
        ):
            text = (ROOT / "systemd/system" / unit).read_text(encoding="utf-8")
            self.assertIn("ProtectSystem=strict", text)
            self.assertIn("NoNewPrivileges=", text)
            self.assertIn("CapabilityBoundingSet=", text)
        keybag = (ROOT / "systemd/system/t2-keybag-load.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("DeviceAllow=/dev/t2-aks rw", keybag)
        refresh = (
            ROOT / "systemd/system/t2-biometric-port-refresh.service"
        ).read_text(encoding="utf-8")
        self.assertIn("ReadWritePaths=/var/lib/t2-touchid", refresh)
        transport = (ROOT / "systemd/system/t2-sep-transport.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("SystemCallFilter=@system-service @module", transport)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_MODULE", transport)

    def test_native_activation_reports_each_prerequisite_before_fprintd(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        helper = (ROOT / "tools/installer-services.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('source "$source_dir/tools/installer-services.sh"', installer)
        self.assertIn("start_linux_native_touchid_chain || exit $?", installer)
        ordered = (
            "start_touchid_stage t2-native-first-run.service",
            "start_touchid_stage t2-biometric-ready.service",
            "start_touchid_stage t2-touchid-post-reboot.service",
            "start_touchid_stage fprintd.service",
        )
        positions = [helper.rindex(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            "Earlier stages may have completed; no automatic rollback or account rebinding was attempted.",
            helper,
        )
        self.assertIn("Account rebinding is intentionally never automatic.", helper)

    def test_native_activation_stops_at_exact_failed_boundary(self):
        helper = ROOT / "tools/installer-services.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "systemctl.log"
            systemctl = root / "systemctl"
            systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >>\"$SYSTEMCTL_LOG\"\n"
                "if [[ $1 == start && $2 == \"$FAIL_UNIT\" ]]; then exit 1; fi\n"
                "if [[ $1 == --no-pager ]]; then echo 'bounded status'; exit 3; fi\n",
                encoding="utf-8",
            )
            systemctl.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{root}:/usr/bin:/bin",
                "SYSTEMCTL_LOG": str(log),
                "FAIL_UNIT": "t2-touchid-post-reboot.service",
            }
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'target_uid=1000; source "$1"; start_linux_native_touchid_chain',
                    "installer-test",
                    str(helper),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            calls = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            calls[:3],
            [
                "start t2-native-first-run.service",
                "start t2-biometric-ready.service",
                "start t2-touchid-post-reboot.service",
            ],
        )
        self.assertIn(
            "--no-pager --full status t2-touchid-post-reboot.service", calls
        )
        self.assertNotIn("start fprintd.service", calls)
        self.assertIn("pending mutation reconciliation", completed.stderr)
        self.assertIn("no automatic rollback or account rebinding", completed.stderr)
        self.assertNotIn("sudo t2-touchid-user-map", completed.stderr)

    def test_product_scripts_do_not_require_a_reboot(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        loader = (ROOT / "src/t2-sep-transport-load.sh").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("reboot required", installer.lower())
        self.assertNotIn("reboot required", uninstaller.lower())
        self.assertNotIn("reboot required", loader.lower())
        self.assertIn(
            "dkms remove -m t2-sep-transport -v 0.1.0 --all",
            uninstaller,
        )
        self.assertIn(
            'rm -rf -- "$dkms_source"',
            uninstaller,
        )
        self.assertNotIn(
            '"$source_dir/src/t2-sep-transport-unload.sh"', uninstaller
        )

    def test_capability_probe_is_independent_from_identity_creation(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        example = (ROOT / "t2-touchid.conf.example").read_text(encoding="utf-8")

        self.assertIn("T2_TOUCHID_PROBE_CAPABILITIES=0", example)
        self.assertIn('module_options+=" probe_capabilities=1"', installer)
        self.assertIn('module_options+=" enable_identity_provisioning=1"', installer)
        self.assertNotIn(
            'module_options+=" probe_capabilities=1 enable_identity_provisioning=1"',
            installer,
        )
        self.assertIn(
            '[[ $acm_research != 1 ]] || [[ $probe_capabilities != 1 ]]',
            installer,
        )
        self.assertNotIn('module_options+=" xart_os_uuid=', installer)
        self.assertNotIn('module_options+=" defer_xart_publish=', installer)

    def test_first_install_requires_logout_before_enroll(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        wrapper = (ROOT / "install-omarchy.sh").read_text(encoding="utf-8")
        self.assertIn("T2TOUCH_OMARCHY_WRAPPER=1", wrapper)
        self.assertIn("Log out and sign back in now, then run: t2touch enroll", wrapper)
        self.assertIn("NEXT STEP", wrapper)
        self.assertNotIn(
            "t2touch is ready. Enroll a fingerprint with:",
            installer,
        )
        self.assertIn(
            "Log out and sign back in, then enroll a fingerprint with:",
            installer,
        )

    def test_umask_is_scoped_to_credential_encrypt(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn(
            "( umask 077; printf '%s\\n' \"$identity_credential\" | systemd-creds encrypt",
            installer,
        )
        self.assertNotIn("\n      umask 077\n", installer)

    def test_dkms_precedes_unit_enable(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        enable = (
            "systemctl enable t2-bridge-network.service "
            "t2-sep-transport.service "
            "t2-biometric-port-refresh.service t2-biometric-ready.service "
            "fprintd.service"
        )
        rebuild = installer.index("\nrebuild_boot_images\n")
        self.assertLess(installer.index("t2-sep-boot-state.conf"), rebuild)
        self.assertLess(rebuild, installer.index(enable))
        self.assertLess(installer.index("dkms build --force"), installer.index(enable))
        self.assertLess(installer.index("dkms build --force"), rebuild)
        self.assertIn("rollback_units_after_dkms_failure", installer)
        self.assertIn("capture_prior_install_state", installer)
        self.assertLess(
            installer.index("capture_prior_install_state"),
            installer.index('"$source_dir/systemd/system/fprintd.service"'),
        )
        self.assertGreater(
            installer.index("capture_prior_install_state"),
            installer.index("check_applesmc_prerequisite"),
        )
        self.assertNotIn(
            "\n        disable_and_remove_product_units\n", installer
        )
        self.assertIn(
            "product units will still be enabled without a DKMS-registered transport",
            installer,
        )

    def test_research_helpers_are_installed_off_path(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("/opt/t2-touchid/bin/t2-catacomb-fixture-check", installer)
        self.assertIn("/opt/t2-touchid/bin/t2-fprintd-negative-tui-launch", installer)
        self.assertIn("/usr/local/sbin/t2-fprintd-enroll-tui-launch", installer)
        self.assertIn("/usr/local/sbin/t2-acm-preflight", installer)
        self.assertNotIn(
            "/usr/local/sbin/t2-catacomb-fixture-check", installer
        )
        self.assertNotIn(
            "/usr/local/sbin/t2-fprintd-negative-tui-launch", installer
        )
        self.assertIn("t2-catacomb-fixture-check", uninstaller)
        self.assertIn("t2-sudo-pam-test-launch", uninstaller)
        self.assertIn("remove_legacy_path_research_helpers", installer)

    def test_uninstall_removes_native_enroll_and_mbp162_override(self):
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("t2-native-enroll", uninstaller)
        self.assertIn("t2-sep-prerequisite-ready", uninstaller)
        self.assertIn("t2-sep-create-version.conf", uninstaller)

    def test_sudo_user_is_validated_before_use(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn(
            '[[ ! $SUDO_USER =~ ^[a-z_][a-z0-9_-]*$ ]]', installer
        )
        self.assertIn("tools/provision-credential.sh", installer)
        self.assertIn("restore_checkout_build_outputs", installer)

    def test_expected_reboot_stop_prints_next_step_on_stdout(self):
        helper = (ROOT / "tools/installer-kernel.sh").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('printf \'\\n%s\\n%s\\n\\n\' "NEXT STEP"', helper)
        self.assertIn("Remedy: install matching kernel headers", helper)
        self.assertIn("exits `3` when a reboot is required", readme)

    def _run_dkms_rollback_fixture(
        self,
        *,
        prior_units=(),
        recovery_hold=False,
        recovery_dropins=(),
        config=False,
        copy_after_capture=(),
        extra_bash="",
    ):
        helper = ROOT / "tools/installer-services.sh"
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        unit_root = root / "units"
        state_root = root / "state"
        sleep_dir = root / "sleep.conf.d"
        config_path = root / "t2-touchid.conf"
        log = root / "systemctl.log"
        unit_root.mkdir()
        state_root.mkdir()
        sleep_dir.mkdir()
        systemctl = root / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >>\"$SYSTEMCTL_LOG\"\n"
            "if [[ $1 == is-active ]]; then\n"
            "  exit 3\n"
            "fi\n",
            encoding="utf-8",
        )
        systemctl.chmod(0o755)
        for name in prior_units:
            path = unit_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("prior-unit\n", encoding="utf-8")
        if recovery_hold:
            hold = state_root / "native-recovery-hold"
            hold.write_text("", encoding="utf-8")
            hold.chmod(0o600)
        for name in recovery_dropins:
            path = unit_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "[Unit]\nConditionPathExists=!hold\n", encoding="utf-8"
            )
        if config:
            config_path.write_text("T2_TOUCHID_USER=desktop\n", encoding="utf-8")
        if copy_after_capture:
            copy_lines = "\n".join(
                f'mkdir -p "$unit_root/$(dirname "{name}")"\n'
                f'printf \'this-run\\n\' >"$unit_root/{name}"'
                for name in copy_after_capture
            )
        else:
            copy_lines = ":"
        completed = subprocess.run(
            [
                "bash",
                "-c",
                rf"""
set -euo pipefail
source "$1"
unit_root=$2
state_root=$3
config_path=$4
sleep_conf=$5/90-t2-touchid-s2idle.conf
active_installed_upgrade=0
{extra_bash}
capture_prior_install_state "$unit_root" "$state_root" "$config_path" "$sleep_conf"
{copy_lines}
rollback_units_after_dkms_failure "$unit_root" "$5"
printf 'prior_product_install=%s\n' "$prior_product_install"
printf 'prior_recovery_hold=%s\n' "$prior_recovery_hold"
""",
                "installer-test",
                str(helper),
                str(unit_root),
                str(state_root),
                str(config_path),
                str(sleep_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "PATH": f"{root}:/usr/bin:/bin",
                "SYSTEMCTL_LOG": str(log),
            },
        )
        return completed, unit_root, state_root, log

    def test_dkms_failure_rolls_back_copied_units(self):
        helper = ROOT / "tools/installer-services.sh"
        self.assertIn("disable_and_remove_product_units()", helper.read_text())
        self.assertNotIn(
            "active_installed_upgrade",
            helper.read_text().split("rollback_units_after_dkms_failure")[1],
        )
        completed, unit_root, _, log = self._run_dkms_rollback_fixture(
            copy_after_capture=(
                "t2-sep-transport.service",
                "fprintd.service",
                "t2-biometric-ready.service",
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("prior_product_install=0", completed.stdout)
        self.assertIn("prior_recovery_hold=0", completed.stdout)
        self.assertFalse((unit_root / "t2-sep-transport.service").exists())
        self.assertFalse((unit_root / "fprintd.service").exists())
        calls = log.read_text(encoding="utf-8")
        self.assertIn("disable --now fprintd.service", calls)
        self.assertIn("disable t2-sep-transport.service", calls)
        self.assertIn("daemon-reload", calls)
        self.assertNotIn("is-active", calls)

    def test_stopped_install_dkms_failure_preserves_units(self):
        completed, unit_root, _, log = self._run_dkms_rollback_fixture(
            prior_units=(
                "t2-sep-transport.service",
                "fprintd.service",
                "t2-biometric-ready.service",
            ),
            copy_after_capture=("t2-sep-transport.service",),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("prior_product_install=1", completed.stdout)
        self.assertTrue((unit_root / "t2-sep-transport.service").exists())
        self.assertTrue((unit_root / "fprintd.service").exists())
        self.assertIn(
            "existing product units and recovery holds were left in place",
            completed.stderr,
        )
        self.assertFalse(log.exists())

    def test_recovery_held_install_dkms_failure_preserves_holds(self):
        dropin = "t2-native-first-run.service.d/90-native-recovery.conf"
        completed, unit_root, state_root, log = self._run_dkms_rollback_fixture(
            prior_units=("t2-sep-transport.service", "t2-native-first-run.service"),
            recovery_hold=True,
            recovery_dropins=(dropin, "fprintd.service.d/90-native-recovery.conf"),
            copy_after_capture=("t2-sep-transport.service",),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("prior_product_install=1", completed.stdout)
        self.assertIn("prior_recovery_hold=1", completed.stdout)
        self.assertTrue((state_root / "native-recovery-hold").exists())
        self.assertTrue((unit_root / dropin).exists())
        self.assertTrue(
            (unit_root / "fprintd.service.d/90-native-recovery.conf").exists()
        )
        self.assertTrue((unit_root / "t2-sep-transport.service").exists())
        self.assertFalse(log.exists())

    def test_changed_transport_dkms_failure_preserves_units(self):
        completed, unit_root, _, log = self._run_dkms_rollback_fixture(
            prior_units=("t2-sep-transport.service", "t2-bridge-network.service"),
            config=True,
            copy_after_capture=("t2-sep-transport.service",),
            extra_bash="live_transport_matches=0\n",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("prior_product_install=1", completed.stdout)
        self.assertTrue((unit_root / "t2-sep-transport.service").exists())
        self.assertTrue((unit_root / "t2-bridge-network.service").exists())
        self.assertFalse(log.exists())
        self.assertNotIn("is-active", completed.stdout)

    def test_upgrade_removes_legacy_path_research_helpers(self):
        helper = ROOT / "tools/installer-services.sh"
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            leftover = prefix / "t2-catacomb-fixture-check"
            leftover.write_text("old-path-copy\n", encoding="utf-8")
            keep = prefix / "t2-acm-preflight"
            keep.write_text("product-helper\n", encoding="utf-8")
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; remove_legacy_path_research_helpers "$2"',
                    "installer-test",
                    str(helper),
                    str(prefix),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(leftover.exists())
            self.assertTrue(keep.exists())

    def test_activation_journal_tmpfiles_are_installed_and_removed(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        conf = (ROOT / "systemd/tmpfiles.d/t2-touchid.conf").read_text(
            encoding="utf-8"
        )
        target = "/usr/lib/tmpfiles.d/t2-touchid.conf"
        self.assertIn(target, installer)
        self.assertIn(target, uninstaller)
        self.assertIn("/var/lib/t2-touchid/activation", conf)
        self.assertIn("d /var/lib/t2-touchid/activation 0700 root root -", conf)
        self.assertNotIn("7d", conf)

if __name__ == "__main__":
    unittest.main()
