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
            installer.index(
                'check_applesmc_prerequisite "$active_installed_upgrade" || exit $?'
            ),
            installer.index("target_dir=/opt/t2-touchid"),
        )
        self.assertLess(
            installer.index("prepare_transport_update || exit $?"),
            installer.index("target_dir=/opt/t2-touchid"),
        )

    def test_active_upgrade_exception_requires_complete_running_chain(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")

        self.assertIn("if (( live_transport_matches ))", installer)
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
            'check_applesmc_prerequisite "$active_installed_upgrade"', installer
        )

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
        self.assertNotIn(
            "\n  /usr/local/sbin/t2-sep-transport-unload\n", installer
        )

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

if __name__ == "__main__":
    unittest.main()
