#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free checks for installer portability assumptions."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def test_live_applesmc_gate_stages_owned_dkms_before_product_mutation(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        wrapper = (ROOT / "install-omarchy.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        live_gate = "/sys/module/applesmc/parameters/t2_sep_boot_state"
        stage_call = "stage_applesmc_prerequisite || exit 2"
        first_product_write = "target_dir=/opt/t2-touchid"

        self.assertIn(live_gate, installer)
        self.assertNotIn("modinfo -p applesmc", wrapper)
        self.assertIn(stage_call, installer)
        self.assertLess(installer.index(stage_call), installer.index(first_product_write))
        self.assertIn("/usr/src/$package_name-$package_version", installer)
        self.assertIn("mkinitcpio -P", installer)
        self.assertIn(
            "dkms remove -m applesmc-t2touch -v 0.1.0 --all",
            uninstaller,
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
