# SPDX-License-Identifier: GPL-2.0-only
"""Execute the installer gates with fake sysfs and package/service boundaries."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/installer-kernel.sh"


class KernelPrerequisiteTests(unittest.TestCase):
    def test_boot_rebuild_selects_limine_and_propagates_failure(self):
        for available, expected in ((True, "limine"), (False, "mkinitcpio -P")):
            for status in (0, 7):
                with self.subTest(limine=available, status=status):
                    result = subprocess.run(
                        ["bash", "-c", '''
set -euo pipefail
source "$1"
command() {
  if [[ $* == '-v limine-mkinitcpio' ]]; then
    [[ $LIMINE_AVAILABLE == yes ]]
  else
    builtin command "$@"
  fi
}
limine-mkinitcpio() { echo limine; return "$BUILD_STATUS"; }
mkinitcpio() { echo "mkinitcpio $*"; return "$BUILD_STATUS"; }
rebuild_boot_images
''', "fixture", str(HELPER)],
                        env={**os.environ, "LIMINE_AVAILABLE": "yes" if available else "no",
                             "BUILD_STATUS": str(status)},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)

    def run_gate(self, result, disk=True, fail_stage=False, active_upgrade=False):
        return subprocess.run(
            ["bash", "-c", '''
set -euo pipefail
source "$1"
applesmc_boot_result() { printf '%s\n' "$RESULT"; }
modinfo() { [[ $DISK == yes ]] && printf 't2_sep_boot_state: publisher\n'; }
stage_applesmc_prerequisite() { echo staged; [[ $FAIL_STAGE == no ]]; }
enable_applesmc_next_boot() { echo boot-options; }
check_applesmc_prerequisite "$ACTIVE_UPGRADE" || exit $?
echo product-ready
''', "fixture", str(HELPER)],
            env={**os.environ, "RESULT": result, "DISK": "yes" if disk else "no",
                 "FAIL_STAGE": "yes" if fail_stage else "no",
                 "ACTIVE_UPGRADE": "1" if active_upgrade else "0"},
            capture_output=True, text=True, check=False,
        )

    def test_successful_live_and_disk_driver_need_no_staging(self):
        result = self.run_gate("response-received:1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["product-ready"])

    def test_firmware_reboot_reply_stops_without_replaying_or_staging(self):
        for disk in (False, True):
            with self.subTest(disk=disk):
                result = self.run_gate("response-received:3", disk=disk)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(result.stdout, "")
                self.assertIn("requests a system reboot", result.stderr)
                self.assertIn("response-received:3", result.stderr)
                self.assertIn("preserve diagnostics", result.stderr)

    def test_firmware_reboot_reply_allows_verified_active_upgrade(self):
        result = self.run_gate(
            "response-received:3", disk=True, active_upgrade=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["product-ready"])
        self.assertIn("verified active in-place upgrade", result.stderr)

    def test_active_upgrade_restores_removed_disk_prerequisite(self):
        result = self.run_gate(
            "response-received:3", disk=False, active_upgrade=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["staged", "product-ready"])

    def test_active_upgrade_allowance_is_typed(self):
        result = subprocess.run(
            ["bash", "-c", 'source "$1"; check_applesmc_prerequisite invalid',
             "fixture", str(HELPER)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be 0 or 1", result.stderr)

    def test_reinstall_restores_removed_disk_prerequisite_before_ready(self):
        result = self.run_gate("response-received:1", disk=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["staged", "product-ready"])

    def test_staging_failure_cannot_report_ready(self):
        result = self.run_gate("response-received:1", disk=False, fail_stage=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("product-ready", result.stdout)

    def test_absent_and_disabled_publishers_prepare_next_boot_then_stop(self):
        for state in ("absent", "disabled"):
            for disk in (False, True):
                with self.subTest(state=state, disk=disk):
                    result = self.run_gate(state, disk=disk)
                    self.assertEqual(result.returncode, 3, result.stderr)
                    self.assertIn("boot-options", result.stdout)
                    self.assertNotIn("product-ready", result.stdout)
                    self.assertEqual("staged" in result.stdout, not disk)

    def test_failed_or_unknown_publication_never_stages_or_continues(self):
        for state in ("failed", "rejected", "commit-uncertain", "not-applicable",
                      "ambiguous", "unavailable", "", "response-received:0",
                      "response-received:2", "response-received:256"):
            with self.subTest(state=state):
                result = self.run_gate(state, disk=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("installation stopped before product setup", result.stderr)
                if state:
                    self.assertIn(state, result.stderr)

    def test_reads_device_result_instead_of_enabled_parameter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parameter = root / "module/applesmc/parameters/t2_sep_boot_state"
            parameter.parent.mkdir(parents=True)
            parameter.write_text("Y\n")
            paths = [root / "bus/acpi/devices/APP0001:00/t2_sep_boot_state",
                     root / "bus/platform/devices/applesmc.0/t2_sep_boot_state"]
            def read():
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; applesmc_boot_result "$2"',
                     "fixture", str(HELPER), directory],
                    capture_output=True, text=True, check=True,
                )
                return result.stdout.strip()
            self.assertEqual(read(), "absent")
            paths[0].parent.mkdir(parents=True)
            paths[0].write_text("commit-uncertain\n")
            self.assertEqual(read(), "commit-uncertain")
            paths[0].write_text("response-received:1\n")
            self.assertEqual(read(), "response-received:1")
            paths[1].parent.mkdir(parents=True)
            paths[1].write_text("response-received:1\n")
            self.assertEqual(read(), "ambiguous")

    def test_update_preparation_orders_retirement_before_next_boot_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            uninstall = Path(directory) / "uninstall.sh"
            uninstall.write_text('#!/usr/bin/env bash\necho retired\nexit "${UNINSTALL_STATUS:-0}"\n')
            uninstall.chmod(0o755)
            for failure in (0, 1):
                with self.subTest(uninstall_status=failure):
                    result = subprocess.run(
                        ["bash", "-c", '''
set -euo pipefail
source "$1"
source_dir=$2
ensure_applesmc_on_disk() { echo staged; }
enable_applesmc_next_boot() { echo boot-options; }
prepare_transport_update || exit $?
echo product-ready
''', "fixture", str(HELPER), directory],
                        env={**os.environ, "UNINSTALL_STATUS": str(failure)},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 2 if failure else 3)
                    self.assertEqual(result.stdout.splitlines(),
                                     ["retired"] if failure else ["retired", "staged", "boot-options"])

    def test_transport_entry_gate_requires_explicit_identified_change(self):
        # Execute the real pre-product installer block, replacing only the
        # kernel sysfs root and external make/modinfo/package boundaries.
        installer = (ROOT / "install.sh").read_text()
        block = installer[installer.index("# Build and compare"):installer.index("target_dir=")]
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "module"
            module.mkdir()
            version = module / "srcversion"
            block = block.replace("/sys/module/t2_sep_transport", str(module))
            for live, prepare, expected, output in (
                ("old", "0", 2, []),
                ("old", "1", 3, ["prepare"]),
                ("", "1", 2, []),
                ("new", "0", 0, ["ready"]),
                ("new", "1", 2, []),
            ):
                with self.subTest(live=live, prepare=prepare):
                    version.write_text(live)
                    result = subprocess.run(
                        ["bash", "-c", '''
set -euo pipefail
source_dir=unused
prepare_update=$1
make() { :; }
modinfo() { echo new; }
systemctl() { return 1; }
prepare_transport_update() { echo prepare; return 3; }
check_applesmc_prerequisite() { echo "ready:$1"; }
''' + block, "fixture", prepare],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(
                        result.stdout.splitlines(),
                        ["ready:0" if item == "ready" else item for item in output],
                    )

    def test_active_upgrade_gate_requires_every_prerequisite(self):
        installer = (ROOT / "install.sh").read_text()
        block = installer[installer.index("# A recurring BootPolicyReboot"):installer.index("target_dir=")]
        units = (
            "t2-bridge-network.service", "t2-biometric-port-refresh.service",
            "t2-sep-transport.service", "t2-native-first-run.service",
            "t2-biometric-ready.service", "fprintd.service",
        )
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.touch()
            product = Path(directory) / "t2-fprintd.py"
            product.touch()
            block = block.replace("/etc/t2-touchid.conf", str(config))
            block = block.replace("/opt/t2-touchid/src/t2-fprintd.py", str(product))
            cases = [("", "1", "0:0:600:1", 0)]
            cases += [(unit, "1", "0:0:600:1", 3) for unit in units]
            cases += [("all", "1", "0:0:600:1", 3),
                      ("", "0", "0:0:600:1", 3),
                      ("", "1", "0:0:644:1", 3)]
            for inactive, matches, metadata, expected in cases:
                with self.subTest(inactive=inactive, matches=matches, metadata=metadata):
                    result = subprocess.run(
                        ["bash", "-c", r'''
set -euo pipefail
source "$1"
live_transport_matches=$2
inactive=$3
metadata=$4
stat() { printf '%s\n' "$metadata"; }
# Match systemctl's ANY-active semantics for multiple positional units.
systemctl() {
  [[ $1 == is-active && $2 == --quiet ]] || return 2
  shift 2
  local unit
  for unit in "$@"; do
    if [[ $inactive != all && $unit != "$inactive" ]]; then
      return 0
    fi
  done
  return 3
}
applesmc_boot_result() { echo response-received:3; }
ensure_applesmc_on_disk() { :; }
''' + block + "\necho product-ready\n",
                         "fixture", str(HELPER), matches, inactive, metadata],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stdout.strip(), "product-ready" if expected == 0 else "")
