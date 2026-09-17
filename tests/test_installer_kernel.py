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
                self.assertIn("NEXT STEP", result.stdout)
                self.assertIn("A reboot is required before fresh setup can continue", result.stdout)
                self.assertNotIn("product-ready", result.stdout)
                self.assertIn("requests a system reboot", result.stderr)
                self.assertIn("response-received:3", result.stderr)
                self.assertIn("preserve diagnostics", result.stderr)

    def test_firmware_reboot_reply_allows_verified_active_upgrade(self):
        result = self.run_gate(
            "response-received:3", disk=True, active_upgrade=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["product-ready"])
        self.assertIn("verified in-place upgrade", result.stderr)

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

    def test_prepared_transport_marker_requires_target_and_new_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "prepared-transport-update"
            current_boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()

            def check(prepared_boot, target="ABCDEF0123456789"):
                marker.write_text(
                    "format=1\n"
                    f"prepared_boot_id={prepared_boot}\n"
                    "old_srcversion=0123456789ABCDEF\n"
                    "new_srcversion=ABCDEF0123456789\n"
                )
                return subprocess.run(
                    ["bash", "-c", r'''
set -euo pipefail
source "$1"
transport_update_marker=$2
real_stat=$(command -v stat)
stat() {
  if [[ ${*: -1} == "$transport_update_marker" ]]; then
    printf '0:0:600:1:140\n'
  else
    "$real_stat" "$@"
  fi
}
prepared_transport_update_matches "$3"
''', "fixture", str(HELPER), str(marker), target],
                    capture_output=True, text=True, check=False,
                )

            accepted = check("11111111-2222-3333-4444-555555555555")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertNotEqual(
                "11111111-2222-3333-4444-555555555555", current_boot
            )
            self.assertNotEqual(check(current_boot).returncode, 0)
            self.assertNotEqual(check(
                "11111111-2222-3333-4444-555555555555",
                "FEDCBA9876543210",
            ).returncode, 0)

    def test_interrupted_preparation_resumes_only_exact_same_boot_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "marker"
            current_boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            uninstall = root / "uninstall.sh"
            uninstall.write_text("#!/bin/bash\necho uninstall\n")
            uninstall.chmod(0o755)
            for boot, old, new, metadata, allowed in (
                (current_boot, "0123456789ABCDEF", "ABCDEF0123456789", "0:0:600:1:140", True),
                ("11111111-2222-3333-4444-555555555555", "0123456789ABCDEF", "ABCDEF0123456789", "0:0:600:1:140", False),
                (current_boot, "1111111111111111", "ABCDEF0123456789", "0:0:600:1:140", False),
                (current_boot, "0123456789ABCDEF", "1111111111111111", "0:0:600:1:140", False),
                (current_boot, "0123456789ABCDEF", "ABCDEF0123456789", "1000:0:600:1:140", False),
                (current_boot, "", "ABCDEF0123456789", "0:0:600:1:140", False),
            ):
                with self.subTest(boot=boot, old=old, new=new, metadata=metadata):
                    marker.write_text(f"format=1\nprepared_boot_id={boot}\nold_srcversion=0123456789ABCDEF\nnew_srcversion=ABCDEF0123456789\n")
                    before = marker.read_bytes()
                    result = subprocess.run(
                        ["bash", "-c", r'''
set -euo pipefail
source "$1"
source_dir=$2
transport_update_marker=$2/marker
stat() { printf '%s\n' "$METADATA"; }
record_prepared_transport_update() { echo unexpected-record; return 1; }
ensure_applesmc_on_disk() { echo applesmc; }
enable_applesmc_next_boot() { echo enable; }
prepare_transport_update "$3" "$4" 0
''', "fixture", str(HELPER), str(root), old, new],
                        env={**os.environ, "METADATA": metadata},
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 3 if allowed else 2, result.stderr)
                    if allowed:
                        self.assertIn("uninstall\napplesmc\nenable\n", result.stdout)
                        self.assertIn("Resuming", result.stderr)
                    else:
                        self.assertEqual(result.stdout, "")
                    self.assertEqual(marker.read_bytes(), before)

    def test_preparation_records_exact_transport_identities_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "state/prepared-transport-update"
            result = subprocess.run(
                ["bash", "-c", r'''
set -euo pipefail
source "$1"
transport_update_marker=$2
install() {
  [[ $1 == -d ]] || return 2
  mkdir -p -- "${*: -1}"
}
record_prepared_transport_update 0123456789abcdef abcdef0123456789
cat "$transport_update_marker"
''', "fixture", str(HELPER), str(marker)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], "format=1")
            self.assertRegex(
                lines[1],
                r"^prepared_boot_id=[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
            )
            self.assertEqual(lines[2], "old_srcversion=0123456789ABCDEF")
            self.assertEqual(lines[3], "new_srcversion=ABCDEF0123456789")
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertFalse(list(marker.parent.glob(".prepared-transport-update.*")))

    def test_unverified_preparation_is_non_destructive(self):
        result = subprocess.run(
            ["bash", "-c", r'''
set -euo pipefail
source "$1"
source_dir=$2
record_prepared_transport_update() { echo record; }
ensure_applesmc_on_disk() { echo applesmc; }
enable_applesmc_next_boot() { echo enable; }
prepare_transport_update 0123456789ABCDEF ABCDEF0123456789 0
''', "fixture", str(HELPER), "/missing"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("requires a healthy or validated completed installation", result.stderr)

    def test_preparation_rejects_same_transport_with_different_case(self):
        result = subprocess.run(
            ["bash", "-c", r'''
set -euo pipefail
source "$1"
transport_update_marker=$2
record_prepared_transport_update abcdef0123456789 ABCDEF0123456789
''', "fixture", str(HELPER), "/unused"],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("module identities are invalid", result.stderr)

    def test_prepared_marker_does_not_relax_fresh_response_three(self):
        result = self.run_gate("response-received:3", active_upgrade=False)
        self.assertEqual(result.returncode, 3)
        self.assertNotIn("product-ready", result.stdout)

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
                    self.assertIn("NEXT STEP", result.stdout)
                    self.assertIn("Restart when convenient, then rerun ./install-omarchy.sh.", result.stdout)
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

    def test_update_preparation_records_recovery_before_retirement(self):
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
record_prepared_transport_update() { echo recorded; }
ensure_applesmc_on_disk() { echo staged; }
enable_applesmc_next_boot() { echo boot-options; }
prepare_transport_update 0123456789ABCDEF ABCDEF0123456789 1 || exit $?
echo product-ready
''', "fixture", str(HELPER), directory],
                        env={**os.environ, "UNINSTALL_STATUS": str(failure)},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 2 if failure else 3)
                    if failure:
                        self.assertEqual(
                            result.stdout.splitlines(), ["recorded", "retired"]
                        )
                    else:
                        self.assertEqual(
                            result.stdout.splitlines()[:4],
                            ["recorded", "retired", "staged", "boot-options"],
                        )
                        self.assertIn("NEXT STEP", result.stdout)
                        self.assertIn("Restart, then rerun ./install-omarchy.sh.", result.stdout)

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
                ("", "0", 2, []),
                (None, "0", 2, []),
                ("", "1", 2, []),
                ("new", "0", 0, ["ready"]),
                ("new", "1", 2, []),
                ("absent", "0", 0, ["ready"]),
            ):
                with self.subTest(live=live, prepare=prepare):
                    if live is None or live == "absent":
                        version.unlink(missing_ok=True)
                        if live == "absent":
                            module.rmdir()
                    else:
                        version.write_text(live)
                    result = subprocess.run(
                        ["bash", "-c", '''
set -euo pipefail
source_dir=unused
running_kernel=test
prepare_update=$1
make() { :; }
modinfo() { echo new; }
systemctl() { return 1; }
restore_checkout_build_outputs() { :; }
prepare_transport_update() { echo prepare; return 3; }
require_t2_hardware() { :; }
check_applesmc_prerequisite() { echo "ready:$1"; }
capture_prior_install_state() { :; }
prepared_transport_update_matches() { return 1; }
python3() { return 1; }
''' + block, "fixture", prepare],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(
                        result.stdout.splitlines(),
                        ["ready:0" if item == "ready" else item for item in output],
                    )

    def test_transport_preparation_accepts_completed_unhealthy_install(self):
        installer = (ROOT / "install.sh").read_text()
        block = installer[installer.index("# Preserve proof of a healthy"):installer.index("target_dir=")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module").mkdir()
            (root / "config").touch()
            (root / "product").touch()
            block = block.replace("/sys/module/t2_sep_transport", str(root / "module"))
            block = block.replace("/etc/t2-touchid.conf", str(root / "config"))
            block = block.replace("/opt/t2-touchid/src/t2-fprintd.py", str(root / "product"))
            for completed, installed, metadata, expected in (
                ("yes", "ABCDEF0123456789", "0:0:600:1", 3),
                ("no", "ABCDEF0123456789", "0:0:600:1", 2),
                ("yes", "9999999999999999", "0:0:600:1", 2),
                ("yes", "", "0:0:600:1", 2),
                ("yes", "ABCDEF0123456789", "0:0:644:1", 2),
            ):
                with self.subTest(completed=completed, installed=installed, metadata=metadata):
                    result = subprocess.run(
                        ["bash", "-c", r'''
set -euo pipefail
source_dir=unused
running_kernel=test
prepare_update=1
live_transport_matches=0
live_srcversion=ABCDEF0123456789
desired_srcversion=0123456789ABCDEF
completed=$1
installed=$2
metadata=$3
stat() { printf '%s\n' "$metadata"; }
modinfo() { printf '%s\n' "$installed"; }
systemctl() { return 3; }
python3() { [[ $completed == yes ]]; }
prepare_transport_update() {
  [[ $1 == ABCDEF0123456789 && $2 == 0123456789ABCDEF ]] || return 99
  [[ $3 == 1 ]] || return 2
  echo verified-preparation
  return 3
}
''' + block, "fixture", completed, installed, metadata],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stdout.strip(), "verified-preparation" if expected == 3 else "")

    def test_upgrade_gate_accepts_only_health_or_completed_recovery(self):
        installer = (ROOT / "install.sh").read_text()
        block = installer[installer.index("# Preserve proof of a healthy"):installer.index("target_dir=")]
        units = (
            "t2-bridge-network.service", "t2-biometric-port-refresh.service",
            "t2-sep-transport.service", "t2-native-first-run.service",
            "t2-biometric-ready.service", "fprintd.service",
        )
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "module"
            module.mkdir()
            block = block.replace("/sys/module/t2_sep_transport", str(module))
            config = Path(directory) / "config"
            config.touch()
            product = Path(directory) / "t2-fprintd.py"
            product.touch()
            block = block.replace("/etc/t2-touchid.conf", str(config))
            block = block.replace("/opt/t2-touchid/src/t2-fprintd.py", str(product))
            cases = [
                ("", "0:0:600:1", "no", "ABCDEF0123456789", True, 0)
            ]
            cases += [
                (unit, "0:0:600:1", "no", "ABCDEF0123456789", True, 3)
                for unit in units
            ]
            cases += [
                (
                    "fprintd.service",
                    "0:0:600:1",
                    "yes",
                    "ABCDEF0123456789",
                    True,
                    0,
                ),
                ("all", "0:0:600:1", "yes", "ABCDEF0123456789", True, 0),
                ("all", "0:0:600:1", "yes", "0123456789ABCDEF", True, 3),
                ("all", "0:0:600:1", "yes", "ABCDEF0123456789", False, 3),
                ("", "0:0:644:1", "yes", "ABCDEF0123456789", True, 3),
            ]
            for (
                inactive,
                metadata,
                completed,
                installed,
                product_exists,
                expected,
            ) in cases:
                with self.subTest(
                    inactive=inactive,
                    metadata=metadata,
                    completed=completed,
                    installed=installed,
                    product_exists=product_exists,
                ):
                    if product_exists:
                        product.touch()
                    else:
                        product.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", "-c", r'''
set -euo pipefail
source "$1"
source_dir=unused
running_kernel=test
prepare_update=0
live_transport_matches=0
live_srcversion=ABCDEF0123456789
desired_srcversion=ABCDEF0123456789
inactive=$2
metadata=$3
completed=$4
installed=$5
stat() { printf '%s\n' "$metadata"; }
modinfo() {
  if [[ $1 == -k ]]; then
    printf '%s\n' "$installed"
  else
    printf '%s\n' ABCDEF0123456789
  fi
}
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
require_t2_hardware() { :; }
applesmc_boot_result() { echo response-received:3; }
ensure_applesmc_on_disk() { :; }
capture_prior_install_state() { :; }
prepared_transport_update_matches() { return 1; }
python3() { [[ $completed == yes ]]; }
''' + block + "\necho product-ready\n",
                         "fixture", str(HELPER), inactive, metadata, completed,
                         installed],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected == 0:
                        self.assertEqual(result.stdout.strip(), "product-ready")
                        if inactive:
                            self.assertIn(
                                "continuing a verified userspace repair",
                                result.stderr,
                            )
                    else:
                        self.assertNotIn("product-ready", result.stdout)
                        self.assertIn("NEXT STEP", result.stdout)

    def _run_t2_hardware_gate(self, root: Path):
        rewritten = (root / "installer-kernel.sh")
        rewritten.write_text(
            HELPER.read_text(encoding="utf-8").replace(
                "/sys/bus/", f"{root}/sys/bus/"
            ),
            encoding="utf-8",
        )
        return subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"; require_t2_hardware; echo accepted',
                "fixture",
                str(rewritten),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_require_t2_hardware_refuses_without_pci_or_usb(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sys/bus/pci/devices").mkdir(parents=True)
            (root / "sys/bus/usb/devices").mkdir(parents=True)
            result = self._run_t2_hardware_gate(root)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("No Apple T2 hardware detected", result.stderr)
            self.assertIn("Refusing to replace applesmc", result.stderr)

    def test_require_t2_hardware_accepts_sep_pci_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            device = root / "sys/bus/pci/devices/0000:01:00.0"
            device.mkdir(parents=True)
            (device / "vendor").write_text("0x106b\n", encoding="utf-8")
            (device / "device").write_text("0x1802\n", encoding="utf-8")
            (root / "sys/bus/usb/devices").mkdir(parents=True)
            result = self._run_t2_hardware_gate(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "accepted")
