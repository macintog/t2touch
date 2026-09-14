#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
if [[ ${1:-} == --help ]]; then
  echo "Usage: sudo ./uninstall.sh"
  exit 0
fi
[[ $# -eq 0 ]] || exit 2

source_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
target_user=
target_home=
target_uid=
if [[ -r /etc/t2-touchid.conf ]]; then
  target_user=$(sed -n 's/^T2_TOUCHID_USER=//p' /etc/t2-touchid.conf | tail -n 1)
  if [[ $target_user =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    target_home=$(getent passwd "$target_user" | cut -d: -f6)
    target_uid=$(id -u -- "$target_user" 2>/dev/null || true)
  fi
fi

systemctl disable --now fprintd.service t2-touchid-adaptive-sync.service \
  t2-touchid-post-reboot.service t2-biometric-ready.service \
  t2-native-first-run.service \
  t2-biometric-port-refresh.service t2-bridge-network.service \
  t2-credential-unlock.service t2-interactive-unlock.service t2-keybag-load.service \
  2>/dev/null || true
# SEP retains the registered DMA addresses, so the live transport is pinned
# until the machine's next ordinary kernel start. Disable future loading but
# do not unbind or unload the safe live instance during uninstall.
systemctl disable t2-sep-transport.service 2>/dev/null || true
dkms_source=/usr/src/t2-sep-transport-0.1.0
dkms_state=/var/lib/dkms/t2-sep-transport/0.1.0
if [[ -d $dkms_state ]]; then
  command -v dkms >/dev/null 2>&1 || {
    echo "DKMS is required to unregister the installed transport." >&2
    exit 1
  }
  dkms remove -m t2-sep-transport -v 0.1.0 --all
fi
rm -rf -- "$dkms_source"
applesmc_dkms_source=/usr/src/applesmc-t2touch-0.1.0
applesmc_dkms_state=/var/lib/dkms/applesmc-t2touch/0.1.0
if [[ -d $applesmc_dkms_state ]]; then
  command -v dkms >/dev/null 2>&1 || {
    echo "DKMS is required to unregister the installed applesmc prerequisite." >&2
    exit 1
  }
  dkms remove -m applesmc-t2touch -v 0.1.0 --all
fi
rm -rf -- "$applesmc_dkms_source"
pam_backup_present=0
for marker in /var/lib/t2-touchid/pam-backups/*.original \
  /var/lib/t2-touchid/pam-backups/*.absent; do
  [[ -e $marker ]] && pam_backup_present=1
done
if (( pam_backup_present )); then
  "$source_dir/tools/rollback-pam.sh"
fi
for file in /etc/systemd/system/{fprintd,t2-native-first-run,t2-touchid-adaptive-sync,t2-touchid-post-reboot,t2-biometric-ready,t2-biometric-port-refresh,t2-bridge-network,t2-credential-unlock,t2-interactive-unlock,t2-keybag-load,t2-sep-transport}.service \
  /etc/systemd/system/t2-bridge-network-ready@.service \
  /usr/local/bin/t2touch \
  /usr/local/sbin/{t2-aks-tool,t2-keybag-load,t2-keybag-unlock,t2-pam-unlock,t2-pam-fingerprint-ready,t2-pam-fingerprint-prompt,t2-credential-unlock,t2-biometric-ready,t2-biometric-port-refresh,t2-bridge-network-prepare,t2-bridge-network-ready,t2-sep-transport-load,t2-sep-transport-unload,t2-fprintd-enroll-tui-launch,t2-fprintd-preview-tui-launch,t2-fprintd-verify-tui-launch,t2-fprintd-negative-tui-launch,t2-fprintd-delete-tui-launch,t2-sudo-pam-test-launch,t2-native-enroll-tui-launch,t2-native-new-finger-tui-launch,t2-native-match-tui-launch,t2-native-negative-tui-launch,t2-second-finger-tui-launch,t2-touchid-doctor,t2-touchid-inventory,t2-touchid-identities,t2-touchid-provision-catacomb,t2-touchid-identify-finger,t2-touchid-manage,t2-touchid-baseline,t2-catacomb-fixture-check,t2-acm-preflight,t2-aks-observe-test,t2-acm-lifecycle-test,t2-acm-policy-preflight,t2-acm-authorize-test,t2-acm-identity-secret-test,t2-touchid-enroll-test,t2-touchid-enroll,t2-touchid-user-map,t2-touchid-user-broker-gate,t2-touchid-fprint-status,t2-touchid-fprint-enrollment-gate,t2-touchid-post-reboot,t2-fprint-enrollment-worker,t2-fprint-delete-worker} \
  /etc/systemd/system/fprintd.service.d/05-account-home.conf \
  /etc/systemd/system/fprintd.service.d/10-authority.conf \
  /etc/systemd/system/t2-touchid-adaptive-sync.service.d/05-account-home.conf \
  /etc/systemd/system/fprintd.service.d/10-native-enrollment.conf \
  /etc/systemd/system/fprintd.service.d/20-native-identity-management.conf \
  /etc/systemd/system/t2-native-first-run.service.d/10-authority.conf \
  /etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf \
  /etc/modprobe.d/t2-sep-transport.conf \
  /etc/modprobe.d/t2-sep-transport-autoload.conf \
  /etc/modprobe.d/t2-sep-boot-state.conf \
  /usr/share/polkit-1/actions/org.t2linux.touchid.policy \
  /etc/dbus-1/system.d/99-t2-touchid-fprint.conf; do
  [[ ! -e $file ]] || rm -- "$file"
done
rmdir /etc/systemd/system/fprintd.service.d 2>/dev/null || true
rmdir /etc/systemd/system/t2-native-first-run.service.d 2>/dev/null || true
rmdir /etc/systemd/system/t2-touchid-adaptive-sync.service.d 2>/dev/null || true
rmdir /etc/systemd/sleep.conf.d 2>/dev/null || true
rm -rf -- /opt/t2-touchid /usr/local/lib/t2-touchid
if [[ -n $target_home && -d $target_home/.config/systemd/user ]]; then
  for unit in t2-touchid-alert.service t2-touchid-failure.service t2-touchid-success.service; do
    file=$target_home/.config/systemd/user/$unit
    [[ ! -e $file ]] || rm -- "$file"
  done
  target_runtime_dir=/run/user/$target_uid
  if [[ $target_uid =~ ^[0-9]+$ && -S $target_runtime_dir/bus ]]; then
    runuser -u "$target_user" -- env \
      XDG_RUNTIME_DIR="$target_runtime_dir" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$target_runtime_dir/bus" \
      systemctl --user daemon-reload 2>/dev/null || true
  fi
fi
systemctl daemon-reload
systemctl reload dbus.service 2>/dev/null || true
if command -v depmod >/dev/null 2>&1; then
  depmod -a "$(uname -r)"
fi
if command -v mkinitcpio >/dev/null 2>&1; then
  mkinitcpio -P
fi

echo "Removed installed files. Preserved config, credentials, and biometric data."
