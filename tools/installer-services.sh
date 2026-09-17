#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

# Start the Linux-native product chain one boundary at a time. A single
# `systemctl start fprintd.service` collapses prerequisite failures into a
# generic dependency error and hides the state that actually needs attention.

start_touchid_stage() {
  local unit=$1
  local stage=$2
  if systemctl start "$unit"; then
    return 0
  fi
  echo >&2
  echo "Touch ID setup stopped at $stage ($unit)." >&2
  echo "Earlier stages may have completed; no automatic rollback or account rebinding was attempted." >&2
  systemctl --no-pager --full status "$unit" >&2 || true
  echo >&2
  echo "Inspect the complete privacy-safe stack report with:" >&2
  echo "  sudo t2-touchid-doctor" >&2
  if [[ $unit == t2-native-first-run.service ]]; then
    echo "Inspect the redacted account binding with:" >&2
    # install.sh resolves target_uid before starting the service chain.
    # shellcheck disable=SC2154
    echo "  sudo t2-touchid-user-map status --linux-uid $target_uid" >&2
    echo "Account rebinding is intentionally never automatic." >&2
  fi
  return 1
}

start_linux_native_touchid_chain() {
  start_touchid_stage t2-native-first-run.service \
    "Linux account and protected authority validation" || return 2
  start_touchid_stage t2-biometric-ready.service \
    "biometric transport readiness" || return 2
  start_touchid_stage t2-touchid-post-reboot.service \
    "pending mutation reconciliation" || return 2
  start_touchid_stage fprintd.service \
    "fprintd activation" || return 2
}

# Persist the recovery boundary before replacing units or reloading D-Bus.
# A disabled service can still be dependency- or D-Bus-activated, so keep a
# condition on every automatic biometric owner until normal setup resumes.
hold_native_recovery() {
  local state_root=${1:-/var/lib/t2-touchid}
  local unit_root=${2:-/etc/systemd/system}
  local unit dropin
  local -a owners=(
    t2-native-first-run.service t2-biometric-ready.service
    t2-touchid-post-reboot.service t2-touchid-adaptive-sync.service fprintd.service
  )
  install -d -m 0700 "$state_root" || return
  install -m 0600 /dev/null "$state_root/native-recovery-hold" || return
  for unit in "${owners[@]}"; do
    dropin=$unit_root/$unit.d
    install -d -m 0755 "$dropin" || return
    printf '[Unit]\nConditionPathExists=!%s/native-recovery-hold\n' "$state_root" \
      >"$dropin/90-native-recovery.conf" || return
    chmod 0644 "$dropin/90-native-recovery.conf" || return
  done
  systemctl daemon-reload || return
  for unit in "${owners[@]}"; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      systemctl stop "$unit" || return
    fi
  done
}

resume_native_recovery() {
  local state_root=${1:-/var/lib/t2-touchid}
  # Only the normal installer calls this, after software and transport setup.
  rm -f -- "$state_root/native-recovery-hold"
}

# Research helpers that used to land on PATH. Fresh installs put them under
# /opt/t2-touchid/bin; upgrades must delete the leftover sbin copies.
LEGACY_PATH_RESEARCH_HELPERS=(
  t2-catacomb-fixture-check
  t2-aks-observe-test
  t2-acm-lifecycle-test
  t2-acm-policy-preflight
  t2-acm-authorize-test
  t2-acm-identity-secret-test
  t2-touchid-enroll-test
  t2-native-enroll-tui-launch
  t2-fprintd-preview-tui-launch
  t2-fprintd-verify-tui-launch
  t2-sudo-pam-test-launch
  t2-fprintd-negative-tui-launch
  t2-fprintd-delete-tui-launch
  t2-native-new-finger-tui-launch
  t2-native-match-tui-launch
  t2-native-negative-tui-launch
  t2-second-finger-tui-launch
)

remove_legacy_path_research_helpers() {
  local prefix=${1:-/usr/local/sbin}
  local name
  for name in "${LEGACY_PATH_RESEARCH_HELPERS[@]}"; do
    rm -f -- "$prefix/$name"
  done
}

# Snapshot product units and recovery holds before this run writes files.
# Service health and live transport identity are not evidence of an install:
# a stopped chain, a recovery hold, or a transport-changing upgrade can all
# make active_installed_upgrade=0 while an installation still exists.
capture_prior_install_state() {
  local unit_root=${1:-/etc/systemd/system}
  local state_root=${2:-/var/lib/t2-touchid}
  local config_path=${3:-/etc/t2-touchid.conf}
  local sleep_conf=${4:-/etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf}
  local file
  prior_product_install=0
  prior_recovery_hold=0
  prior_install_paths=

  for file in \
    "$unit_root"/{fprintd,t2-native-first-run,t2-touchid-adaptive-sync,t2-touchid-post-reboot,t2-biometric-ready,t2-biometric-port-refresh,t2-bridge-network,t2-credential-unlock,t2-interactive-unlock,t2-keybag-load,t2-sep-transport}.service \
    "$unit_root"/t2-bridge-network-ready@.service \
    "$unit_root"/fprintd.service.d/{05-account-home,10-authority,10-native-enrollment,20-native-identity-management}.conf \
    "$unit_root"/t2-touchid-adaptive-sync.service.d/05-account-home.conf \
    "$unit_root"/t2-native-first-run.service.d/10-authority.conf \
    "$config_path" \
    "$sleep_conf"; do
    if [[ -e $file ]]; then
      prior_product_install=1
      prior_install_paths+="$file"$'\n'
    fi
  done

  if [[ -e $state_root/native-recovery-hold ]]; then
    prior_recovery_hold=1
    prior_install_paths+="$state_root/native-recovery-hold"$'\n'
  fi
  for file in \
    "$unit_root"/{fprintd,t2-native-first-run,t2-biometric-ready,t2-touchid-post-reboot,t2-touchid-adaptive-sync}.service.d/90-native-recovery.conf; do
    if [[ -e $file ]]; then
      prior_recovery_hold=1
      prior_install_paths+="$file"$'\n'
    fi
  done
}

path_existed_before_this_run() {
  local path=$1
  [[ -n ${prior_install_paths:-} ]] || return 1
  grep -Fxq -- "$path" <<<"$prior_install_paths"
}

# Fresh installs copied units this run but never had a working chain.
# An existing installation, including a stopped, recovery-held, or
# transport-changing one, must keep its units and recovery holds.
rollback_units_after_dkms_failure() {
  if (( ${prior_product_install:-0} || ${prior_recovery_hold:-0} )); then
    echo "DKMS failed; the existing product units and recovery holds were left in place." >&2
    return 0
  fi
  disable_and_remove_product_units "$@"
}

# Unit-removal portion of uninstall.sh. Used when this run copied product
# units but transport DKMS then failed, so boot is not left with enabled
# services that cannot load t2_sep_transport. Skip paths that existed
# before this run so leftover files are not treated as this install's.
disable_and_remove_product_units() {
  local unit_root=${1:-/etc/systemd/system}
  local sleep_dir=${2:-/etc/systemd/sleep.conf.d}
  systemctl disable --now fprintd.service t2-touchid-adaptive-sync.service \
    t2-touchid-post-reboot.service t2-biometric-ready.service \
    t2-native-first-run.service \
    t2-biometric-port-refresh.service t2-bridge-network.service \
    t2-credential-unlock.service t2-interactive-unlock.service t2-keybag-load.service \
    2>/dev/null || true
  systemctl disable t2-sep-transport.service 2>/dev/null || true
  local file
  for file in \
    "$unit_root"/{fprintd,t2-native-first-run,t2-touchid-adaptive-sync,t2-touchid-post-reboot,t2-biometric-ready,t2-biometric-port-refresh,t2-bridge-network,t2-credential-unlock,t2-interactive-unlock,t2-keybag-load,t2-sep-transport}.service \
    "$unit_root"/t2-bridge-network-ready@.service \
    "$unit_root"/{fprintd,t2-native-first-run,t2-biometric-ready,t2-touchid-post-reboot,t2-touchid-adaptive-sync}.service.d/90-native-recovery.conf \
    "$unit_root"/fprintd.service.d/05-account-home.conf \
    "$unit_root"/fprintd.service.d/10-authority.conf \
    "$unit_root"/t2-touchid-adaptive-sync.service.d/05-account-home.conf \
    "$unit_root"/fprintd.service.d/10-native-enrollment.conf \
    "$unit_root"/fprintd.service.d/20-native-identity-management.conf \
    "$unit_root"/t2-native-first-run.service.d/10-authority.conf \
    "$sleep_dir"/90-t2-touchid-s2idle.conf; do
    path_existed_before_this_run "$file" && continue
    [[ ! -e $file ]] || rm -- "$file"
  done
  rmdir "$unit_root"/fprintd.service.d 2>/dev/null || true
  rmdir "$unit_root"/t2-native-first-run.service.d 2>/dev/null || true
  rmdir "$unit_root"/t2-touchid-adaptive-sync.service.d 2>/dev/null || true
  rmdir "$unit_root"/t2-biometric-ready.service.d 2>/dev/null || true
  rmdir "$unit_root"/t2-touchid-post-reboot.service.d 2>/dev/null || true
  rmdir "$sleep_dir" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}
