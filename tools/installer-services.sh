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
