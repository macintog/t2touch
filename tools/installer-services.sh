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
  echo "Existing fingerprint, keybag, mapping, and mutation state was preserved." >&2
  systemctl --no-pager --full status "$unit" >&2 || true
  echo >&2
  echo "Inspect the complete privacy-safe stack report with:" >&2
  echo "  sudo t2-touchid-doctor" >&2
  if [[ $unit == t2-native-first-run.service ]]; then
    echo "Inspect the redacted account binding with:" >&2
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
