#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ $# == 0 || ( $# == 1 && $1 == --check ) ]] || { echo "Usage: $0 [--check]" >&2; exit 2; }
exec 9>/run/lock/t2-touchid-pam.lock
flock -x 9
backup_dir=/var/lib/t2-touchid/pam-backups
restored=0

restore_one() {
  local name=$1 mode=$2
  local backup=$backup_dir/$name.original absent=$backup_dir/$name.absent
  local installed=$backup_dir/$name.installed target=/etc/pam.d/$name tmp
  [[ -f $backup || -f $absent ]] || return 0
  [[ ! -L $target ]] || { echo "Unsafe PAM destination: $target" >&2; exit 1; }
  # Package restoration or an earlier interrupted rollback may already have
  # restored the original while leaving our ownership receipts behind.
  if [[ -f $backup ]] && cmp -s -- "$target" "$backup"; then
    :
  elif [[ -f $absent && ! -e $target && ! -L $target ]]; then
    :
  elif [[ -e $target || -L $target ]]; then
    if [[ ! -f $installed || -L $target ]] || ! cmp -s -- "$target" "$installed"; then
      echo "Refusing to overwrite changed PAM stack: $target" >&2
      exit 1
    fi
  fi
  [[ $mode == check ]] && return 0
  if [[ -f $backup ]]; then
    if ! cmp -s -- "$target" "$backup"; then
      tmp=$(mktemp "/etc/pam.d/.$name.t2.XXXXXX")
      install -o root -g root -m 0644 "$backup" "$tmp"
      mv -f -- "$tmp" "$target"
    fi
  else
    rm -f -- "$target"
  fi
  rm -f -- "$backup" "$absent" "$installed"
  restored=1
}

restore_system_auth() {
  local mode=$1 target=/etc/pam.d/system-auth backup=$backup_dir/system-auth.original
  local gate='auth [success=ignore default=1] pam_succeed_if.so quiet service = sudo'
  local hook='auth optional pam_exec.so quiet seteuid /usr/local/sbin/t2-pam-unlock'
  local legacy_hook='auth optional pam_exec.so quiet expose_authtok seteuid /usr/local/sbin/t2-pam-unlock'
  local removed=0 line tmp gate_count hook_count
  [[ -f $backup ]] || return 0
  [[ ! -L $target ]] || { echo "Unsafe system-auth destination." >&2; exit 1; }
  if cmp -s -- "$target" "$backup"; then
    [[ $mode == check ]] && return 0
    rm -f -- "$backup"
    restored=1
    return 0
  fi
  [[ -f $target && ! -L $target ]] || { echo "Unsafe system-auth destination." >&2; exit 1; }
  gate_count=$(grep -Fxc "$gate" "$target" || true)
  hook_count=$(grep -Fxc -e "$hook" -e "$legacy_hook" "$target" || true)
  [[ $gate_count == 1 && $hook_count == 1 ]] || {
    echo "Refusing to alter a system-auth stack without the exact managed hook." >&2
    exit 1
  }
  [[ $mode == check ]] && return 0
  tmp=$(mktemp /etc/pam.d/.system-auth.t2.XXXXXX)
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$gate" || $line == "$hook" || $line == "$legacy_hook" ]]; then
      ((removed += 1))
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$target"
  [[ $removed == 2 ]] || { rm -f -- "$tmp"; exit 1; }
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$target"
  rm -f -- "$backup"
  restored=1
}

# Preflight the entire set while holding the lock, before any destination or
# ownership receipt is changed. A late conflict must not half-restore PAM.
for name in sudo polkit-1 omarchy-lock-password omarchy-lock-fingerprint; do
  restore_one "$name" check
done
restore_system_auth check
[[ ${1:-} != --check ]] || exit 0
for name in sudo polkit-1 omarchy-lock-password omarchy-lock-fingerprint; do
  restore_one "$name" apply
done
restore_system_auth apply
[[ $restored == 1 ]] || { echo "No PAM backups found." >&2; exit 1; }
rm -f -- /etc/security/t2-touchid-sudo-prompt
echo "Original PAM files restored."
