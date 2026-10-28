#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Sourced by install-omarchy.sh and install.sh before either changes anything.
# On a Mac that also runs macOS, macOS removed the account's Touch ID
# fingerprints and replaced its keybag and login keychain after T2Touch had run
# in Linux. Refuse wherever Apple storage shows macOS might be present, unless
# the user states that this Mac doesn't run macOS.

macos_guard_override_flag=--this-mac-does-not-run-macos
macos_guard_confirmation="this Mac does not run macOS"
# Set to 1 once the user has typed the statement in this process.
macos_guard_statement_taken=0
# Shown first in both the refusal and the override prompt.
macos_guard_harm="On our test Mac, after T2Touch had run in Linux, macOS removed the account's
Touch ID fingerprints and replaced its keybag. It also replaced the login
keychain, where macOS keeps saved passwords. The old login keychain no longer
opens with the account's password."

# GPT partition types and Apple partition map names for APFS, HFS+ and Core
# Storage, and the filesystem names blkid gives Apple filesystems.
macos_guard_partition_types=(
  7c3457ef-0000-11aa-aa11-00306543ecac
  48465300-0000-11aa-aa11-00306543ecac
  53746f72-6167-11aa-aa11-00306543ecac
  apple_apfs
  apple_hfs
  apple_corestorage
)
macos_guard_filesystems=(apfs hfs hfsplus hfsx)

# Print one line per block device that is Apple storage or can't be checked.
# lsblk needs no root: it reads partition and filesystem types from udev.
find_macos_guard_storage() {
  local listing line path type parttype fstype known
  local pairs='^PATH="([^"]*)" TYPE="([^"]*)" PARTTYPE="([^"]*)" FSTYPE="([^"]*)"$'
  if ! listing=$(lsblk --noheadings --pairs --output PATH,TYPE,PARTTYPE,FSTYPE 2>&1); then
    printf '  lsblk could not list the disks: %s\n' "${listing:-no output}"
    return
  fi
  # A Mac has at least its internal disk; an empty list means lsblk can't see.
  if [[ -z ${listing//[[:space:]]/} ]]; then
    echo "  lsblk listed no disks"
    return
  fi
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    if [[ ! $line =~ $pairs ]]; then
      printf '  lsblk output not understood: %s\n' "$line"
      continue
    fi
    path=${BASH_REMATCH[1]}
    type=${BASH_REMATCH[2]}
    parttype=${BASH_REMATCH[3],,}
    fstype=${BASH_REMATCH[4],,}
    for known in "${macos_guard_partition_types[@]}"; do
      if [[ $parttype == "$known" ]]; then
        printf '  %s: Apple partition type %s\n' "$path" "$parttype"
        continue 2
      fi
    done
    for known in "${macos_guard_filesystems[@]}"; do
      if [[ $fstype == "$known" ]]; then
        printf '  %s: Apple filesystem %s\n' "$path" "$fstype"
        continue 2
      fi
    done
    # Without udev data lsblk shows a blank type, which proves nothing.
    if [[ $type == part && -z $parttype ]]; then
      printf '  %s: partition type unreadable\n' "$path"
    fi
  done <<<"$listing"
}

# Usage: refuse_if_macos_possible OVERRIDE CONFIRMED
# OVERRIDE is 1 when the user passed the override flag. CONFIRMED is 1 when
# the Omarchy wrapper already took the typed confirmation for this run.
refuse_if_macos_possible() {
  local override=$1 confirmed=$2 findings answer
  findings=$(find_macos_guard_storage)
  [[ -n $findings ]] || return 0
  if (( override && confirmed )); then
    return 0
  fi
  if (( ! override )); then
    printf '%s\n' \
      "Stopped before changing anything: T2Touch can't rule out macOS on this Mac." \
      "" "$macos_guard_harm" "" \
      "Don't install T2Touch on a Mac that also runs macOS. See" \
      "\"Macs that also run macOS\" in README.md." \
      "" "Found:" "$findings" "" \
      "If this Mac can't start macOS from any disk, for example because the storage" \
      "above is left over from a removed macOS or is an external disk, rerun with" \
      "$macos_guard_override_flag." >&2
    return 1
  fi
  printf '%s\n' \
    "T2Touch can't rule out macOS on this Mac." \
    "" "$macos_guard_harm" "" \
    "Found:" "$findings" "" \
    "You passed $macos_guard_override_flag. Continue only if this Mac can't start" \
    "macOS from any disk. To continue, type: $macos_guard_confirmation" >&2
  if ! read -r -p "> " answer || [[ $answer != "$macos_guard_confirmation" ]]; then
    echo "Not confirmed. Stopped before changing anything." >&2
    return 1
  fi
  # shellcheck disable=SC2034 # install-omarchy.sh reads it.
  macos_guard_statement_taken=1
}
