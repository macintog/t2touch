#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
LOG="$SCRIPT_DIR/t2-export-control-private.log"

if [[ "$(uname -s)" != Darwin ]]; then
  echo "This helper must run from macOS." >&2
  exit 1
fi

exec > >(/usr/bin/tee "$LOG") 2>&1
chmod 600 "$LOG" 2>/dev/null || true

echo "Starting both private Apple-control captures."
echo "This log is private and may contain local macOS paths."
started_at="$(date +%s)"

keybag_status=0
catacomb_status=0
"$SCRIPT_DIR/macos-export-keybags.sh" || keybag_status=$?
"$SCRIPT_DIR/macos-export-touchid-catacomb.sh" --no-reboot \
  || catacomb_status=$?

missing=0
stale=0
invalid=0
for archive in \
  "$SCRIPT_DIR/t2-keybags.tar.gz" \
  "$SCRIPT_DIR/t2-touchid-catacomb.tar.gz"; do
  if [[ ! -s "$archive" ]]; then
    echo "Expected private archive was not created: $archive" >&2
    missing=1
    continue
  fi
  archive_mtime="$(stat -f '%m' "$archive" 2>/dev/null || printf '0')"
  if (( archive_mtime < started_at )); then
    echo "Expected archive was not refreshed by this run: $archive" >&2
    stale=1
  fi
  chmod 600 "$archive" 2>/dev/null || true
done

if [[ -s "$SCRIPT_DIR/t2-keybags.tar.gz" ]]; then
  if ! tar -xOzf "$SCRIPT_DIR/t2-keybags.tar.gz" state/path-map.txt \
      2>/dev/null | awk 'NF { found=1 } END { exit found ? 0 : 1 }'; then
    echo "Keybag archive contains no copied-candidate map." >&2
    invalid=1
  fi
  if ! tar -tzf "$SCRIPT_DIR/t2-keybags.tar.gz" 2>/dev/null \
      | awk '/^state\/candidate-[0-9][0-9][0-9][0-9](\/|$)/ { found=1 }
             END { exit found ? 0 : 1 }'; then
    echo "Keybag archive contains no copied candidate payload." >&2
    invalid=1
  fi
fi

if [[ -s "$SCRIPT_DIR/t2-touchid-catacomb.tar.gz" ]] \
    && ! tar -tzf "$SCRIPT_DIR/t2-touchid-catacomb.tar.gz" 2>/dev/null \
      | awk '/[.]cat$/ { found=1 } END { exit found ? 0 : 1 }'; then
  echo "Catacomb archive contains no Catacomb record." >&2
  invalid=1
fi

sync

if (( keybag_status != 0 || catacomb_status != 0 \
      || missing != 0 || stale != 0 || invalid != 0 )); then
  echo "Apple-control capture incomplete:" >&2
  echo "  keybag helper status: $keybag_status" >&2
  echo "  Catacomb helper status: $catacomb_status" >&2
  echo "  missing expected archive: $missing" >&2
  echo "  stale expected archive: $stale" >&2
  echo "  structurally invalid archive: $invalid" >&2
  echo "Private diagnostic log: $LOG" >&2
  exit 1
fi

echo "Both private control archives are present and flushed."
echo "Reboot normally and choose Linux; this helper does not reboot the Mac."
