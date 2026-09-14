#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if (( EUID == 0 )); then
  echo "Run the graphical authorization demo as the desktop user." >&2
  exit 2
fi

result=1
if pkexec --disable-internal-agent /usr/bin/true; then
  result=0
  summary='Administrator authorization approved'
  body='Touch ID successfully authorized a harmless privileged action.'
else
  summary='Administrator authorization not approved'
  body='No privileged action was performed.'
fi

if command -v notify-send >/dev/null 2>&1; then
  notify-send --app-name='T2 Touch ID' "$summary" "$body" || true
fi
exit "$result"
