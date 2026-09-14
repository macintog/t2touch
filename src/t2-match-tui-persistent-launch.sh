#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -u

project_root=$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)
cd "$project_root" || exit 1

while true; do
  ./src/t2-match-tui-launch.sh
  status=$?
  printf '\nCapture TUI exited with status %s. Evidence was preserved.\n' "$status"
  printf 'Press Enter to restart it, or close this terminal when finished.\n'
  IFS= read -r || exit "$status"
done
