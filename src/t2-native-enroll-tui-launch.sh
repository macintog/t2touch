#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if (( $# != 0 )); then
  echo 'the fixed-purpose native enrollment launcher accepts no arguments' >&2
  exit 2
fi

if (( EUID != 0 )); then
  exec sudo -n "$0"
fi

tui=/opt/t2-touchid/src/t2-native-enroll-tui.py
[[ -f $tui ]] || tui=${BASH_SOURCE[0]%/*}/t2-native-enroll-tui.py
exec 3<<<'test'
exec /usr/bin/python3 "$tui" --credential-fd 3
