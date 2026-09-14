#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if (( EUID != 0 )); then
  exec sudo -n "$0" "$@"
fi

/usr/bin/install -d -o root -g root -m 0700 /var/lib/t2-touchid/native-match
exec /usr/bin/python3 /opt/t2-touchid/src/t2-match-tui.py "$@"
