#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if (( $# != 0 )); then
  echo 'the fixed-purpose second-finger launcher accepts no arguments' >&2
  exit 2
fi
if (( EUID != 0 )); then
  exec sudo -n "$0"
fi
exec /usr/bin/python3 /opt/t2-touchid/src/t2-second-finger-ceremony.py
