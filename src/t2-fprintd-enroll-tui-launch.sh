#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# `verify` opens the same screen in verification mode; anything else is the
# neutral finger handle to enroll.
mode=${1:-finger-1}

if [[ $mode == verify ]]; then
  exec /opt/t2-touchid/.venv/bin/python \
    /opt/t2-touchid/src/t2-fprintd-enroll-tui.py \
    --verify
fi

exec /opt/t2-touchid/.venv/bin/python \
  /opt/t2-touchid/src/t2-fprintd-enroll-tui.py \
  --finger "$mode"
