#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

finger=${1:-finger-1}

exec /opt/t2-touchid/.venv/bin/python \
  /opt/t2-touchid/src/t2-fprintd-enroll-tui.py \
  --finger "$finger"
