#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

exec /opt/t2-touchid/.venv/bin/python \
  /opt/t2-touchid/src/t2-fprintd-enroll-tui.py \
  --expect-no-match --finger finger-1
