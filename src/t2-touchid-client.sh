#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
case ${0##*/} in
  t2-touchid-status) command=status ;;
  t2-touchid-list) command=list ;;
  t2-touchid-count) command=count ;;
  t2-touchid-verify) command=verify ;;
  *) echo "Unknown Touch ID command" >&2; exit 2 ;;
esac
exec /opt/t2-touchid/.venv/bin/python -I \
  /opt/t2-touchid/src/t2-touchid-client.py "$command" "$@"
