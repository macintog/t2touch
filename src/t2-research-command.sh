#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
command=${0##*/}
case $command in
  t2-native-enroll|t2-native-enroll-tui|t2-native-match|t2-native-provision|\
  t2-native-provision-verify|t2-native-provisioning-preflight|t2-native-replace|\
  t2-native-replace-activate|t2-second-finger-ceremony) ;;
  *) echo "Unknown Touch ID research command" >&2; exit 2 ;;
esac
# Execute the canonical source so sibling-module resolution cannot load a
# stale second implementation from bin. The source owns its original gates.
exec /opt/t2-touchid/.venv/bin/python -I \
  "/opt/t2-touchid/src/$command.py" "$@"
