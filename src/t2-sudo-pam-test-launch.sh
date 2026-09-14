#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# `sudo -v` deliberately enters PAM even for this reference machine's
# NOPASSWD command policy. Invalidating the timestamp makes the result belong
# to this one visible transaction rather than an earlier cached success.
/usr/bin/sudo -K
if /usr/bin/sudo -v; then
  printf '\nSUDO AUTHENTICATION SUCCEEDED\n'
else
  status=$?
  printf '\nSUDO AUTHENTICATION FAILED (%d)\n' "$status"
  exit "$status"
fi
