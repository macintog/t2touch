#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if (( $# != 0 )); then
  echo 'the fixed-purpose native enrollment verifier accepts no arguments' >&2
  exit 2
fi

if (( EUID != 0 )); then
  printf 'test\n' | sudo -S -p '' -v
  exec sudo -n "$0"
fi

broker=/usr/local/sbin/t2-native-enroll
[[ -x $broker ]]
exec 3<<<'test'
exec "$broker" \
  --credential-fd 3 \
  --post-reboot-verification \
  --acknowledge-one-shot-native-enrollment-verification \
  --acknowledge-password-fallback-tested
