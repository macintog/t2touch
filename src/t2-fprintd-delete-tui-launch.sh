#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

finger=${1:-}
if [[ ! $finger =~ ^finger-([1-9][0-9]{0,8})$ ]]; then
  printf 'DELETION STOPPED\nInvalid numbered fingerprint handle.\n'
  exit 2
fi

number=${BASH_REMATCH[1]}
printf '\033[2J\033[H'
printf '                         T2 TOUCH ID\n'
printf '                  STANDARD FPRINTD DELETION\n\n'
printf '                       DELETING FINGER %s\n' "$number"
printf '             The selected identity is being removed once.\n\n'

status=0
if /usr/bin/fprintd-delete "${USER:?}" -f "$finger"; then
  printf '\n                    FINGERPRINT DELETED\n'
  printf '             Finger %s was removed successfully.\n\n' "$number"
  printf '               CLOSE THIS WINDOW WHEN FINISHED\n'
else
  status=$?
  printf '\n                      DELETION STOPPED\n'
  printf '          No successful deletion was reported by fprintd.\n\n'
  printf '               RETURN TO CODEX FOR RECONCILIATION\n'
fi

# Keep the terminal result visible without an acknowledgement before dispatch.
# Closing the dedicated window sends SIGHUP and ends this passive hold.
while IFS= read -r -s -n 1 key; do
  [[ $key == q || $key == Q || $key == $'\e' ]] && break
done
exit "$status"
