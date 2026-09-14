#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# PAM gate: success permits the following fingerprint modules; any failure
# skips directly to password authentication.
[[ $EUID -eq 0 ]] || exit 1
config=/etc/t2-touchid.conf
mapfile -t authority_modes < <(
  sed -n 's/^T2_TOUCHID_AUTHORITY_MODE=//p' "$config"
)
(( ${#authority_modes[@]} == 1 )) || exit 1
if [[ ${authority_modes[0]} == linux-native ]]; then
  exec /opt/t2-touchid/.venv/bin/python \
    /opt/t2-touchid/src/t2_native_pam_ready.py
fi
[[ ${authority_modes[0]} == macos-control-oracle ]] || exit 1
state_file=/run/t2-touchid/keybag.env
ready_file=/run/t2-touchid/keybags-unlocked
[[ -f $state_file && -f $ready_file ]] || exit 1
[[ $(stat -c '%a:%U:%G' "$state_file" 2>/dev/null) == 600:root:root ]] || exit 1
[[ $(stat -c '%a:%U:%G' "$ready_file" 2>/dev/null) == 600:root:root ]] || exit 1
cmp -s -- "$state_file" "$ready_file"
