#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

interface=${1:-}
if [[ ! $interface =~ ^[a-zA-Z0-9_.:-]+$ ]]; then
  echo "A valid network interface name is required." >&2
  exit 2
fi

net_path=/sys/class/net/$interface
[[ -d $net_path ]] || {
  echo "Network interface $interface is absent." >&2
  exit 1
}
if [[ -r $net_path/carrier ]] && [[ $(<"$net_path/carrier") == 1 ]]; then
  exit 0
fi

device=$(readlink -f -- "$net_path/device")
driver=$(readlink -f -- "$device/driver")
usb_interface=$(basename -- "$device")
if [[ $(basename -- "$driver") != cdc_ncm ]] ||
   [[ ! $usb_interface =~ ^[0-9]+-[0-9.]+:[0-9.]+$ ]]; then
  echo "Network interface $interface is not a USB CDC-NCM function." >&2
  exit 1
fi

printf '%s' "$usb_interface" >"$driver/unbind"
sleep 2
printf '%s' "$usb_interface" >"$driver/bind"

deadline=$((SECONDS + 10))
while (( SECONDS < deadline )); do
  if [[ -d $net_path ]]; then
    ip link set dev "$interface" up 2>/dev/null || true
    if [[ -r $net_path/carrier ]] && [[ $(<"$net_path/carrier") == 1 ]]; then
      exit 0
    fi
  fi
  sleep 0.5
done

echo "CDC-NCM carrier did not appear after rebinding $interface." >&2
exit 1
