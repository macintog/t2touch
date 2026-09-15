#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

module=t2_sep_transport
provisioning_parameter=/sys/module/$module/parameters/enable_identity_provisioning
replacement_parameter=/sys/module/$module/parameters/enable_identity_replacement
config=/etc/t2-touchid.conf
prepare_native_recovery=0
case "${1:-}" in
  '') [[ $# -eq 0 ]] || exit 2 ;;
  --prepare-native-recovery) [[ $# -eq 1 ]] || exit 2; prepare_native_recovery=1 ;;
  *) exit 2 ;;
esac

mapfile -t authority_modes < <(
  sed -n 's/^T2_TOUCHID_AUTHORITY_MODE=//p' "$config"
)
if (( ${#authority_modes[@]} != 1 )) ||
  [[ ${authority_modes[0]} != linux-native &&
     ${authority_modes[0]} != macos-control-oracle ]]; then
  echo "invalid T2 Touch ID authority mode" >&2
  exit 1
fi

needs_native_provisioning=0
needs_native_replacement=0
if [[ ${authority_modes[0]} == linux-native && $prepare_native_recovery == 1 ]]; then
  # Recovery restores the transport while userspace journals remain frozen.
  # These capabilities do not dispatch mutations: each operation still needs
  # its normal kernel-owned absence, ACM, session and replacement checks.
  # No first-run owner is started by the recovery installer.
  needs_native_provisioning=1
  needs_native_replacement=1
elif [[ ${authority_modes[0]} == linux-native ]]; then
  native_gate_output=$(
    /opt/t2-touchid/.venv/bin/python \
      /opt/t2-touchid/src/t2-native-transport-gates.py
  )
  if [[ $native_gate_output =~ ^([01])[[:space:]]([01])$ ]]; then
    needs_native_provisioning=${BASH_REMATCH[1]}
    needs_native_replacement=${BASH_REMATCH[2]}
  else
    echo "invalid Linux-native transport gate result" >&2
    exit 1
  fi
fi

if [[ -e /dev/t2-aks && -e /dev/t2-acm ]] &&
  { (( ! needs_native_provisioning )) ||
    [[ -r $provisioning_parameter && $(<$provisioning_parameter) == Y ]]; } &&
  { (( ! needs_native_replacement )) ||
    [[ -r $replacement_parameter && $(<$replacement_parameter) == Y ]]; }; then
  exit 0
fi

if [[ -d /sys/module/$module ]]; then
  /usr/local/sbin/t2-sep-transport-unload
fi

# Pass probe_capabilities explicitly: modprobe.d must stay observation-only by
# default (early auto-load safety), so the service load cannot inherit it.
# The v1 negotiation is a SEP-side prerequisite, not just a check — without it
# SEP ignores all endpoint-7 exchanges (keybag-load and even the read-only
# capabilities query time out). Observed MacBookPro15,2 2026-09-06.
module_arguments=(register_ool=1 probe_capabilities=1)
if [[ ${authority_modes[0]} == macos-control-oracle ]]; then
  module_arguments+=(register_acm=1 retain_runtime_handle=1)
else
  mapfile -t platform_asids < <(
    sed -n 's/^T2_TOUCHID_AKS_PLATFORM_ASID=//p' "$config"
  )
  mapfile -t platform_cdhashes < <(
    sed -n 's/^T2_TOUCHID_AKS_PLATFORM_CDHASH=//p' "$config"
  )
  if (( ${#platform_asids[@]} != 1 )) ||
    [[ ! ${platform_asids[0]} =~ ^[0-9]+$ ]] ||
    (( 10#${platform_asids[0]} > 4294967295 )); then
    echo "invalid Linux-native AKS platform ASID" >&2
    exit 1
  fi
  if (( ${#platform_cdhashes[@]} != 1 )) ||
    [[ -n ${platform_cdhashes[0]} &&
       ! ${platform_cdhashes[0]} =~ ^[[:xdigit:]]{40}$ ]]; then
    echo "invalid Linux-native AKS platform CDHash" >&2
    exit 1
  fi
  module_arguments+=(
    register_acm=1
    "aks_platform_asid=${platform_asids[0]}"
    aks_platform_proc_uniqueid=1
  )
  if [[ -n ${platform_cdhashes[0]} ]]; then
    module_arguments+=("aks_platform_cdhash=${platform_cdhashes[0],,}")
  fi
  if (( needs_native_provisioning )); then
    module_arguments+=(enable_identity_provisioning=1)
  fi
  if (( needs_native_replacement )); then
    module_arguments+=(enable_identity_provisioning=1 enable_identity_replacement=1)
  fi
fi
/usr/bin/modprobe "$module" "${module_arguments[@]}"
[[ -e /dev/t2-aks ]] || {
  echo "$module loaded without creating /dev/t2-aks" >&2
  exit 1
}
[[ -e /dev/t2-acm ]] || {
  echo "$module loaded without creating /dev/t2-acm" >&2
  exit 1
}
