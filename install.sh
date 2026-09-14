#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo ./install.sh" >&2
  exit 1
fi
if [[ -z ${SUDO_USER:-} || $SUDO_USER == root ]]; then
  echo "Run through sudo from the desktop user that will use Touch ID." >&2
  exit 1
fi

source_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)

prepare_update=0
case "${1:-}" in
  '') [[ $# -eq 0 ]] || exit 2 ;;
  --prepare-transport-update) [[ $# -eq 1 ]] || exit 2; prepare_update=1 ;;
  *) echo "Usage: sudo ./install.sh [--prepare-transport-update]" >&2; exit 2 ;;
esac
# shellcheck source=tools/installer-kernel.sh
source "$source_dir/tools/installer-kernel.sh"

# Build and compare against the running module before changing installed
# files, configuration, DKMS stamps, or service state. A disk source stamp
# describes the next load, not the module already resident in this kernel.
make -C "$source_dir/src"
live_transport_matches=0
if [[ -d /sys/module/t2_sep_transport ]]; then
  live_srcversion=$(cat /sys/module/t2_sep_transport/srcversion 2>/dev/null || true)
  desired_srcversion=$(modinfo -F srcversion "$source_dir/src/t2_sep_transport.ko" 2>/dev/null || true)
  if [[ -z $live_srcversion || -z $desired_srcversion ||
        $live_srcversion != "$desired_srcversion" ]]; then
    if [[ -n $live_srcversion && -n $desired_srcversion && $prepare_update == 1 ]]; then
      prepare_transport_update || exit $?
    fi
    echo "The running T2 transport differs or cannot be identified; installation stopped." >&2
    echo "For an identified transport change, run ./install-omarchy.sh --prepare-transport-update, then restart and rerun the installer." >&2
    exit 2
  fi
  live_transport_matches=1
fi
if (( prepare_update )); then
  echo "No identified transport change needs preparation." >&2
  exit 2
fi
check_applesmc_prerequisite || exit $?

target_dir=/opt/t2-touchid
target_user=$SUDO_USER
target_uid=$(id -u -- "$target_user")
target_gid=$(id -g -- "$target_user")
target_home=$(getent passwd "$target_user" | cut -d: -f6)
if [[ ! $target_uid =~ ^[0-9]+$ || -z $target_home || ! -d $target_home ]]; then
  echo "Could not determine the home directory for $target_user." >&2
  exit 1
fi

detect_t2_interface() {
  local path driver properties
  local -a candidates=()
  for path in /sys/class/net/*; do
    [[ -e $path ]] || continue
    driver=$(basename -- "$(readlink -f -- "$path/device/driver" 2>/dev/null)" 2>/dev/null || true)
    [[ $driver == cdc_ncm ]] || continue
    properties=$(udevadm info -q property -p "$path" 2>/dev/null || true)
    if grep -Fxq 'ID_VENDOR_ID=05ac' <<<"$properties" &&
      grep -Fxq 'ID_MODEL_ID=8233' <<<"$properties"; then
      candidates+=("${path##*/}")
    fi
  done
  if (( ${#candidates[@]} != 1 )); then
    echo "Expected one Apple T2 Controller network interface; found ${#candidates[@]}." >&2
    return 1
  fi
  printf '%s\n' "${candidates[0]}"
}

if [[ ! -f /etc/t2-touchid.conf ]]; then
  t2_interface=$(detect_t2_interface)
  install -o root -g root -m 0600 "$source_dir/t2-touchid.conf.example" /etc/t2-touchid.conf
  sed -i "s/^T2_TOUCHID_USER=.*/T2_TOUCHID_USER=$target_user/" /etc/t2-touchid.conf
  sed -i "s/^T2_TOUCHID_INTERFACE=.*/T2_TOUCHID_INTERFACE=$t2_interface/" /etc/t2-touchid.conf
  # Apple T2 Controller exposes a fixed private CDC-NCM peer.  The persistent
  # network service validates reachability before any biometric operation.
  t2_fixed_peer=fe80::aede:48ff:fe33:4455
  sed -i "s/^T2_TOUCHID_HOST=.*/T2_TOUCHID_HOST=$t2_fixed_peer/" /etc/t2-touchid.conf
  echo "Detected the Apple T2 Controller on $t2_interface."
fi

# Migrate older configurations without overwriting administrator choices.
ensure_config_default() {
  local key=$1 value=$2
  grep -q "^${key}=" /etc/t2-touchid.conf || printf '%s=%s\n' "$key" "$value" >>/etc/t2-touchid.conf
}
ensure_config_default T2_TOUCHID_MACOS_USER_ID 501
ensure_config_default T2_TOUCHID_SPECIAL_BAG -501
# The old singleton anatomy label was fabricated presentation metadata.  The
# numbered identity model derives no runtime authority from it.
sed -i '/^T2_TOUCHID_ENROLLED_FINGER=/d' /etc/t2-touchid.conf
ensure_config_default T2_TOUCHID_AUTO_SYNC_ADAPTIVE 0
ensure_config_default T2_TOUCHID_ENABLE_ACM_RESEARCH 0
ensure_config_default T2_TOUCHID_PROBE_CAPABILITIES 0
ensure_config_default T2_TOUCHID_ENABLE_IDENTITY_PROVISIONING 0
ensure_config_default T2_TOUCHID_ENABLE_IDENTITY_REPLACEMENT 0
ensure_config_default T2_TOUCHID_INVENTORY_ONLY 0
ensure_config_default T2_TOUCHID_AKS_PLATFORM_ASID 0
ensure_config_default T2_TOUCHID_AKS_PLATFORM_CDHASH ''
ensure_config_default T2_TOUCHID_MACOS_APP_VERSION 0
ensure_config_default T2_TOUCHID_SEP_EPOCH_MAJOR 1
ensure_config_default T2_TOUCHID_SEP_EPOCH_MINOR 0
ensure_config_default T2_TOUCHID_XART_OS_UUID_FILE ''
ensure_config_default T2_TOUCHID_DEFER_XART_PUBLISH 0
ensure_config_default T2_TOUCHID_REQUIRE_ORACLE_SKS_READY 0
# Existing installations predate the selector and therefore use the
# macOS-control-oracle path. Fresh installs receive linux-native from the
# example configuration copied above.
ensure_config_default T2_TOUCHID_AUTHORITY_MODE macos-control-oracle
ensure_config_default T2_TOUCHID_XART_OS_UUID ''
chmod 0600 /etc/t2-touchid.conf

acm_research=$(sed -n 's/^T2_TOUCHID_ENABLE_ACM_RESEARCH=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ $acm_research != 0 && $acm_research != 1 ]]; then
  echo "T2_TOUCHID_ENABLE_ACM_RESEARCH must be exactly 0 or 1." >&2
  exit 2
fi
probe_capabilities=$(sed -n 's/^T2_TOUCHID_PROBE_CAPABILITIES=//p' /etc/t2-touchid.conf | tail -n 1)
identity_provisioning=$(sed -n 's/^T2_TOUCHID_ENABLE_IDENTITY_PROVISIONING=//p' /etc/t2-touchid.conf | tail -n 1)
identity_replacement=$(sed -n 's/^T2_TOUCHID_ENABLE_IDENTITY_REPLACEMENT=//p' /etc/t2-touchid.conf | tail -n 1)
inventory_only=$(sed -n 's/^T2_TOUCHID_INVENTORY_ONLY=//p' /etc/t2-touchid.conf | tail -n 1)
defer_xart_publish=$(sed -n 's/^T2_TOUCHID_DEFER_XART_PUBLISH=//p' /etc/t2-touchid.conf | tail -n 1)
require_oracle_sks_ready=$(sed -n 's/^T2_TOUCHID_REQUIRE_ORACLE_SKS_READY=//p' /etc/t2-touchid.conf | tail -n 1)
authority_mode=$(sed -n 's/^T2_TOUCHID_AUTHORITY_MODE=//p' /etc/t2-touchid.conf | tail -n 1)
for setting in "$probe_capabilities" "$identity_provisioning" "$identity_replacement" "$inventory_only"; do
  if [[ $setting != 0 && $setting != 1 ]]; then
    echo "native research toggles must be exactly 0 or 1." >&2
    exit 2
  fi
done
if [[ $defer_xart_publish != 0 ]]; then
  echo "T2_TOUCHID_DEFER_XART_PUBLISH is retired and must be 0." >&2
  exit 2
fi
if [[ $require_oracle_sks_ready != 0 && $require_oracle_sks_ready != 1 ]]; then
  echo "T2_TOUCHID_REQUIRE_ORACLE_SKS_READY must be exactly 0 or 1." >&2
  exit 2
fi
if [[ $authority_mode != linux-native && $authority_mode != macos-control-oracle ]]; then
  echo "T2_TOUCHID_AUTHORITY_MODE must be linux-native or macos-control-oracle." >&2
  exit 2
fi
if [[ $authority_mode == linux-native ]]; then
  native_mapping=/var/lib/t2-touchid/users.json
  native_journal=/var/lib/t2-touchid/native-provisioning.jsonl
  native_credential=/etc/credstore.encrypted/t2-touchid-password
  if [[ ! -e $native_mapping && ! -e $native_journal ]]; then
    if [[ ! -e $native_credential ]]; then
      install -d -o root -g root -m 0700 /etc/credstore.encrypted
      identity_credential=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
      if [[ ! $identity_credential =~ ^[0-9a-f]{64}$ ]]; then
        unset identity_credential
        echo "Could not generate the private identity credential." >&2
        exit 2
      fi
      umask 077
      if ! printf '%s\n' "$identity_credential" | systemd-creds encrypt \
        --name=t2-touchid-password - "$native_credential"; then
        unset identity_credential
        echo "Could not protect the private identity credential." >&2
        exit 2
      fi
      unset identity_credential
      chmod 0600 "$native_credential"
    fi
    if [[ ! -f $native_credential || -L $native_credential ]] ||
      [[ $(stat -c '%u:%g:%a:%h' "$native_credential" 2>/dev/null) != 0:0:600:1 ]]; then
      echo "A blank Linux-native install requires the root-owned mode-0600 encrypted credential at $native_credential." >&2
      echo "Create it with systemd-creds as documented in README.md, then rerun." >&2
      exit 2
    fi
  elif [[ ! -e $native_mapping || ! -e $native_journal ]]; then
    echo "Linux-native first-run state is incomplete and requires reconciliation." >&2
    exit 2
  fi
fi
auto_sync_adaptive=$(sed -n 's/^T2_TOUCHID_AUTO_SYNC_ADAPTIVE=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ $auto_sync_adaptive != 0 && $auto_sync_adaptive != 1 ]]; then
  echo "T2_TOUCHID_AUTO_SYNC_ADAPTIVE must be exactly 0 or 1." >&2
  exit 2
fi
mapfile -t macos_user_ids < <(
  sed -n 's/^T2_TOUCHID_MACOS_USER_ID=//p' /etc/t2-touchid.conf
)
if (( ${#macos_user_ids[@]} != 1 )); then
  echo "T2_TOUCHID_MACOS_USER_ID must occur exactly once." >&2
  exit 2
fi
macos_user_id=${macos_user_ids[0]}
if [[ ! $macos_user_id =~ ^[1-9][0-9]*$ || ${#macos_user_id} -gt 10 ]] || \
    (( 10#$macos_user_id < 10 || 10#$macos_user_id > 2147483647 )); then
  echo "T2_TOUCHID_MACOS_USER_ID cannot form a signed AKS alias." >&2
  exit 2
fi
mapfile -t special_bags < <(
  sed -n 's/^T2_TOUCHID_SPECIAL_BAG=//p' /etc/t2-touchid.conf
)
if (( ${#special_bags[@]} != 1 )) || \
    [[ ${special_bags[0]} != "-$macos_user_id" ]]; then
  echo "T2_TOUCHID_SPECIAL_BAG must be the derived negative Apple user ID." >&2
  exit 2
fi
aks_platform_cdhash=$(sed -n 's/^T2_TOUCHID_AKS_PLATFORM_CDHASH=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ -n $aks_platform_cdhash && ! $aks_platform_cdhash =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "T2_TOUCHID_AKS_PLATFORM_CDHASH must be empty or exactly 40 hexadecimal characters." >&2
  exit 2
fi
aks_platform_asid=$(sed -n 's/^T2_TOUCHID_AKS_PLATFORM_ASID=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ ! $aks_platform_asid =~ ^[0-9]+$ ]] || (( aks_platform_asid > 4294967295 )); then
  echo "T2_TOUCHID_AKS_PLATFORM_ASID must be an unsigned 32-bit integer." >&2
  exit 2
fi
macos_app_version=$(sed -n 's/^T2_TOUCHID_MACOS_APP_VERSION=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ $macos_app_version != 0 ]]; then
  echo "T2_TOUCHID_MACOS_APP_VERSION is retired and must be 0." >&2
  exit 2
fi
sep_epoch_major=$(sed -n 's/^T2_TOUCHID_SEP_EPOCH_MAJOR=//p' /etc/t2-touchid.conf | tail -n 1)
sep_epoch_minor=$(sed -n 's/^T2_TOUCHID_SEP_EPOCH_MINOR=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ ! $sep_epoch_major =~ ^[0-9]+$ ]] || (( sep_epoch_major > 255 )); then
  echo "T2_TOUCHID_SEP_EPOCH_MAJOR must be an unsigned byte." >&2
  exit 2
fi
if [[ ! $sep_epoch_minor =~ ^[0-9]+$ ]] || (( sep_epoch_minor > 255 )); then
  echo "T2_TOUCHID_SEP_EPOCH_MINOR must be an unsigned byte." >&2
  exit 2
fi
xart_os_uuid_inline=$(sed -n 's/^T2_TOUCHID_XART_OS_UUID=//p' /etc/t2-touchid.conf | tail -n 1)
xart_os_uuid_file=$(sed -n 's/^T2_TOUCHID_XART_OS_UUID_FILE=//p' /etc/t2-touchid.conf | tail -n 1)
if [[ -n $xart_os_uuid_inline && -n $xart_os_uuid_file ]]; then
  echo "Set only one of T2_TOUCHID_XART_OS_UUID and T2_TOUCHID_XART_OS_UUID_FILE." >&2
  exit 2
fi
xart_os_uuid=$xart_os_uuid_inline
if [[ -n $xart_os_uuid || -n $xart_os_uuid_file ]]; then
  echo "Direct-PCI xART OS-UUID publication is retired; both xART settings must be empty." >&2
  exit 2
fi
if [[ $inventory_only == 1 ]] && { [[ $acm_research == 1 ]] || [[ $probe_capabilities == 1 ]] || [[ $identity_provisioning == 1 ]] || [[ $identity_replacement == 1 ]] || [[ -n $xart_os_uuid ]]; }; then
  echo "Inventory-only mode requires ACM research, capability probing, identity provisioning, identity replacement, and xART OS-UUID publication to be disabled." >&2
  exit 2
fi
if [[ $identity_provisioning == 1 ]] && { [[ $acm_research != 1 ]] || [[ $probe_capabilities != 1 ]]; }; then
  echo "Identity provisioning requires ACM research and capability probing enabled." >&2
  exit 2
fi
if [[ $identity_replacement == 1 ]] && { [[ $identity_provisioning != 1 ]] || [[ $acm_research != 1 ]] || [[ $probe_capabilities != 1 ]]; }; then
  echo "Identity replacement requires identity provisioning, ACM research, and capability probing enabled." >&2
  exit 2
fi

install -d -o root -g root -m 0755 "$target_dir" "$target_dir/src" /usr/local/lib/t2-touchid
install -d -o root -g root -m 0700 \
  /var/lib/t2-touchid /var/lib/t2-touchid/activation \
  /var/lib/t2-touchid/biolockout /var/lib/t2-touchid/catacomb \
  /var/lib/t2-touchid/fprint-sequence \
  /var/lib/t2-touchid/mutations /var/lib/t2-touchid/native-match \
  /var/lib/t2-touchid/users \
  /var/lib/t2-touchid/replacement-archive \
  "/var/lib/t2-touchid/users/$target_uid" \
  "/var/lib/t2-touchid/users/$target_uid/identities"
install -d -o root -g root -m 0755 /usr/share/polkit-1/actions
install -d -o root -g root -m 0700 \
  /var/lib/t2-touchid /var/lib/t2-touchid/users \
  /var/lib/t2-touchid/mutations /var/lib/t2-touchid/recovery-anchors \
  /var/lib/t2-touchid/external-reconciliation-backups
install -d -o root -g root -m 0700 /run/t2-touchid/workers
install -o root -g root -m 0755 "$source_dir/src/"*.py "$target_dir/src/"
install -o root -g root -m 0755 "$source_dir/src/t2touch.py" /usr/local/bin/t2touch
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-delete.sh" /usr/local/sbin/t2-touchid-delete
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-doctor.py" /usr/local/sbin/t2-touchid-doctor
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-inventory.py" /usr/local/sbin/t2-touchid-inventory
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-identities.py" /usr/local/sbin/t2-touchid-identities
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-provision-catacomb.py" /usr/local/sbin/t2-touchid-provision-catacomb
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-identify-finger.py" /usr/local/sbin/t2-touchid-identify-finger
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-manage.py" /usr/local/sbin/t2-touchid-manage
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-baseline.py" /usr/local/sbin/t2-touchid-baseline
install -o root -g root -m 0755 "$source_dir/src/t2-catacomb-fixture-check.py" /usr/local/sbin/t2-catacomb-fixture-check
install -o root -g root -m 0755 "$source_dir/src/t2-acm-preflight.py" /usr/local/sbin/t2-acm-preflight
install -o root -g root -m 0755 "$source_dir/src/t2-aks-observe-test.py" /usr/local/sbin/t2-aks-observe-test
install -o root -g root -m 0755 "$source_dir/src/t2-acm-lifecycle-test.py" /usr/local/sbin/t2-acm-lifecycle-test
install -o root -g root -m 0755 "$source_dir/src/t2-acm-policy-preflight.py" /usr/local/sbin/t2-acm-policy-preflight
install -o root -g root -m 0755 "$source_dir/src/t2-acm-authorize-test.py" /usr/local/sbin/t2-acm-authorize-test
install -o root -g root -m 0755 "$source_dir/src/t2-acm-identity-secret-test.py" /usr/local/sbin/t2-acm-identity-secret-test
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-enroll-test.py" /usr/local/sbin/t2-touchid-enroll-test
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-enroll.py" /usr/local/sbin/t2-touchid-enroll
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-user-map.py" /usr/local/sbin/t2-touchid-user-map
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-user-broker-gate.py" /usr/local/sbin/t2-touchid-user-broker-gate
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-fprint-status.py" /usr/local/sbin/t2-touchid-fprint-status
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-fprint-enrollment-gate.py" /usr/local/sbin/t2-touchid-fprint-enrollment-gate
install -o root -g root -m 0755 "$source_dir/src/t2-touchid-post-reboot.py" /usr/local/sbin/t2-touchid-post-reboot
install -o root -g root -m 0755 "$source_dir/src/t2-native-enroll.py" /usr/local/sbin/t2-native-enroll
install -o root -g root -m 0700 "$source_dir/src/t2-fprint-enrollment-worker.py" /usr/local/sbin/t2-fprint-enrollment-worker
install -o root -g root -m 0700 "$source_dir/src/t2-fprint-delete-worker.py" /usr/local/sbin/t2-fprint-delete-worker
install -o root -g root -m 0644 "$source_dir/README.md" "$target_dir/README.md"
install -o root -g root -m 0644 "$source_dir/ROADMAP.md" "$target_dir/ROADMAP.md"
install -o root -g root -m 0644 \
  "$source_dir/polkit/org.t2linux.touchid.policy" \
  /usr/share/polkit-1/actions/org.t2linux.touchid.policy

python -m venv "$target_dir/.venv"
requirements_stamp=$target_dir/.requirements.sha256
requirements_hash=$(sha256sum "$source_dir/requirements.txt" | cut -d' ' -f1)
installed_hash=$(sed -n '1p' "$requirements_stamp" 2>/dev/null || true)
if [[ $installed_hash != "$requirements_hash" ]] || \
    ! "$target_dir/.venv/bin/python" -c 'import dbus_next, pymobiledevice3' 2>/dev/null; then
  "$target_dir/.venv/bin/pip" install --requirement "$source_dir/requirements.txt"
  printf '%s\n' "$requirements_hash" >"$requirements_stamp"
  chmod 0644 "$requirements_stamp"
else
  echo "Python dependencies are already installed."
fi

install -o root -g root -m 0755 "$source_dir/src/t2-aks-tool" /usr/local/sbin/t2-aks-tool
install -o root -g root -m 0755 \
  "$source_dir/src/t2-pam-fingerprint-prompt" \
  /usr/local/sbin/t2-pam-fingerprint-prompt
install -o root -g root -m 0644 "$source_dir/src/t2_sep_transport.ko" /usr/local/lib/t2-touchid/t2_sep_transport.ko
install -o root -g root -m 0755 "$source_dir/src/t2-keybag-load.sh" /usr/local/sbin/t2-keybag-load
install -o root -g root -m 0700 "$source_dir/src/t2-keybag-unlock.sh" /usr/local/sbin/t2-keybag-unlock
install -o root -g root -m 0700 "$source_dir/src/t2-pam-unlock.sh" /usr/local/sbin/t2-pam-unlock
install -o root -g root -m 0700 "$source_dir/src/t2-pam-fingerprint-ready.sh" /usr/local/sbin/t2-pam-fingerprint-ready
install -o root -g root -m 0700 "$source_dir/src/t2-credential-unlock.sh" /usr/local/sbin/t2-credential-unlock
install -o root -g root -m 0700 "$source_dir/src/t2-biometric-ready.sh" /usr/local/sbin/t2-biometric-ready
install -o root -g root -m 0700 "$source_dir/src/t2-biometric-port-refresh.sh" /usr/local/sbin/t2-biometric-port-refresh
install -o root -g root -m 0700 "$source_dir/src/t2-bridge-network-prepare.sh" /usr/local/sbin/t2-bridge-network-prepare
install -o root -g root -m 0700 "$source_dir/src/t2-sep-transport-load.sh" /usr/local/sbin/t2-sep-transport-load
install -o root -g root -m 0700 "$source_dir/src/t2-sep-transport-unload.sh" /usr/local/sbin/t2-sep-transport-unload
install -o root -g root -m 0700 "$source_dir/src/t2-sep-prerequisite-ready.sh" /usr/local/sbin/t2-sep-prerequisite-ready
install -o root -g root -m 0700 "$source_dir/src/t2-bridge-network-ready.sh" /usr/local/sbin/t2-bridge-network-ready
install -o root -g root -m 0755 "$source_dir/src/t2-native-enroll-tui-launch.sh" /usr/local/sbin/t2-native-enroll-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-fprintd-enroll-tui-launch.sh" /usr/local/sbin/t2-fprintd-enroll-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-fprintd-preview-tui-launch.sh" /usr/local/sbin/t2-fprintd-preview-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-fprintd-verify-tui-launch.sh" /usr/local/sbin/t2-fprintd-verify-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-sudo-pam-test-launch.sh" /usr/local/sbin/t2-sudo-pam-test-launch
install -o root -g root -m 0755 "$source_dir/src/t2-fprintd-negative-tui-launch.sh" /usr/local/sbin/t2-fprintd-negative-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-fprintd-delete-tui-launch.sh" /usr/local/sbin/t2-fprintd-delete-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-new-finger-tui-launch.sh" /usr/local/sbin/t2-native-new-finger-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-match-tui-launch.sh" /usr/local/sbin/t2-native-match-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-negative-tui-launch.sh" /usr/local/sbin/t2-native-negative-tui-launch
install -o root -g root -m 0755 "$source_dir/src/t2-second-finger-tui-launch.sh" /usr/local/sbin/t2-second-finger-tui-launch
install -o root -g root -m 0644 \
  "$source_dir/systemd/system/fprintd.service" \
  "$source_dir/systemd/system/t2-biometric-port-refresh.service" \
  "$source_dir/systemd/system/t2-biometric-ready.service" \
  "$source_dir/systemd/system/t2-bridge-network-ready@.service" \
  "$source_dir/systemd/system/t2-bridge-network.service" \
  "$source_dir/systemd/system/t2-credential-unlock.service" \
  "$source_dir/systemd/system/t2-interactive-unlock.service" \
  "$source_dir/systemd/system/t2-keybag-load.service" \
  "$source_dir/systemd/system/t2-native-first-run.service" \
  "$source_dir/systemd/system/t2-sep-transport.service" \
  "$source_dir/systemd/system/t2-touchid-adaptive-sync.service" \
  "$source_dir/systemd/system/t2-touchid-post-reboot.service" \
  /etc/systemd/system/
install -d -o root -g root -m 0755 /etc/systemd/sleep.conf.d
install -o root -g root -m 0644 \
  "$source_dir/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf" \
  /etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf
if [[ ! $target_home =~ ^/[A-Za-z0-9._/-]+$ ]] || \
    [[ $target_home == *//* || $target_home == */../* || \
       $target_home == */./* || $target_home == */.. || $target_home == */. ]] || \
    [[ $(realpath -e -- "$target_home") != "$target_home" ]]; then
  echo "The configured home path is unsafe for the fprintd sandbox." >&2
  exit 2
fi
for service in fprintd t2-touchid-adaptive-sync; do
  dropin_dir=/etc/systemd/system/$service.service.d
  install -d -o root -g root -m 0755 "$dropin_dir"
  printf '[Service]\nBindReadOnlyPaths=%s\n' "$target_home" \
    >"$dropin_dir/05-account-home.conf"
  chmod 0644 "$dropin_dir/05-account-home.conf"
done
authority_dropin=/etc/systemd/system/fprintd.service.d/10-authority.conf
first_run_dropin_dir=/etc/systemd/system/t2-native-first-run.service.d
first_run_dropin=$first_run_dropin_dir/10-authority.conf
install -d -o root -g root -m 0755 "$first_run_dropin_dir"
if [[ $authority_mode == macos-control-oracle ]]; then
  printf '[Unit]\nRequires=t2-keybag-load.service t2-credential-unlock.service\nAfter=t2-keybag-load.service t2-credential-unlock.service\n' \
    >"$authority_dropin"
  printf '[Unit]\n# Compatibility authority does not use native first-run credentials.\n' \
    >"$first_run_dropin"
else
  printf '[Unit]\n# Linux-native E4 authority owns activation; no macOS keybag unit dependency.\n' \
    >"$authority_dropin"
  printf '[Service]\nSetCredential=t2-touchid-password:native-first-run-credential-unavailable\nLoadCredentialEncrypted=t2-touchid-password:/etc/credstore.encrypted/t2-touchid-password\n' \
    >"$first_run_dropin"
fi
chmod 0644 "$authority_dropin" "$first_run_dropin"
printf '[Service]\nBindReadOnlyPaths=%s\nEnvironment=SUDO_UID=%s\n' \
  "$target_home" "$target_uid" \
  >/etc/systemd/system/t2-touchid-adaptive-sync.service.d/05-account-home.conf
chmod 0644 \
  /etc/systemd/system/t2-touchid-adaptive-sync.service.d/05-account-home.conf
install -d -o root -g root -m 0755 /etc/modprobe.d
install -o root -g root -m 0644 \
  "$source_dir/modprobe.d/t2-sep-transport-autoload.conf" \
  /etc/modprobe.d/t2-sep-transport-autoload.conf
# Do NOT force register_ool=1 / probe_capabilities=1 here. Those apply to
# EVERY load including the early PCI-modalias auto-load (before bridgeOS is
# ready): the capability probe can time out and leave an unusable early owner.
# The product service loads the configured owner only after readiness.
# Leave the driver observation-only by default (BAR4 map, status only); the
# service loader passes register_ool=1 explicitly on its own modprobe line.
# Probe negotiation stays off unless ACM research opts in below.
module_options='# observation-only by default; t2-sep-transport-load passes register_ool=1 explicitly'
if [[ $acm_research == 1 ]]; then
  module_options+=$'\n'"options t2_sep_transport register_acm=1 aks_platform_asid=$aks_platform_asid aks_platform_proc_uniqueid=1"
  if [[ -n $aks_platform_cdhash ]]; then
    module_options+=" aks_platform_cdhash=${aks_platform_cdhash,,}"
  fi
fi
if [[ $probe_capabilities == 1 ]]; then
  module_options+=" probe_capabilities=1"
fi
if [[ $identity_provisioning == 1 ]]; then
  module_options+=" enable_identity_provisioning=1"
fi
if [[ $identity_replacement == 1 ]]; then
  module_options+=" enable_identity_replacement=1"
fi
printf '%s\n' "$module_options" >/etc/modprobe.d/t2-sep-transport.conf
chmod 0644 /etc/modprobe.d/t2-sep-transport.conf
{
  printf 'options applesmc t2_sep_boot_state=1 t2_sep_epoch_major=%s t2_sep_epoch_minor=%s\n' \
    "$sep_epoch_major" "$sep_epoch_minor"
  printf 'softdep t2_sep_transport pre: applesmc\n'
} >/etc/modprobe.d/t2-sep-boot-state.conf
chmod 0644 /etc/modprobe.d/t2-sep-boot-state.conf
# Persist both the selected applesmc module and its boot-state options. This is
# required even when the running module was already capable: uninstall may have
# rebuilt the image without this product-owned configuration.
rebuild_boot_images

install -d -o "$target_user" -g "$target_gid" -m 0755 "$target_home/.config/systemd/user"
install -o "$target_user" -g "$target_gid" -m 0644 \
  "$source_dir/systemd/user/"*.service "$target_home/.config/systemd/user/"

install -d -o root -g root -m 0755 /etc/dbus-1/system.d
cat >/etc/dbus-1/system.d/99-t2-touchid-fprint.conf <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy context="default"><deny send_destination="net.reactivated.Fprint"/></policy>
  <policy user="root"><allow own="net.reactivated.Fprint"/><allow send_destination="net.reactivated.Fprint"/></policy>
  <policy user="$target_user"><allow send_destination="net.reactivated.Fprint"/></policy>
</busconfig>
EOF
chmod 0644 /etc/dbus-1/system.d/99-t2-touchid-fprint.conf

systemctl daemon-reload
systemctl disable --now t2-interactive-unlock.service 2>/dev/null || true
systemctl enable t2-bridge-network.service t2-sep-transport.service t2-biometric-port-refresh.service t2-biometric-ready.service fprintd.service
if [[ $authority_mode == macos-control-oracle ]]; then
  systemctl enable t2-keybag-load.service t2-credential-unlock.service
else
  systemctl disable --now t2-keybag-load.service t2-credential-unlock.service 2>/dev/null || true
fi
systemctl reload dbus.service
target_runtime_dir=/run/user/$target_uid
if [[ -S $target_runtime_dir/bus ]]; then
  if ! runuser -u "$target_user" -- env \
    XDG_RUNTIME_DIR="$target_runtime_dir" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$target_runtime_dir/bus" \
    systemctl --user daemon-reload; then
    echo "Warning: could not reload $target_user's active user manager." >&2
  fi
fi

if command -v dkms >/dev/null 2>&1; then
  dkms_source=/usr/src/t2-sep-transport-0.1.0
  dkms_stamp=$dkms_source/.source.sha256
  module_source_hash=$(
    sha256sum "$source_dir/dkms.conf" "$source_dir/src/t2_sep_transport.c" \
      "$source_dir/src/t2_acm_lifecycle.h" \
      "$source_dir/src/t2_aks_protocol.h" \
      "$source_dir/src/t2_sep_transport_uapi.h" "$source_dir/src/Makefile" |
      awk '{print $1}' | sha256sum | awk '{print $1}'
  )
  installed_source_hash=$(sed -n '1p' "$dkms_stamp" 2>/dev/null || true)
  install -d -o root -g root -m 0755 "$dkms_source/src"
  install -o root -g root -m 0644 "$source_dir/dkms.conf" "$dkms_source/dkms.conf"
  install -o root -g root -m 0644 "$source_dir/src/t2_sep_transport.c" \
    "$source_dir/src/t2_acm_lifecycle.h" \
    "$source_dir/src/t2_aks_protocol.h" \
    "$source_dir/src/t2_sep_transport_uapi.h" "$source_dir/src/Makefile" "$dkms_source/src/"
  running_kernel=$(uname -r)
  dkms_state=$(dkms status -m t2-sep-transport -v 0.1.0 2>/dev/null || true)
  if grep -Fq "t2-sep-transport/0.1.0, $running_kernel" <<<"$dkms_state" && \
      grep -Fq ': installed' <<<"$dkms_state" && \
      [[ $installed_source_hash == "$module_source_hash" ]]; then
    echo "DKMS module is already installed for $running_kernel."
  else
    if [[ -z $dkms_state ]]; then
      dkms add -m t2-sep-transport -v 0.1.0
    fi
    dkms build --force -m t2-sep-transport -v 0.1.0 -k "$running_kernel"
    dkms install --force -m t2-sep-transport -v 0.1.0 -k "$running_kernel"
    printf '%s\n' "$module_source_hash" >"$dkms_stamp"
    chmod 0644 "$dkms_stamp"
  fi
else
  echo "Warning: dkms is unavailable; rerun this installer after kernel upgrades." >&2
fi

if [[ $authority_mode == linux-native ]]; then
  # SEP retains the registered DMA addresses and the transport deliberately
  # pins their backing module. A matching live transport must remain bound;
  # userspace upgrades restart only this product's upper service chain.
  systemctl stop fprintd.service t2-touchid-post-reboot.service \
    t2-native-first-run.service t2-biometric-ready.service 2>/dev/null || true
  if [[ ${live_transport_matches:-0} != 1 ]]; then
    if [[ -d /sys/module/t2_sep_transport ]]; then
      echo "A different T2 transport build is active; leave it running and load the installed build at the next planned kernel restart." >&2
      exit 2
    fi
    systemctl stop t2-sep-transport.service \
      t2-biometric-port-refresh.service t2-bridge-network.service \
      2>/dev/null || true
  fi
  systemctl reset-failed t2-bridge-network.service \
    t2-biometric-port-refresh.service t2-sep-transport.service \
    t2-native-first-run.service t2-biometric-ready.service \
    t2-touchid-post-reboot.service fprintd.service 2>/dev/null || true
  systemctl start fprintd.service
  systemctl is-active --quiet fprintd.service || {
    echo "Touch ID setup did not become ready; run sudo t2-touchid-doctor." >&2
    exit 2
  }
  "$source_dir/tools/install-pam.sh"
  echo
  echo "t2touch is ready. Enroll a fingerprint with:"
  echo "  t2touch enroll"
else
  echo "Compatibility mode is installed. Run sudo t2-touchid-doctor for its status."
fi
