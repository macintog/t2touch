#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Sourced by install.sh; functions are also exercised by hardware-free fixtures.
# shellcheck disable=SC2154 # source_dir is supplied by the sourcing caller.

require_t2_hardware() {
  # Cheap presence gate used before applesmc DKMS or boot-image writes.
  # Prefer the SEP mailbox PCI ID from the transport driver, then the T2
  # USB controller, then the already-configured CDC-NCM interface.
  local path vendor device
  for path in /sys/bus/pci/devices/*; do
    [[ -r $path/vendor && -r $path/device ]] || continue
    vendor=$(<"$path/vendor")
    device=$(<"$path/device")
    if [[ $vendor == 0x106b && $device == 0x1802 ]]; then
      return 0
    fi
  done
  for path in /sys/bus/usb/devices/*/idVendor; do
    [[ -r $path ]] || continue
    vendor=$(<"$path")
    device=$(<"${path%/*}/idProduct")
    if [[ $vendor == 05ac && $device == 8233 ]]; then
      return 0
    fi
  done
  if declare -F detect_t2_interface >/dev/null && detect_t2_interface >/dev/null; then
    return 0
  fi
  echo "No Apple T2 hardware detected (PCI 106b:1802 or USB 05ac:8233)." >&2
  echo "Refusing to replace applesmc or rebuild boot images on this machine." >&2
  return 1
}

rebuild_boot_images() {
  # Omarchy's mkinitcpio wrapper prompts to redirect here. Use the supported
  # UKI generator directly instead of feeding answers into an interactive hook.
  if command -v limine-mkinitcpio >/dev/null 2>&1; then
    limine-mkinitcpio
  else
    mkinitcpio -P
  fi
}

# Exit 3 is an expected stop: a reboot is required before the installer can
# continue. Print a labelled block on stdout so the terminal is not only red
# stderr that looks like a failure.
emit_next_step() {
  printf '\n%s\n%s\n\n' "NEXT STEP" "$1"
}

restore_checkout_build_outputs() {
  local owner=$1 dir=$2
  [[ $owner =~ ^[0-9]+(:[0-9]+)?$ ]] || return 0
  [[ -d $dir ]] || return 0
  find "$dir" -maxdepth 1 \( \
    -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' \
    -o -name 't2-aks-tool' -o -name 't2-pam-fingerprint-prompt' \
    -o -name 'pam_t2touch_action_prompt.so' \
    -o -name 'modules.order' -o -name 'Module.symvers' \
  \) -exec chown -- "$owner" {} + 2>/dev/null || true
}

stage_applesmc_prerequisite() {
  local package_name=applesmc-t2touch
  local package_version=0.1.0
  local running_kernel dkms_source dkms_stamp source_hash
  local disk_module dkms_state

  for command in dkms depmod mkinitcpio modinfo; do
    command -v "$command" >/dev/null 2>&1 || {
      echo "Cannot stage the T2 boot prerequisite: $command is unavailable." >&2
      return 1
    }
  done
  running_kernel=$(uname -r)
  if [[ ! -d /usr/lib/modules/$running_kernel/build ]]; then
    echo "Cannot stage the T2 boot prerequisite: headers for $running_kernel are unavailable." >&2
    return 1
  fi
  for file in applesmc.c Makefile dkms.conf; do
    if [[ ! -f $source_dir/packaging/applesmc-t2touch/$file ]]; then
      echo "Cannot stage the T2 boot prerequisite: packaged $file is missing." >&2
      return 1
    fi
  done

  dkms_source=/usr/src/$package_name-$package_version
  dkms_stamp=$dkms_source/.source.sha256
  source_hash=$(
    sha256sum "$source_dir/packaging/applesmc-t2touch/"{applesmc.c,Makefile,dkms.conf} |
      awk '{print $1}' | sha256sum | awk '{print $1}'
  ) || return 1
  install -d -o root -g root -m 0755 "$dkms_source" || return 1
  install -o root -g root -m 0644 \
    "$source_dir/packaging/applesmc-t2touch/"{applesmc.c,Makefile,dkms.conf} \
    "$dkms_source/" || return 1
  dkms_state=$(dkms status -m "$package_name" -v "$package_version") || return 1
  if [[ -z $dkms_state ]]; then
    dkms add -m "$package_name" -v "$package_version" || {
      echo "applesmc-t2touch DKMS add failed." >&2
      echo "Remedy: install dkms and matching kernel headers, then rerun ./install-omarchy.sh." >&2
      return 1
    }
  fi
  dkms build --force -m "$package_name" -v "$package_version" \
    -k "$running_kernel" || {
    echo "applesmc-t2touch DKMS build failed for $running_kernel." >&2
    echo "Remedy: install matching kernel headers, then rerun ./install-omarchy.sh." >&2
    return 1
  }
  dkms install --force -m "$package_name" -v "$package_version" \
    -k "$running_kernel" || {
    echo "applesmc-t2touch DKMS install failed for $running_kernel." >&2
    echo "Remedy: install matching kernel headers, then rerun ./install-omarchy.sh." >&2
    return 1
  }
  printf '%s\n' "$source_hash" >"$dkms_stamp" || return 1
  chmod 0644 "$dkms_stamp" || return 1
  write_applesmc_boot_options || return 1
  depmod -a "$running_kernel" || return 1
  disk_module=$(modinfo -k "$running_kernel" -n applesmc 2>/dev/null || true)
  if [[ $disk_module != /lib/modules/$running_kernel/updates/dkms/applesmc.ko* &&
        $disk_module != /usr/lib/modules/$running_kernel/updates/dkms/applesmc.ko* ]] ||
    ! modinfo -k "$running_kernel" -p applesmc 2>/dev/null |
      grep -q '^t2_sep_boot_state:'; then
    echo "The staged applesmc replacement did not become the selected on-disk module." >&2
    return 1
  fi
  rebuild_boot_images || return 1
}

write_applesmc_boot_options() {
  cat >/etc/modprobe.d/t2-sep-boot-state.conf <<'EOF' || return 1
options applesmc t2_sep_boot_state=1 t2_sep_epoch_major=1 t2_sep_epoch_minor=0
softdep t2_sep_transport pre: applesmc
EOF
  chmod 0644 /etc/modprobe.d/t2-sep-boot-state.conf || return 1
}

enable_applesmc_next_boot() {
  write_applesmc_boot_options || return 1
  rebuild_boot_images || return 1
}

# Read the result attribute, never the module's enable flag. APP0001 is
# the ACPI SMC identity; older driver layouts expose a platform device.
applesmc_boot_result() {
  local sys_root=${1:-/sys} path
  local -a results=()
  for path in "$sys_root"/bus/acpi/devices/APP0001:*/t2_sep_boot_state \
    "$sys_root"/bus/platform/devices/applesmc*/t2_sep_boot_state; do
    [[ -e $path ]] || continue
    [[ -r $path ]] || { printf '%s\n' unavailable; return; }
    local value
    value=$(cat "$path") || return 2
    results+=("$value")
  done
  if (( ${#results[@]} == 0 )); then
    printf '%s\n' absent
  elif (( ${#results[@]} == 1 )); then
    printf '%s\n' "${results[0]}"
  else
    printf '%s\n' ambiguous
  fi
}

ensure_applesmc_on_disk() {
  # A resident replacement can outlive DKMS removal. Restore the next-boot
  # module even if this session already published boot state successfully.
  if ! modinfo -k "$(uname -r)" -p applesmc 2>/dev/null |
    grep -q '^t2_sep_boot_state:'; then
    stage_applesmc_prerequisite || return 2
  fi
}

check_applesmc_prerequisite() {
  local allow_active_upgrade=${1:-0} result
  if [[ $allow_active_upgrade != 0 && $allow_active_upgrade != 1 ]]; then
    echo "Internal error: active-upgrade allowance must be 0 or 1." >&2
    return 2
  fi
  result=$(applesmc_boot_result) || return 2
  case "$result" in
    response-received:1)
      # Reference T2 policy response. Versioned-app readiness is still proved
      # independently by the service chain before PAM is installed.
      ensure_applesmc_on_disk || return 2
      ;;
    response-received:3)
      # EFMS BootPolicyReboot is a completed firmware reply, not a missing
      # publisher. It blocks first-time product setup, but it must not block a
      # userspace-only upgrade after the matching resident transport and the
      # complete installed service chain have already proved SEP readiness.
      if (( allow_active_upgrade )); then
        ensure_applesmc_on_disk || return 2
        echo "The T2 boot-policy reply is response-received:3; continuing a verified in-place upgrade." >&2
        return 0
      fi
      echo "The applesmc publisher loaded; T2 boot policy requests a system reboot (response-received:3)." >&2
      echo "An ordinary Linux reboot or poweroff may leave the T2 boot session unchanged." >&2
      echo "Fresh setup remains blocked; preserve diagnostics rather than repeatedly rebooting." >&2
      emit_next_step "A reboot is required before fresh setup can continue. Preserve diagnostics; do not retry the boot-policy transaction in this session."
      return 3
      ;;
    absent|disabled)
      ensure_applesmc_on_disk || return 2
      enable_applesmc_next_boot || return 2
      echo "Restart when convenient, then rerun ./install-omarchy.sh." >&2
      emit_next_step "Restart when convenient, then rerun ./install-omarchy.sh."
      return 3
      ;;
    *)
      printf 'The applesmc boot-state result is %q; installation stopped before product setup.\n' "$result" >&2
      echo "Preserve diagnostics; do not retry the boot-policy transaction in this session." >&2
      return 2
      ;;
  esac
}

prepare_transport_update() {
  local old_srcversion=${1:-} new_srcversion=${2:-}
  local verified_installed_upgrade=${3:-0}
  if [[ $verified_installed_upgrade != 0 && $verified_installed_upgrade != 1 ]]; then
    echo "Internal error: prepared-upgrade verification must be 0 or 1." >&2
    return 2
  fi
  [[ $old_srcversion =~ ^[[:xdigit:]]{16,64}$ &&
     $new_srcversion =~ ^[[:xdigit:]]{16,64}$ &&
     ${old_srcversion^^} != "${new_srcversion^^}" ]] || {
    echo "Cannot prepare transport update: module identities are invalid." >&2
    return 2
  }
  local resuming=0
  if prepared_transport_update_matches "$new_srcversion" "$old_srcversion"; then
    resuming=1
  fi
  if (( ! verified_installed_upgrade && ! resuming )); then
    echo "Transport replacement requires a healthy or validated completed installation and matching installed module." >&2
    return 2
  fi
  # Commit the proof before the destructive step. It cannot be consumed in
  # this boot for installation; retaining it allows an exact preparation retry.
  if (( resuming )); then
    echo "Resuming the recorded transport preparation for this boot and driver pair." >&2
  else
    record_prepared_transport_update "$old_srcversion" "$new_srcversion" || return 2
  fi
  # Uninstall leaves SEP-pinned DMA resident, disables the old userspace for
  # next boot, and preserves the private account and fingerprint state.
  "$source_dir/uninstall.sh" || return 2
  ensure_applesmc_on_disk || return 2
  enable_applesmc_next_boot || return 2
  echo "Transport update prepared. Restart, then rerun ./install-omarchy.sh." >&2
  emit_next_step "Restart, then rerun ./install-omarchy.sh."
  return 3
}

transport_update_marker=${T2TOUCH_TRANSPORT_UPDATE_MARKER:-/var/lib/t2-touchid/prepared-transport-update}

record_prepared_transport_update() {
  local old_srcversion=$1 new_srcversion=$2 boot_id temporary
  old_srcversion=${old_srcversion^^}
  new_srcversion=${new_srcversion^^}
  if [[ ! $old_srcversion =~ ^[[:xdigit:]]{16,64}$ ||
        ! $new_srcversion =~ ^[[:xdigit:]]{16,64}$ ||
        $old_srcversion == "$new_srcversion" ]]; then
    echo "Cannot record the prepared transport update: module identities are invalid." >&2
    return 1
  fi
  boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
  if [[ ! $boot_id =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
    echo "Cannot record the prepared transport update: boot identity is unavailable." >&2
    return 1
  fi
  install -d -o root -g root -m 0700 "${transport_update_marker%/*}" || return 1
  temporary=$(mktemp "${transport_update_marker%/*}/.prepared-transport-update.XXXXXX") || return 1
  chmod 0600 "$temporary" || { rm -f -- "$temporary"; return 1; }
  if ! printf 'format=1\nprepared_boot_id=%s\nold_srcversion=%s\nnew_srcversion=%s\n' \
      "$boot_id" "${old_srcversion^^}" "${new_srcversion^^}" >"$temporary" ||
    ! sync -f "$temporary" || ! mv -fT -- "$temporary" "$transport_update_marker" ||
    ! sync -f "${transport_update_marker%/*}"; then
    rm -f -- "$temporary"
    return 1
  fi
}

prepared_transport_update_matches() {
  # With an old identity, authorize only resuming preparation in its original
  # boot. Without one, authorize only completing installation after reboot.
  local desired_srcversion=$1 resume_old_srcversion=${2:-} marker_metadata current_boot_id
  local format='' prepared_boot_id='' old_srcversion='' new_srcversion='' key value
  [[ $desired_srcversion =~ ^[[:xdigit:]]{16,64}$ ]] || return 1
  [[ -f $transport_update_marker && ! -L $transport_update_marker ]] || return 1
  marker_metadata=$(stat -c '%u:%g:%a:%h:%s' "$transport_update_marker" 2>/dev/null) || return 1
  [[ $marker_metadata =~ ^0:0:600:1:([1-9][0-9]{0,3})$ ]] || return 1
  while IFS='=' read -r key value; do
    case "$key" in
      format) [[ -z $format ]] || return 1; format=$value ;;
      prepared_boot_id) [[ -z $prepared_boot_id ]] || return 1; prepared_boot_id=$value ;;
      old_srcversion) [[ -z $old_srcversion ]] || return 1; old_srcversion=$value ;;
      new_srcversion) [[ -z $new_srcversion ]] || return 1; new_srcversion=$value ;;
      *) return 1 ;;
    esac
  done <"$transport_update_marker"
  current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
  [[ $format == 1 &&
     $prepared_boot_id =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ &&
     $current_boot_id =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ &&
     $old_srcversion =~ ^[[:xdigit:]]{16,64}$ &&
     $new_srcversion == "${desired_srcversion^^}" &&
     $old_srcversion != "$new_srcversion" ]] || return 1
  if [[ -n $resume_old_srcversion ]]; then
    [[ $current_boot_id == "$prepared_boot_id" &&
       $resume_old_srcversion =~ ^[[:xdigit:]]{16,64}$ &&
       $old_srcversion == "${resume_old_srcversion^^}" ]]
  else
    [[ $current_boot_id != "$prepared_boot_id" ]]
  fi
}

clear_prepared_transport_update() {
  [[ ! -e $transport_update_marker && ! -L $transport_update_marker ]] ||
    rm -f -- "$transport_update_marker"
}
