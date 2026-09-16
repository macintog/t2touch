#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Sourced by install.sh; functions are also exercised by hardware-free fixtures.
# shellcheck disable=SC2154 # source_dir is supplied by the sourcing caller.

rebuild_boot_images() {
  # Omarchy's mkinitcpio wrapper prompts to redirect here. Use the supported
  # UKI generator directly instead of feeding answers into an interactive hook.
  if command -v limine-mkinitcpio >/dev/null 2>&1; then
    limine-mkinitcpio
  else
    mkinitcpio -P
  fi
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
    dkms add -m "$package_name" -v "$package_version" || return 1
  fi
  dkms build --force -m "$package_name" -v "$package_version" \
    -k "$running_kernel" || return 1
  dkms install --force -m "$package_name" -v "$package_version" \
    -k "$running_kernel" || return 1
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
  local result
  result=$(applesmc_boot_result) || return 2
  case "$result" in
    response-received:1)
      # Reference T2 policy response. Versioned-app readiness is still proved
      # independently by the service chain before PAM is installed.
      ensure_applesmc_on_disk || return 2
      ;;
    absent|disabled)
      ensure_applesmc_on_disk || return 2
      enable_applesmc_next_boot || return 2
      echo "Restart when convenient, then rerun ./install-omarchy.sh." >&2
      return 3
      ;;
    *)
      echo "The applesmc boot-state result is missing, ambiguous, failed, or unsupported; installation stopped." >&2
      echo "Preserve diagnostics; do not retry the boot-policy transaction in this session." >&2
      return 2
      ;;
  esac
}

prepare_transport_update() {
  # Uninstall leaves SEP-pinned DMA resident, disables the old userspace for
  # next boot, and preserves the private account and fingerprint state.
  "$source_dir/uninstall.sh" || return 2
  ensure_applesmc_on_disk || return 2
  enable_applesmc_next_boot || return 2
  echo "Transport update prepared. Restart, then rerun ./install-omarchy.sh." >&2
  return 3
}
