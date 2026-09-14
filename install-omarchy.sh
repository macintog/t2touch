#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

if (( EUID == 0 )); then
  echo "Run this as your Omarchy desktop user, without sudo." >&2
  exit 1
fi
command -v omarchy >/dev/null || {
  echo "This installer is for Omarchy. See README.md for other systems." >&2
  exit 1
}

if ! modinfo -p applesmc 2>/dev/null | grep -q '^t2_sep_boot_state:'; then
  echo "The running T2 kernel lacks t2touch's required typed SEP boot-state publisher." >&2
  echo "Install a kernel carrying linux_native/patches/applesmc-t2-sep-boot-state.patch before running this installer." >&2
  exit 2
fi

source_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
running_kernel=$(uname -r)
mapfile -t kernel_packages < <(
  pacman -Qoq "/usr/lib/modules/$running_kernel" 2>/dev/null |
    sed '/-headers$/d' | sort -u
)
if (( ${#kernel_packages[@]} != 1 )); then
  echo "Could not identify the package for the running kernel." >&2
  exit 1
fi
headers_package=${kernel_packages[0]}-headers
if ! pacman -Si "$headers_package" >/dev/null 2>&1 &&
  ! pacman -Q "$headers_package" >/dev/null 2>&1; then
  echo "Kernel headers are unavailable: $headers_package" >&2
  exit 1
fi

omarchy pkg add base-devel dkms fprintd python "$headers_package"
sudo "$source_dir/install.sh"
