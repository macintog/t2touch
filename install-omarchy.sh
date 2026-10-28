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

usage="Usage: ./install-omarchy.sh [--prepare-transport-update|--prepare-native-recovery] [--this-mac-does-not-run-macos]"
mode=
macos_override=0
for arg in "$@"; do
  case $arg in
    --prepare-transport-update|--prepare-native-recovery)
      [[ -z $mode ]] || { echo "$usage" >&2; exit 2; }
      mode=$arg ;;
    --this-mac-does-not-run-macos)
      (( ! macos_override )) || { echo "$usage" >&2; exit 2; }
      macos_override=1 ;;
    *) echo "$usage" >&2; exit 2 ;;
  esac
done

source_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=tools/installer-macos-guard.sh
source "$source_dir/tools/installer-macos-guard.sh"
refuse_if_macos_possible "$macos_override" 0 || exit 1
install_args=(${mode:+"$mode"})
# Hand the flag on only with the statement typed here, so install.sh's own
# scan never skips the question.
(( ! macos_guard_statement_taken )) || install_args+=(--this-mac-does-not-run-macos)

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
sudo env T2TOUCH_OMARCHY_WRAPPER=1 "$source_dir/install.sh" "${install_args[@]}"
[[ $mode != --prepare-native-recovery ]] || exit 0

# UWSM reads this on the next graphical login. Resolve devices on that machine
# at that login; DRM card numbers and PCI addresses are not portable.
env_dir=${XDG_CONFIG_HOME:-$HOME/.config}/uwsm/env-hyprland.d
mkdir -p -- "$env_dir"
install -m 0644 "$source_dir/src/t2-hyprland-drm-devices.sh" "$env_dir/20-t2touch-drm-devices.sh"
echo "Omarchy display compatibility installed; it takes effect at your next login."

sudo python3 "$source_dir/tools/install-omarchy-lock-ui.py" "${OMARCHY_PATH:-/usr/share/omarchy}"

echo
echo "NEXT STEP"
echo "Log out and sign back in now, then run: t2-touchid-enroll"
echo "Enrolling in this session can skip the permission prompt."
