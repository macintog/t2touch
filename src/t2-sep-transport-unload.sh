#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

module=t2_sep_transport
[[ -d /sys/module/$module ]] || exit 0

# The kernel reference count protects SEP-registered DMA memory. Let module
# removal enforce that ownership before any PCI teardown; unbinding first
# destroys device endpoints even when the subsequent removal is refused.
if ! /usr/bin/modprobe --remove "$module"; then
  echo "The T2 transport remains loaded and bound; a SEP-pinned transport stays resident until the next planned kernel restart." >&2
  exit 1
fi
