#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# One research boot only: publish xART before the x86 ANS2 NVMe driver binds.

# QUARANTINED: the only boot of D113 did not preserve its early result. This
# source remains for forensic comparison and must never be installed or run.

set -u

config=/etc/t2-xart-pre-nvme.conf
result=/run/t2-xart-pre-nvme.result
ans2_device=
ans2_count=0
sep_device=
sep_count=0
outcome=not-started
sep_status=not-run
nvme_status=not-run
nvme_released=0

log()
{
	printf '<6>t2-xart-pre-nvme: %s\n' "$*" > /dev/kmsg
}

# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
release_nvme()
{
	if [ "$nvme_released" -eq 0 ]; then
		/usr/bin/modprobe nvme
		nvme_status=$?
		nvme_released=1
	fi

	{
		printf 'outcome=%s\n' "$outcome"
		printf 'sep_modprobe_status=%s\n' "$sep_status"
		printf 'nvme_modprobe_status=%s\n' "$nvme_status"
	} > "$result"
	log "outcome=$outcome sep_status=$sep_status nvme_status=$nvme_status"
}

trap release_nvme 0

for candidate in /sys/bus/pci/devices/*; do
	[ -r "$candidate/vendor" ] || continue
	[ -r "$candidate/device" ] || continue
	read -r vendor < "$candidate/vendor"
	read -r device < "$candidate/device"
	if [ "$vendor" = 0x106b ] && [ "$device" = 0x2005 ]; then
		ans2_device=$candidate
		ans2_count=$((ans2_count + 1))
	fi
	if [ "$vendor" = 0x106b ] && [ "$device" = 0x1802 ]; then
		sep_device=$candidate
		sep_count=$((sep_count + 1))
	fi
done

if [ "$ans2_count" -ne 1 ] || [ "$sep_count" -ne 1 ]; then
	outcome=skipped-device-count
	exit 0
fi

if [ -e "$ans2_device/driver" ]; then
	outcome=skipped-nvme-already-bound
	exit 0
fi

if [ -e /sys/module/t2_sep_transport ]; then
	outcome=skipped-sep-already-loaded
	exit 0
fi

xart_uuid=
if [ -r "$config" ]; then
	while IFS='=' read -r key value; do
		if [ "$key" = XART_OS_UUID ]; then
			xart_uuid=$value
		fi
	done < "$config"
fi

case "$xart_uuid" in
	????????-????-????-????-????????????) ;;
	*)
		outcome=skipped-invalid-uuid-shape
		exit 0
		;;
esac

compact_uuid=$(printf '%s' "$xart_uuid" | /usr/bin/tr -d -)
case "$compact_uuid" in
	*[!0-9a-fA-F]*|'')
		outcome=skipped-invalid-uuid-hex
		exit 0
		;;
esac

log 'ANS2 is unbound; issuing the single pre-NVMe xART generation'
outcome=xart-attempted-before-nvme
/usr/bin/modprobe t2_sep_transport \
	register_ool=1 \
	mirror_apple_start=1 \
	macos_app_version=256 \
	xart_os_uuid="$xart_uuid" \
	defer_xart_publish=0 \
	register_acm=0 \
	probe_capabilities=0 \
	enable_identity_provisioning=0 \
	inventory_only=0
sep_status=$?

if [ -e "$ans2_device/driver" ]; then
	outcome=ordering-violated-nvme-bound-during-xart
elif [ "$sep_status" -ne 0 ] || [ ! -e "$sep_device/driver" ]; then
	outcome=xart-owner-not-bound-before-nvme
else
	outcome=xart-completed-before-nvme
fi

exit 0
