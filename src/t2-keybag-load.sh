#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

TOOL=/usr/local/sbin/t2-aks-tool
PYTHON=/opt/t2-touchid/.venv/bin/python
SOURCE=/opt/t2-touchid/src
SESSION=1
CONFIG_FILE=/etc/t2-touchid.conf
SPECIAL_BAG=$(sed -n 's/^T2_TOUCHID_SPECIAL_BAG=//p' "$CONFIG_FILE" | tail -n 1)
printf '%s\n' "$SPECIAL_BAG" | grep -Eq '^-[0-9]+$' || {
	echo "invalid T2_TOUCHID_SPECIAL_BAG" >&2
	exit 1
}
BAG=$(PYTHONPATH="$SOURCE" "$PYTHON" -m t2_keybag_loader)
printf '%s\n' "$BAG" | grep -Eq '^/var/lib/t2-touchid/users/[1-9][0-9]*/user\.kb$' || {
	echo "invalid compatibility keybag path" >&2
	exit 1
}
STATE_DIR=/run/t2-touchid
STATE_FILE=$STATE_DIR/keybag.env
READY_FILE=$STATE_DIR/keybags-unlocked

rm -f -- "$READY_FILE"

output="$($TOOL load-system-keybag "$BAG" "$SESSION" "$SPECIAL_BAG")"
case "$output" in
	status=0\ handle=*\ response_length=*) ;;
	*)
		echo "unexpected load-keybag result: $output" >&2
		exit 1
		;;
esac
handle=${output#*handle=}
handle=${handle%% *}
install -d -o root -g root -m 0700 "$STATE_DIR"
umask 077
printf 'T2_KEYBAG_SESSION=%s\nT2_KEYBAG_HANDLE=%s\nT2_KEYBAG_SPECIAL=%s\n' \
	"$SESSION" "$handle" "$SPECIAL_BAG" >"$STATE_FILE"
printf 'loaded keybag handle=%s session=%s special=%s\n' \
	"$handle" "$SESSION" "$SPECIAL_BAG"
