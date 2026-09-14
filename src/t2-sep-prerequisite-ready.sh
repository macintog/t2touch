#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

PATH=/usr/bin:/bin
export PATH
ulimit -c 0

config=/etc/t2-touchid.conf
runtime=/opt/t2-touchid
module=t2_sep_transport

read_config() {
  sed -n "s/^$1=//p" "$config" | tail -n 1
}

[[ -r $config ]] || {
  echo "$config is not readable" >&2
  exit 1
}
[[ ! -d /sys/module/$module ]] || {
  echo "$module loaded before BridgeOS readiness; reboot required" >&2
  exit 1
}

host=$(read_config T2_TOUCHID_HOST)
interface=$(read_config T2_TOUCHID_INTERFACE)
macos_user_id=$(read_config T2_TOUCHID_MACOS_USER_ID)
require_oracle_sks_ready=$(read_config T2_TOUCHID_REQUIRE_ORACLE_SKS_READY)
python=$runtime/.venv/bin/python
discovery=$runtime/src/discover-biometric-port.py
probe=$runtime/src/bridge-xpc-probe.py

[[ -n $host && -n $interface ]] || {
  echo "T2 host/interface configuration is missing" >&2
  exit 1
}
[[ $require_oracle_sks_ready == 0 || $require_oracle_sks_ready == 1 ]] || {
  echo "T2_TOUCHID_REQUIRE_ORACLE_SKS_READY must be 0 or 1" >&2
  exit 1
}
if [[ $require_oracle_sks_ready == 1 ]] &&
   { [[ ! $macos_user_id =~ ^[0-9]+$ ]] || (( macos_user_id > 4294967295 )); }; then
  echo "oracle SKS readiness requires a valid configured Apple user" >&2
  exit 1
fi
[[ -x $python && -f $discovery && -f $probe ]] || {
  echo "BridgeOS readiness tools are not installed" >&2
  exit 1
}

probe_helo() {
  local port=$1
  "$python" "$probe" \
    --host "$host" --interface "$interface" --port "$port" \
    --timeout 3 >/dev/null 2>&1
}

probe_ready() {
  local port=$1
  if [[ $require_oracle_sks_ready == 0 ]]; then
    probe_helo "$port"
    return
  fi
  "$python" "$probe" \
    --host "$host" --interface "$interface" --port "$port" \
    --timeout 5 --macos-user-id "$macos_user_id" --sks-lock-state \
    2>/dev/null |
    "$python" -c '
import json
import sys

value = json.load(sys.stdin)
reply = value.get("sks_lock_state_reply", {})
valid = (
    reply.get("valid") is True
    and reply.get("status") == 0
    and isinstance(value.get("sks_lock_state"), int)
)
raise SystemExit(0 if valid else 1)
' >/dev/null
}

# A cached dynamic port is only a fast-path hint. A failed readiness gate forces
# fresh RemoteXPC discovery. Oracle SKS mode sends only the read-only lock-state
# query and suppresses its value.
port_file=/var/lib/t2-touchid/biometric-port
if [[ -r $port_file ]]; then
  port=$(<"$port_file")
  if [[ $port =~ ^[0-9]+$ ]] && probe_ready "$port"; then
    logger --priority daemon.info --tag t2-sep-prerequisite \
      "BridgeOS readiness gate passed before SEP transport load (oracle_sks=$require_oracle_sks_ready)"
    exit 0
  fi
fi

deadline=$((SECONDS + 60))
while (( SECONDS < deadline )); do
  port=$(
    "$python" "$discovery" \
      --host "$host" --interface "$interface" \
      --probe-timeout 0.2 --concurrency 512 2>/dev/null
  ) || port=
  if [[ $port =~ ^[0-9]+$ ]] && probe_ready "$port"; then
    logger --priority daemon.info --tag t2-sep-prerequisite \
      "BridgeOS readiness gate passed before SEP transport load (oracle_sks=$require_oracle_sks_ready)"
    exit 0
  fi
  sleep 1
done

echo "BridgeOS did not become ready before the SEP transport deadline" >&2
exit 1
