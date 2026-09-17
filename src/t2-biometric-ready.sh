#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -u
PATH=/usr/bin:/bin
export PATH
ulimit -c 0

CONFIG_FILE=/etc/t2-touchid.conf
[[ -r $CONFIG_FILE ]] || exit 1

read_config() {
  sed -n "s/^$1=//p" "$CONFIG_FILE" | tail -n 1
}

user=$(read_config T2_TOUCHID_USER)
host=$(read_config T2_TOUCHID_HOST)
interface=$(read_config T2_TOUCHID_INTERFACE)
project=$(read_config T2_TOUCHID_PROJECT_DIR)
[[ -n $user && -n $host && -n $interface && -n $project ]] || exit 1

if [[ -x $project/.venv/bin/python && -f $project/src/discover-biometric-port.py ]]; then
  python=$project/.venv/bin/python
  source_dir=$project/src
elif [[ -x $project/.venv-re/bin/python && -f $project/linux/discover-biometric-port.py ]]; then
  # Compatibility with early research installs.
  python=$project/.venv-re/bin/python
  source_dir=$project/linux
  export PYTHONPATH=$project/third-party/pymobiledevice3
else
  exit 1
fi

export T2_TOUCHID_USER=$user
export T2_TOUCHID_HOST=$host
export T2_TOUCHID_INTERFACE=$interface
export T2_TOUCHID_PROJECT_DIR=$project

port_file=/var/lib/t2-touchid/biometric-port
umask 077
deadline=$((SECONDS + 45))
port=
validated=0
if [[ -r $port_file ]]; then
  candidate=$(<"$port_file")
  [[ $candidate =~ ^[0-9]+$ ]] && port=$candidate
fi

validate_port() {
  /usr/bin/flock --exclusive --timeout 10 --no-fork \
    /run/t2-touchid/operation.lock \
    "$python" "$source_dir/bridge-xpc-probe.py" \
    --host "$host" --interface "$interface" --port "$1" \
    >/dev/null 2>&1
}

if [[ -n $port ]]; then
  if validate_port "$port"; then
    validated=1
  else
    port=
  fi
fi
while (( SECONDS < deadline )); do
  [[ -n $port ]] && break
  port=$($python "$source_dir/discover-biometric-port.py" \
    --host "$host" --interface "$interface" \
    --probe-timeout 0.2 --concurrency 256 2>/dev/null) && break
  sleep 1
done
[[ $port =~ ^[0-9]+$ ]] || exit 1

if [[ $validated != 1 ]]; then
  validate_port "$port" || exit 1
fi
temporary_port_file=$(mktemp "${port_file}.XXXXXX")
trap 'rm -f -- "$temporary_port_file"' EXIT
printf '%s\n' "$port" >"$temporary_port_file"
chmod 0600 "$temporary_port_file"
mv -f "$temporary_port_file" "$port_file"
trap - EXIT
logger --priority authpriv.info --tag t2-biometric-ready \
  'T2 BiometricKit endpoint discovery and HELO validation passed'
