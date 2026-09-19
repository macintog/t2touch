#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# pkexec authorizes this exact installed path before any reader claim or lock.
# Normal desktop invocation obtains fresh authorization through this same
# PolicyKit-bound path. Root execution still validates PKEXEC_UID in the helper.
if (( EUID != 0 )); then
  exec /opt/t2-touchid/.venv/bin/python -I \
    /opt/t2-touchid/src/t2-touchid-client.py delete "$@"
fi
exec /opt/t2-touchid/.venv/bin/python -I /opt/t2-touchid/src/t2-touchid-delete.py "$@"
