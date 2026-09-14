#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# pkexec authorizes this exact installed path before any reader claim or lock.
exec /opt/t2-touchid/.venv/bin/python -I /opt/t2-touchid/src/t2-touchid-delete.py "$@"
