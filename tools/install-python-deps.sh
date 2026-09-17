#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
python_executable=${1:?Usage: install-python-deps.sh /path/to/python}
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$source_dir"
# Hash mode does not cover pip's isolated build dependencies. Bootstrap the
# exact backend from wheels, then forbid that implicit dependency installation.
"$python_executable" -m pip install --require-hashes --only-binary=:all: \
  --requirement requirements-build-hashed.txt
"$python_executable" -m pip install --require-hashes --no-build-isolation \
  --requirement requirements-hashed.txt
