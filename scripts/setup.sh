#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export UV_PROJECT_ENVIRONMENT="$PWD/.venv"
export UV_CACHE_DIR="$PWD/.cache/uv"
export UV_PYTHON_DOWNLOADS=never
if [[ ! -x .tools/uv ]]; then
    python3 scripts/bootstrap_uv.py
fi
if [[ ! -d .venv ]]; then
    .tools/uv venv --python /usr/bin/python3.14 .venv
fi
# Install the locked build backend first; then use it without isolated, unlocked downloads.
.tools/uv sync --locked --group build --no-install-project --no-install-package liboqs-python
.tools/uv sync --locked --group build --no-build-isolation
.tools/uv pip check --python .venv/bin/python
