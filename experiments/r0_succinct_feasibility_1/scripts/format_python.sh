#!/bin/bash
set -eu
../../.venv/bin/ruff check --fix --exit-zero scripts
../../.venv/bin/ruff format scripts
../../.venv/bin/ruff check scripts --output-format concise
../../.venv/bin/ruff format --check scripts
