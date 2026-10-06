"""Redirect only newly run test diagnostics; old tests/evidence remain immutable."""

import os
from pathlib import Path


def pytest_collection_modifyitems(items):
    destination = Path(__file__).resolve().parents[2] / "docs/data/s2_authority_isolation_pilot_1"
    for item in items:
        if item.module.__name__ == "test_owner_boundary":
            item.module.EVIDENCE = destination
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
