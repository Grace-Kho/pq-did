"""Frozen ordinary-native signatures, independently generated from the verifier."""

import json
from pathlib import Path

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "mldsa65_native_vectors.json"


def load_cases() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


def vector_arguments(item: dict) -> tuple[bytes, bytes, bytes, bytes]:
    return tuple(
        bytes.fromhex(item[key]) for key in ("public_key", "message", "signature", "context")
    )
