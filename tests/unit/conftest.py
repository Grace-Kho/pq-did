"""Fixed specification fixtures, independent of native cryptographic setup."""

import json
from pathlib import Path

import pytest

from pqdid.schema import AttributeField, Schema

VECTOR_FILE = Path(__file__).resolve().parents[2] / "configs" / "encoding_examples.json"
VECTORS = {item["id"]: item for item in json.loads(VECTOR_FILE.read_text())["vectors"]}


@pytest.fixture
def vectors():
    return VECTORS


@pytest.fixture
def schema():
    inputs = VECTORS["E29"]["inputs"]
    fields = tuple(AttributeField(f["name"], f["type"], f["capacity"]) for f in inputs["fields"])
    return Schema(fields, inputs["did_index"], inputs["version_index"])


@pytest.fixture
def attributes():
    return (b"did:pqdid:" + b"1" * 64 + b":" + b"2" * 96, bytes(56), True, 3, b"SG", 2000000000)
