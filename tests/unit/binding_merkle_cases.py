"""Read-only access to labelled synthetic fixtures; no expected-value generation."""

import json
from pathlib import Path

from pqdid.hash_domain import HashDomain

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "binding_merkle_vectors.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text())
DOMAINS = {item["name"]: item for item in FIXTURE["domains"]}
TREES = {item["name"]: item for item in FIXTURE["trees"]}


def domain(name: str = "primary") -> HashDomain:
    item = DOMAINS[name]
    return HashDomain(
        item["suite_ascii"].encode("ascii"),
        bytes.fromhex(item["issuer_reference_hex"]),
        bytes.fromhex(item["namespace_hex"]),
    )


def path(tree_name: str, identifier: int) -> bytes:
    item = next(item for item in TREES[tree_name]["paths"] if item["identifier"] == identifier)
    return bytes.fromhex(item["path_hex"])


def root(tree_name: str) -> bytes:
    return bytes.fromhex(TREES[tree_name]["root_hex"])
