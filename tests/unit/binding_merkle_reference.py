"""Independent synthetic fixture builder; NEVER imports pqdid or traverses PathRoot.

Run explicitly with --output NEW_PATH to freeze/review candidate vectors. Tests read
the committed JSON and never rewrite it. Every secret in these fixtures is synthetic.
The sparse tree stores global node indices bottom-up, from revoked leaves alone.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
DEPTH = 20


def record(tag: str, *fields: bytes) -> bytes:
    # Independent rendering of VII's equation, without production codec helpers.
    chunks = [tag.encode("ascii"), *fields]
    framed = [struct.pack(">I", len(chunk)) + chunk for chunk in chunks]
    return framed[0] + struct.pack(">I", len(fields)) + b"".join(framed[1:])


def digest(data: bytes) -> bytes:
    return hashlib.sha3_384(data).digest()


def schema_bytes(fields: list[dict]) -> bytes:
    return record(
        "schema",
        b"\x06",
        b"\x01",
        b"\x02",
        *(
            record(
                "field",
                field["name"].encode("ascii"),
                bytes([field["type"]]),
                struct.pack(">H", field["capacity"]),
            )
            for field in fields
        ),
    )


class SparseReferenceTree:
    """Test-only global tree map; absent subtrees use their default root."""

    def __init__(self, suite: bytes, metadata: bytes, revoked: list[int]):
        self.suite = suite
        self.metadata = metadata
        self.revoked = frozenset(revoked)
        assert all(type(r) is int and 0 <= r < 2**DEPTH for r in revoked)
        self.defaults = [self.leaf(0)]
        for level in range(1, DEPTH + 1):
            previous = self.defaults[-1]
            self.defaults.append(self.node(level, previous, previous))
        self.layers = [{r: self.leaf(1) for r in self.revoked}]
        for level in range(1, DEPTH + 1):
            lower = self.layers[-1]
            parents = {index // 2 for index in lower}
            self.layers.append(
                {
                    parent: self.node(
                        level,
                        lower.get(2 * parent, self.defaults[level - 1]),
                        lower.get(2 * parent + 1, self.defaults[level - 1]),
                    )
                    for parent in parents
                }
            )
        self.root = self.layers[DEPTH].get(0, self.defaults[DEPTH])

    def leaf(self, status: int) -> bytes:
        return digest(record("leaf", self.suite, self.metadata, bytes([status])))

    def node(self, level: int, left: bytes, right: bytes) -> bytes:
        return digest(record("node", self.suite, self.metadata, bytes([level]), left, right))

    def path(self, identifier: int) -> bytes:
        # Obtain siblings from global indexed levels. Do not fold a target leaf
        # or use the production traversal to obtain the expected root.
        return b"".join(
            self.layers[j].get((identifier // (2**j)) ^ 1, self.defaults[j]) for j in range(DEPTH)
        )


def build_fixture() -> dict:
    source = json.loads((PROJECT / "configs/encoding_examples.json").read_text())
    e29 = next(v for v in source["vectors"] if v["id"] == "E29")
    fields = e29["inputs"]["fields"]
    schema = schema_bytes(fields)
    assert schema.hex() == e29["expected_hex"]
    suite = b"PQ-DID-MITH-1"
    secret = bytes(range(32))  # SYNTHETIC, PUBLIC TEST SECRET; never a real holder.
    payloads = (
        b"did:pqdid:" + b"1" * 64 + b":" + b"2" * 96,
        bytes(56),
        b"\x01",
        struct.pack(">Q", 3),
        b"SG",
        struct.pack(">Q", 2000000000),
    )
    padded = b"".join(
        struct.pack(">H", len(payload)) + payload + bytes(field["capacity"] - len(payload))
        for field, payload in zip(fields, payloads, strict=True)
    )
    attributes = padded + bytes(1024 - len(padded))
    altered_schema = schema_bytes(
        [{**f, "name": "kycFlag"} if i == 2 else f for i, f in enumerate(fields)]
    )
    domains = []
    for name, issuer, key, namespace, encoded_schema in [
        ("primary", b"fixture-issuer", b"fixture-key", b"\x11" * 32, schema),
        ("other_issuer", b"other-issuer", b"fixture-key", b"\x11" * 32, schema),
        ("other_key", b"fixture-issuer", b"other-key", b"\x11" * 32, schema),
        ("other_namespace", b"fixture-issuer", b"fixture-key", b"\x12" * 32, schema),
        ("other_schema", b"fixture-issuer", b"fixture-key", b"\x11" * 32, altered_schema),
    ]:
        ref = record("iref", issuer, key, encoded_schema)
        metadata = record("meta", ref, namespace)
        preimage = record("holder", suite, metadata, secret)
        tree = SparseReferenceTree(suite, metadata, [])
        domains.append(
            {
                "name": name,
                "suite_ascii": suite.decode(),
                "issuer_reference_hex": ref.hex(),
                "namespace_hex": namespace.hex(),
                "metadata_hex": metadata.hex(),
                "holder_input_hex": preimage.hex(),
                "holder_value_hex": digest(preimage).hex(),
                "unrevoked_leaf_hex": tree.leaf(0).hex(),
                "revoked_leaf_hex": tree.leaf(1).hex(),
                "default_roots_hex": [root.hex() for root in tree.defaults],
            }
        )
    primary = domains[0]
    metadata = bytes.fromhex(primary["metadata_hex"])
    leaves = [
        {
            "status": status,
            "input_hex": (raw := record("leaf", suite, metadata, bytes([status]))).hex(),
            "digest_hex": digest(raw).hex(),
        }
        for status in (0, 1)
    ]
    left, right = bytes(range(48)), bytes(range(48, 96))
    nodes = []
    for level, a, b in [(1, left, right), (2, left, right), (20, left, right), (1, right, left)]:
        raw = record("node", suite, metadata, bytes([level]), a, b)
        nodes.append(
            {
                "level": level,
                "left_hex": a.hex(),
                "right_hex": b.hex(),
                "input_hex": raw.hex(),
                "digest_hex": digest(raw).hex(),
            }
        )
    identifiers = [
        0,
        1,
        2,
        3,
        7,
        8,
        9,
        42,
        43,
        1024,
        0x55555,
        1 << 19,
        (1 << 19) + 3,
        0xAAAAA,
        (1 << 20) - 2,
        (1 << 20) - 1,
    ]
    old_revoked = [1, 7, 9, 1024, (1 << 19) + 3, (1 << 20) - 2]
    trees = []
    for name, revoked in [
        ("empty", []),
        ("old", old_revoked),
        ("updated", sorted([*old_revoked, 42])),
    ]:
        tree = SparseReferenceTree(suite, metadata, revoked)
        trees.append(
            {
                "name": name,
                "revoked_identifiers": revoked,
                "root_hex": tree.root.hex(),
                "stored_nondefault_nodes": sum(map(len, tree.layers)),
                "paths": [
                    {
                        "identifier": r,
                        "leaf_status": int(r in tree.revoked),
                        "path_hex": tree.path(r).hex(),
                    }
                    for r in identifiers
                ],
            }
        )
    return {
        "record_format": "pqdid-synthetic-binding-merkle-reference-vectors",
        "record_version": 1,
        "synthetic_only": True,
        "manuscript_sha256": source["manuscript_sha256"],
        "source": "Sections II-VIII only; VII opening/A.1/A.5 pp. 14-15; SPEC-001 path payload",
        "provenance": (
            "Independent struct/SHA3 encoding and globally indexed sparse trees; "
            "no pqdid imports or PathRoot calls; expectations frozen before production test runs"
        ),
        "profile": {"depth": 20, "hash_bytes": 48, "path_bytes": 960, "identifier_limit": 1048576},
        "binding": {
            "synthetic_public_test_secret_hex": secret.hex(),
            "schema_fields": fields,
            "attribute_payloads_hex": [p.hex() for p in payloads],
            "encoded_attributes_hex": attributes.hex(),
            "binding_encoding_hex": record(
                "binding", bytes.fromhex(primary["holder_value_hex"]), attributes
            ).hex(),
        },
        "domains": domains,
        "leaf_examples": leaves,
        "node_examples": nodes,
        "trees": trees,
        "transition": {
            "old_tree": "old",
            "new_tree": "updated",
            "newly_revoked": 42,
            "surviving_neighbour": 43,
            "nonuniform_wrong_path_pair": [0, 2],
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new synthetic fixture file")
    args = parser.parse_args()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(build_fixture(), stream, indent=2)
        stream.write("\n")
