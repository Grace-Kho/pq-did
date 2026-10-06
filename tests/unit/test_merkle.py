"""R-029 reference mathematics; no signature, allocation or freshness claims."""

import hashlib

import pytest

from pqdid.codec import (
    EncodingError,
    encode_length_prefixed,
    pack_sibling_path,
    unpack_sibling_path,
)
from pqdid.merkle import (
    default_subtree_roots,
    leaf_hash,
    node_hash,
    path_root,
    verify_non_revocation_path,
)

from .binding_merkle_cases import DOMAINS, FIXTURE, TREES, domain, path, root
from .binding_merkle_reference import build_fixture


def test_fixture_provenance_and_sparse_storage():
    assert FIXTURE["synthetic_only"] is True
    # This builder uses independent framing/global tree indices, never pqdid.
    # Rebuilding in memory checks provenance; it cannot rewrite the fixed JSON.
    assert build_fixture() == FIXTURE
    for tree in TREES.values():
        assert tree["stored_nondefault_nodes"] <= 21 * len(tree["revoked_identifiers"])
        assert len(tree["paths"]) == 16


@pytest.mark.parametrize("case", FIXTURE["leaf_examples"], ids=lambda c: str(c["status"]))
def test_fixed_leaf_input_and_digest(case, monkeypatch):
    real_sha3 = hashlib.sha3_384
    inputs = []

    def capture(encoded):
        inputs.append(encoded)
        return real_sha3(encoded)

    monkeypatch.setattr("pqdid.merkle.hashlib.sha3_384", capture)
    assert leaf_hash(domain(), case["status"]) == bytes.fromhex(case["digest_hex"])
    assert inputs == [bytes.fromhex(case["input_hex"])]


@pytest.mark.parametrize(
    "case", FIXTURE["node_examples"], ids=lambda c: f"level-{c['level']}-left-{c['left_hex'][:2]}"
)
def test_fixed_node_input_and_digest(case, monkeypatch):
    real_sha3 = hashlib.sha3_384
    inputs = []

    def capture(encoded):
        inputs.append(encoded)
        return real_sha3(encoded)

    monkeypatch.setattr("pqdid.merkle.hashlib.sha3_384", capture)
    assert node_hash(
        domain(), case["level"], bytes.fromhex(case["left_hex"]), bytes.fromhex(case["right_hex"])
    ) == bytes.fromhex(case["digest_hex"])
    assert inputs == [bytes.fromhex(case["input_hex"])]


@pytest.mark.parametrize("name", DOMAINS)
def test_fixed_default_subtree_roots(name):
    assert default_subtree_roots(domain(name)) == tuple(
        bytes.fromhex(x) for x in DOMAINS[name]["default_roots_hex"]
    )
    assert len(default_subtree_roots(domain(name))) == 21


CASES = [(tree["name"], item) for tree in TREES.values() for item in tree["paths"]]


@pytest.mark.parametrize(
    "tree_name,item", CASES, ids=[f"{name}-{item['identifier']}" for name, item in CASES]
)
def test_fixed_depth20_paths_and_non_revocation(tree_name, item):
    instance = domain()
    packed = bytes.fromhex(item["path_hex"])
    assert len(packed) == 960 and len(unpack_sibling_path(packed)) == 20
    assert pack_sibling_path(unpack_sibling_path(packed)) == packed
    assert path_root(instance, item["identifier"], item["leaf_status"], packed) == root(tree_name)
    assert verify_non_revocation_path(instance, item["identifier"], packed, root(tree_name)) is (
        item["leaf_status"] == 0
    )


def test_uniform_tree_paths_and_nonuniform_identifier_mismatch():
    instance = domain()
    # A default tree does not prove allocation, and no rid occurs in a leaf.
    assert path("empty", 0) == path("empty", 1048575)
    assert root("empty") == default_subtree_roots(instance)[20]
    for identifier in (0, 1, 2, 0x55555, 1048575):
        assert verify_non_revocation_path(instance, identifier, path("empty", 0), root("empty"))
    # Both 0 and 2 are unrevoked; the fixture deliberately revokes neighbour 1.
    assert 0 not in TREES["old"]["revoked_identifiers"]
    assert 2 not in TREES["old"]["revoked_identifiers"]
    assert not verify_non_revocation_path(instance, 2, path("old", 0), root("old"))


@pytest.mark.parametrize("sibling_index", range(20))
def test_altered_sibling_at_each_level(sibling_index):
    siblings = list(unpack_sibling_path(path("old", 0)))
    sibling = siblings[sibling_index]
    siblings[sibling_index] = bytes([sibling[0] ^ 1]) + sibling[1:]
    assert not verify_non_revocation_path(domain(), 0, pack_sibling_path(siblings), root("old"))


def test_reversed_siblings_and_incorrect_root():
    instance = domain()
    packed = path("old", 0)
    reversed_path = pack_sibling_path(tuple(reversed(unpack_sibling_path(packed))))
    assert not verify_non_revocation_path(instance, 0, reversed_path, root("old"))
    wrong_root = bytes([root("old")[0] ^ 1]) + root("old")[1:]
    assert not verify_non_revocation_path(instance, 0, packed, wrong_root)


def test_old_and_updated_roots_do_not_implement_freshness():
    instance = domain()
    # Only 42 changes from unrevoked to revoked. Its own siblings stay unchanged.
    assert path("old", 42) == path("updated", 42)
    assert root("old") != root("updated")
    assert verify_non_revocation_path(instance, 42, path("old", 42), root("old"))
    assert not verify_non_revocation_path(instance, 42, path("updated", 42), root("updated"))
    assert path_root(instance, 42, 1, path("updated", 42)) == root("updated")
    # The surviving neighbour needs a new sibling at index 0; there is no
    # production witness-update service in this task, only independent fixtures.
    old = unpack_sibling_path(path("old", 43))
    new = unpack_sibling_path(path("updated", 43))
    assert old[0] != new[0] and old[1:] == new[1:]
    assert verify_non_revocation_path(instance, 43, path("old", 43), root("old"))
    assert not verify_non_revocation_path(instance, 43, path("old", 43), root("updated"))
    assert verify_non_revocation_path(instance, 43, path("updated", 43), root("updated"))


@pytest.mark.parametrize("identifier", [-1, 1048576, 2**32, True, False, 1.0, "1", None])
def test_invalid_identifier(identifier):
    with pytest.raises(EncodingError):
        path_root(domain(), identifier, 0, path("old", 0))
    with pytest.raises(EncodingError):
        verify_non_revocation_path(domain(), identifier, path("old", 0), root("old"))


@pytest.mark.parametrize("status", [-1, 2, 256, True, False, 0.0, b"\0", None])
def test_invalid_leaf_status(status):
    with pytest.raises(EncodingError):
        leaf_hash(domain(), status)
    with pytest.raises(EncodingError):
        path_root(domain(), 0, status, path("old", 0))


@pytest.mark.parametrize("level", [-1, 0, 21, 256, True, 1.0, b"\1", None])
def test_invalid_node_level(level):
    with pytest.raises(EncodingError):
        node_hash(domain(), level, bytes(48), bytes(48))


@pytest.mark.parametrize("bad_hash", [b"", bytes(47), bytes(49), bytearray(48), "x" * 48])
def test_invalid_hash_lengths_and_types(bad_hash):
    for left, right in [(bad_hash, bytes(48)), (bytes(48), bad_hash)]:
        with pytest.raises(EncodingError):
            node_hash(domain(), 1, left, right)
    with pytest.raises(EncodingError):
        verify_non_revocation_path(domain(), 0, path("old", 0), bad_hash)


@pytest.mark.parametrize(
    "packed",
    [b"", bytes(959), bytes(961), bytes(48 * 19), bytes(48 * 21), bytearray(960), [bytes(48)] * 20],
)
def test_invalid_raw_path(packed):
    with pytest.raises(EncodingError):
        path_root(domain(), 0, 0, packed)


def test_path_payload_not_enclosing_record():
    with pytest.raises(EncodingError):
        path_root(domain(), 0, 0, encode_length_prefixed(path("old", 0)))
    with pytest.raises(EncodingError):
        pack_sibling_path((bytes(48),) * 19 + (bytes(47),))


@pytest.mark.parametrize("name", [name for name in DOMAINS if name != "primary"])
def test_domain_separation(name):
    instance = domain(name)
    assert leaf_hash(instance, 0) != leaf_hash(domain(), 0)
    assert leaf_hash(instance, 1) != leaf_hash(domain(), 1)
    assert not verify_non_revocation_path(instance, 0, path("old", 0), root("old"))
    assert node_hash(instance, 1, bytes(48), bytes(48)) != node_hash(
        domain(), 1, bytes(48), bytes(48)
    )


def test_node_levels_and_child_order_are_domain_separated():
    instance = domain()
    left, right = bytes(range(48)), bytes(range(48, 96))
    assert len({node_hash(instance, level, left, right) for level in range(1, 21)}) == 20
    assert node_hash(instance, 1, left, right) != node_hash(instance, 1, right, left)
    with pytest.raises(EncodingError):
        leaf_hash(None, 0)
