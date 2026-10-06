"""Freeze NEW relation fixtures using independent framing/tree and ordinary signing.

Never imports production statements, witnesses, relations or the bounded verifier.
All openings are synthetic public test material; signing keys stay only in memory.
No candidate is filtered or retried using production relation acceptance.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from pqdid.backend import LIBRARY, load_backend

ROOT = Path(__file__).resolve().parents[2]
TREE_BUILDER = ROOT / "tests/unit/binding_merkle_reference.py"
SPEC = importlib.util.spec_from_file_location("independent_tree", TREE_BUILDER)
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)
record = REFERENCE.record


def uint(value, width):
    return value.to_bytes(width, "big")


def generate():
    previous_path = ROOT / "tests/fixtures/binding_merkle_vectors.json"
    previous = json.loads(previous_path.read_text())
    domains = {item["name"]: item for item in previous["domains"]}
    capacities = [item["capacity"] for item in previous["binding"]["schema_fields"]]
    schema = REFERENCE.schema_bytes(previous["binding"]["schema_fields"])
    suite = b"PQ-DID-MITH-1"
    native = load_backend()
    instances, credentials, auth_cases, enrol_cases = [], [], [], []
    with native.Signature("ML-DSA-65") as oracle:
        for instance, domain_name in [("alpha", "primary"), ("beta", "other_issuer")]:
            domain = domains[domain_name]
            ref, namespace, meta = (
                bytes.fromhex(domain[key])
                for key in ("issuer_reference_hex", "namespace_hex", "metadata_hex")
            )
            with native.Signature("ML-DSA-65") as issuer, native.Signature("ML-DSA-65") as manager:
                pk_i, pk_r = issuer.generate_keypair(), manager.generate_keypair()
                pp = record("parameters", suite, ref, namespace, pk_i, pk_r, schema)

                def sign(signer, key, message, context):
                    signature = signer.sign_with_ctx_str(message, context)
                    assert oracle.verify_with_ctx_str(message, signature, context, key)
                    return signature

                states, trees = {}, {}
                for index, tree_item in enumerate(previous["trees"]):
                    name = tree_item["name"]
                    tree = REFERENCE.SparseReferenceTree(
                        suite, meta, tree_item["revoked_identifiers"]
                    )
                    trees[name] = tree
                    epoch = (0, 7, 8)[index]
                    message = record("state", suite, meta, uint(epoch, 8), tree.root)
                    signature = sign(manager, pk_r, message, b"PQ-DID/state/v1")
                    encoded = record("rstate", namespace, uint(epoch, 8), tree.root, signature)
                    states[name] = {
                        "epoch": epoch,
                        "root": tree.root.hex(),
                        "message": message.hex(),
                        "encoded": encoded.hex(),
                        "signature": signature.hex(),
                        "wrong_role_signature": sign(
                            manager, pk_r, message, b"PQ-DID/credential/v1"
                        ).hex(),
                        "revoked": sorted(tree.revoked),
                        "paths": {str(r): tree.path(r).hex() for r in (0, 2, 42, 43)},
                    }
                instances.append(
                    {
                        "name": instance,
                        "parameters": pp.hex(),
                        "metadata": meta.hex(),
                        "states": states,
                    }
                )
                for rid in (42, 43) if instance == "alpha" else (42,):
                    name = f"{instance}-{rid}"
                    secret = bytes(
                        (i + rid + (100 if instance == "beta" else 0)) % 256 for i in range(32)
                    )
                    attributes = bytearray.fromhex(previous["binding"]["encoded_attributes_hex"])
                    if rid == 43:
                        attributes[246:248] = b"GB"
                    attributes = bytes(attributes)
                    y = hashlib.sha3_384(record("holder", suite, meta, secret)).digest()
                    binding = record("binding", y, attributes)
                    mcred = record("cred", suite, meta, binding, uint(rid, 4))
                    sigma = sign(issuer, pk_i, mcred, b"PQ-DID/credential/v1")
                    certificate = record("certificate", binding, sigma)
                    credential = record(
                        "credential", certificate, attributes, uint(rid, 4), b"", meta
                    )
                    credentials.append(
                        {
                            "name": name,
                            "instance": instance,
                            "rid": rid,
                            "secret": secret.hex(),
                            "attributes": attributes.hex(),
                            "binding": binding.hex(),
                            "message": mcred.hex(),
                            "signature": sigma.hex(),
                            "encoded": credential.hex(),
                        }
                    )
                    enrol = record(
                        "enrol-statement",
                        pp,
                        meta,
                        attributes,
                        uint(rid, 4),
                        binding,
                        bytes(range(32)),
                        bytes.fromhex(states["old"]["encoded"]),
                    )
                    enrol_cases.append(
                        {
                            "credential": name,
                            "statement": enrol.hex(),
                            "witness": secret.hex(),
                            "expected": True,
                        }
                    )
                    fields, offset = [], 0
                    for capacity in capacities:
                        fields.append(attributes[offset : offset + 2 + capacity])
                        offset += 2 + capacity
                    for tree_name, disclosed, audience, session in [
                        ("empty", (), b"aud-A", b"session-A"),
                        ("old", (3, 4, 6), b"aud-A", b"session-A"),
                        ("old", (3, 5, 6), b"aud-B", b"session-B"),
                        ("updated", tuple(range(1, 7)), b"aud-B", b"session-C"),
                    ]:
                        state = states[tree_name]
                        root = bytes.fromhex(state["root"])
                        mask = uint(sum(1 << (j - 1) for j in disclosed), 2)
                        projection = b"".join(fields[j - 1] for j in disclosed)
                        # A real public equality clause, plus a range when field 4 is disclosed.
                        clauses = [] if not disclosed else [record("eq", b"\x03", fields[2])]
                        if 4 in disclosed:
                            clauses.append(record("range", b"\x04", uint(2, 8), uint(4, 8)))
                        policy = record("policy", mask, *sorted(clauses))
                        rref = record("rref", namespace, uint(state["epoch"], 8), root)
                        context = record(
                            "context",
                            suite,
                            audience,
                            session,
                            b"N" * 32,
                            policy,
                            ref,
                            rref,
                            uint(1900000000, 8),
                        )
                        statement = record(
                            "auth-statement",
                            pp,
                            meta,
                            context,
                            bytes.fromhex(state["encoded"]),
                            mask,
                            projection,
                        )
                        witness = (
                            secret + attributes + uint(rid, 4) + sigma + trees[tree_name].path(rid)
                        )
                        assert len(witness) == 5329
                        auth_cases.append(
                            {
                                "name": f"{name}-{tree_name}-{mask.hex()}",
                                "credential": name,
                                "tree": tree_name,
                                "context": context.hex(),
                                "statement": statement.hex(),
                                "witness": witness.hex(),
                                "disclosed": list(disclosed),
                                "disclosed_attributes": projection.hex(),
                                "expected": rid not in trees[tree_name].revoked,
                            }
                        )
    return {
        "record_format": "pqdid-synthetic-local-relations-v1",
        "synthetic_only": True,
        "provenance": {
            "generator": "tests/reference/generate_relation_fixtures.py",
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "tree_builder_sha256": hashlib.sha256(TREE_BUILDER.read_bytes()).hexdigest(),
            "prior_fixture_sha256": hashlib.sha256(previous_path.read_bytes()).hexdigest(),
            "native_dependencies": json.loads((ROOT / "native/dependencies.json").read_text()),
            "installed_library_sha256": hashlib.sha256(LIBRARY.read_bytes()).hexdigest(),
            "bounded_keygen_or_signing": False,
            "relation_filtering_or_retry": False,
            "signing_secrets_saved": False,
            "expectations": (
                "Independent struct framing and indexed sparse tree; ordinary-native verified "
                "signatures; canonical projections and supported satisfied clauses; "
                "revocation outcome by set membership"
            ),
        },
        "instances": instances,
        "credentials": credentials,
        "enrolment": enrol_cases,
        "authentication": auth_cases,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x") as output:
        json.dump(generate(), output, indent=2)
        output.write("\n")
