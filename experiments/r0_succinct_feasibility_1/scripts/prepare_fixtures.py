"""Focused experimental cases using unchanged independent fixtures and Python oracles."""

import hashlib
import json
from pathlib import Path

from pqdid.backend import load_backend
from pqdid.bounded_mldsa import bounded_verify_mldsa65
from pqdid.codec import EncodingError, decode_record
from pqdid.credentials import cred_valid, decode_credential
from pqdid.parameters import decode_parameters
from pqdid.relations import enrol
from pqdid.statements import decode_enrol_statement
from pqdid.witnesses import decode_enrol_witness

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
P = b"PQDID-R0S-DIAG1"
context = bytes(range(32))
cases = []


def enc(tag, *fields):
    def lp(x):
        return len(x).to_bytes(4, "big") + x

    return lp(tag) + len(fields).to_bytes(4, "big") + b"".join(lp(f) for f in fields)


def public(op, pp, payload, ctx=context):
    return enc(b"r0-statement", P, op, pp, ctx, payload)


def reference(op, pub, private):
    # Experimental envelope framing is independent of production tag registration.
    def unpack(data, tag):
        at = 0

        def field():
            nonlocal at
            n = int.from_bytes(data[at : at + 4], "big")
            at += 4
            v = data[at : at + n]
            at += n
            return v

        if field() != tag:
            raise ValueError("tag")
        n = int.from_bytes(data[at : at + 4], "big")
        at += 4
        parts = [field() for _ in range(n)]
        if at != len(data):
            raise ValueError("trailing")
        return parts

    try:
        p, o, rawpp, ctx, payload = unpack(pub, b"r0-statement")
        if p != P or o != op or len(ctx) != 32:
            return False
        pp = decode_parameters(rawpp)
        if op == b"enrol":
            return enrol(pp, decode_enrol_statement(pp, payload), decode_enrol_witness(private))
        from pqdid.parameters import decode_instance_metadata

        decode_instance_metadata(pp, payload)
        credential, secret = unpack(private, b"r0-credential-witness")
        return cred_valid(pp, decode_credential(pp, credential), secret)
    except EncodingError, ValueError:
        return False


def add(name, op, pub, priv, want):
    result = reference(op, pub, priv)
    assert result == want, (name, result, want)
    (ROOT / "fixtures/public" / f"{name}.bin").write_bytes(pub)
    (ROOT / "fixtures/private" / f"{name}.bin").write_bytes(priv)
    cases.append(
        {
            "name": name,
            "operation": op.decode(),
            "public": "fixtures/public/" + name + ".bin",
            "private": "fixtures/private/" + name + ".bin",
            "reference_expected": result,
            "public_SHA256": hashlib.sha256(pub).hexdigest(),
            "private_fixture_SHA256": hashlib.sha256(priv).hexdigest(),
            "synthetic_only": True,
        }
    )


d = json.loads((PROJECT / "tests/fixtures/relations_vectors.json").read_text())
instances = {x["name"]: bytes.fromhex(x["parameters"]) for x in d["instances"]}
creds = {x["name"]: x for x in d["credentials"]}
for c in d["credentials"]:
    name = c["name"]
    pp = instances[c["instance"]]
    e = next(x for x in d["enrolment"] if x["credential"] == name)
    stmt = bytes.fromhex(e["statement"])
    secret = bytes.fromhex(c["secret"])
    cred = bytes.fromhex(c["encoded"])
    meta = decode_record(cred, "credential")[4]
    add("enrol-" + name, b"enrol", public(b"enrol", pp, stmt), secret, True)
    add(
        "cred-" + name,
        b"cred-valid",
        public(b"cred-valid", pp, meta),
        enc(b"r0-credential-witness", cred, secret),
        True,
    )
c = creds["alpha-42"]
pp = instances["alpha"]
secret = bytes.fromhex(c["secret"])
cred = bytes.fromhex(c["encoded"])
fields = list(decode_record(cred, "credential"))
meta = fields[4]
pub = public(b"cred-valid", pp, meta)


def w(v, s=secret):
    return enc(b"r0-credential-witness", v, s)


add("cred-wrong-secret", b"cred-valid", pub, w(cred, bytes(32)), False)
add("cred-trailing", b"cred-valid", pub, w(cred + b"\0"), False)
add("cred-truncated", b"cred-valid", pub, w(cred[:-1]), False)
add(
    "cred-wrong-instance",
    b"cred-valid",
    public(
        b"cred-valid",
        instances["beta"],
        decode_record(bytes.fromhex(creds["beta-42"]["encoded"]), "credential")[4],
    ),
    w(cred),
    False,
)
add("cred-wrong-operation", b"cred-valid", public(b"enrol", pp, meta), w(cred), False)
add(
    "cred-context-width",
    b"cred-valid",
    public(b"cred-valid", pp, meta, context[:-1]),
    w(cred),
    False,
)
add(
    "cred-changed-context-valid",
    b"cred-valid",
    public(b"cred-valid", pp, meta, bytes(reversed(context))),
    w(cred),
    True,
)
for name, index, value in [
    ("rid-changed", 2, (43).to_bytes(4, "big")),
    ("rid-overflow", 2, (1 << 20).to_bytes(4, "big")),
    ("auxiliary", 3, b"\0"),
    ("metadata", 4, decode_record(bytes.fromhex(creds["beta-42"]["encoded"]), "credential")[4]),
    ("attribute-tail", 1, fields[1][:-1] + b"\1"),
]:
    changed = fields.copy()
    changed[index] = value
    add("cred-" + name, b"cred-valid", pub, w(enc(b"credential", *changed)), False)
cert = list(decode_record(fields[0], "certificate"))
b = list(decode_record(cert[0], "binding"))
for name, cb, cs in [
    ("binding", enc(b"binding", bytes(48), b[1]), cert[1]),
    ("signature", cert[0], bytes([cert[1][0] ^ 1]) + cert[1][1:]),
    ("signature-length", cert[0], cert[1][:-1]),
]:
    f = fields.copy()
    f[0] = enc(b"certificate", cb, cs)
    add("cred-" + name, b"cred-valid", pub, w(enc(b"credential", *f)), False)
# Coherent canonical changed attributes in both copies still fail the old signature.
other = bytes.fromhex(creds["alpha-43"]["attributes"])
f = fields.copy()
f[0] = enc(b"certificate", enc(b"binding", b[0], other), cert[1])
f[1] = other
add("cred-coherent-changed-attributes", b"cred-valid", pub, w(enc(b"credential", *f)), False)
e = next(x for x in d["enrolment"] if x["credential"] == "alpha-42")
stmt = bytes.fromhex(e["statement"])
add("enrol-wrong-secret", b"enrol", public(b"enrol", pp, stmt), bytes(32), False)
add("enrol-wrong-instance", b"enrol", public(b"enrol", instances["beta"], stmt), secret, False)
add("enrol-trailing", b"enrol", public(b"enrol", pp, stmt + b"\0"), secret, False)
s = list(decode_record(stmt, "enrol-statement"))
s[2] = other
add(
    "enrol-changed-approved",
    b"enrol",
    public(b"enrol", pp, enc(b"enrol-statement", *s)),
    secret,
    False,
)
s = list(decode_record(stmt, "enrol-statement"))
r = list(decode_record(s[6], "rstate"))
r[3] = bytes(3309)
s[6] = enc(b"rstate", *r)
add(
    "enrol-invalid-state-signature-outside-relation",
    b"enrol",
    public(b"enrol", pp, enc(b"enrol-statement", *s)),
    secret,
    True,
)
# Fresh synthetic key supplies full-CredValid positive and wrong-signing-context cases.
# Signing is an ordinary local fixture generator, not a bounded protocol signer.
# Retain bytes once generated; the proof guest never invokes the native backend.

context_fixture = ROOT / "fixtures/private/signing_context_fixture.json"
if context_fixture.exists():
    context_data = json.loads(context_fixture.read_text())
else:
    oqs = load_backend()
    with oqs.Signature("ML-DSA-65") as signer:
        key = signer.generate_keypair()
        message = bytes.fromhex(c["message"])
        signatures = [
            signer.sign_with_ctx_str(message, ctx)
            for ctx in [b"PQ-DID/credential/v1", b"PQ-DID/state/v1"]
        ]
    context_data = {"key": key.hex(), "signatures": [x.hex() for x in signatures]}
    context_fixture.write_text(json.dumps(context_data) + "\n")
newpp = list(decode_record(pp, "parameters"))
newpp[3] = bytes.fromhex(context_data["key"])
for i, label in enumerate(["proper-signing-context", "wrong-signing-context"]):
    f = fields.copy()
    f[0] = enc(b"certificate", cert[0], bytes.fromhex(context_data["signatures"][i]))
    add(
        "cred-" + label,
        b"cred-valid",
        public(b"cred-valid", enc(b"parameters", *newpp), meta),
        w(enc(b"credential", *f)),
        i == 0,
    )
# Shared bounded verifier context checks, independent native signatures.
raw = []
native = json.loads((PROJECT / "tests/fixtures/mldsa65_native_vectors.json").read_text())
for item in native["vectors"][:3]:
    for wrong in [False, True]:
        name = item["name"] + ("-wrong-context" if wrong else "-valid")
        ctx = bytes.fromhex(item["context"]) + (b"x" if wrong else b"")
        pk, msg, sig = (bytes.fromhex(item[k]) for k in ["public_key", "message", "signature"])
        expected = bounded_verify_mldsa65(pk, msg, sig, context=ctx)
        assert expected is not wrong
        path = "fixtures/private/" + name + ".mldsa"
        (ROOT / path).write_bytes(enc(b"r0-mldsa-test", pk, msg, sig, ctx))
        raw.append({"name": name, "path": path, "expected": expected})
(ROOT / "fixtures/cases.json").write_text(
    json.dumps(
        {
            "synthetic_only": True,
            "cases": cases,
            "mldsa_tests": raw,
            "source_SHA256": hashlib.sha256(
                (PROJECT / "tests/fixtures/relations_vectors.json").read_bytes()
            ).hexdigest(),
        },
        indent=2,
    )
    + "\n"
)
print(
    json.dumps(
        {"reference_cases": len(cases), "raw_context_cases": len(raw), "all_expected_matched": True}
    )
)
