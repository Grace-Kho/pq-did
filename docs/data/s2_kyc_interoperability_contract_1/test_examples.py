"""Four counted example cases: private hand-off, each audience, strict expiry.

No lifecycle replay, native ABI call, signing or proof verification is performed.
These checks do not implement a production JSON parser or W3C conformance suite.
"""

# ruff: noqa: E402

import base64
import json
import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

D = Path(__file__).resolve().parent
P = D.parents[2]
sys.path.insert(0, str(P))
from pqdid.credentials import decode_credential, encode_credential
from pqdid.expiry import decode_timestamp, encode_timestamp, is_unexpired
from pqdid.schema import decode_disclosed_attributes
from pqdid.statements import (
    decode_auth_statement,
    decode_context,
    decode_state,
    encode_auth_statement,
)
from pqdid.witnesses import decode_auth_witness, encode_auth_witness
from tests.unit.relation_cases import auth_case


def read(name):
    return json.loads((D / "examples" / (name + ".json")).read_text())


def unb64(value):
    assert type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]*", value)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    assert base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value
    return raw


def test_private_holder_canonical_handoff():
    pp, x, witness = auth_case()
    example = read("private-holder")
    assert example["exposure"] == "private-holder-only" and example["synthetic"] is True
    body = example["body"]
    credential_bytes = unb64(body["credential"])
    credential = decode_credential(pp, credential_bytes)
    assert encode_credential(pp, credential) == credential_bytes
    local = decode_auth_witness(pp.schema, unb64(body["authenticationWitness"]))
    assert local == witness
    assert encode_auth_witness(pp.schema, local) == unb64(body["authenticationWitness"])
    assert (
        credential.attributes,
        credential.revocation_identifier,
        credential.certificate.signature,
    ) == (local.attributes, local.revocation_identifier, local.signature)
    assert decode_state(pp, unb64(body["state"])) == x.state


@pytest.mark.parametrize("audience", ["a", "b"])
def test_public_projection_and_privacy(audience):
    pp, original, witness = auth_case()
    example, request = read("presentation-" + audience), read("request-" + audience)
    assert set(example) == {"profile", "kind", "synthetic", "exposure", "evidenceStatus", "body"}
    assert example["exposure"] == "public-disclosed"
    assert "NON-VERIFYING" in example["evidenceStatus"]
    body = example["body"]
    assert set(body) == {"statement", "proof", "disclosedClaims"} and body["proof"] is None
    raw = unb64(body["statement"])
    x = decode_auth_statement(pp, raw)
    context = replace(
        original.context,
        audience=("verifier-" + audience).encode(),
        session=("session-" + audience).encode(),
        nonce=audience.encode() * 32,
    )
    assert x == replace(original, context=context)
    assert encode_auth_statement(pp, x) == raw
    assert decode_context(pp, unb64(request["body"]["context"])) == context
    assert decode_state(pp, unb64(request["body"]["state"])) == x.state
    assert request["body"]["requestSignature"] is None
    values = decode_disclosed_attributes(pp.schema, x.disclosed, x.disclosed_attributes)
    assert x.disclosed == (3, 4, 6)
    assert pp.schema.did_index not in values and pp.schema.version_index not in values
    # Three claims are one projection, not three separately injected test variants.
    assert body["disclosedClaims"] == [
        {"index": "3", "name": "kycPassed", "type": "boolean", "value": values[3]},
        {"index": "4", "name": "assuranceLevel", "type": "uint64", "value": str(values[4])},
        {"index": "6", "name": "validUntil", "type": "uint64", "value": str(values[6])},
    ]
    assert witness.holder_secret not in raw and witness.attributes not in raw
    assert witness.signature not in raw and witness.path not in raw
    # The exact decoded statement type has no rid, binding or persistent holder ID field.
    assert x.parameters == pp and x.metadata == pp.metadata


def test_session_expiry_equality_is_expired():
    pp, original, _ = auth_case()
    request = read("request-a")["body"]
    value = request["sessionExpiresAtSeconds"]
    assert type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
    seconds = int(value)
    assert seconds == decode_context(pp, unb64(request["context"])).expires_at
    assert decode_timestamp(encode_timestamp(seconds)) == original.context.expires_at
    assert not is_unexpired(seconds, now=seconds)
    assert "validUntil" not in request and "credentialExpiry" not in request
