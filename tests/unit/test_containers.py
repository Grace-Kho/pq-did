"""24 independently counted cases; no signing, proof or lifecycle execution."""

import base64
import json
from pathlib import Path

import pytest

from pqdid import containers
from pqdid.containers import (
    PROFILE,
    ContainerAdapter,
    ContainerError,
    ConvertedInput,
    ExamplePreview,
    UnsupportedContainer,
    UpdateQuery,
)
from pqdid.credentials import build_mcred, encode_credential
from pqdid.parameters import encode_parameters
from pqdid.statements import (
    decode_auth_statement,
    encode_auth_statement,
    encode_context,
    encode_state,
)
from pqdid.verifier_state import REQUEST_CONTEXT, AuthenticationRequest
from pqdid.witnesses import encode_auth_witness
from tests.unit.relation_cases import CREDENTIALS, auth_case, parameters

EXAMPLES = (
    Path(__file__).resolve().parents[2] / "docs/data/s2_kyc_interoperability_contract_1/examples"
)


def example(name, *, normal=True):
    value = json.loads((EXAMPLES / (name + ".json")).read_text())
    if normal:
        value.update(profile=PROFILE, synthetic=False, evidenceStatus="unverified-input")
    return value


def raw(value):
    return json.dumps(value, separators=(",", ":")).encode()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def context_a():
    pp, x, _ = auth_case()
    return decode_auth_statement(pp, unb64(example("presentation-a")["body"]["statement"])).context


def test_private_holder_exact_canonical_handoff():
    pp, _, witness = auth_case()
    adapter = ContainerAdapter(pp, "holder")
    source = example("private-holder")
    output = adapter.parse(raw(source), kind="private-holder")
    assert type(output) is ConvertedInput and output.kind == "private-holder"
    value = output.value
    assert encode_credential(pp, value.credential) == unb64(source["body"]["credential"])
    assert encode_auth_witness(pp.schema, value.witness) == unb64(
        source["body"]["authenticationWitness"]
    )
    assert value.witness == witness
    assert build_mcred(
        pp,
        value.credential.metadata,
        value.credential.certificate.binding,
        value.credential.revocation_identifier,
    ) == bytes.fromhex(CREDENTIALS["alpha-42"]["message"])
    assert not hasattr(output, "accepted") and not hasattr(value, "proof")


def test_issuance_request_exact_approved_input():
    pp, _, witness = auth_case()
    source = example("issuance-request")
    value = ContainerAdapter(pp, "issuer").parse(raw(source), kind="issuance-request").value
    assert value.attributes == value.holder_approval == witness.attributes
    assert value.did == unb64(source["body"]["did"])
    assert value.version == unb64(source["body"]["version"])
    assert value.evidence == unb64(source["body"]["evidence"])


def test_request_exact_message_not_verification():
    pp, original, _ = auth_case()
    source = example("request-a")
    # Existing state signature is only width-correct here, NOT a request signature.
    source["body"]["requestSignature"] = b64(original.state.signature)
    expected = context_a()
    value = (
        ContainerAdapter(pp, "holder")
        .parse(raw(source), kind="presentation-request", context=expected)
        .value
    )
    assert type(value) is AuthenticationRequest
    assert encode_context(pp, value.context) == unb64(source["body"]["context"])
    assert value.signature == original.state.signature
    assert REQUEST_CONTEXT == b"PQ-DID/request/v1"  # Selected by lifecycle, never metadata.
    assert value.context.expires_at == int(source["body"]["sessionExpiresAtSeconds"])


def test_history_page_bound_to_local_start_and_query():
    pp, x, _ = auth_case()
    source = example("updates-response")
    query = UpdateQuery(pp.namespace, x.state.epoch, x.state.epoch)
    value = (
        ContainerAdapter(pp, "holder")
        .parse(raw(source), kind="updates-response", query=query, starting=x.state)
        .value
    )
    assert value.records == () and value.complete and value.next_epoch == x.state.epoch
    assert encode_state(pp, value.starting_state) == unb64(source["body"]["startingState"])
    assert value.endpoint_state == x.state


def test_public_example_is_only_a_canonical_statement():
    pp, _, witness = auth_case()
    source = example("presentation-a", normal=False)
    output = ContainerAdapter(pp, "verifier").inspect_example(
        raw(source), kind="presentation-submission", context=context_a()
    )
    assert type(output) is ExamplePreview and not isinstance(output, ConvertedInput)
    encoded = encode_auth_statement(pp, output.value)
    assert encoded == unb64(source["body"]["statement"])
    assert output.value.disclosed == (3, 4, 6)
    assert witness.holder_secret not in encoded and witness.attributes not in encoded
    assert witness.signature not in encoded and witness.path not in encoded
    assert not hasattr(output, "proof") and not hasattr(output, "accepted")


NEGATIVES = (
    "binary-alphabet",
    "binary-unused-bits",
    "uint64-overflow",
    "boolean-integer",
    "nested-duplicate",
    "version",
    "type",
    "role-override",
    "private-field",
    "oversize",
    "depth",
    "collection",
    "instance",
    "context-conflict",
    "claim-conflict",
    "proof-placeholder",
    "verification-flag",
    "truncated",
    "floating-number",
)


@pytest.mark.parametrize("case", NEGATIVES)
def test_distinct_rejection(case, monkeypatch):
    pp, original, _ = auth_case()
    adapter = ContainerAdapter(pp, "revocation")
    obj = example("updates-request")
    kwargs = {"kind": "updates-request"}
    error, code = ContainerError, None
    if case == "binary-alphabet":
        obj["body"]["namespace"] = "!" * 43
        code = "binary"
    elif case == "binary-unused-bits":
        obj["body"]["namespace"] = "A" * 42 + "B"
        code = "binary-canonical"
    elif case == "uint64-overflow":
        obj["body"]["targetEpoch"] = str(1 << 64)
        code = "integer-range"
    elif case == "boolean-integer":
        obj["body"]["afterEpoch"] = True
        code = "integer"
    elif case == "nested-duplicate":
        code = "duplicate-key"
    elif case == "version":
        obj["profile"] = "pqdid-application-container-999"
        code = "version"
    elif case == "type":
        obj["kind"] = "private-holder"
        code = "type"
    elif case == "role-override":
        obj["body"]["role"] = "manager"
        code = "fields"
    elif case == "private-field":
        adapter, obj = ContainerAdapter(pp, "verifier"), example("presentation-a")
        obj["body"]["authenticationWitness"] = example("private-holder")["body"][
            "authenticationWitness"
        ]
        kwargs = {"kind": "presentation-submission", "context": context_a()}
        code = "fields"
    elif case in {"oversize", "depth", "collection"}:
        # The underlying JSON allocator must not run for these resource rejections.
        def forbidden(*args, **kwargs):
            pytest.fail("json.loads ran before resource preflight rejected input")

        monkeypatch.setattr(containers.json, "loads", forbidden)
        code = {
            "oversize": "document-limit",
            "depth": "depth-limit",
            "collection": "collection-limit",
        }[case]
    elif case == "instance":
        adapter, obj = ContainerAdapter(pp, "holder"), example("instance")
        obj["body"]["parameters"] = b64(encode_parameters(parameters("beta")))
        kwargs = {"kind": "instance"}
        code = "canonical-input"
    elif case == "context-conflict":
        adapter, obj = ContainerAdapter(pp, "holder"), example("request-a")
        obj["body"]["sessionExpiresAtSeconds"] = str(context_a().expires_at + 1)
        kwargs = {"kind": "presentation-request", "context": context_a()}
        code = "context-binding"
    elif case == "claim-conflict":
        adapter, obj = ContainerAdapter(pp, "verifier"), example("presentation-a")
        obj["body"]["disclosedClaims"][0]["value"] = False
        kwargs = {"kind": "presentation-submission", "context": context_a()}
        code = "claim-binding"
    elif case == "proof-placeholder":
        adapter, obj = ContainerAdapter(pp, "verifier"), example("presentation-a")
        kwargs = {"kind": "presentation-submission", "context": context_a()}
        error, code = UnsupportedContainer, "proof-transport-unsupported"
    elif case == "verification-flag":
        adapter, obj = ContainerAdapter(pp, "application"), example("verification-result")
        obj["body"].update(
            accepted=True, challengeConsumed=True, decision="reference-model-accepted"
        )
        kwargs = {"kind": "verification-result"}
        error, code = UnsupportedContainer, "outcome-admission-unsupported"
    elif case == "truncated":
        code = "json"
    elif case == "floating-number":
        obj["body"]["targetEpoch"] = 1.25
        code = "json-number"
    else:
        raise AssertionError("unaccounted case")
    payload = raw(obj)
    if case == "nested-duplicate":
        payload = payload.replace(b'"afterEpoch":', b'"afterEpoch":"0","afterEpoch":')
    elif case == "oversize":
        payload = b" " * 65537
    elif case == "depth":
        payload = b"[" * 9 + b"0" + b"]" * 9
    elif case == "collection":
        payload = b"[" + b",".join([b"null"] * 33) + b"]"
    elif case == "truncated":
        payload = payload[:-1]
    before = (adapter.parameters, adapter.receiver, encode_auth_statement(pp, original))
    with pytest.raises(error, match="^" + code + "$"):
        adapter.parse(payload, **kwargs)
    assert (adapter.parameters, adapter.receiver, encode_auth_statement(pp, original)) == before
    assert adapter.parameters is pp
