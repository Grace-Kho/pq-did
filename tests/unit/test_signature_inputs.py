"""Same-witness preparation and independently evaluated message-hash fragments."""

import hashlib
import io
from dataclasses import replace

import pytest

from pqdid import bounded_mldsa as reference
from pqdid.binding import create_binding, encode_binding, encode_holder_input
from pqdid.circuits import words as w
from pqdid.circuits.auth_parsing import link_disclosure, parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, ResourceLimit, evaluate
from pqdid.circuits.keccak import shake256
from pqdid.circuits.parsing import public_bytes
from pqdid.circuits.signature import _hint_boundary, _hint_cells, decode_responses
from pqdid.circuits.signature_inputs import (
    certified_message,
    compile_input_preparation,
    decode_expected_public_key,
    message_representative,
    prepare_verifier_inputs,
)
from pqdid.codec import EncodingError
from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT, build_mcred
from pqdid.statements import encode_auth_statement
from pqdid.witnesses import encode_auth_witness
from tests.reference.signature_oracle import observed

from .auth_arithmetic_cases import extended_limits
from .relation_cases import auth_case, parameters


def message_case(name="alpha-42-old-002c", mode="materialised", sink=None):
    pp, statement, witness = auth_case(name)
    e = Emitter(
        42632,
        limits=extended_limits(),
        mode=mode,
        sink=sink,
        public_data=encode_auth_statement(pp, statement),
    )
    scope = Scope(e)
    parsed = parse_auth_witness(scope, pp.schema, e.inputs)
    link_disclosure(scope, pp.schema, parsed, statement.disclosed, statement.disclosed_attributes)
    message = certified_message(scope, pp, statement.metadata, parsed)
    return pp, statement, witness, e, scope, parsed, message


def run(circuit, raw):
    return evaluate(circuit, raw, max_seconds=5, max_wires=2_065_538).output


@pytest.mark.parametrize("instance", ["alpha", "beta"])
def test_public_key_decode_uses_expected_instance_and_public_bits(instance):
    pp = parameters(instance)
    e = Emitter(0, limits=extended_limits())
    key = decode_expected_public_key(e, pp)
    circuit = e.finish(key.valid)
    values, (rho,), flags = observed(
        circuit,
        b"",
        words=tuple(x for p in key.t1 for x in p),
        byte_strings=(key.rho,),
        flags=(key.valid,),
    )
    expected_rho, t1 = reference._decode_public_key(pp.issuer_public_key)
    assert rho == expected_rho and values == tuple(x for p in t1 for x in p)
    assert flags == (1,) and circuit.counts.gates == 0
    assert all(b.public is not None for p in key.t1 for x in p for b in x)


def test_public_key_full_shake_gadget_folds_to_reference_hash():
    pp = parameters()
    e = Emitter(0, limits=extended_limits())
    digest = shake256(e, public_bytes(e, pp.issuer_public_key), 64)
    circuit = e.finish(e.one)
    _, (actual,), _ = observed(circuit, b"", byte_strings=(digest,))
    assert actual == hashlib.shake_256(pp.issuer_public_key).digest(64)
    assert circuit.counts.gates == 0 and sum(circuit.folded_operations) > 2_000_000


def test_exact_certified_bytes_and_hash_fragment_chain():
    pp, statement, witness, e, scope, parsed, message = message_case()
    circuit = e.finish(scope.output(()))
    raw = encode_auth_witness(pp.schema, witness)
    assert run(circuit, raw) == 1
    _, outputs, flags = observed(
        circuit,
        raw,
        byte_strings=(
            message.holder_preimage,
            message.holder_value,
            message.encoded_binding,
            message.certified_message,
            message.formatted_message,
        ),
        flags=(message.valid,),
    )
    holder_preimage, holder_value, binding_bytes, mcred, formatted = outputs
    binding = create_binding(pp.domain, witness.holder_secret, witness.attributes)
    assert holder_preimage == encode_holder_input(pp.domain, witness.holder_secret)
    assert holder_value == binding.holder_value
    assert binding_bytes == encode_binding(pp.domain, binding)
    assert mcred == build_mcred(pp, statement.metadata, binding, witness.revocation_identifier)
    assert (
        formatted
        == bytes((0, len(CREDENTIAL_SIGNING_CONTEXT))) + CREDENTIAL_SIGNING_CONTEXT + mcred
    )
    assert flags == (1,)
    assert parsed.attributes == e.inputs[256:8448]
    assert parsed.identifier_bytes == e.inputs[8448:8480]
    # Release the completed emitter's mutable trace before building the next
    # diagnostic fragment; neither trace nor any gate schedule is shortened.
    del e, scope, parsed, message, circuit

    # Test-only fragment chain. Intermediate bytes are evaluated above, not an
    # independent binding accepted by the preparation API or an enlarged witness.
    # Split at the public header boundary, preserving every suffix byte as private.
    tr = hashlib.shake_256(pp.issuer_public_key).digest(64)
    preimage = tr + formatted
    public_prefix_length = len(preimage) - (48 + 4 + 1024 + 4 + 4)
    e2 = Emitter((len(preimage) - public_prefix_length) * 8, limits=extended_limits())
    digest = shake256(e2, public_bytes(e2, preimage[:public_prefix_length]) + e2.inputs, 64)
    fragment = e2.finish(e2.one)
    _, (actual,), _ = observed(fragment, preimage[public_prefix_length:], byte_strings=(digest,))
    assert actual == hashlib.shake_256(preimage).digest(64)
    assert run(fragment, preimage[public_prefix_length:]) == 1
    for wrong in (
        tr + CREDENTIAL_SIGNING_CONTEXT + mcred,
        tr + formatted + CREDENTIAL_SIGNING_CONTEXT,
        tr + bytes((0, 0)) + formatted,
    ):
        assert actual != hashlib.shake_256(wrong).digest(64)
    assert len(raw) == 5329  # Two diagnostic traces do not form one auth trace.


@pytest.mark.parametrize("change", ["holder", "hidden_attributes", "identifier", "presentation"])
def test_message_dependency_and_context_separation(change):
    pp, statement, witness, e, scope, _, message = message_case()
    circuit = e.finish(scope.output(()))
    raw = encode_auth_witness(pp.schema, witness)
    changed = bytearray(raw)
    if change == "holder":
        changed[0] ^= 1
    elif change == "hidden_attributes":
        changed[34] ^= 1
    elif change == "identifier":
        changed[1059] ^= 1
    else:
        # Presentation-only changes affect E(X), never the certified message.
        changed_statement = replace(
            statement, context=replace(statement.context, audience=b"another audience")
        )
        e2 = Emitter(
            42632,
            limits=extended_limits(),
            public_data=encode_auth_statement(pp, changed_statement),
        )
        scope2 = Scope(e2)
        parsed2 = parse_auth_witness(scope2, pp.schema, e2.inputs)
        message2 = certified_message(scope2, pp, changed_statement.metadata, parsed2)
        circuit2 = e2.finish(scope2.output(()))
        _, (other,), _ = observed(circuit2, raw, byte_strings=(message2.certified_message,))
        _, (original,), _ = observed(circuit, raw, byte_strings=(message.certified_message,))
        assert other == original and circuit2.public_digest != circuit.public_digest
        return
    _, (original,), _ = observed(circuit, raw, byte_strings=(message.certified_message,))
    _, (other,), _ = observed(circuit, bytes(changed), byte_strings=(message.certified_message,))
    assert original != other and run(circuit, bytes(changed)) == 1


def test_composed_parser_response_boundary_message_failure_is_sticky():
    pp, _, witness, e, scope, parsed, message = message_case()
    response = decode_responses(scope, parsed.signature)
    cells = _hint_cells(e, response.encoded_hints)
    _hint_boundary(scope, cells, w.constant(e, 0, 64), 0)
    # A tautological later result cannot clear parsing/hint faults.
    scope.require(w.equal(e, response.responses[0][0], response.responses[0][0]))
    circuit = e.finish(scope.output(()))
    raw = encode_auth_witness(pp.schema, witness)
    assert run(circuit, raw) == 1
    for offset, value in [(32, 255), (1056, 255), (1060 + 3248 + 55, 56)]:
        bad = bytearray(raw)
        bad[offset] = value
        assert run(circuit, bytes(bad)) == 0
    assert message.formatted_message[-32:] == parsed.identifier_bytes


def test_message_modes_and_identity_do_not_depend_on_private_values():
    circuits = []
    sink = io.BytesIO()
    for mode in ("materialised", "count", "stream"):
        pp, _, witness, e, scope, _, _ = message_case(
            mode=mode, sink=sink if mode == "stream" else None
        )
        circuits.append(e.finish(scope.output(())))
    assert len({c.fingerprint for c in circuits}) == 1
    assert len({c.counts for c in circuits}) == 1
    assert sink.getvalue() == circuits[0].serialised
    raw = encode_auth_witness(pp.schema, witness)
    bad = raw[:32] + b"\xff\xff" + raw[34:]
    assert run(circuits[0], raw) == 1 and run(circuits[0], bad) == 0


@pytest.mark.parametrize("component", ["message", "full-preparation"])
def test_full_compositions_are_resource_failures_not_prepared_results(component):
    pp, statement, _ = auth_case()
    with pytest.raises(ResourceLimit, match="gate-count limit") as failure:
        if component == "full-preparation":
            compile_input_preparation(pp, statement, limits=extended_limits(), mode="count")
        else:
            pp, _, _, _, scope, _, message = message_case(mode="count")
            message_representative(scope, pp, message)
    assert failure.value.progress["complete"] is False


def test_composition_routes_exact_signature_to_decoder(monkeypatch):
    import pqdid.circuits.signature_inputs as implementation

    pp, statement, _ = auth_case()
    e = Emitter(42632, limits=extended_limits(), mode="count")

    class ReachedDecoder(Exception):
        pass

    def observe_decoder(scope, signature):
        assert signature == e.inputs[8480:34952]
        raise ReachedDecoder

    monkeypatch.setattr(implementation, "decode_signature", observe_decoder)
    with pytest.raises(ReachedDecoder):
        prepare_verifier_inputs(Scope(e), pp, statement, e.inputs)


def test_public_mismatch_rejects_before_full_construction():
    _, statement, _ = auth_case()
    with pytest.raises(EncodingError):
        compile_input_preparation(parameters("beta"), statement, limits=extended_limits())
