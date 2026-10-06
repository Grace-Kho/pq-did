"""Complete comparison boundary: public domain rejection plus private circuit."""

import hashlib
import io
from dataclasses import replace

import pytest

from pqdid.binding import create_binding, encode_holder_input
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from pqdid.circuits.enrolment import compile_encoded_enrolment, compile_enrolment
from pqdid.circuits.enrolment_accounting import enrolment_count_admitted, enrolment_proof_bytes
from pqdid.circuits.parsing import equal_bytes, holder_message, public_bytes, reverse_byte_bits
from pqdid.codec import EncodingError
from pqdid.public_checks import enrol_public_ok
from pqdid.relations import enrol
from pqdid.statements import encode_enrol_statement
from pqdid.witnesses import EnrolmentWitness

from .relation_cases import enrol_case, state


@pytest.fixture(scope="module", params=["alpha-42", "alpha-43", "beta-42"])
def instance(request):
    pp, statement, witness = enrol_case(request.param)
    return pp, statement, witness, compile_enrolment(pp, statement, limits=Limits())


def test_reference_equivalence_and_reuse_for_wrong_openings(instance):
    pp, statement, witness, circuit = instance
    assert circuit.counts.inputs == 256 and circuit.counts.and_ > 35000
    for raw in (
        witness.holder_secret,
        bytes(32),
        b"\xff" * 32,
        bytes(reversed(witness.holder_secret)),
    ):
        assert evaluate(circuit, raw).output == int(enrol(pp, statement, EnrolmentWitness(raw)))
    assert evaluate(circuit, witness.holder_secret).output == 1
    for raw in (b"", bytes(31), bytes(33)):
        with pytest.raises(ValueError, match="length"):
            evaluate(circuit, raw)
        assert not enrol(pp, statement, EnrolmentWitness(raw))


def test_encoded_typed_and_all_modes_have_identical_structure():
    pp, statement, witness = enrol_case()
    material = compile_enrolment(pp, statement, limits=Limits())
    sink = io.BytesIO()
    for mode in ("count", "stream"):
        circuit = compile_encoded_enrolment(
            pp,
            encode_enrol_statement(pp, statement),
            limits=Limits(),
            mode=mode,
            sink=sink if mode == "stream" else None,
        )
        assert circuit.fingerprint == material.fingerprint
        assert circuit.counts == material.counts
        assert circuit.serialised_bytes == material.serialised_bytes
    assert sink.getvalue() == material.serialised
    # Fresh generation receives the same public inputs regardless of witness outcome.
    fresh = compile_enrolment(pp, statement, limits=Limits())
    assert fresh.serialised == material.serialised
    assert evaluate(fresh, witness.holder_secret).output == 1
    assert evaluate(fresh, b"\0" * 32).output == 0


@pytest.mark.parametrize(
    "change", ["target", "attributes", "nonce", "rid", "state", "bad_signature"]
)
def test_each_public_condition_at_its_specified_boundary(change):
    pp, statement, witness = enrol_case()
    _, other, _ = enrol_case("alpha-43")
    changes = {
        "target": {"binding": replace(statement.binding, holder_value=bytes(48))},
        "attributes": {"approved_attributes": other.approved_attributes},
        "nonce": {"issuer_nonce": b"Z" * 32},
        "rid": {"revocation_identifier": 999},
        "state": {"state": state("updated")},
        "bad_signature": {"state": replace(statement.state, signature=bytes(3309))},
    }
    changed = replace(statement, **changes[change])
    circuit = compile_enrolment(pp, changed, limits=Limits())
    assert circuit.public_digest == hashlib.sha256(encode_enrol_statement(pp, changed)).digest()
    assert circuit.public_digest != hashlib.sha256(encode_enrol_statement(pp, statement)).digest()
    expected = change not in ("target", "attributes")
    assert evaluate(circuit, witness.holder_secret).output == int(expected)
    assert enrol(pp, changed, witness) is expected
    public = enrol_public_ok(pp, changed, changed.approved_attributes)
    assert public is (change not in ("attributes", "bad_signature"))
    assert bool(public and evaluate(circuit, witness.holder_secret).output) == bool(
        public and enrol(pp, changed, witness)
    )
    if change == "attributes":
        # False public equality does not skip the private holder computation.
        assert circuit.counts.and_ > 35000


def test_zero_secret_has_no_extra_representation_constraint():
    pp, statement, _ = enrol_case()
    secret = bytes(32)
    changed = replace(
        statement, binding=create_binding(pp.domain, secret, statement.approved_attributes)
    )
    circuit = compile_enrolment(pp, changed, limits=Limits())
    assert evaluate(circuit, secret).output == 1
    assert enrol(pp, changed, EnrolmentWitness(secret))


def test_instance_substitution_and_public_domain_rejection():
    pp, statement, witness = enrol_case()
    other_pp, other, _ = enrol_case("beta-42")
    # Coherent other public domain with the old binding target gives a circuit rejection.
    changed = replace(
        other, binding=statement.binding, approved_attributes=statement.approved_attributes
    )
    circuit = compile_enrolment(other_pp, changed, limits=Limits())
    assert (
        evaluate(circuit, witness.holder_secret).output
        == int(enrol(other_pp, changed, witness))
        == 0
    )
    # Inconsistent public instance/domain fails before any circuit can be produced.
    for bad in (
        replace(statement, metadata=other.metadata),
        replace(statement, revocation_identifier=1 << 20),
        replace(statement, approved_attributes=bytes(1024)),
        replace(statement, issuer_nonce=b""),
    ):
        with pytest.raises(EncodingError):
            compile_enrolment(pp, bad, limits=Limits())
        assert not enrol(pp, bad, witness)
    raw = encode_enrol_statement(pp, statement)
    for malformed in (
        raw[:-1],
        raw + b"\0",
        b"\xff" * 4 + raw[4:],
        raw.replace(b"enrol-statement", b"enrol-statemenu", 1),
    ):
        with pytest.raises(EncodingError):
            compile_encoded_enrolment(pp, malformed, limits=Limits())


def test_holder_framing_and_byte_wiring_are_exact():
    pp, _, witness = enrol_case()
    e = Emitter(256, limits=Limits())
    message = holder_message(e, pp.domain, e.inputs)
    assert reverse_byte_bits(e, reverse_byte_bits(e, message)) == message
    assert e.counts.gates == 0
    with pytest.raises(ValueError):
        holder_message(e, pp.domain, e.inputs[:248])
    circuit = e.finish(
        equal_bytes(
            e, message, public_bytes(e, encode_holder_input(pp.domain, witness.holder_secret))
        )
    )
    assert evaluate(circuit, witness.holder_secret).output == 1
    assert evaluate(circuit, b"\xff" * 32).output == 0


def test_resource_failure_is_not_a_false_or_completed_relation():
    pp, statement, _ = enrol_case()
    with pytest.raises(ResourceLimit) as exc:
        compile_enrolment(pp, statement, limits=Limits(max_gates=3))
    assert not exc.value.progress["complete"] and exc.value.progress["gates"] == 3


@pytest.mark.parametrize("g", [0, 1, 3, 4, 5, 38787, 10**100])
def test_enrolment_projection_uses_256_input_bits(g):
    assert enrolment_proof_bytes(g) == 64 + 480 * (515 + 2 * ((256 + 2 * g + 7) // 8))
    assert enrolment_proof_bytes(g) == 277984 + 960 * ((g + 3) // 4)
    assert enrolment_count_admitted(g) is (((256 + 2 * g + 7) // 8) <= (1 << 32) - 1)
