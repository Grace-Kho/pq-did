"""Independent pilot expectations, attribution transparency and context classification."""

from dataclasses import asdict

import pytest

from pqdid.binding import create_binding, encode_binding, encode_holder_input
from pqdid.circuits import signature as sig
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits
from pqdid.codec import EncodingError
from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT, build_mcred
from pqdid.parameters import encode_instance_metadata
from pqdid.schema import project_attributes
from pqdid.witnesses import decode_auth_witness, encode_auth_witness
from scripts.review_feasibility import PILOTS, AttributedEmitter, attribution, mutated
from tests.reference.preparation_oracle import preparation_bytes

from .relation_cases import auth_case


@pytest.mark.parametrize("case", PILOTS)
def test_pilot_mutations_and_independent_framing(case):
    pp, statement, witness = auth_case()
    raw = mutated(case, encode_auth_witness(pp.schema, witness), pp.schema, statement.disclosed)
    expected = preparation_bytes(
        pp.suite, encode_instance_metadata(pp, statement.metadata), pp.issuer_public_key, raw
    )
    if case in PILOTS[1:4]:
        with pytest.raises(EncodingError):
            decode_auth_witness(pp.schema, raw)
        return
    decoded = decode_auth_witness(pp.schema, raw)
    binding = create_binding(pp.domain, decoded.holder_secret, decoded.attributes)
    assert expected[0] == encode_holder_input(pp.domain, decoded.holder_secret)
    assert expected[2] == encode_binding(pp.domain, binding)
    assert expected[3] == build_mcred(
        pp, statement.metadata, binding, decoded.revocation_identifier
    )
    assert (
        expected[4]
        == bytes((0, len(CREDENTIAL_SIGNING_CONTEXT))) + CREDENTIAL_SIGNING_CONTEXT + expected[3]
    )
    assert (
        project_attributes(pp.schema, decoded.attributes, statement.disclosed)
        == statement.disclosed_attributes
    ) == (case != "disclosure-mismatch")


def two_steps(e, private_parent=False):
    scope = Scope(e)
    if private_parent:
        scope.rejected = e.inputs[-1]
    cells = sig._hint_cells(e, e.inputs[:488])
    index = w.constant(e, 0, 64)
    end = sig._hint_boundary(scope, cells, index, 0)
    first = index
    polynomial = tuple(w.constant(e, 0, 64) for _ in range(256))
    for _ in range(2):
        index, polynomial = sig._hint_iteration(scope, cells, index, first, end, polynomial)
    return e.finish(scope.output(()))


def test_attribution_preserves_trace_and_counts_every_gate_once():
    limits = Limits(max_gates=500000, max_output_bytes=10 * 1024**2)
    ordinary = two_steps(Emitter(489, limits=limits))
    e = AttributedEmitter(489, limits=limits)
    events = {"iterations_started": 0, "iterations_completed": 0}
    with attribution(e, events):
        instrumented = two_steps(e)
    assert instrumented.fingerprint == ordinary.fingerprint
    assert instrumented.counts == ordinary.counts
    assert instrumented.folded_operations == ordinary.folded_operations
    assert (
        tuple(map(sum, zip(*e.emitted.values(), strict=True)))
        == tuple(asdict(e.counts).values())[:3]
    )
    assert sum(map(sum, e.folded.values())) == sum(instrumented.folded_operations)
    assert {"read/selectors", "read/mux", "write/selectors", "write/mux"} <= e.emitted.keys()
    assert events["iterations_completed"] == 2 and e._buffer is None and e._sink is None


def test_private_upstream_rejection_does_not_make_hint_step_inputs_public():
    counts = []
    for private in (False, True):
        e = Emitter(489, mode="count", limits=Limits(max_gates=500000))
        circuit = two_steps(e, private)
        counts.append(circuit.counts)
    assert counts[1].and_ >= counts[0].and_
    assert counts[1].gates >= counts[0].gates
