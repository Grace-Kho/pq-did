"""One admitted bounded prefix; incomplete is never a completed relation count."""

import hashlib
import time

from pqdid.circuits.emitter import Limits, ResourceLimit

from .fixtures import auth_case
from .private_relation import compile_private
from .statement import prepare_public
from .stream import R1CSSink


def run_case(meter):
    pp, statement, _witness = auth_case()
    prepared = prepare_public(pp, statement)
    sink = R1CSSink(
        hashlib.sha256(prepared.encoded_statement).digest(),
        charge=lambda _kind, count: meter(count),
        max_rows=2_065_538,
    )
    started = time.monotonic()
    try:
        compile_private(prepared, sink, Limits(max_gates=2_000_000, max_seconds=90))
    except ResourceLimit as error:
        if error.reason != "gate-count limit":
            raise
        assert sink.state == "incomplete" and sink.descriptor is None
        assert sum(sink.gates) == 2_000_000
        return {
            "complete_relation": False,
            "outcome": "labelled-prefix-only",
            "reason": error.reason,
            "progress": error.progress,
            "completed_components": sink.relation_progress,
            "gate_counts_xor_and_not": sink.gates,
            "partial_rows": sink.counter.rows,
            "partial_nonzero_terms": sink.counter.nnz,
            "partial_matrix_sha256": sink.counter.digest.hexdigest(),
            "counting_seconds": time.monotonic() - started,
            "witness_evaluation_performed": False,
            "stored_trace_or_matrix_bytes": 0,
            "codewords_allocated": 0,
            "repeated_generation_authorised": False,
        }
    raise AssertionError("unexpected completion below known component lower bound")
