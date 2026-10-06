"""Individually dispatched public synthetic affine-representation checks.

No top-level execution. Tiny exact rows and exact host integers are independent
expectations. The previous uncompressed stream supplies a second lowering of the
same source records, not the sole arithmetic oracle.
"""

import hashlib
from dataclasses import asdict

from experiments.auth_relation_integration_1.stream import CountedEmitter, R1CSSink
from experiments.mldsa_modmul_lowering_1.candidate import Q, ntt_mul_public_q
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import FOOTER, GATE, HEADER, MAGIC, Limits
from pqdid.circuits.scalar_ring import Domain, Scalar

from .affine import AffineSink, verify_assignment

PUBLIC = b"OCT31-COMPACT-AUTH-REPRESENTATION-1/synthetic-affine-v1"
IDENTITY = hashlib.sha256(PUBLIC).digest()
ONE = ((0, 1),)
TINY_ROWS = (
    (((2, 1),), ((0, 1), (2, 1)), ()),
    (((3, 1),), ((0, 1), (3, 1)), ()),
    (((0, 1), (2, 1), (3, 1)), ((2, 1),), ((4, 1),)),
    (((4, 1),), ONE, ((1, 1),)),
    (((1, 1),), ONE, ONE),
)
TINY_ASSIGNMENT = (1, 1, 1, 1)
CASE_NAMES = {
    "C-01": "exact independent affine row table and valid assignment",
    "C-02": "same-record compressed/uncompressed agreement",
    "C-03": "arbitrary non-Boolean field input rejected",
    "C-04": "inconsistent AND auxiliary rejected",
    "C-05": "zero public acceptance rejected",
    "C-06": "noncanonical field assignment rejected",
    "C-07": "forward/missing producer rejected",
    "C-08": "stale statement identity rejected",
    "C-09": "missing footer cannot complete",
    "C-10": "incorrect footer counts rejected",
    "C-11": "65-term affine support emits exact bounded spill",
    "C-12": "changed matrix content rejected against trusted digest",
    "C-13": "equal-operand AND still emits its original constraint",
    "C-14": "retained wire-form cap produces incomplete result",
    "C-15": "retained term-entry cap produces incomplete result",
    "C-16": "row cap produces incomplete result",
    "C-17": "unconstrained trailing assignment column rejected",
    "C-18": "malformed constraint column rejected",
    "C-19": "truncated assignment rejected",
    "C-20": "malformed NOT second operand rejected",
    "C-21": "fully guarded public modmul valid upper residue",
    "C-22": "fully guarded public modmul rejects noncanonical q",
    "C-23": "signed64 checked addition at valid upper boundary",
    "C-24": "signed64 checked addition rejects overflow",
}


def _reject(call, exception=ValueError):
    try:
        call()
    except exception as error:
        return str(error)
    raise AssertionError("required rejection was not observed")


def _tiny(meter, *, retained=False):
    rows = [] if retained else None
    sink = AffineSink(
        IDENTITY,
        charge=lambda kind, count: meter(count),
        witness_bits=b"\x01\x01",
        max_rows=20,
        max_wire_forms=20,
        max_term_entries=100,
        max_columns=20,
        max_source_gates=10,
        row_consumer=None if rows is None else rows.append,
    )
    sink.write(HEADER.pack(MAGIC, 2, IDENTITY))
    sink.write(GATE.pack(1, 2, 3))
    sink.write(GATE.pack(3, 4, 0))
    sink.write(GATE.pack(2, 5, 2))
    sink.write(FOOTER.pack(255, 6, 1, 1, 1))
    descriptor = sink.completed()
    assert descriptor.rows == 5 and descriptor.variables == 4
    assert sink.satisfied and tuple(sink.assignment) == TINY_ASSIGNMENT
    if rows is not None:
        assert tuple(rows) == TINY_ROWS
    return sink, descriptor


class _Tee:
    def __init__(self, left, right):
        self.left, self.right = left, right
        self.state = "open"
        self.descriptor = None

    def write(self, record):
        self.left.write(record)
        self.right.write(record)
        return len(record)


def _paired(meter, witness_bits, builder):
    compact = AffineSink(
        IDENTITY,
        charge=lambda kind, count: meter(count),
        witness_bits=witness_bits,
        max_rows=100_000,
        max_wire_forms=200_000,
        max_term_entries=2_000_000,
        max_columns=100_000,
        max_source_gates=199_000,
    )
    ordinary = R1CSSink(
        IDENTITY,
        charge=lambda kind, count: meter(count),
        witness_bits=witness_bits,
        max_rows=200_000,
        max_assignment_wires=200_000,
    )
    e = CountedEmitter(
        len(witness_bits),
        sink=_Tee(compact, ordinary),
        public_data=PUBLIC,
        limits=Limits(max_gates=199_000, max_seconds=45),
    )
    output, observed = builder(e)
    circuit = e.finish(output)
    compact_descriptor, ordinary_descriptor = compact.completed(), ordinary.completed()
    assert compact_descriptor.gates == ordinary_descriptor.gates == circuit.counts.gates
    assert compact_descriptor.and_rows == circuit.counts.and_
    assert compact.satisfied == ordinary.satisfied
    for index in observed:
        expected = index if index < 2 else ordinary.assignment[index - 1]
        assert compact.value(index) == expected
    return compact, {
        "compact": asdict(compact_descriptor),
        "uncompressed": asdict(ordinary_descriptor),
        "same_source_fingerprint": circuit.fingerprint,
        "retained_source_trace_bytes": circuit.stored_bytes,
        "work_accounting": "each of both lowering traversals charged separately",
    }


def _bits(value, width=64):
    return bytes((value >> bit) & 1 for bit in range(width))


def _component(case_id, meter):
    observed_words = []
    if case_id in ("C-21", "C-22"):
        value = Q - 1 if case_id == "C-21" else Q
        factor = 4_808_194  # Actual first forward-NTT twiddle.
        expected_valid = value < Q
        expected_word = (value * factor) % Q if expected_valid else 0

        def builder(e):
            result = ntt_mul_public_q(Scope(e), Scalar(tuple(e.inputs), Domain.NTT), factor)
            observed_words.append(result.value.value)
            return result.valid, tuple(bit.index for bit in result.value.value)

        sink, result = _paired(meter, _bits(value), builder)
        result.update(
            oracle="exact host integer (input * 4808194) % 8380417 plus canonical range",
            input=value,
            factor=factor,
            expected_word=expected_word,
            expected_acceptance=expected_valid,
            contract="fully guarded canonical signed64 entry and masked64 output",
        )
    else:
        value = (1 << 63) - (2 if case_id == "C-23" else 1)
        expected_valid = case_id == "C-23"
        expected_word = (value + 1) & ((1 << 64) - 1)

        def builder(e):
            scope = Scope(e)
            checked = w.add64(e, tuple(e.inputs), w.constant(e, 1, 64))
            scope.checked(checked)
            observed_words.append(checked.value)
            return scope.output(()), tuple(bit.index for bit in checked.value)

        sink, result = _paired(meter, _bits(value), builder)
        result.update(
            oracle="exact host integer addition and signed64 representability",
            input=value,
            expected_word=expected_word,
            expected_acceptance=expected_valid,
            contract="existing checked signed64 ADD and active-path rejection",
            rejected_output_usable=False,
        )
    actual = sum(sink.value(bit.index) << index for index, bit in enumerate(observed_words[0]))
    assert actual == expected_word and sink.satisfied == expected_valid
    result["actual_word"] = actual
    result["actual_acceptance"] = sink.satisfied
    return result


def case(case_id, meter):
    if case_id not in CASE_NAMES:
        raise ValueError("unknown individually counted affine case")
    result = {"case": case_id, "purpose": CASE_NAMES[case_id], "full_relation": False}
    if case_id in {"C-21", "C-22", "C-23", "C-24"}:
        return result | _component(case_id, meter)
    if case_id == "C-02":

        def builder(e):
            a, b = e.inputs
            output = e.and_(e.not_(e.xor(a, b)), a)
            return output, (output.index,)

        sink, compared = _paired(meter, b"\x01\x01", builder)
        assert sink.satisfied
        return result | compared
    if case_id in {"C-01", "C-03", "C-04", "C-05", "C-06", "C-12", "C-17", "C-18", "C-19"}:
        _, descriptor = _tiny(meter, retained=case_id == "C-01")
        rows, assignment = TINY_ROWS, TINY_ASSIGNMENT
        if case_id == "C-03":
            assignment = (1, 2, 1, 1)
        elif case_id == "C-04":
            assignment = (1, 1, 1, 2)
        elif case_id == "C-05":
            assignment = (0, 1, 1, 1)
        elif case_id == "C-06":
            assignment = (1, 1, 1, 1 << 192)
        elif case_id == "C-12":
            rows = (*TINY_ROWS[:2], (ONE, ONE, ((4, 1),)), *TINY_ROWS[3:])
        elif case_id == "C-17":
            assignment = (*TINY_ASSIGNMENT, 1)
        elif case_id == "C-18":
            rows = (*TINY_ROWS[:2], (ONE, ONE, ((5, 1),)), *TINY_ROWS[3:])
        elif case_id == "C-19":
            assignment = TINY_ASSIGNMENT[:-1]

        def check():
            return verify_assignment(descriptor, rows, assignment, IDENTITY, meter)

        if case_id == "C-01":
            assert check() is True
        elif case_id in {"C-03", "C-04", "C-05"}:
            assert check() is False
        else:
            result["rejection"] = _reject(check)
        result["descriptor"] = asdict(descriptor)
        return result
    if case_id == "C-11":
        sink = AffineSink(
            IDENTITY,
            charge=lambda kind, count: meter(count),
            witness_bits=b"\x01" + bytes(64),
            max_rows=100,
            max_wire_forms=140,
            max_term_entries=5000,
            max_columns=100,
        )
        e = CountedEmitter(65, sink=sink, public_data=PUBLIC, limits=Limits(max_gates=100))
        parity = e.inputs[0]
        for bit in e.inputs[1:]:
            parity = e.xor(parity, bit)
        e.finish(parity)
        descriptor = sink.completed()
        assert descriptor.spill_rows == 1 and descriptor.rows == 68
        assert descriptor.maximum_stored_support == 64 and sink.satisfied
        assert sink.value(parity.index) == 1  # Explicit parity of one set bit.
        result["descriptor"] = asdict(descriptor)
        return result
    if case_id == "C-13":
        sink = AffineSink(IDENTITY, charge=lambda kind, count: meter(count), witness_bits=b"\x01")
        sink.write(HEADER.pack(MAGIC, 1, IDENTITY))
        sink.write(GATE.pack(2, 2, 2))
        sink.write(FOOTER.pack(255, 3, 0, 1, 0))
        descriptor = sink.completed()
        assert descriptor.and_rows == 1 and descriptor.rows == 4 and descriptor.variables == 3
        assert sink.satisfied
        result["descriptor"] = asdict(descriptor)
        return result
    limits = {}
    if case_id == "C-14":
        limits["max_wire_forms"] = 3
    elif case_id == "C-15":
        limits["max_term_entries"] = 2
    elif case_id == "C-16":
        limits["max_rows"] = 3
    sink = AffineSink(IDENTITY, charge=lambda kind, count: meter(count), **limits)
    if case_id == "C-08":
        result["rejection"] = _reject(lambda: sink.write(HEADER.pack(MAGIC, 1, bytes(32))))
    else:
        sink.write(HEADER.pack(MAGIC, 1, IDENTITY))
        if case_id == "C-07":
            result["rejection"] = _reject(lambda: sink.write(GATE.pack(1, 2, 3)))
        elif case_id == "C-09":
            result["rejection"] = _reject(sink.completed, RuntimeError)
        elif case_id == "C-10":
            result["rejection"] = _reject(lambda: sink.write(FOOTER.pack(255, 2, 1, 0, 0)))
        elif case_id in {"C-14", "C-15"}:
            result["rejection"] = _reject(lambda: sink.write(GATE.pack(3, 2, 0)), RuntimeError)
        elif case_id == "C-16":
            sink.write(GATE.pack(2, 2, 2))
            result["rejection"] = _reject(
                lambda: sink.write(FOOTER.pack(255, 3, 0, 1, 0)), RuntimeError
            )
        elif case_id == "C-20":
            result["rejection"] = _reject(lambda: sink.write(GATE.pack(3, 2, 2)))
        else:
            raise AssertionError("case dispatch incomplete")
    assert sink.descriptor is None
    _reject(sink.completed, RuntimeError)
    result["state"] = sink.state
    return result
