"""Experimental exact affine substitution over the retained GF(2^192).

This is a proposed representation, not canonical BC-1 and not a prover. Source
gates are unchanged. Only XOR/NOT variables and their defining linear rows are
eliminated; every original AND retains a fresh variable and multiplication row.
"""

import hashlib
from dataclasses import dataclass

from experiments.auth_relation_integration_1.r1cs import (
    RowCounter,
    evaluate_row,
    field,
    input_row,
    multiply,
    row_bytes,
)
from pqdid.circuits.emitter import FOOTER, GATE, HEADER, MAGIC

Form = tuple[int, ...]
ONE = ((0, 1),)


def linear(form: Form):
    return tuple((column, 1) for column in form)


def symmetric_difference(left: Form, right: Form) -> Form:
    """Merge sorted unique supports without coefficient/field approximation."""
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] == right[j]:
            i += 1
            j += 1
        elif left[i] < right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result.extend(left[i:])
    result.extend(right[j:])
    return tuple(result)


@dataclass(frozen=True)
class AffineDescriptor:
    complete: bool
    inputs: int
    gates: int
    rows: int
    variables: int
    primary: int
    output_wire: int
    nonzero_terms: tuple[int, int, int]
    matrix_sha256: str
    public_identity: str
    gate_counts: tuple[int, int, int]
    free_input_booleanity_rows: int
    and_rows: int
    spill_rows: int
    output_rows: int
    retained_wire_forms: int
    retained_term_entries: int
    maximum_stored_support: int
    assignment_storage_bytes: int
    representation: str = "GF192-exact-affine-XOR-NOT-elimination-v1"


class AffineSink:
    """Bounded source-record consumer; no trace or matrix is retained here.

    Support is capped at 64 per retained form. An oversized XOR/NOT expression
    (at most 128 terms transiently) receives an exact linear-link row. The wire
    table and its total term entries remain bounded independently. Capacity
    failure is explicit non-completion and never yields a descriptor.
    """

    def __init__(
        self,
        public_identity: bytes,
        *,
        charge=None,
        witness_bits: bytes | None = None,
        max_rows=200_000,
        max_wire_forms=200_000,
        max_term_entries=2_000_000,
        max_columns=200_000,
        max_source_gates=2_000_000,
        row_consumer=None,
    ):
        if type(public_identity) is not bytes or len(public_identity) != 32:
            raise ValueError("public identity must be SHA-256 engineering digest")
        limits = (max_rows, max_wire_forms, max_term_entries, max_columns, max_source_gates)
        if any(type(value) is not int or value <= 0 for value in limits):
            raise ValueError("strict positive integer capacities required")
        if (
            max_rows > 32_065_538
            or max_wire_forms > 2_065_538
            or max_term_entries > 4_000_000
            or max_columns > 2_065_538
            or max_source_gates > 32_000_000
        ):
            raise ValueError("representation capacity outside experimental ceiling")
        if witness_bits is not None and (
            type(witness_bits) is not bytes or any(bit not in (0, 1) for bit in witness_bits)
        ):
            raise ValueError("one canonical byte per input bit required")
        self.public_identity = public_identity
        self.charge = charge or (lambda kind, count: None)
        self.counter = RowCounter(maximum=max_rows, charge=self.charge, row_consumer=row_consumer)
        self.max_wire_forms = max_wire_forms
        self.max_term_entries = max_term_entries
        self.max_columns = max_columns
        self.max_source_gates = max_source_gates
        self.witness_bits = witness_bits
        self.assignment = None
        self.forms = []
        self.term_entries = 0
        self.maximum_support = 0
        self.inputs = None
        self.variables = 1
        self.gates = [0, 0, 0]
        self.spills = 0
        self.state = "open"
        self.descriptor = None
        self.satisfied = True

    def _reserve_form(self, support):
        if len(self.forms) >= self.max_wire_forms:
            raise RuntimeError("incomplete: retained wire-form capacity")
        if self.term_entries + support > self.max_term_entries:
            raise RuntimeError("incomplete: retained term-entry capacity")

    def _store(self, form):
        self._reserve_form(len(form))
        self.forms.append(form)
        self.term_entries += len(form)
        self.maximum_support = max(self.maximum_support, len(form))

    def value(self, wire_index):
        if self.assignment is None:
            raise ValueError("count-only representation has no assignment")
        if type(wire_index) is not int or not 0 <= wire_index < len(self.forms):
            raise ValueError("invalid source wire")
        return self._form_value(self.forms[wire_index])

    def _form_value(self, form):
        result = 0
        for column in form:
            result ^= 1 if column == 0 else self.assignment[column - 1]
        return result

    def _fresh(self, value):
        if self.variables >= self.max_columns:
            raise RuntimeError("incomplete: auxiliary-column capacity")
        self.variables += 1
        if self.assignment is not None:
            self.assignment.append(value)
        return self.variables

    def _emit(self, row):
        self.counter.emit(row)
        if self.assignment is not None:
            self.charge("evaluated_row", 1)
            a, b, c = evaluate_row(row, self.assignment)
            # Convenience assignments have Boolean atoms; these exact linear
            # forms also evaluate to bits. Arbitrary field assignments are
            # checked separately by verify_assignment using field multiplication.
            if any(value not in (0, 1) for value in (a, b, c)):
                raise ValueError("internal Boolean-assignment invariant violated")
            self.satisfied = self.satisfied and a * b == c

    def write(self, record: bytes):
        if self.state != "open":
            self.state = "incomplete"
            self.descriptor = None
            raise RuntimeError("representation stream not open")
        try:
            if type(record) is not bytes:
                raise ValueError("exact bytes record required")
            self._write(record)
            return len(record)
        except BaseException:
            self.state = "incomplete"
            self.descriptor = None
            raise

    def _write(self, record):
        if self.inputs is None:
            if len(record) != HEADER.size:
                raise ValueError("missing exact circuit header")
            magic, inputs, public_digest = HEADER.unpack(record)
            if magic != MAGIC or inputs > 65_536 or public_digest != self.public_identity:
                raise ValueError("circuit header identity/input limit mismatch")
            if (
                inputs + 2 > self.max_wire_forms
                or inputs + 1 > self.max_term_entries
                or inputs + 1 > self.max_columns
                or inputs + 2 > self.counter.maximum
            ):
                raise RuntimeError("incomplete: initial representation capacity")
            if self.witness_bits is not None and len(self.witness_bits) != inputs:
                raise ValueError("private assignment shape mismatch")
            self.inputs = inputs
            self.variables = inputs + 1
            if self.witness_bits is not None:
                self.assignment = bytearray(b"\x01" + self.witness_bits)
            self._store(())
            self._store((0,))
            for column in range(2, inputs + 2):
                self._store((column,))
                self._emit(input_row(column))
            return
        if len(record) == FOOTER.size and record[0] == 255:
            _, output, *counts = FOOTER.unpack(record)
            if counts != self.gates or output >= len(self.forms):
                raise ValueError("invalid completion footer")
            if self.counter.rows + 2 > self.counter.maximum:
                raise RuntimeError("incomplete: final-row capacity")
            self._emit((linear(self.forms[output]), ONE, ((1, 1),)))
            self._emit((((1, 1),), ONE, ONE))
            self.descriptor = AffineDescriptor(
                True,
                self.inputs,
                sum(self.gates),
                self.counter.rows,
                self.variables,
                1,
                output,
                tuple(self.counter.nnz),
                self.counter.digest.hexdigest(),
                self.public_identity.hex(),
                tuple(self.gates),
                self.inputs,
                self.gates[1],
                self.spills,
                2,
                len(self.forms),
                self.term_entries,
                self.maximum_support,
                0 if self.assignment is None else len(self.assignment),
            )
            self.state = "complete"
            return
        if len(record) != GATE.size:
            raise ValueError("malformed gate record")
        opcode, left, right = GATE.unpack(record)
        if opcode not in (1, 2, 3) or left >= len(self.forms) or right >= len(self.forms):
            raise ValueError("missing producer or invalid opcode")
        if opcode == 3 and right != 0:
            raise ValueError("noncanonical NOT operand")
        if sum(self.gates) >= self.max_source_gates:
            raise RuntimeError("incomplete: source-gate capacity")
        self.charge("emitted_gate", 1)
        a, b = self.forms[left], self.forms[right]
        value = None
        if self.assignment is not None:
            av, bv = self._form_value(a), self._form_value(b)
            value = av ^ bv if opcode == 1 else av & bv if opcode == 2 else av ^ 1
            self.charge("evaluated_gate", 1)
        if opcode == 2:
            self._reserve_form(1)
            if self.counter.rows >= self.counter.maximum:
                raise RuntimeError("incomplete: AND-row capacity")
            column = self._fresh(value)
            self._emit((linear(a), linear(b), ((column, 1),)))
            result = (column,)
        else:
            expression = symmetric_difference(a, b if opcode == 1 else (0,))
            if len(expression) > 64:
                self._reserve_form(1)
                if self.counter.rows >= self.counter.maximum:
                    raise RuntimeError("incomplete: spill-row capacity")
                column = self._fresh(value)
                self._emit((linear(expression), ONE, ((column, 1),)))
                self.spills += 1
                result = (column,)
            else:
                result = expression
        self._store(result)
        self.gates[opcode - 1] += 1

    def completed(self):
        if self.state != "complete" or self.descriptor is None or self.counter.failed:
            raise RuntimeError("incomplete representation cannot yield a relation")
        return self.descriptor


def verify_assignment(descriptor, rows, assignment, expected_public_identity, charge):
    """Check an assignment against a trusted complete matrix descriptor.

    The descriptor is a local compilation result, not caller-provided security
    evidence. Rows and assignments may be adversarial. Exact dimensions and the
    sealed row digest prevent appended unconstrained columns or omitted rows.
    """
    if type(descriptor) is not AffineDescriptor or not descriptor.complete:
        raise ValueError("trusted complete descriptor required")
    if (
        type(expected_public_identity) is not bytes
        or len(expected_public_identity) != 32
        or descriptor.public_identity != expected_public_identity.hex()
    ):
        raise ValueError("public identity mismatch")
    if type(assignment) not in (tuple, list, bytearray) or len(assignment) != descriptor.variables:
        raise ValueError("exact assignment dimension required")
    for value in assignment:
        field(value)
    if type(rows) not in (tuple, list) or len(rows) != descriptor.rows:
        raise ValueError("exact complete row collection required")
    digest = hashlib.sha256(b"PQDID-EXPERIMENTAL-R1CS-GF192-1")
    satisfied = True
    for row in rows:
        if type(row) is not tuple or len(row) != 3:
            raise ValueError("invalid row shape")
        for terms in row:
            if type(terms) is not tuple or len(terms) > 128:
                raise ValueError("bounded canonical linear term tuple required")
            previous = -1
            for term in terms:
                if type(term) is not tuple or len(term) != 2:
                    raise ValueError("invalid term shape")
                column, coefficient = term
                if (
                    type(column) is not int
                    or not previous < column <= descriptor.variables
                    or field(coefficient) == 0
                ):
                    raise ValueError("noncanonical row term/index")
                previous = column
        digest.update(row_bytes(row))
        charge(1)
        a, b, c = evaluate_row(row, assignment)
        satisfied = (multiply(a, b) == c) and satisfied
    if digest.hexdigest() != descriptor.matrix_sha256:
        raise ValueError("row content differs from trusted completed matrix")
    return satisfied
