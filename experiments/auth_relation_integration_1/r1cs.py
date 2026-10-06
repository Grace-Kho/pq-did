"""Experimental conservative Boolean-to-GF(2^192) rows; never active BC-1."""

import hashlib
import struct
from dataclasses import dataclass

FIELD_BITS = 192
FIELD_MASK = (1 << FIELD_BITS) - 1
MODULUS = (1 << FIELD_BITS) | 0x87
Term = tuple[int, int]
Linear = tuple[Term, ...]
Row = tuple[Linear, Linear, Linear]


def field(value: int) -> int:
    if type(value) is not int or not 0 <= value <= FIELD_MASK:
        raise ValueError("noncanonical field element")
    return value


def multiply(a: int, b: int) -> int:
    """Independent exact polynomial arithmetic, including full-degree operands."""
    field(a)
    field(b)
    product = 0
    for bit in range(FIELD_BITS):
        if b & (1 << bit):
            product ^= a << bit
    for bit in range(2 * FIELD_BITS - 2, FIELD_BITS - 1, -1):
        if product & (1 << bit):
            product ^= MODULUS << (bit - FIELD_BITS)
    return product


def canonical(terms) -> Linear:
    combined = {}
    for column, coefficient in terms:
        if type(column) is not int or not 0 <= column < 2**63:
            raise ValueError("invalid column")
        combined[column] = combined.get(column, 0) ^ field(coefficient)
    return tuple((column, value) for column, value in sorted(combined.items()) if value)


def wire(index: int) -> Linear:
    if type(index) is not int or index < 0:
        raise ValueError("invalid wire")
    if index == 0:
        return ()
    return ((0 if index == 1 else index, 1),)


def add(left: Linear, right: Linear) -> Linear:
    return canonical(left + right)


def gate_row(opcode: int, left: int, right: int, output: int) -> Row:
    a, b, c = wire(left), wire(right), wire(output)
    if opcode == 1:
        return add(a, b), ((0, 1),), c
    if opcode == 2:
        return a, b, c
    if opcode == 3:
        if right != 0:
            raise ValueError("noncanonical NOT second operand")
        return add(a, ((0, 1),)), ((0, 1),), c
    raise ValueError("unknown Boolean opcode")


def input_row(column: int) -> Row:
    value = ((column, 1),)
    return value, ((0, 1), (column, 1)), ()


def row_bytes(row: Row) -> bytes:
    out = bytearray()
    for terms in row:
        out.extend(struct.pack(">I", len(terms)))
        for column, coefficient in terms:
            out.extend(struct.pack(">Q", column))
            out.extend(field(coefficient).to_bytes(24, "little"))
    return bytes(out)


def evaluate_linear(terms: Linear, assignment) -> int:
    value = 0
    for column, coefficient in terms:
        atom = 1 if column == 0 else field(assignment[column - 1])
        value ^= atom if coefficient == 1 else multiply(coefficient, atom)
    return value


def evaluate_row(row: Row, assignment) -> tuple[int, int, int]:
    return tuple(evaluate_linear(terms, assignment) for terms in row)


@dataclass(frozen=True)
class Descriptor:
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
    output_rows: int
    assignment_storage_bytes: int
    memory_model: str = "bounded retained byte assignment; no last-use claim"


class RowCounter:
    """No matrix retention. An exception poisons the sink permanently."""

    def __init__(self, *, maximum: int, charge=None, row_consumer=None):
        self.maximum = maximum
        self.charge = charge or (lambda kind, count: None)
        self.row_consumer = row_consumer
        self.rows = 0
        self.nnz = [0, 0, 0]
        self.digest = hashlib.sha256(b"PQDID-EXPERIMENTAL-R1CS-GF192-1")
        self.failed = False

    def emit(self, row: Row):
        if self.failed or self.rows >= self.maximum:
            self.failed = True
            raise RuntimeError("incomplete row stream: capacity or prior failure")
        try:
            self.charge("emitted_row", 1)
            self.digest.update(row_bytes(row))
            if self.row_consumer is not None:
                self.row_consumer(row)
            self.rows += 1
            for side, terms in enumerate(row):
                self.nnz[side] += len(terms)
        except BaseException:
            self.failed = True
            raise
