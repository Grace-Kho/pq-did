"""Bounded streaming adapter consuming exact existing Emitter records.

No disk trace or matrix is retained. Optional assignment uses one byte per wire,
explicitly bounded; it is not a claimed last-use-frontier implementation.
"""

from pqdid.circuits.emitter import FOOTER, GATE, HEADER, MAGIC, Emitter

from .r1cs import Descriptor, RowCounter, evaluate_row, gate_row, input_row, wire


class R1CSSink:
    def __init__(
        self,
        public_identity: bytes,
        *,
        charge=None,
        witness_bits: bytes | None = None,
        max_rows=32_000_000,
        max_assignment_wires=32_000_000,
        row_consumer=None,
    ):
        if type(public_identity) is not bytes or len(public_identity) != 32:
            raise ValueError("public identity must be SHA-256 engineering digest")
        if not 0 < max_rows <= 32_065_538 or not 0 < max_assignment_wires <= 32_065_538:
            raise ValueError("partition cap outside approved maximum")
        if witness_bits is not None and (
            type(witness_bits) is not bytes or any(value > 1 for value in witness_bits)
        ):
            raise ValueError("one canonical byte per private bit required")
        self.public_identity = public_identity
        self.charge = charge or (lambda kind, count: None)
        self.counter = RowCounter(maximum=max_rows, charge=self.charge, row_consumer=row_consumer)
        self.witness_bits = witness_bits
        self.max_assignment_wires = max_assignment_wires
        self.assignment = None
        self.inputs = None
        self.gates = [0, 0, 0]
        self.descriptor = None
        self.state = "open"
        self.satisfied = True

    def _emit(self, row):
        self.counter.emit(row)
        if self.assignment is not None:
            self.charge("evaluated_row", 1)
            a, b, c = evaluate_row(row, self.assignment)
            self.satisfied = self.satisfied and (a * b == c)

    def write(self, record: bytes) -> int:
        if self.state != "open":
            raise RuntimeError("stream not open")
        try:
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
            self.inputs = inputs
            if self.witness_bits is not None:
                if len(self.witness_bits) != inputs or inputs + 1 > self.max_assignment_wires:
                    raise ValueError("private assignment shape/cap mismatch")
                self.assignment = bytearray(b"\x01" + self.witness_bits)
            for column in range(2, inputs + 2):
                self._emit(input_row(column))
            return
        if len(record) == FOOTER.size and record[0] == 255:
            _, output, *counts = FOOTER.unpack(record)
            gates = sum(self.gates)
            if counts != self.gates or output >= 2 + self.inputs + gates:
                raise ValueError("invalid completion footer")
            self._emit((wire(output), ((0, 1),), ((1, 1),)))
            self._emit((((1, 1),), ((0, 1),), ((0, 1),)))
            self.descriptor = Descriptor(
                True,
                self.inputs,
                gates,
                self.counter.rows,
                self.inputs + gates + 1,
                1,
                output,
                tuple(self.counter.nnz),
                self.counter.digest.hexdigest(),
                self.public_identity.hex(),
                tuple(self.gates),
                self.inputs,
                2,
                0 if self.assignment is None else len(self.assignment),
            )
            self.state = "complete"
            return
        if len(record) != GATE.size:
            raise ValueError("malformed gate record")
        opcode, a, b = GATE.unpack(record)
        output = 2 + self.inputs + sum(self.gates)
        if opcode not in (1, 2, 3) or a >= output or b >= output:
            raise ValueError("missing producer or invalid opcode")
        if opcode == 3 and b != 0:
            raise ValueError("noncanonical NOT operand")
        if sum(self.gates) >= 32_000_000:
            raise RuntimeError("incomplete individual gate cap")
        self.charge("emitted_gate", 1)
        if self.assignment is not None:
            if len(self.assignment) >= self.max_assignment_wires:
                raise RuntimeError("incomplete assignment storage cap")
            av = a if a < 2 else self.assignment[a - 1]
            bv = b if b < 2 else self.assignment[b - 1]
            value = av ^ bv if opcode == 1 else (av & bv if opcode == 2 else 1 ^ av)
            self.assignment.append(value)
            self.charge("evaluated_gate", 1)
        self._emit(gate_row(opcode, a, b, output))
        self.gates[opcode - 1] += 1

    def completed(self):
        if self.state != "complete" or self.descriptor is None or self.counter.failed:
            raise RuntimeError("incomplete stream cannot produce a completed relation")
        return self.descriptor


def check_stream(sink: R1CSSink) -> bool:
    sink.completed()
    if sink.assignment is None:
        raise ValueError("count-only stream has no satisfaction evidence")
    return sink.satisfied


class CountedEmitter(Emitter):
    """Reuse exact gate construction, hashing and folding without retaining trace bytes.

    The production stream mode charges logical output bytes as stored output. Here
    the row sink consumes each record immediately; count mode correctly reports
    stored_bytes=0. Gate, input, time, row, assignment and work limits still apply.
    """

    def __init__(self, private_inputs, *, sink: R1CSSink, limits, public_data=b""):
        self.relation_sink = sink
        super().__init__(private_inputs, limits=limits, mode="count", public_data=public_data)

    def _write(self, record):
        try:
            self.relation_sink.write(record)
            super()._write(record)
        except BaseException:
            self.relation_sink.state = "incomplete"
            self.relation_sink.descriptor = None
            raise

    def finish(self, output):
        try:
            return super().finish(output)
        except BaseException:
            self.relation_sink.state = "incomplete"
            self.relation_sink.descriptor = None
            raise
