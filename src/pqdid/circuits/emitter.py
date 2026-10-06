"""Canonical BC-1 gate emission and bounded development evaluation.

The binary trace/fingerprint is an internal engineering format, never a protocol
commitment. Construction sees public constants and symbolic private positions only.
"""

import hashlib
import math
import struct
import sys
import time
from dataclasses import dataclass
from typing import BinaryIO

HEADER = struct.Struct(">16sQ32s")
GATE = struct.Struct(">BQQ")
FOOTER = struct.Struct(">BQQQQ")
MAGIC = b"PQDID-BC1-DEV1".ljust(16, b"\x00")
XOR, AND, NOT = 1, 2, 3


def _nonnegative(value: int) -> None:
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("expected non-negative bounded integer")


@dataclass(frozen=True)
class Limits:
    max_gates: int = 200_000
    max_output_bytes: int = 8 * 1024 * 1024
    max_seconds: float = 10.0
    max_inputs: int = 65_536

    def __post_init__(self):
        for value in (self.max_gates, self.max_output_bytes, self.max_inputs):
            _nonnegative(value)
        if (
            type(self.max_seconds) not in (float, int)
            or not math.isfinite(self.max_seconds)
            or self.max_seconds < 0
        ):
            raise ValueError("invalid execution-time limit")


class ResourceLimit(RuntimeError):
    """Non-completion, carrying only public progress counters, never a circuit."""

    def __init__(self, reason: str, progress: dict):
        super().__init__(reason)
        self.reason = reason
        self.progress = {**progress, "complete": False}


@dataclass(frozen=True, slots=True)
class Bit:
    index: int
    public: int | None
    _owner: object

    def __bool__(self):
        raise TypeError("symbolic bits cannot control Python branching")


@dataclass(frozen=True)
class Counts:
    xor: int
    and_: int
    not_: int
    inputs: int

    @property
    def gates(self) -> int:
        return self.xor + self.and_ + self.not_

    @property
    def wires(self) -> int:
        return 2 + self.inputs + self.gates


@dataclass(frozen=True)
class Circuit:
    """Completed development circuit description; only materialised mode has bytes."""

    counts: Counts
    output: int
    fingerprint: str
    public_digest: bytes
    serialised_bytes: int
    stored_bytes: int
    generation_seconds: float
    serialised: bytes | None
    folded_operations: tuple[int, int, int]

    @property
    def retained_trace_bytes(self) -> int:
        return 0 if self.serialised is None else sys.getsizeof(self.serialised)


class Emitter:
    def __init__(
        self,
        private_inputs: int,
        *,
        limits: Limits,
        mode: str = "materialised",
        public_data: bytes = b"",
        sink: BinaryIO | None = None,
    ):
        _nonnegative(private_inputs)
        if type(limits) is not Limits or mode not in ("materialised", "count", "stream"):
            raise ValueError("invalid emitter configuration")
        if type(public_data) is not bytes or len(public_data) > 65536:
            raise ValueError("development public description must be at most 65536 bytes")
        if (mode == "stream") != (sink is not None):
            raise ValueError("stream mode requires exactly one binary sink")
        self._started = time.perf_counter()
        self._state = "open"
        self._limits = limits
        self._mode = mode
        self._sink = sink
        self._buffer = bytearray() if mode == "materialised" else None
        self._hash = hashlib.sha256()
        self._op_counts = [0, 0, 0]
        self._folded = [0, 0, 0]
        self._inputs_count = private_inputs
        self._wire_count = 2 + private_inputs
        self._serialised_bytes = 0
        self._stored_bytes = 0
        self._token = object()
        self.zero = Bit(0, 0, self._token)
        self.one = Bit(1, 1, self._token)
        self.public_digest = hashlib.sha256(public_data).digest()
        if private_inputs > limits.max_inputs:
            self._abort("input-position limit")
        self.poll()
        self._write(HEADER.pack(MAGIC, private_inputs, self.public_digest))
        try:
            self.inputs = tuple(Bit(i + 2, None, self._token) for i in range(private_inputs))
            self.poll()
        except BaseException:
            self._state = "aborted"
            raise

    @property
    def state(self) -> str:
        return self._state

    @property
    def counts(self) -> Counts:
        return Counts(*self._op_counts, self._inputs_count)

    def progress(self) -> dict:
        return {
            "gates": self.counts.gates,
            "wires": self._wire_count,
            "serialised_bytes_so_far": self._serialised_bytes,
            "stored_bytes": self._stored_bytes,
        }

    def _abort(self, reason: str):
        self._state = "aborted"
        raise ResourceLimit(reason, self.progress())

    def poll(self):
        if self._state != "open":
            raise RuntimeError("emitter is no longer open")
        if time.perf_counter() - self._started >= self._limits.max_seconds:
            self._abort("generation-time limit")

    def _write(self, record: bytes):
        self.poll()
        if (
            self._mode != "count"
            and self._stored_bytes + len(record) > self._limits.max_output_bytes
        ):
            self._abort("output-storage limit")
        try:
            if self._buffer is not None:
                self._buffer.extend(record)
            elif self._sink is not None:
                if self._sink.write(record) != len(record):
                    raise OSError("short circuit-record write")
            self._hash.update(record)
        except BaseException:
            self._state = "aborted"
            raise
        self._serialised_bytes += len(record)
        if self._mode != "count":
            self._stored_bytes += len(record)

    def check_bit(self, bit: Bit):
        if type(bit) is not Bit or bit._owner is not self._token:
            raise ValueError("wire belongs to another emitter")
        if not 0 <= bit.index < self._wire_count:
            raise ValueError("wire not yet defined")
        if bit.public != (bit.index if bit.index < 2 else None):
            raise ValueError("invalid public classification")

    def constant(self, value: int) -> Bit:
        self.poll()
        if type(value) is not int or value not in (0, 1):
            raise ValueError("constant must be integer 0 or 1")
        return self.one if value else self.zero

    def _operation(self, opcode: int, a: Bit, b: Bit) -> Bit:
        self.poll()
        self.check_bit(a)
        self.check_bit(b)
        if a.public is not None and b.public is not None:
            value = (
                (a.public ^ b.public)
                if opcode == XOR
                else ((a.public & b.public) if opcode == AND else (1 ^ a.public))
            )
            self._folded[opcode - 1] += 1
            return self.one if value else self.zero
        if self.counts.gates >= self._limits.max_gates:
            self._abort("gate-count limit")
        output = self._wire_count
        result = Bit(output, None, self._token)
        self._write(GATE.pack(opcode, a.index, b.index))
        self._op_counts[opcode - 1] += 1
        self._wire_count += 1
        return result

    def xor(self, a: Bit, b: Bit) -> Bit:
        return self._operation(XOR, a, b)

    def and_(self, a: Bit, b: Bit) -> Bit:
        return self._operation(AND, a, b)

    def not_(self, a: Bit) -> Bit:
        return self._operation(NOT, a, self.zero)

    def or_(self, a: Bit, b: Bit) -> Bit:
        left = self.xor(a, b)
        right = self.and_(a, b)
        return self.xor(left, right)

    def mux(self, selector: Bit, a: Bit, b: Bit) -> Bit:
        difference = self.xor(a, b)
        selected = self.and_(selector, difference)
        return self.xor(a, selected)

    def finish(self, output: Bit) -> Circuit:
        self.poll()
        self.check_bit(output)
        self._write(FOOTER.pack(255, output.index, *self._op_counts))
        try:
            serialised = bytes(self._buffer) if self._buffer is not None else None
            self.poll()
            result = Circuit(
                self.counts,
                output.index,
                self._hash.hexdigest(),
                self.public_digest,
                self._serialised_bytes,
                self._stored_bytes,
                time.perf_counter() - self._started,
                serialised,
                tuple(self._folded),
            )
        except BaseException:
            self._state = "aborted"
            raise
        self._state = "completed"
        self._buffer = None  # Do not retain a second copy of a completed trace.
        return result


@dataclass(frozen=True)
class Evaluation:
    output: int
    seconds: float
    wire_storage_bytes: int


def evaluate(
    circuit: Circuit, witness: bytes, *, max_seconds: float = 5.0, max_wires: int = 300_000
) -> Evaluation:
    """Boolean evaluation only; byte-per-wire storage, MSB-first packed inputs."""
    limits = Limits(max_inputs=max_wires, max_seconds=max_seconds)
    started = time.perf_counter()
    if type(circuit) is not Circuit or circuit.serialised is None:
        raise ValueError("evaluation requires a completed materialised circuit")
    if type(witness) is not bytes or len(witness) != (circuit.counts.inputs + 7) // 8:
        raise ValueError("incorrect packed private-input length")
    padding = (-circuit.counts.inputs) % 8
    if padding and witness[-1] & ((1 << padding) - 1):
        raise ValueError("non-zero terminal input padding")

    def poll():
        if time.perf_counter() - started >= limits.max_seconds:
            raise ResourceLimit("evaluation-time limit", {"complete": False})

    poll()
    if circuit.counts.wires > max_wires:
        raise ResourceLimit("evaluation wire-storage limit", {"wires": circuit.counts.wires})
    data = circuit.serialised
    expected_size = HEADER.size + GATE.size * circuit.counts.gates + FOOTER.size
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != circuit.fingerprint:
        raise ValueError("corrupt development circuit")
    if HEADER.unpack_from(data) != (MAGIC, circuit.counts.inputs, circuit.public_digest):
        raise ValueError("inconsistent circuit header")
    if FOOTER.unpack_from(data, len(data) - FOOTER.size) != (
        255,
        circuit.output,
        circuit.counts.xor,
        circuit.counts.and_,
        circuit.counts.not_,
    ):
        raise ValueError("inconsistent circuit footer")
    values = bytearray(circuit.counts.wires)
    values[1] = 1
    for i in range(circuit.counts.inputs):
        poll()
        values[2 + i] = (witness[i // 8] >> (7 - i % 8)) & 1
    counts = [0, 0, 0]
    for index, offset in enumerate(range(HEADER.size, len(data) - FOOTER.size, GATE.size)):
        poll()
        opcode, a, b = GATE.unpack_from(data, offset)
        out = 2 + circuit.counts.inputs + index
        if opcode not in (XOR, AND, NOT) or a >= out or b >= out or (opcode == NOT and b != 0):
            raise ValueError("invalid gate or forward reference")
        counts[opcode - 1] += 1
        values[out] = (
            values[a] ^ values[b]
            if opcode == XOR
            else (values[a] & values[b] if opcode == AND else 1 ^ values[a])
        )
    if tuple(counts) != (
        circuit.counts.xor,
        circuit.counts.and_,
        circuit.counts.not_,
    ) or not 0 <= circuit.output < len(values):
        raise ValueError("inconsistent output/counts")
    poll()
    return Evaluation(values[circuit.output], time.perf_counter() - started, sys.getsizeof(values))
