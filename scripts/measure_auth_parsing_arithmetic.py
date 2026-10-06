"""Fresh bounded component predicates; no authentication count/proof projection.

Run through validate_auth_arithmetic.py for process/RSS supervision. Source-target
preparation uses independent mathematical/test fixtures outside timed construction.
"""

import hashlib
import tempfile
import time
import tracemalloc
from dataclasses import asdict

from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.auth_parsing import compile_auth_parsing
from pqdid.circuits.control import Scope
from pqdid.circuits.division import centred64, divmod64, mod64
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from pqdid.witnesses import encode_auth_witness

COMPONENTS = (
    "auth-parsing",
    "attribute-capacity",
    "divmod-q",
    "canonical-q",
    "centred-even",
    "ring-add",
    "ring-subtract",
    "ring-multiply",
    "ring-public-multiply",
    "decompose",
    "use-hint",
    "ntt-butterfly",
)


def prepare(component):
    from tests.reference.scalar_oracle import centred, decompose, floor_pair, use_hint
    from tests.unit.relation_cases import auth_case

    if component == "attribute-capacity":
        from pqdid.schema import AttributeField, Schema, encode_attributes

        schema = Schema(
            (
                AttributeField("did", 0, 171),
                AttributeField("version", 0, 56),
                AttributeField("empty", 0, 0),
                AttributeField("full", 0, 789),
            ),
            1,
            2,
        )
        raw = encode_attributes(schema, (b"", b"", b"", b"x" * 789))
        return {"schema": schema, "inputs": 8192}, raw
    if component == "auth-parsing":
        pp, statement, witness = auth_case()
        return {"pp": pp, "statement": statement}, encode_auth_witness(pp.schema, witness)
    values = {
        "divmod-q": (-(1 << 63),),
        "canonical-q": (-ring.Q - 1,),
        "centred-even": (ring.GAMMA2 + 1,),
        "ring-add": (ring.Q - 1, ring.Q - 1),
        "ring-subtract": (0, ring.Q - 1),
        "ring-multiply": (ring.Q - 1, ring.Q - 1),
        "ring-public-multiply": (ring.Q - 1,),
        "decompose": (ring.Q - 1,),
        "use-hint": (ring.Q - 1,),
        "ntt-butterfly": (ring.Q - 1, ring.Q - 2),
    }[component]
    raw = b"".join(v.to_bytes(8, "big", signed=True) for v in values)
    a = values[0]
    if component == "divmod-q":
        target = floor_pair(a, ring.Q)
    elif component == "canonical-q":
        target = (floor_pair(a, ring.Q)[1],)
    elif component == "centred-even":
        target = (centred(a, 2 * ring.GAMMA2),)
    elif component == "ring-add":
        target = ((a + values[1]) % ring.Q,)
    elif component == "ring-subtract":
        target = ((a - values[1]) % ring.Q,)
    elif component == "ring-multiply":
        target = ((a * values[1]) % ring.Q,)
    elif component == "ring-public-multiply":
        target = ((25847 * a) % ring.Q,)
    elif component == "decompose":
        target = decompose(a)
    elif component == "use-hint":
        target = (use_hint(1, a),)
        raw += b"\x80"
    else:
        product = 25847 * values[1] % ring.Q
        target = ((a + product) % ring.Q, (a - product) % ring.Q)
    return {"target": target, "inputs": 65 if component == "use-hint" else 64 * len(values)}, raw


def build(component, public, mode, limits, sink):
    if component == "attribute-capacity":
        from pqdid.circuits.auth_parsing import parse_attributes
        from pqdid.schema import encode_schema

        e = Emitter(
            8192,
            limits=limits,
            mode=mode,
            sink=sink,
            public_data=b"attribute-capacity" + encode_schema(public["schema"]),
        )
        scope = Scope(e)
        parse_attributes(scope, public["schema"], e.inputs)
        return e.finish(scope.output(()))
    if component == "auth-parsing":
        return compile_auth_parsing(
            public["pp"], public["statement"], limits=limits, mode=mode, sink=sink
        )
    description = component.encode() + b"".join(
        v.to_bytes(8, "big", signed=True) for v in public["target"]
    )
    e = Emitter(public["inputs"], limits=limits, mode=mode, sink=sink, public_data=description)
    scope = Scope(e)
    a = w.from_serialised(e, e.inputs[:64])
    if component == "divmod-q":
        result = divmod64(e, a, ring.Q)
        scope.require(result.valid)
        output = (result.quotient, result.remainder)
    elif component == "canonical-q":
        output = (scope.checked(mod64(e, a, ring.Q)),)
    elif component == "centred-even":
        output = (scope.checked(centred64(e, a, 2 * ring.GAMMA2)),)
    elif component == "decompose":
        output = ring.decompose(scope, a)
    elif component == "use-hint":
        output = (ring.use_hint(scope, e.inputs[-1], a),)
    else:
        if component == "ring-public-multiply":
            left = ring.Scalar(w.constant(e, 25847, 64), ring.Domain.NTT)
            right = ring.Scalar(a, ring.Domain.NTT)
        else:
            left = ring.Scalar(a, ring.Domain.NTT)
            right = ring.Scalar(w.from_serialised(e, e.inputs[64:]), ring.Domain.NTT)
        if component == "ntt-butterfly":
            output = tuple(s.value for s in ring.ntt_butterfly(scope, left, right, 25847))
        else:
            operation = {
                "ring-add": ring.add,
                "ring-subtract": ring.subtract,
                "ring-multiply": ring.ntt_pointwise_multiply,
                "ring-public-multiply": ring.ntt_pointwise_multiply,
            }[component]
            output = (operation(scope, left, right).value,)
    checks = tuple(
        w.equal(e, word, w.constant(e, expected, 64, signed=True))
        for word, expected in zip(output, public["target"], strict=True)
    )
    return e.finish(scope.output(checks))


def probe(component, mode, profile):
    public, witness = prepare(component)
    limits = Limits(
        max_gates=profile["max_gates"],
        max_output_bytes=profile["max_output_bytes"],
        max_seconds=profile["generation_seconds"],
        max_inputs=profile["max_inputs"],
    )
    result = {
        "component": component,
        "mode": mode,
        "outcome": "resource_limit",
        "limits": asdict(limits),
        "tracemalloc": True,
        "generation_complete": False,
        "private_input_bits": 42632 if component == "auth-parsing" else public["inputs"],
        "classification": "witness/attribute bytes private; schema/pp/X public"
        if component in ("auth-parsing", "attribute-capacity")
        else "operand words/hint private; divisors/twiddle/expected outputs public",
    }
    with tempfile.TemporaryFile(mode="w+b", dir="/tmp") as sink:
        tracemalloc.start()
        started = time.perf_counter()
        try:
            circuit = build(component, public, mode, limits, sink if mode == "stream" else None)
            result.update(
                generation_complete=True,
                counts=asdict(circuit.counts),
                gates=circuit.counts.gates,
                wires=circuit.counts.wires,
                serialised_bytes=circuit.serialised_bytes,
                stored_trace_bytes=circuit.stored_bytes,
                fingerprint=circuit.fingerprint,
                generation_seconds=circuit.generation_seconds,
                fresh_construction_seconds=time.perf_counter() - started,
                retained_trace_bytes=circuit.retained_trace_bytes,
                folded_operations=list(circuit.folded_operations),
                generation_traced_peak_bytes=tracemalloc.get_traced_memory()[1],
            )
            if mode == "stream":
                sink.flush()
                result["file_bytes"] = sink.tell()
                sink.seek(0)
                if hashlib.file_digest(sink, "sha256").hexdigest() != circuit.fingerprint:
                    raise AssertionError("stream bytes/fingerprint mismatch")
            if mode == "materialised":
                value = evaluate(
                    circuit,
                    witness,
                    max_seconds=profile["evaluation_seconds"],
                    max_wires=profile["max_gates"] + 65538,
                )
                result["evaluation"] = asdict(value)
                if value.output != 1:
                    raise AssertionError("component predicate rejected")
            result["outcome"] = "passed"
        except ResourceLimit as error:
            result.update(reason=error.reason, progress=error.progress)
        finally:
            result.update(
                probe_seconds=time.perf_counter() - started,
                traced_peak_bytes=tracemalloc.get_traced_memory()[1],
            )
            tracemalloc.stop()
    return result
