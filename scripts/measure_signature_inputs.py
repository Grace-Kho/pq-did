"""Supervised core-only measurements; host output observations add no circuit gates."""

import hashlib
import tempfile
import time
from dataclasses import asdict

from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.auth_parsing import link_disclosure, parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Emitter, Limits, ResourceLimit, evaluate
from pqdid.circuits.keccak import shake256
from pqdid.circuits.parsing import public_bytes
from pqdid.circuits.signature import (
    _hint_boundary,
    _hint_cells,
    _hint_iteration,
    _hint_padding,
    _unsigned,
    decode_hints,
    decode_responses,
    decode_signature,
    response_norm,
)
from pqdid.circuits.signature_inputs import (
    certified_message,
    decode_expected_public_key,
    message_representative,
    prepare_verifier_inputs,
)
from pqdid.statements import encode_auth_statement
from pqdid.witnesses import encode_auth_witness

COMPONENTS = (
    "responses",
    "hint-boundaries",
    "hint-two-steps",
    "hint-padding",
    "response-norm",
    "public-key",
    "public-key-hash",
    "certified-message",
    "representative-hash-kernel",
    "message-preparation",
    "legacy-ring-multiply",
    "legacy-ring-public-multiply",
    "legacy-ntt-butterfly",
    "division-alternative",
    "hints-complete",
    "signature-complete",
    "preparation-complete",
)


def counts(e):
    return {**asdict(e.counts), "gates": e.counts.gates, "wires": e.counts.wires}


def construct(component, mode, limits, sink, phases):
    from tests.unit.relation_cases import auth_case

    pp, statement, witness = auth_case()
    raw = encode_auth_witness(pp.schema, witness)
    if component == "representative-hash-kernel":
        from pqdid.binding import create_binding
        from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT, build_mcred

        binding = create_binding(pp.domain, witness.holder_secret, witness.attributes)
        message = build_mcred(pp, statement.metadata, binding, witness.revocation_identifier)
        preimage = (
            hashlib.shake_256(pp.issuer_public_key).digest(64)
            + bytes((0, len(CREDENTIAL_SIGNING_CONTEXT)))
            + CREDENTIAL_SIGNING_CONTEXT
            + message
        )
        # Test-only SHAKE input component, NOT an alternative preparation API.
        # The prefix is public framing. The suffix starts at Y and includes the
        # two intervening four-byte public lengths as private test positions.
        split = len(preimage) - 1084
        e = Emitter(1084 * 8, mode=mode, limits=limits, sink=sink, public_data=preimage[:split])
        digest = shake256(e, public_bytes(e, preimage[:split]) + e.inputs, 64)
        return e.finish(e.one), preimage[split:], {"byte_strings": (digest,)}
    if component == "division-alternative":
        from pqdid.circuits.division import divmod64
        from tests.reference.division_alternative import separate_compare_and_subtract

        e = Emitter(64, mode=mode, limits=limits, sink=sink)
        scope = Scope(e)
        decoded = divmod64(e, w.from_serialised(e, e.inputs), ring.Q)
        scope.require(decoded.valid)
        circuit = e.finish(scope.output(()))
        other = Emitter(64, mode="count", limits=limits)
        alternate_scope = Scope(other)
        alt = separate_compare_and_subtract(other, w.from_serialised(other, other.inputs), ring.Q)
        alternate_scope.require(alt.valid)
        alternate = other.finish(alternate_scope.output(()))
        phases["alternative_core"] = {
            "counts": asdict(alternate.counts),
            "gates": alternate.counts.gates,
            "fingerprint": alternate.fingerprint,
        }
        return (
            circuit,
            (-(1 << 63)).to_bytes(8, "big", signed=True),
            {"words": (decoded.quotient, decoded.remainder)},
        )
    inputs = 0 if component in ("public-key", "public-key-hash") else 42632
    e = Emitter(
        inputs,
        mode=mode,
        limits=limits,
        sink=sink,
        public_data=encode_auth_statement(pp, statement),
    )
    scope = Scope(e)
    outputs = {"words": (), "byte_strings": (), "flags": ()}
    if component == "public-key":
        key = decode_expected_public_key(e, pp)
        outputs.update(
            words=tuple(x for p in key.t1 for x in p), byte_strings=(key.rho,), flags=(key.valid,)
        )
    elif component == "public-key-hash":
        outputs["byte_strings"] = (shake256(e, public_bytes(e, pp.issuer_public_key), 64),)
    elif component == "preparation-complete":
        prepared = prepare_verifier_inputs(scope, pp, statement, e.inputs)
        outputs["flags"] = (prepared.preparation_valid,)
    elif component in ("certified-message", "message-preparation"):
        parsed = parse_auth_witness(scope, pp.schema, e.inputs)
        link_disclosure(
            scope, pp.schema, parsed, statement.disclosed, statement.disclosed_attributes
        )
        phases["parsing_and_disclosure"] = counts(e)
        message = certified_message(scope, pp, statement.metadata, parsed)
        phases["through_certified_message"] = counts(e)
        outputs["byte_strings"] = (
            message.holder_preimage,
            message.holder_value,
            message.encoded_binding,
            message.certified_message,
            message.formatted_message,
        )
        if component == "message-preparation":
            representative = message_representative(scope, pp, message)
            outputs["byte_strings"] += (
                representative.public_key_hash,
                representative.representative_preimage,
                representative.fips_message_representative,
            )
    elif component in ("responses", "response-norm", "signature-complete"):
        if component == "signature-complete":
            decoded = decode_signature(scope, e.inputs[8480:34952])
        else:
            decoded = decode_responses(scope, e.inputs[8480:34952])
        phases["through_responses"] = counts(e)
        outputs.update(
            words=tuple(x for p in decoded.responses for x in p),
            byte_strings=(decoded.challenge_hash,),
            flags=(decoded.valid,),
        )
        if component == "response-norm":
            norm = response_norm(scope, decoded.responses)
            scope.require(norm.within_bound)
            outputs["flags"] += (norm.within_bound, norm.arithmetic_valid)
    else:
        encoded = e.inputs[8 * (1060 + 3248) : 34952]
        cells = _hint_cells(e, encoded)
        if component == "hints-complete":
            result = decode_hints(scope, encoded)
            outputs.update(words=tuple(x for p in result.hints for x in p), flags=(result.valid,))
        elif component == "hint-boundaries":
            index = w.constant(e, 0, 64)
            for row in range(6):
                index = _hint_boundary(scope, cells, index, row)
            # Boundary-only diagnostic: carry prior endpoint, no reconstructed row.
            outputs["words"] = (index,)
        elif component == "hint-padding":
            _hint_padding(scope, cells, _unsigned(e, cells[-1]))
        elif component == "hint-two-steps":
            index = w.constant(e, 0, 64)
            end = _hint_boundary(scope, cells, index, 0)
            first = index
            polynomial = tuple(w.constant(e, 0, 64) for _ in range(256))
            for _ in range(2):
                index, polynomial = _hint_iteration(scope, cells, index, first, end, polynomial)
            outputs["words"] = (index, *polynomial)
        else:
            raise ValueError(component)
    circuit = e.finish(scope.output(()))
    return circuit, raw if inputs else b"", outputs


def legacy(component, mode, limits, sink):
    from measure_auth_parsing_arithmetic import build, prepare

    original = component.removeprefix("legacy-")
    public, raw = prepare(original)
    description = original.encode() + b"".join(
        v.to_bytes(8, "big", signed=True) for v in public["target"]
    )
    e = Emitter(public["inputs"], limits=limits, mode=mode, sink=sink, public_data=description)
    scope = Scope(e)
    a = w.from_serialised(e, e.inputs[:64])
    if original == "ring-public-multiply":
        left = ring.Scalar(w.constant(e, 25847, 64), ring.Domain.NTT)
        right = ring.Scalar(a, ring.Domain.NTT)
    else:
        left = ring.Scalar(a, ring.Domain.NTT)
        right = ring.Scalar(w.from_serialised(e, e.inputs[64:]), ring.Domain.NTT)
    if original == "ntt-butterfly":
        outputs = tuple(x.value for x in ring.ntt_butterfly(scope, left, right, 25847))
    else:
        outputs = (ring.ntt_pointwise_multiply(scope, left, right).value,)
    core = e.finish(scope.output(()))
    # Reconstruct the unchanged historical probe separately, retaining validity.
    full = build(original, public, "count", limits, None)
    delta = {
        key: getattr(full.counts, key) - getattr(core.counts, key)
        for key in ("xor", "and_", "not_", "gates")
    }
    return (
        core,
        raw,
        {"words": outputs},
        {
            "historical_predicate_counts": asdict(full.counts),
            "historical_predicate_gates": full.counts.gates,
            "historical_predicate_fingerprint": full.fingerprint,
            "extra_test_predicate": delta,
            "expected_words": public["target"],
        },
    )


def probe(component, mode, profile):
    from tests.reference.signature_oracle import observed

    limits = Limits(
        max_gates=profile["max_gates"],
        max_output_bytes=profile["max_output_bytes"],
        max_seconds=profile["generation_seconds"],
        max_inputs=profile["max_inputs"],
    )
    phases = {}
    result = {
        "component": component,
        "mode": mode,
        "outcome": "resource_limit",
        "limits": asdict(limits),
        "generation_complete": False,
        "phases_cumulative": phases,
        "tracemalloc": False,
        "additional_comparison_gates": 0,
        "instrumentation": (
            "external trace observation + supervisor RSS sampling; no circuit instrumentation"
        ),
    }
    started = time.perf_counter()
    with tempfile.TemporaryFile(mode="w+b", dir="/tmp") as sink:
        try:
            if component.startswith("legacy-"):
                circuit, raw, outputs, accounting = legacy(
                    component, mode, limits, sink if mode == "stream" else None
                )
                result.update(accounting)
                result["classification"] = (
                    "public 25847 left / private signed64 right"
                    if component == "legacy-ring-public-multiply"
                    else "two private signed64 words; butterfly twiddle 25847 public"
                )
            else:
                circuit, raw, outputs = construct(
                    component, mode, limits, sink if mode == "stream" else None, phases
                )
                result["classification"] = (
                    "public pp/key/schema/X; existing raw witness wires private; no advice"
                    if circuit.counts.inputs
                    else "entirely public expected-pp issuer key"
                )
                if component == "representative-hash-kernel":
                    result["classification"] = (
                        "test-only 1084-byte private hash suffix; public tr/context/header; "
                        "not an authentication witness or production preparation interface"
                    )
                elif component == "division-alternative":
                    result["classification"] = "private signed64 dividend; public divisor q"
            result.update(
                generation_complete=True,
                counts=asdict(circuit.counts),
                gates=circuit.counts.gates,
                serialised_bytes=circuit.serialised_bytes,
                stored_trace_bytes=circuit.stored_bytes,
                fingerprint=circuit.fingerprint,
                generation_seconds=circuit.generation_seconds,
                folded_operations=circuit.folded_operations,
            )
            if mode == "stream":
                sink.flush()
                sink.seek(0)
                assert hashlib.file_digest(sink, "sha256").hexdigest() == circuit.fingerprint
            if mode == "materialised":
                evaluation = evaluate(
                    circuit,
                    raw,
                    max_seconds=profile["evaluation_seconds"],
                    max_wires=profile["max_gates"] + 65538,
                )
                result["evaluation"] = asdict(evaluation)
                assert evaluation.output == 1
                observation_start = time.perf_counter()
                values, strings, flags = observed(circuit, raw, **outputs)
                # Do not report private values/preimages, even synthetic fixture data.
                result["observed_output_counts"] = {
                    "words": len(values),
                    "byte_strings": len(strings),
                    "flags": len(flags),
                }
                if component.startswith("legacy-"):
                    assert values == tuple(result.pop("expected_words"))
                result["observation_seconds"] = time.perf_counter() - observation_start
            result.pop("expected_words", None)
            result["outcome"] = "passed"
        except ResourceLimit as error:
            result.update(reason=error.reason, progress=error.progress)
    result["probe_seconds"] = time.perf_counter() - started
    if result["generation_complete"]:
        result["preparation_and_reporting_seconds"] = (
            result["probe_seconds"]
            - result["generation_seconds"]
            - result.get("evaluation", {}).get("seconds", 0)
            - result.get("observation_seconds", 0)
        )
    return result
