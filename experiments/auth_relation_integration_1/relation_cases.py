"""Individually dispatched synthetic public/private component comparisons.

No case runs on import. Full-relation J comparisons are explicitly reference-only
after the resident route's capacity no-go: they never claim constrained agreement.
An entire transform/sampler is not represented by a small boundary comparison.
"""

import hashlib
import inspect
from dataclasses import asdict, fields, replace

from experiments.auth_relation_integration_1 import fixtures
from experiments.auth_relation_integration_1 import mldsa_verify as lowered
from experiments.auth_relation_integration_1.assignment import private_bits
from experiments.auth_relation_integration_1.statement import (
    PublicCapacity,
    parse_public,
    prepare_public,
)
from experiments.auth_relation_integration_1.stream import CountedEmitter, R1CSSink, check_stream
from experiments.mldsa_forward_ntt_stage_1.candidate import _from_canonical_producers
from pqdid import bounded_mldsa as reference
from pqdid.binding import create_binding
from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.auth_parsing import parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Limits
from pqdid.circuits.keccak import sha3_384, shake256
from pqdid.circuits.parsing import equal_bytes, holder_message, public_bytes
from pqdid.circuits.signature import unpack_unsigned
from pqdid.circuits.signature_inputs import certified_message
from pqdid.codec import EncodingError, encode_record
from pqdid.credentials import CREDENTIAL_SIGNING_CONTEXT, build_mcred
from pqdid.hash_domain import encode_metadata
from pqdid.policy import Equality, make_policy
from pqdid.public_checks import pub_ok, public_policy_ok
from pqdid.relations import auth
from pqdid.statements import encode_auth_statement
from pqdid.witnesses import decode_auth_witness, encode_auth_witness


def _unsafe_record_change(record, **changes):
    """Test-only malformed typed record, never available at adapter boundaries."""
    result = object.__new__(type(record))
    for field in fields(record):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(record, field.name)))
    return result


def _flip(data, position=0):
    return data[:position] + bytes((data[position] ^ 1,)) + data[position + 1 :]


def public_case(case_id, meter):
    pp, statement, _witness = fixtures.auth_case()
    expected_pp = pp
    if case_id == "P-02":
        expected_pp = fixtures.parameters("beta")
    elif case_id == "P-03":
        statement = replace(
            statement, parameters=replace(pp, issuer_public_key=_flip(pp.issuer_public_key))
        )
    elif case_id == "P-04":
        statement = replace(
            statement, state=replace(statement.state, signature=_flip(statement.state.signature))
        )
    elif case_id == "P-05":
        wrong = replace(statement.context.state_reference, epoch=statement.state.epoch + 1)
        statement = replace(statement, context=replace(statement.context, state_reference=wrong))
    elif case_id == "P-06":
        statement = replace(
            statement, context=replace(statement.context, issuer_reference=b"wrong")
        )
    elif case_id == "P-07":
        schema = replace(
            pp.schema, fields=(replace(pp.schema.fields[0], name="wrong"), *pp.schema.fields[1:])
        )
        statement = replace(statement, parameters=_unsafe_record_change(pp, schema=schema))
    elif case_id == "P-08":
        statement = replace(statement, disclosed=(*statement.disclosed, statement.disclosed[-1]))
    elif case_id == "P-09":
        policy = make_policy(pp.schema, statement.disclosed, (Equality(3, False),))
        statement = replace(statement, context=replace(statement.context, policy=policy))
    elif case_id == "P-10":
        statement = replace(statement, context=replace(statement.context, suite=b"wrong"))
    elif case_id == "P-11":
        statement = replace(
            statement, state=replace(statement.state, root=statement.state.root[:-1])
        )
    elif case_id == "P-12":
        try:
            parse_public(pp, bytes(65_537))
        except PublicCapacity:
            return {
                "coverage": "public transport admission",
                "outcome": "capacity",
                "complete": True,
            }
        raise AssertionError("oversized public transport admitted")
    elif case_id != "P-01":
        raise ValueError("unknown public case")
    expected = pub_ok(expected_pp, statement) and public_policy_ok(expected_pp, statement)
    try:
        prepared = prepare_public(expected_pp, statement)
        actual = True
    except EncodingError:
        actual = False
        prepared = None
    if actual != expected or actual != (case_id == "P-01"):
        raise AssertionError("public preprocessing disagrees with reference")
    meter(0)
    return {
        "coverage": "complete public boundary, not private constraints",
        "expected": expected,
        "actual": actual,
        "preprocessing_sha256": None if prepared is None else prepared.preprocessing_sha256,
    }


def _run(raw, builder, meter, *, expected=True, identity=b"component-v1"):
    """One actual emitted component and every R1CS row checked; no trace on disk."""
    public_identity = hashlib.sha256(identity).digest()
    sink = R1CSSink(
        public_identity,
        charge=lambda _kind, count: meter(count),
        witness_bits=private_bits(raw, expected_bytes=len(raw)),
        max_rows=2_065_538,
        max_assignment_wires=2_065_538,
    )
    emitter = CountedEmitter(
        len(raw) * 8,
        sink=sink,
        public_data=identity,
        limits=Limits(max_gates=2_000_000, max_output_bytes=8_388_608, max_seconds=45),
    )
    try:
        scope = Scope(emitter)
        output = builder(scope)
        circuit = emitter.finish(output)
    except BaseException:
        sink.state = "incomplete"
        sink.descriptor = None
        raise
    descriptor = sink.completed()
    actual = check_stream(sink)
    if actual != expected:
        raise AssertionError("constrained component disagrees with independent expectation")
    return {
        "coverage": "complete named component only",
        "expected": expected,
        "actual": actual,
        "descriptor": asdict(descriptor),
        "generation_and_stream_check_seconds": circuit.generation_seconds,
    }


def _offset(schema, index):
    return sum(2 + field.capacity for field in schema.fields[:index])


def witness_case(case_id, meter):
    pp, statement, witness = fixtures.auth_case()
    original = encode_auth_witness(pp.schema, witness)
    raw = bytearray(original)
    if case_id == "W-03":
        raw[32:34] = (pp.schema.fields[0].capacity + 1).to_bytes(2, "big")
    elif case_id == "W-04":
        raw[32 + _offset(pp.schema, 2) + 2] = 2
    elif case_id == "W-05":
        position = 32 + _offset(pp.schema, 3)
        raw[position : position + 2] = (7).to_bytes(2, "big")
    elif case_id == "W-06":
        raw[1055] = 1
    elif case_id == "W-07":
        raw[1056:1060] = (1 << 20).to_bytes(4, "big")
    elif case_id in {"W-08", "W-09"}:
        value = original[:-1] if case_id == "W-08" else original + b"\0"
        for reject in (
            lambda: private_bits(value),
            lambda: decode_auth_witness(pp.schema, value),
        ):
            try:
                reject()
            except EncodingError, ValueError:
                continue
            raise AssertionError("incorrect witness length accepted")
        return {"coverage": "exact assignment/witness boundary", "rejected": True}
    elif case_id == "W-12":
        from experiments.auth_relation_integration_1.private_relation import compile_private

        if tuple(inspect.signature(compile_private).parameters) != ("prepared", "sink", "limits"):
            raise AssertionError("unexpected private override argument")
        prepared = prepare_public(pp, statement)
        from experiments.auth_relation_integration_1.statement import validate_prepared

        forged = replace(prepared, public_key_hash=_flip(prepared.public_key_hash))
        try:
            validate_prepared(forged)
        except EncodingError:
            return {"coverage": "trusted preprocessing and no Y/B/mu override", "rejected": True}
        raise AssertionError("forged preprocessing accepted")
    elif case_id not in {"W-01", "W-02", "W-10", "W-11"}:
        raise ValueError("unknown witness case")
    raw = bytes(raw)
    try:
        decode_auth_witness(pp.schema, raw)
        expected = True
    except EncodingError:
        expected = False
    if case_id in {"W-10", "W-11"}:
        # Hash/message validation uses the same raw inputs, not a supplied Y/B/mu.
        holder_preimage = encode_record(
            "holder", (pp.suite, encode_metadata(pp.domain), witness.holder_secret)
        )
        holder_value = hashlib.sha3_384(holder_preimage).digest()
        binding = create_binding(pp.domain, witness.holder_secret, witness.attributes)
        mcred = build_mcred(pp, statement.metadata, binding, witness.revocation_identifier)

        def build(scope):
            parsed = parse_auth_witness(scope, pp.schema, scope.e.inputs)
            if case_id == "W-10":
                value = sha3_384(scope.e, holder_message(scope.e, pp.domain, parsed.holder_secret))
                scope.require(equal_bytes(scope.e, value, public_bytes(scope.e, holder_value)))
            else:
                message = certified_message(scope, pp, statement.metadata, parsed)
                formatted = (
                    bytes((0, len(CREDENTIAL_SIGNING_CONTEXT))) + CREDENTIAL_SIGNING_CONTEXT + mcred
                )
                scope.require(
                    equal_bytes(scope.e, message.certified_message, public_bytes(scope.e, mcred))
                )
                scope.require(
                    equal_bytes(
                        scope.e, message.formatted_message, public_bytes(scope.e, formatted)
                    )
                )
            return scope.output(())
    else:

        def build(scope):
            parsed = parse_auth_witness(scope, pp.schema, scope.e.inputs)
            if case_id == "W-02":
                scope.require(
                    w.equal(
                        scope.e,
                        parsed.identifier,
                        w.constant(scope.e, witness.revocation_identifier, 64),
                    )
                )
                coefficients = unpack_unsigned(scope.e, parsed.signature[384 : 384 + 640 * 8], 20)
                expected_first = int.from_bytes(witness.signature[48:688], "little") & (
                    (1 << 20) - 1
                )
                scope.require(
                    w.equal(scope.e, coefficients[0], w.constant(scope.e, expected_first, 64))
                )
            return scope.output(())

    return _run(raw, build, meter, expected=expected, identity=case_id.encode())


def _word(scope, start=0):
    return w.from_serialised(scope.e, scope.e.inputs[start : start + 64])


def arithmetic_case(case_id, meter):
    q = reference._Q
    if case_id in {"M-01", "M-02", "M-03"}:
        raise RuntimeError(
            "full private sampler not admitted: fixed scanned-cell"
            " cost requires separate bounded execution"
        )
    if case_id in {"M-04", "M-05", "M-06", "M-07"}:
        encoded = bytearray(61)
        if case_id == "M-04":
            encoded[55], encoded[56] = 1, 0
        elif case_id == "M-05":
            encoded[55:] = bytes([56] * 6)
        elif case_id == "M-06":
            encoded[0], encoded[1] = 3, 3
            encoded[55:] = bytes([2] * 6)
        else:
            encoded[0] = 1
        try:
            reference._decode_hints(bytes(encoded))
        except reference._InvalidSignature:
            pass
        else:
            raise AssertionError("independent malformed-hint fixture did not reject")

        def build(scope):
            lowered.decode_hints(scope, scope.e.inputs)
            return scope.output(())

        return _run(bytes(encoded), build, meter, expected=False, identity=case_id.encode())
    if case_id == "M-08":
        value = (1 << 19) - 196

        def build(scope):
            scope.require(ring.norm_ok(scope, _word(scope)))
            return scope.output(())

        return _run(
            value.to_bytes(8, "big"), build, meter, expected=False, identity=case_id.encode()
        )
    if case_id == "M-09":
        left, right, zeta = q - 1, q - 2, reference._ZETAS[1]
        expected = ((left + zeta * right) % q, (left - zeta * right) % q)

        def build(scope):
            # Establish canonicality from full signed64 input before producer reuse.
            from pqdid.circuits.division import mod64

            a = scope.checked(mod64(scope.e, _word(scope), q))
            b = scope.checked(mod64(scope.e, _word(scope, 64), q))
            result = _from_canonical_producers(
                scope, ring.Scalar(a, ring.Domain.NTT), ring.Scalar(b, ring.Domain.NTT), zeta
            )
            scope.require(w.equal(scope.e, result.left.value, w.constant(scope.e, expected[0], 64)))
            scope.require(
                w.equal(scope.e, result.right.value, w.constant(scope.e, expected[1], 64))
            )
            return scope.output(())

        result = _run(
            left.to_bytes(8, "big") + right.to_bytes(8, "big"),
            build,
            meter,
            identity=case_id.encode(),
        )
        result["coverage"] = (
            "single actual forward butterfly with full entry"
            " normalisation; complete transform unexecuted"
        )
        return result
    if case_id == "M-10":
        left, right, zeta = 0, q - 1, -reference._ZETAS[255]
        expected = ((left + right) % q, zeta * ((left - right) % q) % q)

        def build(scope):
            a, b = lowered.inverse_butterfly(scope, _word(scope), _word(scope, 64), zeta)
            scope.require(w.equal(scope.e, a, w.constant(scope.e, expected[0], 64)))
            scope.require(w.equal(scope.e, b, w.constant(scope.e, expected[1], 64)))
            scaled = ring.multiply(
                scope,
                ring.Scalar(b, ring.Domain.NTT),
                ring.Scalar(w.constant(scope.e, 8347681, 64), ring.Domain.NTT),
            ).value
            scope.require(
                w.equal(scope.e, scaled, w.constant(scope.e, expected[1] * 8347681 % q, 64))
            )
            return scope.output(())

        result = _run(
            left.to_bytes(8, "big") + right.to_bytes(8, "big"),
            build,
            meter,
            identity=case_id.encode(),
        )
        result["coverage"] = (
            "single actual inverse butterfly and final factor;"
            " complete inverse transform unexecuted"
        )
        return result
    if case_id in {"M-11", "M-12"}:
        total, value, factor = q - 1, q - 2, reference._ZETAS[2]
        expected = (total + (1 if case_id == "M-11" else -1) * value * factor) % q
        function = (
            lowered.accumulate_public_product
            if case_id == "M-11"
            else lowered.subtract_public_product
        )

        def build(scope):
            result = function(scope, _word(scope), _word(scope, 64), factor)
            scope.require(w.equal(scope.e, result, w.constant(scope.e, expected, 64)))
            return scope.output(())

        result = _run(
            total.to_bytes(8, "big") + value.to_bytes(8, "big"),
            build,
            meter,
            identity=case_id.encode(),
        )
        result["coverage"] = "one complete coefficient update, not six polynomial rows"
        return result
    if case_id in {"M-13", "M-14"}:
        value = q - 1
        high, low = reference._decompose(value)

        def build(scope):
            if case_id == "M-13":
                a, b = ring.decompose(scope, _word(scope))
                scope.require(w.equal(scope.e, a, w.constant(scope.e, high, 64)))
                scope.require(w.equal(scope.e, b, w.constant(scope.e, low, 64, signed=True)))
            else:
                result = ring.use_hint(scope, scope.e.one, _word(scope))
                scope.require(
                    w.equal(scope.e, result, w.constant(scope.e, reference._use_hint(1, value), 64))
                )
            return scope.output(())

        return _run(value.to_bytes(8, "big"), build, meter, identity=case_id.encode())
    if case_id == "M-15":
        # All1536 nibbles are private; full output vector, no integer advice.
        values = tuple(tuple((row + i) % 16 for i in range(256)) for row in range(6))
        expected = reference._encode_w1(values)

        def build(scope):
            little = tuple(
                bit
                for pos in range(0, len(scope.e.inputs), 8)
                for bit in reversed(scope.e.inputs[pos : pos + 8])
            )
            words = tuple(
                (*little[i : i + 4], *((scope.e.zero,) * 60)) for i in range(0, len(little), 4)
            )
            vector = tuple(words[i : i + 256] for i in range(0, len(words), 256))
            result = lowered.encode_w1(scope, vector)
            scope.require(equal_bytes(scope.e, result, public_bytes(scope.e, expected)))
            return scope.output(())

        return _run(expected, build, meter, identity=case_id.encode())
    if case_id == "M-16":
        pp, statement, witness = fixtures.auth_case()
        binding = create_binding(pp.domain, witness.holder_secret, witness.attributes)
        message = build_mcred(pp, statement.metadata, binding, witness.revocation_identifier)
        formatted = (
            bytes((0, len(CREDENTIAL_SIGNING_CONTEXT))) + CREDENTIAL_SIGNING_CONTEXT + message
        )
        rho, t1 = reference._decode_public_key(pp.issuer_public_key)
        c_tilde, z, hints = reference._decode_signature(witness.signature)
        challenge = reference._sample_in_ball(reference._shake_reader(256, c_tilde))
        az = reference._matrix_vector_product(
            reference._expand_a(rho), [reference._ntt(poly) for poly in z]
        )
        c_hat = reference._ntt(challenge)
        t1_hat = [reference._ntt([x * (1 << 13) % q for x in poly]) for poly in t1]
        approximate = [
            reference._inverse_ntt(
                [(az[row][i] - c_hat[i] * t1_hat[row][i]) % q for i in range(256)]
            )
            for row in range(6)
        ]
        encoded = reference._encode_w1(
            [
                [reference._use_hint(hints[row][i], approximate[row][i]) for i in range(256)]
                for row in range(6)
            ]
        )
        tr = hashlib.shake_256(pp.issuer_public_key).digest(64)
        mu = hashlib.shake_256(tr + formatted).digest(64)
        if hashlib.shake_256(mu + encoded).digest(48) != c_tilde:
            raise AssertionError("independent retained signature expectation changed")

        def build(scope):
            output = shake256(scope.e, public_bytes(scope.e, mu) + scope.e.inputs, 48)
            scope.require(equal_bytes(scope.e, output, public_bytes(scope.e, c_tilde)))
            return scope.output(())

        result = _run(encoded, build, meter, identity=case_id.encode())
        result["coverage"] = (
            "complete final challenge SHAKE/equality only; mu/w1"
            " obtained from independent reference"
        )
        return result
    raise ValueError("unknown arithmetic case")


def joint_case(case_id, meter):
    """Reference outcome only after no-go; cannot count as complete constrained J."""
    pp, statement, witness = fixtures.auth_case()
    expected = case_id in {"J-01", "J-02", "J-03", "J-04"}
    if case_id == "J-02":
        pp, statement, witness = fixtures.auth_case("alpha-43-old-002c")
    elif case_id == "J-03":
        statement = replace(statement, context=replace(statement.context, session=b"new-session"))
    elif case_id == "J-04":
        pp, statement, witness = fixtures.auth_case("alpha-42-old-0034")
    elif case_id == "J-05":
        witness = replace(witness, holder_secret=_flip(witness.holder_secret))
    elif case_id == "J-06":
        witness = replace(witness, attributes=_flip(witness.attributes, 2))
    elif case_id == "J-07":
        witness = replace(witness, signature=_flip(witness.signature))
    elif case_id == "J-08":
        witness = replace(witness, revocation_identifier=43)
    elif case_id == "J-09":
        witness = replace(witness, signature=fixtures.auth_case("alpha-43-old-002c")[2].signature)
    elif case_id == "J-10":
        witness = replace(witness, path=fixtures.auth_case("alpha-43-updated-003f")[2].path)
    elif case_id == "J-11":
        witness = replace(witness, path=_flip(witness.path))
    elif case_id == "J-12":
        witness = replace(witness, path=witness.path[-48:] + witness.path[:-48])
    elif case_id in {"J-13", "J-14"}:
        target = fixtures.state("updated" if case_id == "J-14" else "empty")
        statement = replace(
            statement,
            state=target,
            context=replace(statement.context, state_reference=target.reference),
        )
        if case_id == "J-14":
            witness = replace(witness, path=fixtures.path(witness.revocation_identifier, "updated"))
    elif case_id == "J-15":
        # Keep a valid public policy, change the disclosed BOOLEAN byte only.
        policy = make_policy(pp.schema, statement.disclosed, ())
        statement = replace(
            statement,
            context=replace(statement.context, policy=policy),
            disclosed_attributes=_flip(statement.disclosed_attributes, 2),
        )
    elif case_id == "J-16":
        sig = bytearray(witness.signature)
        sig[3303] = 56
        witness = replace(witness, signature=bytes(sig))
    elif case_id != "J-01":
        raise ValueError("unknown joint case")
    actual = auth(pp, statement, witness)
    if actual != expected:
        raise AssertionError("retained reference joint expectation did not match")
    meter(0)
    return {
        "coverage": "reference-only; complete constrained comparison not executed",
        "complete_relation_validated": False,
        "expected": expected,
        "reference_result": actual,
        "statement_sha256": hashlib.sha256(encode_auth_statement(pp, statement)).hexdigest(),
        "reason": "native capacity no-go and absent completed full relation descriptor",
    }


def case(case_id, meter):
    if case_id.startswith("P-"):
        return public_case(case_id, meter)
    if case_id.startswith("W-"):
        return witness_case(case_id, meter)
    if case_id.startswith("M-"):
        return arithmetic_case(case_id, meter)
    if case_id.startswith("J-"):
        return joint_case(case_id, meter)
    raise ValueError("case outside relation owner boundary")
