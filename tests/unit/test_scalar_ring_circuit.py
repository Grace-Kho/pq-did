"""Scalar FIPS boundaries against both the reference verifier and independent maths."""

import io

import pytest

from pqdid import bounded_mldsa as reference
from pqdid.circuits import scalar_ring as ring
from pqdid.circuits import words as w
from pqdid.circuits.control import Scope
from pqdid.circuits.division import mod64
from pqdid.circuits.emitter import Emitter, Limits, evaluate
from tests.reference.scalar_oracle import decompose, use_hint

from .auth_arithmetic_cases import extended_limits
from .test_bc1_division import VECTORS, observed

MIN, MAX = -(1 << 63), (1 << 63) - 1
PAIRS = [
    (0, 0),
    (0, 1),
    (1, 1),
    (ring.Q - 1, ring.Q - 1),
    (ring.Q, 2),
    (-1, 1),
    (-ring.Q + 1, ring.Q - 1),
    (MIN, 1),
    (MIN, -1),
    (MAX, 1),
    (MAX, 2),
    (MIN, MIN),
    (MAX, MAX),
    (MIN, MAX),
    (3037000499, 3037000499),
    (3037000500, 3037000500),
]
OPERATIONS = {
    "add": (ring.add, lambda a, b: a + b),
    "subtract": (ring.subtract, lambda a, b: a - b),
    "multiply": (ring.multiply, lambda a, b: a * b),
}


@pytest.fixture(scope="module", params=tuple(OPERATIONS))
def scalar_operation(request):
    e = Emitter(128, limits=extended_limits())
    scope = Scope(e)
    a = ring.Scalar(w.from_serialised(e, e.inputs[:64]), ring.Domain.COEFFICIENT)
    b = ring.Scalar(w.from_serialised(e, e.inputs[64:]), ring.Domain.COEFFICIENT)
    result = OPERATIONS[request.param][0](scope, a, b)
    circuit = e.finish(scope.output(()))
    return request.param, circuit, result.value


@pytest.mark.parametrize("a,b", PAIRS)
def test_private_private_ring_full_width_and_sticky_overflow(scalar_operation, a, b):
    name, circuit, value = scalar_operation
    raw = a.to_bytes(8, "big", signed=True) + b.to_bytes(8, "big", signed=True)
    mathematical = OPERATIONS[name][1](a, b)
    valid = MIN <= mathematical <= MAX
    assert evaluate(circuit, raw, max_wires=2_065_538).output == int(valid)
    if valid:
        assert observed(circuit, raw, value) == (mathematical % ring.Q,)


@pytest.mark.parametrize("operation", tuple(OPERATIONS))
def test_private_public_operands_and_original_extended_mode_identity(operation):
    def build(limits, mode="materialised", sink=None):
        e = Emitter(64, limits=limits, mode=mode, sink=sink, public_data=operation.encode())
        scope = Scope(e)
        a = ring.Scalar(w.from_serialised(e, e.inputs), ring.Domain.NTT)
        b = ring.Scalar(w.constant(e, 25847, 64), ring.Domain.NTT)
        result = OPERATIONS[operation][0](scope, a, b)
        return e.finish(scope.output(())), result.value

    material, value = build(extended_limits())
    for a in (0, 1, ring.Q - 1, -ring.Q, MIN, MAX):
        raw = a.to_bytes(8, "big", signed=True)
        math = OPERATIONS[operation][1](a, 25847)
        valid = MIN <= math <= MAX
        assert evaluate(material, raw, max_wires=2_065_538).output == int(valid)
        if valid:
            assert observed(material, raw, value) == (math % ring.Q,)
    original, _ = build(Limits())
    assert original.serialised == material.serialised
    sink = io.BytesIO()
    for mode in ("count", "stream"):
        circuit, _ = build(extended_limits(), mode, sink if mode == "stream" else None)
        assert circuit.counts == material.counts and circuit.fingerprint == material.fingerprint
    assert sink.getvalue() == material.serialised


def test_reduction_and_tautological_equality_cannot_repair_overflow():
    e = Emitter(128, limits=extended_limits())
    scope = Scope(e)
    a = w.from_serialised(e, e.inputs[:64])
    b = w.from_serialised(e, e.inputs[64:])
    overflowing = scope.checked(w.mul64(e, a, b))
    reduced = scope.checked(mod64(e, overflowing, ring.Q))
    circuit = e.finish(scope.output((w.equal(e, reduced, reduced),)))
    for a, b in ((MIN, -1), (MAX, 2), (MAX, MAX)):
        assert (
            evaluate(
                circuit, a.to_bytes(8, "big", signed=True) + b.to_bytes(8, "big", signed=True)
            ).output
            == 0
        )
    assert evaluate(circuit, (2).to_bytes(8, "big") + (3).to_bytes(8, "big")).output == 1


@pytest.fixture(scope="module")
def decomposition():
    e = Emitter(64, limits=extended_limits())
    scope = Scope(e)
    high, low = ring.decompose(scope, w.from_serialised(e, e.inputs))
    return e.finish(scope.output(())), high, low


@pytest.mark.parametrize("case", VECTORS["decompose"], ids=lambda c: str(c["value"]))
def test_decompose_exceptional_endpoint_and_reference(decomposition, case):
    circuit, high, low = decomposition
    value = case["value"]
    raw = value.to_bytes(8, "big", signed=True)
    assert evaluate(circuit, raw).output == 1
    pair = observed(circuit, raw, high, low)
    assert pair == (case["high"], case["low"]) == decompose(value) == reference._decompose(value)
    assert 0 <= pair[0] < 16 and -ring.GAMMA2 <= pair[1] <= ring.GAMMA2
    assert (pair[0] * 2 * ring.GAMMA2 + pair[1] - value) % ring.Q == 0


@pytest.fixture(scope="module")
def hinted():
    e = Emitter(65, limits=extended_limits())
    scope = Scope(e)
    result = ring.use_hint(scope, e.inputs[-1], w.from_serialised(e, e.inputs[:64]))
    return e.finish(scope.output(())), result


@pytest.mark.parametrize("case", VECTORS["decompose"], ids=lambda c: str(c["value"]))
@pytest.mark.parametrize("hint", [0, 1])
def test_hint_boolean_private_input_and_reference(hinted, case, hint):
    circuit, result = hinted
    value = case["value"]
    raw = value.to_bytes(8, "big", signed=True) + bytes([hint << 7])
    assert evaluate(circuit, raw, max_wires=2_065_538).output == 1
    (output,) = observed(circuit, raw, result)
    assert (
        output == case[f"hint{hint}"] == use_hint(hint, value) == reference._use_hint(hint, value)
    )
    assert 0 <= output < 16


@pytest.mark.parametrize("helper,index", [(ring.high_bits, 0), (ring.low_bits, 1)])
def test_high_and_low_bits_helpers_preserve_decompose(helper, index):
    e = Emitter(64, limits=extended_limits())
    scope = Scope(e)
    value = helper(scope, w.from_serialised(e, e.inputs))
    circuit = e.finish(scope.output(()))
    for a in (0, ring.GAMMA2, ring.Q - ring.GAMMA2, ring.Q - 1):
        raw = a.to_bytes(8, "big")
        assert evaluate(circuit, raw).output == 1
        assert observed(circuit, raw, value) == (reference._decompose(a)[index],)


@pytest.mark.parametrize(
    "a", [MIN, MAX, -524093, -524092, -524091, -1, 0, 1, 524091, 524092, 524093]
)
def test_strict_norm_scalar_and_checked_abs_min(a):
    e = Emitter(64, limits=extended_limits())
    scope = Scope(e)
    norm = ring.norm_ok(scope, w.from_serialised(e, e.inputs))
    circuit = e.finish(scope.output((norm,)))
    assert evaluate(circuit, a.to_bytes(8, "big", signed=True)).output == int(
        reference._norm_ok([[a]])
    )


@pytest.mark.parametrize("left,right", [(0, 0), (1, 1), (ring.Q - 1, ring.Q - 2), (-1, 2)])
def test_prescribed_single_ntt_butterfly_against_independent_and_reference(left, right):
    zeta = pow(1753, 128, ring.Q)
    assert zeta == reference._ZETAS[1]
    e = Emitter(128, limits=extended_limits())
    scope = Scope(e)
    a = ring.Scalar(w.from_serialised(e, e.inputs[:64]), ring.Domain.NTT)
    b = ring.Scalar(w.from_serialised(e, e.inputs[64:]), ring.Domain.NTT)
    out = ring.ntt_butterfly(scope, a, b, zeta)
    circuit = e.finish(scope.output(()))
    raw = left.to_bytes(8, "big", signed=True) + right.to_bytes(8, "big", signed=True)
    assert evaluate(circuit, raw, max_wires=2_065_538).output == 1
    product = zeta * right % ring.Q
    assert observed(circuit, raw, out[0].value, out[1].value) == (
        (left + product) % ring.Q,
        (left - product) % ring.Q,
    )


def test_butterfly_source_order_is_product_then_right_then_left(monkeypatch):
    calls = []
    for name in ("ntt_pointwise_multiply", "subtract", "add"):
        original = getattr(ring, name)

        def observe(*args, _name=name, _original=original):
            calls.append(_name)
            return _original(*args)

        monkeypatch.setattr(ring, name, observe)
    e = Emitter(128, limits=extended_limits())
    scope = Scope(e)
    a = ring.Scalar(e.inputs[:64], ring.Domain.NTT)
    b = ring.Scalar(e.inputs[64:], ring.Domain.NTT)
    ring.ntt_butterfly(scope, a, b, 25847)
    assert calls == ["ntt_pointwise_multiply", "subtract", "add"]


def test_domain_mix_and_coefficientwise_polynomial_claims_rejected():
    e = Emitter(128, limits=extended_limits())
    scope = Scope(e)
    a = ring.Scalar(e.inputs[:64], ring.Domain.COEFFICIENT)
    b = ring.Scalar(e.inputs[64:], ring.Domain.NTT)
    for operation in (ring.add, ring.subtract, ring.multiply, ring.ntt_pointwise_multiply):
        with pytest.raises(ValueError):
            operation(scope, a, b)
    with pytest.raises(ValueError):
        ring.ntt_butterfly(scope, a, a, 25847)


@pytest.mark.parametrize("domain", list(ring.Domain))
def test_reduce_scalar_keeps_domain_annotation(domain):
    e = Emitter(64, limits=extended_limits())
    scope = Scope(e)
    result = ring.reduce_scalar(scope, ring.Scalar(w.from_serialised(e, e.inputs), domain))
    circuit = e.finish(scope.output(()))
    assert result.domain is domain
    for value in (MIN, -ring.Q, 0, ring.Q - 1, MAX):
        raw = value.to_bytes(8, "big", signed=True)
        assert evaluate(circuit, raw).output == 1
        assert observed(circuit, raw, result.value) == (value % ring.Q,)


@pytest.mark.parametrize("hint", [0, 1])
def test_public_hint_preserves_same_mathematical_helper(hint):
    e = Emitter(64, limits=extended_limits())
    scope = Scope(e)
    result = ring.use_hint(scope, e.constant(hint), w.from_serialised(e, e.inputs))
    circuit = e.finish(scope.output(()))
    for value in (0, ring.GAMMA2 + 1, ring.Q - 1):
        raw = value.to_bytes(8, "big", signed=True)
        assert evaluate(circuit, raw, max_wires=2_065_538).output == 1
        assert observed(circuit, raw, result) == (reference._use_hint(hint, value),)


def test_wide_multiply_and_active_vs_inactive_overflow(monkeypatch):
    original = w.mul64
    widths = []

    def observe(*args):
        result = original(*args)
        widths.append(len(result.wide))
        return result

    monkeypatch.setattr(w, "mul64", observe)
    e = Emitter(128, limits=extended_limits())
    scope = Scope(e, active=e.zero)
    a = ring.Scalar(w.from_serialised(e, e.inputs[:64]), ring.Domain.NTT)
    b = ring.Scalar(w.from_serialised(e, e.inputs[64:]), ring.Domain.NTT)
    ring.multiply(scope, a, b)
    circuit = e.finish(scope.output(()))
    assert widths == [128]
    assert evaluate(circuit, MAX.to_bytes(8, "big") + MAX.to_bytes(8, "big")).output == 1
