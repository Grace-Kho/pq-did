"""Four new finite analysis checks; reuse all earlier functional/cryptographic tests."""

import ast
import importlib.util
import json
import struct
from fractions import Fraction
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
spec = importlib.util.spec_from_file_location("mapping", D / "query_mapping.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
checks = []


def checked(name, fn):
    fn()
    checks.append({"name": name, "passed": True})


def profile():
    p = json.loads((P / "analysis/concrete_security/security_profile.json").read_text())
    hashes = p["manuscript_construction"]["hashes"]["outer_proof"]
    assert [hashes[k] for k in ["rate_bits", "capacity_bits", "output_bits", "rounds"]] == [
        1088,
        512,
        1024,
        24,
    ]
    suite = json.loads((P / "configs/suite.json").read_text())
    assert suite["confirmed"]["hashes"]["HRO_output_bits"] == 1024
    tree = ast.parse((P / "src/pqdid/codec.py").read_text())
    arities = next(
        ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_ARITIES" for t in n.targets)
    )
    assert arities["view"] == (7, 7) and arities["challenge"] == (5, 5)
    tree = ast.parse((P / "src/pqdid/circuits/keccak.py").read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "shake256")
    call = next(
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_sponge"
    )
    assert [ast.literal_eval(n) for n in call.args[2:4]] == [136, 31]


def framing():
    def lp(x):
        return struct.pack(">I", len(x)) + x

    def frame(tag, fields):
        return lp(tag) + struct.pack(">I", len(fields)) + b"".join(map(lp, fields))

    # Independent literal byte frames; never allocate declared maximum sizes.
    for kind in [b"auth", b"enrol"]:
        for s, d, g in [(0, 256, 0), (17, 42632, 3), (136, 42632, 11)]:
            v = bytes((d + 2 * g + 7) // 8)
            view = frame(b"view", [b"PQ-DID-MITH-1", kind, bytes(s), b"\0\1", b"\2", bytes(64), v])
            challenge = frame(
                b"challenge", [b"PQ-DID-MITH-1", kind, bytes(s), bytes(64), bytes(185760)]
            )
            assert len(view) == m.view_bytes(s, d, g, kind.decode())
            assert len(challenge) == m.challenge_bytes(s, kind.decode())
            assert view != challenge
    for args in [
        (True, 256, 0, "auth"),
        (0, 256, -1, "auth"),
        (m.L + 1, 256, 0, "auth"),
        (0, 8 * m.L + 1, 0, "auth"),
        (0, 256, 0, "unknown"),
    ]:
        try:
            m.view_bytes(*args)
        except ValueError:
            continue
        raise AssertionError("invalid domain accepted")
    assert 2 * m.L + 125 < m.BMAX
    assert m.challenge_bytes(m.L, "enrol") < m.BMAX


def padding():
    padded = set()
    for size in [0, 1, 134, 135, 136, 137, 271, 272]:
        message = b"x" * size
        remaining = 136 - size % 136
        tail = bytearray(remaining)
        tail[0] = 0x1F
        tail[-1] |= 0x80
        value = message + tail
        assert len(value) == 136 * m.absorb_blocks(size)
        assert value[-136:] != bytes(136)
        assert value not in padded
        padded.add(value)
        assert tail[-1] == (0x9F if remaining == 1 else 0x80)
    assert m.absorb_blocks(m.BMAX - 1) < 2**26
    assert m.absorb_blocks(m.BMAX - 1, 100) + 1 < 2**27


def scaling():
    data = json.loads((D / "query-mapping.json").read_text())
    assert data == m.record()
    expected = [[32, -48], [104, -28], [84, 30], [156, 50], [-58, -39], [14, -19]]
    for row, exponents in zip(data["scaling_only"], expected, strict=True):
        q, e, n = row["log2_q"], row["log2_ell"], row["min_rate_capacity"]
        # Fourth powers remove roots; independently check exact integer exponents.
        powers = [8 * e + 18 * q - 2 * n, 12 * e + 5 * q - n]
        assert powers == [4 * x for x in exponents]
        assert list(map(Fraction, row["log2_monomials"])) == exponents
    assert not data["scaling_is_probability_bound"]
    assert data["numerical_instantiation_advantage"] is None
    assert all(x is None for x in data["unknowns"].values())
    assert (3 * 480 + 1) + (2 * 480 + 1) == data["honest_outer_calls"]["one_each"]


if __name__ == "__main__":
    for name, fn in [
        ("sealed-profile-and-source-constants", profile),
        ("independent-framing-and-field-domains", framing),
        ("padding-boundaries-and-symbolic-large-lengths", padding),
        ("exact-monomial-scales-without-security-claims", scaling),
    ]:
        checked(name, fn)
    (D / "calculation-checks.json").write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps({"focused_checks": len(checks), "passed": True}))
