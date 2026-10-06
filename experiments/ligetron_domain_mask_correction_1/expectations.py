"""Independent exact-integer polynomial oracle; never calls the candidate binary."""

import hashlib
import json
import subprocess
from pathlib import Path

P = Path(__file__).resolve().parents[2]
D = P / "docs/data/ligetron_domain_mask_correction_1"
Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ROOT = 1748695177688661943023146337482803886740723238769601073607632802312037301404
ROOT2 = 2037444462055058054189478067370099086220733342011840546702672064072905551290
WK, W2, WN = pow(ROOT, 2**28 // 8, Q), pow(ROOT, 2**28 // 16, Q), pow(ROOT2, 2**28 // 32, Q)


def eval_poly(c, x):
    ans = 0
    for a in reversed(c):
        ans = (ans * x + a) % Q
    return ans


def interpolation(row, root):
    # Direct inverse Vandermonde formula on roots of unity, no radix-2 schedule.
    n = len(row)
    return [
        sum(a * pow(root, (-i * j) % n, Q) for i, a in enumerate(row)) * pow(n, -1, Q) % Q
        for j in range(n)
    ]


def encode(row, root=WK):
    c = interpolation(row, root)
    return [eval_poly(c, 7 * pow(WN, i, Q) % Q) for i in range(32)]


def mask_values(draw):
    code = [next(draw) for _ in range(8)]
    coeff = [next(draw) for _ in range(15)] + [0]
    linear = [eval_poly(coeff, pow(W2, i, Q)) for i in range(16)]
    mean = sum(linear[0:8:2]) * pow(4, -1, Q) % Q
    linear = [(v - mean) % Q for v in linear]
    quad = [0 if i < 8 and i % 2 == 0 else next(draw) for i in range(15)] + [0]
    # Independent inverse-Vandermonde last coefficient equation.
    quad[-1] = -sum(quad[i] * pow(W2, i, Q) for i in range(15)) * pow(pow(W2, 15, Q), -1, Q) % Q
    return code, linear, quad


def fields():
    raw = subprocess.run(
        [
            "/usr/bin/openssl",
            "enc",
            "-aes-256-ctr",
            "-K",
            bytes(range(32)).hex(),
            "-iv",
            bytes(16).hex(),
        ],
        input=bytes(8192),
        capture_output=True,
        check=True,
        timeout=2,
    ).stdout
    return [
        x
        for i in range(0, len(raw), 32)
        if (x := int.from_bytes(raw[i : i + 32], "little") >> 2) < Q
    ]


def main():
    cases = {}

    def add(id, args, expected, rows=(), layer="CPU transform model using native field"):
        cases[id] = {
            "args": args.split(),
            "stdin": "".join(str(len(r)) + " " + " ".join(map(str, r)) + "\n" for r in rows),
            "expected": list(map(str, expected)),
            "layer": layer,
        }

    row = [0, 1, Q - 1, 3, 4, 5, 6, 7]
    impulse = [0, 0, 0, 1, 0, 0, 0, 0]
    coeff = list(range(15))
    code = [eval_poly(coeff, 7 * pow(WN, i, Q) % Q) for i in range(32)]
    add("D-01", "roots", [1, 1, 0], layer="actual pinned root generator")
    add("D-02", "encode", encode(row), [row])
    add("D-03", "encode", encode(impulse), [impulse])
    add("D-04", "decode 8", row, [encode(row)])
    add("D-05", "decode 15", [eval_poly(coeff, pow(WK, i, Q)) for i in range(8)], [code])
    add("D-06", "old-domain", [row[3]], [row], "negative control; old-domain CPU model")
    masks = mask_values(iter(range(1, 1000)))
    native_fields = fields()
    native_masks = mask_values(iter(native_fields))
    add(
        "M-01",
        "masks",
        sum(map(list, masks), []),
        layer="native mask helper; independent direct polynomial oracle",
    )
    add(
        "M-02",
        "manager",
        sum(map(list, native_masks), []),
        layer="actual native witness_manager and RNG",
    )
    add("M-03", "mask-check linear", [1], [masks[1]])
    add("M-04", "mask-check quad", [1], [masks[2]])
    u = [1, 0, 0, 0, 5, 9, 2, 3]
    a = [2, 6, 3, 4, 0, 0, 0, 0]
    target = encode([7, 0, 0, 0, 0, 0, 0, 0])[1]
    add("M-05", "statistic", [target], [u, a], "negative control; zero-tail disclosure equation")
    a2 = [2, 6, 3, 4, 8, 2, 6, 1]
    add(
        "M-06",
        "statistic",
        [(target - encode([0, 0, 0, 0] + a2[4:])[1]) % Q],
        [u, a2],
        "full-tail statistic; not a distribution proof",
    )
    padded = [1, 2, 3, 4] + native_fields[:4]
    add("P-01", "row", padded, layer="actual native witness_manager row release")
    add("P-02", "encode", encode([1, 2, 3, 4, 0, 0, 0, 0]), [[1, 2, 3, 4, 0, 0, 0, 0]])
    add("P-03", "encode", encode(padded), [padded], "batch-init CPU representation model")
    bitrow = [0, 1, 1, 0, 5, 6, 7, 8]
    add(
        "P-04",
        "product",
        [(x * x - x) % Q for x in bitrow],
        [bitrow, bitrow, bitrow],
        "batch-bit CPU model",
    )
    add("P-05", "difference", [0] * 8, [row, row], "batch-equality CPU model")
    x, y = list(range(8)), list(range(8, 16))
    z = [a * b % Q for a, b in zip(x, y, strict=True)]
    add("P-06", "product", [0] * 8, [x, y, z], "ordinary/batch quadratic CPU model")
    add("P-07", "encode2", encode(masks[2], W2), [masks[2]], "degree-2k mask CPU model")
    add("P-08", "profile 7936", [1], layer="native fixed-profile admission")
    add("N-01", "encode", ["rejected"], [[-1] + [0] * 7])
    add("N-02", "encode", ["rejected"], [[Q] + [0] * 7])
    add("N-03", "delta", ["rejected"], [row])
    add("N-04", "dimensions", ["rejected"])
    add("N-05", "decode 15", ["rejected"], [[pow(7 * pow(WN, i, Q) % Q, 15, Q) for i in range(32)]])
    add("N-06", "profile 8000", ["rejected"])
    add("N-07", "mask-check linear", ["rejected"], [[1] * 16])
    add("N-08", "mask-check quad", ["rejected"], [[1] * 16])
    add("R-01", "replay", [1], layer="actual native manager deterministic stage replay")
    add(
        "R-02",
        "public",
        [0] * 40,
        layer="actual native public-policy mask placeholders; not acceptance",
    )
    add(
        "R-03",
        "prefix",
        sum(map(list, mask_values(iter(native_fields[4:]))), []),
        layer="actual native row-padding then mask RNG consumption",
    )
    add(
        "R-04",
        "exhaust",
        [256, 0],
        layer="actual bounded sampler exhaustion propagated before release",
    )
    assert len(cases) == 32
    data = json.dumps(cases, indent=2) + "\n"
    (D / "expectations.json").write_text(data)
    (D / "expectation-seal.json").write_text(
        json.dumps(
            {
                "sha256": hashlib.sha256(data.encode()).hexdigest(),
                "provenance": (
                    "Direct host-integer polynomial/Vandermonde oracle; "
                    "OpenSSL CLI shares AES primitive only; frozen before candidate execution"
                ),
            },
            indent=2,
        )
        + "\n"
    )
    (D / "execution-plan.json").write_text(
        json.dumps(
            {
                "cases": list(cases),
                "fixed_count": 32,
                "corrective_reruns": 4,
                "negative_controls": ["D-06", "M-05"],
                "GPU_VM_prover_verifier": "UNRUN",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
