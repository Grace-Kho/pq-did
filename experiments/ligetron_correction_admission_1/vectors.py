"""Independent byte-contract expectations, frozen before any candidate execution.

AES uses the installed OpenSSL CLI (shared primitive, separate framing/consumption).
Hashing uses Python hashlib. No candidate header, executable or generator is called.
"""

import hashlib
import struct
import subprocess
import sys
from pathlib import Path

P = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(P))
from experiments.ligetron_correction_admission_1 import run as guard  # noqa: E402

D = guard.D
A, B = bytes(range(32)), bytes(range(32, 64))
Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
DOMAIN = b"PQDID-Ligetron-RNG-EXP1/query"


def query(key, n, start=0):
    return b"".join(
        hashlib.sha256(DOMAIN + key + struct.pack(">Q", i)).digest()
        for i in range(start, start + (n + 31) // 32)
    )[:n]


def aes(key, role, n):
    return subprocess.check_output(
        [
            "/usr/bin/openssl",
            "enc",
            "-aes-256-ctr",
            "-nosalt",
            "-K",
            key.hex(),
            "-iv",
            (bytes([role]) + bytes(15)).hex(),
        ],
        input=bytes(n),
        timeout=2,
    )


def raw(data):
    return ",".join(
        format(int.from_bytes(data[i : i + 32], "little"), "x") for i in range(0, len(data), 32)
    )


def sample_fields(data):
    out = []
    for i in range(0, len(data), 32):
        candidate = int.from_bytes(data[i : i + 32], "little") >> 2
        if candidate < Q:
            out.append(format(candidate, "x"))
        if len(out) == 4:
            return ",".join(out)
    raise ValueError("reference fixture too short")


def query_indices():
    # Algebraic description of this pinned Boost adapter's byte-to-integer law
    # on ranges 32576..32767, independently implemented without Boost or C++.
    stream = iter(query(A, 8192))
    population = list(range(32768))
    chosen = []
    for low in range(192):
        limit = 32767 - low
        while True:
            lo = next(stream)
            top = limit // 256
            bucket = 256 // (top + 1)
            while True:
                hi = next(stream) // bucket
                if hi <= top:
                    break
            value = lo + 256 * hi
            if value <= limit:
                break
        target = low + value
        population[low], population[target] = population[target], population[low]
        chosen.append(population[low])
    return ",".join(map(str, sorted(chosen)))


def main():
    result = {}
    result["ENT-01"] = A.hex() + "|" + raw(aes(A, 0, 32))
    result["ENT-02"] = "entropy-error|stage-entered=0|release=0"
    for label, key in (("A", A), ("B", B)):
        result["ENT-03-" + label] = "|".join([raw(aes(key, 0, 64))] * 3)
    for label, key in (("A", A), ("B", B)):
        result["Q-01-" + label] = query(key, 32).hex()
    result["Q-02"] = query(A, 65).hex()
    for label, key in (("partial", B), ("full", B), ("zero", bytes(32))):
        result["Q-03-" + label] = query(key, 40).hex()
    for count in (0, 1, 31, 32, 33, 64, 65):
        result[f"Q-04-{count}"] = query(A, count + 40)[count:].hex()
    result["Q-05"] = query(A, 32, (1 << 64) - 1).hex() + "|overflow"
    old = hashlib.sha256(bytes(8)).digest()[::-1].hex()
    result["Q-06"] = "|".join((old, old, query(A, 32).hex(), query(B, 32).hex()))
    result.update(
        {
            "F-01-zero": "0|1",
            "F-01-max": format(Q - 1, "x") + "|1",
            "F-02": "7|3",
            "F-03": "b|256",
            "F-04": "exhausted|256|19",
            "F-05": "engine-error|2|19",
        }
    )
    streams = [aes(A, role, 512) for role in (1, 2, 3)]
    for role in range(3):
        result[f"D-01-{role}"] = sample_fields(streams[role])
    for role in range(3):
        result[f"D-02-{role}"] = "|".join([sample_fields(streams[role])] * 2)
    result["D-03"] = raw(streams[0][:64])
    result["D-04"] = raw(aes(A, 1, 16416)[16352:16416])
    result["I-01"] = query_indices()
    stage1 = hashlib.sha256(b"PQDID-Ligetron-RNG-EXP1/Stage1\0" + A + B).hexdigest()
    stage2 = hashlib.sha256(
        b"PQDID-Ligetron-RNG-EXP1/Stage2\0" + A + struct.pack("<6I", 0, 1, 0xFFFFFFFF, 7, 8, 9)
    ).hexdigest()
    result["I-02"] = stage1 + "|" + stage2
    assert len(result) == 35
    assert not (D / "expectations.json").exists()
    guard.write(D / "expectations.json", result)
    guard.write(
        D / "expectation-seal.json",
        {
            "sha256": hashlib.sha256((D / "expectations.json").read_bytes()).hexdigest(),
            "reference_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "cases": list(result),
            "count": 35,
            "candidate_executed": False,
            "AES_primitive_shared_with_candidate": True,
            "independence": (
                "Independent byte specification, integer import, rejection and "
                "pinned Boost sampling law; not an independent AES implementation"
            ),
        },
    )
    guard.write(
        D / "execution-plan.json",
        {
            "cases": list(result),
            "fixed_cases": 35,
            "targeted_reruns": 4,
            "historical_reserved_slots_untouched": 7,
            "case_deadline_seconds": 2,
            "build_attempts": 2,
            "proofs": 0,
            "full_WebGPU_callers": "UNRUN",
            "completion_reserve_seconds": 60,
        },
    )


if __name__ == "__main__":
    main()
