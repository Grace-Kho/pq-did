"""One admitted public case only; the coordinator owns every invocation and guard."""

import hashlib
import json
import subprocess
import time
from pathlib import Path

P = Path(__file__).resolve().parents[2]
R = Path(__file__).resolve().parent
OLD = P / "docs/data/s3_aurora_native_transcript_pilot_1"
INPUTS = (
    P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/guarded-build-v2/overlay"
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gf_mod(value, modulus):
    while value.bit_length() >= modulus.bit_length():
        value ^= modulus << (value.bit_length() - modulus.bit_length())
    return value


def gf_mul(a, b, modulus):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return gf_mod(result, modulus)


def gf_gcd(a, b):
    while b:
        a, b = b, gf_mod(a, b)
    return a


def field_certificate(stdout):
    """Independent GF(2) polynomial arithmetic: Rabin criterion, degree192."""
    modulus = (1 << 192) | 0x87
    power = 2
    checks = {}
    for exponent in range(1, 193):
        power = gf_mul(power, power, modulus)
        if exponent in (64, 96):
            checks[str(exponent)] = gf_gcd(power ^ 2, modulus)
    if power != 2 or checks != {"64": 1, "96": 1}:
        raise AssertionError("pinned GF192 modulus did not meet irreducibility criterion")
    expected = [
        gf_mul(1 << 191, 2, modulus),
        gf_mul(1 << 64, 1 << 128, modulus),
        (0x8877665544332211 << 128) | (0xFFEEDDCCBBAA0099 << 64) | 0x0123456789ABCDEF,
    ]
    lines = [s.split()[2:] for s in stdout.splitlines() if s.startswith("VALUE field-products ")]
    if lines != [[f"{n:048x}" for n in expected]]:
        raise AssertionError("native field basis/word/product mismatch with exact GF(2) oracle")
    return {"modulus": hex(modulus), "frobenius192_equals_x": True, "gcd_checks": checks}


def compare_exp2(stdout, expected):
    """Retained independent Python-vector comparison, unchanged conditions."""
    lines = [
        line.split()
        for line in stdout.splitlines()
        if line[:2] in {"T ", "R ", "V ", "I ", "F ", "X ", "L ", "A "} or line == "N"
    ]
    if "states_and_blocks" in expected:
        traces = [
            {"label": row[1], "value_hex": row[2], "input_bytes": int(row[3])}
            for row in lines
            if row[0] == "T"
        ]
        records = [row[1] for row in lines if row[0] == "R"]
        outputs = [
            row[1] if row[0] == "V" else int(row[1]) for row in lines if row[0] in {"V", "I"}
        ]
        final = [row for row in lines if row[0] == "F"]
        assert traces == expected["states_and_blocks"], "exact trace states/blocks/lengths"
        assert records == expected["round_records_hex"], "round frames"
        assert outputs == expected["mapped_outputs"], "mapped outputs"
        assert len(final) == 1 and final[0][1:] == [
            expected["finish"][0],
            str(expected["finish"][1]),
            "FINISHED",
        ], "finish"
        assert ["A", "replay-equal"] in lines
        return {"exact_trace_frames_challenges": True, "replay_equal": True}
    if "prior_digest_retained" in expected:
        assert lines == [
            [
                "X",
                expected["prior_digest_retained"],
                str(expected["counter_retained"]),
                str(expected["trace_entries_retained"]),
            ]
        ], "rejection state"
        return {"rejected": True, "atomic_state_retained": True, "sticky_failure": True}
    if "usable_object_returned" in expected:
        assert lines == [["N"]], "initialisation rejection"
        return {"rejected": True, "usable_object_returned": False}
    assert lines == [
        ["L", expected["old_hex"], expected["repair_u_hex"], expected["repair_v_hex"]]
    ], "legacy omission control"
    return {"original_omission_control": True, "forgery_experiment": False}


def run_case(case_id, root=None):
    """Execute exactly one coordinator-admitted case; no retries or counter mutation."""
    del root  # Public stateless native cases have no synthetic persistent store.
    if case_id.startswith("N-"):
        n = int(case_id[2:])
        if case_id != f"N-{n:02d}" or not 1 <= n <= 24:
            raise ValueError("unlisted native case")
        command = [str(R / "build/aurora_masking_native"), str(n)]
        expected_path = R / "overlay/masking_native.cpp"
        expected_sha = sha(expected_path)
    elif case_id.startswith("TR-"):
        n = int(case_id[3:])
        if case_id != f"TR-{n:02d}" or not 1 <= n <= 16:
            raise ValueError("unlisted transcript case")
        row = json.loads((OLD / "case-plan.json").read_text())["cases"][n - 1]
        assert row["id"] == case_id
        expected_path = P / row["retained_expectation"]
        expected_sha = row["retained_sha256"]
        if sha(expected_path) != expected_sha:
            raise ValueError("historical expectation integrity failure")
        command = [
            str(R / "build/exp2_native"),
            str(n),
            str(INPUTS / ("nonce-mutated.bin" if n == 3 else "canonical.bin")),
        ]
    else:
        raise ValueError("unlisted native case")
    started = time.monotonic()
    run = subprocess.run(command, capture_output=True, timeout=20, check=False)
    elapsed = time.monotonic() - started
    if len(run.stdout) + len(run.stderr) > 61440:
        raise RuntimeError("native diagnostic limit")
    stdout, stderr = run.stdout.decode("ascii"), run.stderr.decode("ascii")
    record = {
        "id": case_id,
        "command": command,
        "exit_code": run.returncode,
        "seconds": elapsed,
        "stdout": stdout,
        "stderr": stderr,
        "binary_sha256": sha(Path(command[0])),
        "expected_path": str(expected_path.relative_to(P)),
        "expected_sha256": expected_sha,
        "private_witness": False,
        "proof_attempt": False,
    }
    if run.returncode != 0 or stderr:
        raise RuntimeError(json.dumps(record, sort_keys=True))
    if case_id.startswith("TR-"):
        record["comparison"] = compare_exp2(stdout, json.loads(expected_path.read_text()))
        record["actual_calls"] = [
            "bcs_protocol::EXP2 public common caller",
            "blake2b_hashchain::EXP2",
        ]
        if n == 16:
            record["actual_calls"] = ["blake2b_hashchain::legacy absorb negative control"]
    else:
        if f"PASS {case_id}\n" not in stdout:
            raise AssertionError("native case did not finish")
        record["comparison"] = (
            field_certificate(stdout)
            if n == 1
            else {
                "independent_schoolbook_polynomial_assertions": True,
                "oracle": "overlay/masking_native.cpp: add/mul/divrem/at/interpolate",
                "finite_public_fixture_only": True,
            }
        )
        calls = [
            name
            for line in stdout.splitlines()
            if line.startswith("PATH ")
            for name in line[5:].split(";")
        ]
        if 10 <= n <= 15 and n != 10:
            calls = [
                name
                for name in calls
                if not name.startswith("LDT_instance_reducer::")
                and name != "submit_masking_polynomial[N-10]"
            ]
        if n in (16, 17):
            calls = [name for name in calls if "[N-18]" not in name]
        record["actual_calls"] = [
            name.replace("[N-10]", "").replace("[N-18]", "") for name in calls
        ]
        if not record["actual_calls"]:
            record["actual_calls"] = [
                {
                    9: "iop_protocol::submit_prover_message length rejection",
                    14: "combined_LDT_virtual_oracle::set_random_coefficients rejection",
                    15: "combined_LDT_virtual_oracle::evaluation_at_point rejection",
                    19: "FRI_protocol_parameters degree-divisibility rejection",
                    22: (
                        "batch_sumcheck_protocol::calculate_and_submit_proof and "
                        "iop_protocol::signal_prover_round_done ordering rejection"
                    ),
                    23: "batch_sumcheck_protocol constructor unsupported mode rejection",
                    24: "batch_sumcheck_protocol::attach_oracle_for_summing rejection",
                }[n]
            ]
    record["status"] = "pass"
    return record


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("one case identifier required; run under milestone coordinator")
    print(json.dumps(run_case(sys.argv[1]), sort_keys=True))
