"""Thirteen serial batches, 97 generations and ten counted cases; no retries.

Six transform cases each contain 97 evaluator/observer pairs. Exact counts are
charged at generation; an interrupted unreported prefix retains its reservation.
"""

# ruff: noqa: E402

import hashlib
import json
import resource
import struct
import sys
import time
from pathlib import Path

resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
P = Path(__file__).resolve().parents[2]
D = P / "docs/data/s3_mldsa_full_forward_ntt_pilot_1"
sys.path.insert(0, str(P))
from experiments.mldsa_full_forward_ntt_1.candidate import (
    INPUTS,
    MAX,
    MIN,
    Q,
    admit_polynomial,
    build,
)
from experiments.mldsa_full_forward_ntt_1.oracle import reverse8, transform
from pqdid.bounded_mldsa import _ntt
from pqdid.circuits.emitter import Emitter, Limits, evaluate
from tests.reference.signature_oracle import observed

START = time.monotonic()
S = None
CURRENT = None
ALIAS = struct.Struct(">16386Q")
CG = Path("/sys/fs/cgroup") / next(
    line[3:].lstrip("/")
    for line in Path("/proc/self/cgroup").read_text().splitlines()
    if line.startswith("0::")
)


def read(path):
    if path.stat().st_size > 1048576:
        raise ValueError("bounded record exceeded")
    return json.loads(path.read_text())


def write(path, value):
    text = json.dumps(value, indent=2) + "\n"
    if len(text.encode()) > 1048576:
        raise ValueError("bounded output exceeded")
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(text)
    temporary.replace(path)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def save():
    write(D / "pilot-state.json", S)


def poll():
    if time.monotonic() - START >= 9:
        raise TimeoutError("nine-second batch inner stop; retain evidence, no retry")
    if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024 >= 134217728:
        raise MemoryError("128MiB arithmetic-process RSS stop")


def memory():
    return {
        "python_high_water_RSS_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "cgroup_memory_peak_bytes": int((CG / "memory.peak").read_text()),
    }


def begin(name, kind):
    global CURRENT
    if len(S["invocations"]) >= 107 or any(r["id"] == name for r in S["invocations"]):
        raise ValueError("invocation cap or duplicate admission")
    row = {"id": name, "kind": kind, "status": "pending"}
    S["invocations"].append(row)
    CURRENT = name
    save()
    return row


def entry(name):
    return next(row for row in S["invocations"] if row["id"] == name)


def refuse(name, operation, expected_fragment):
    row = begin(name, "malformed-entry" if name.startswith("M") else "checkpoint-refusal")
    try:
        operation()
    except ValueError as error:
        if expected_fragment not in str(error):
            raise AssertionError("wrong refusal reason") from error
        row.update(status="pass", refusal=str(error), external_output=None)
        save()
    else:
        raise AssertionError("invalid input accepted")


def initialise(seal):
    global S
    S = {
        "package": "S3-MLDSA-FULL-FORWARD-NTT-PILOT-1",
        "passed": False,
        "invocations": [],
        "completed_partitions": 0,
        "aggregate_emitted_gates": 0,
        "inflight_gate_reservation": 0,
        "counts": {"xor": 0, "and_": 0, "not_": 0},
        "generation_seconds": 0.0,
        "evaluation_seconds": 0.0,
        "observer_seconds": 0.0,
        "reference_seconds": 0.0,
        "evaluator_calls": 0,
        "observer_passes": 0,
        "case_states": [],
        "source_seal_sha256": seal,
        "batch_workers": [],
        "checkpoint_sha256": None,
        "peak_retained_trace_bytes": 0,
    }
    save()
    refuse("M0", lambda: admit_polynomial((0,) * 255), "256")
    refuse("M1", lambda: admit_polynomial(((1 << 63),) + (0,) * 255), "integer")
    mixed = tuple(((-1) ** (i % 2)) * (((i + 1) ** 3 + 17 * i + 11) % Q) for i in range(256))
    cases = [
        ((0,) * 256, 1, 0),
        ((0, 1) + (0,) * 254, 1, 0),
        ((MIN, MAX, -Q, Q, -1, 0, 1, Q - 1) * 32, 1, 0),
        (mixed, 1, 0),
        (mixed, 0, 0),
        (mixed, 1, 1),
    ]
    for i, (values, active, rejected) in enumerate(cases):
        poll()
        row = begin(f"V{i}", "full-transform-case")
        admit_polynomial(values)
        start = time.perf_counter()
        reference = _ntt(list(values))
        independent = transform(values)
        seconds = time.perf_counter() - start
        assert reference == independent
        S["reference_seconds"] += seconds
        row.update(
            partitions_compared=0,
            active=active,
            initial_R=rejected,
            reference_oracle_agreement=True,
            reference_seconds=seconds,
        )
        expected = reference if active and not rejected else [0] * 256
        write(
            D / f"case-V{i}.json",
            {
                "id": f"V{i}",
                "inputs": values,
                "active": active,
                "prior_R": rejected,
                "reference_uninterrupted": reference,
                "independent_Horner": independent,
                "expected_final": expected,
                "expected_valid": 1 - rejected,
                "status": "pending",
                "reference_seconds": seconds,
            },
        )
        S["case_states"].append(
            {"id": f"V{i}", "active": active, "R": rejected, "words": list(values)}
        )
        save()
    return list(range(2, 2 + INPUTS))


def validate_checkpoint(checkpoint, expected_digest, alias_digest):
    if checkpoint["ordinal"] != S["completed_partitions"] - 1:
        raise ValueError("checkpoint ordering")
    if checkpoint["source"] != S["source_seal_sha256"] or checkpoint["alias"] != alias_digest:
        raise ValueError("checkpoint source/alias mismatch")
    prefix = min(256, 8 * (checkpoint["ordinal"] + 1))
    if len(checkpoint["cases"]) != 6:
        raise ValueError("checkpoint case count")
    for i, row in enumerate(checkpoint["cases"]):
        declared = entry(f"V{i}")
        if row["id"] != declared["id"] or row["active"] != declared["active"]:
            raise ValueError("checkpoint identity/control mismatch")
        if row["R"] != declared["initial_R"]:
            raise ValueError("checkpoint rejection changed")
        if len(row["words"]) != 256 or any(
            type(v) is not int or not MIN <= v <= MAX for v in row["words"]
        ):
            raise ValueError("checkpoint signed64 shape")
        if any(not 0 <= v < Q for v in row["words"][:prefix]):
            raise ValueError("checkpoint noncanonical frontier")
    if digest(checkpoint) != expected_digest:
        raise ValueError("checkpoint parent/state digest mismatch")


def checkpoint(ordinal, aliases):
    raw = ALIAS.pack(*aliases)
    alias_digest = hashlib.sha256(raw).hexdigest()
    value = {
        "ordinal": ordinal,
        "source": S["source_seal_sha256"],
        "alias": alias_digest,
        "parent": S["checkpoint_sha256"],
        "cases": S["case_states"],
    }
    expected = digest(value)
    validate_checkpoint(value, expected, alias_digest)
    path = D / "tmp/frontier.bin"
    temporary = path.with_suffix(".new")
    temporary.write_bytes(raw)
    temporary.replace(path)
    write(D / "tmp/state.json", value)
    S["checkpoint_sha256"] = expected
    save()
    return value


def check_transport(value):
    bad = json.loads(json.dumps(value))
    bad["cases"][0]["words"][0] = Q
    refuse(
        "T0",
        lambda: validate_checkpoint(bad, S["checkpoint_sha256"], value["alias"]),
        "noncanonical",
    )
    bad = json.loads(json.dumps(value))
    bad["cases"][5]["R"] = 0
    refuse(
        "T1", lambda: validate_checkpoint(bad, S["checkpoint_sha256"], value["alias"]), "rejection"
    )


def compose(e, boundary, aliases, offset):
    """Virtual wire alpha-renaming; never reads fixture values."""
    assert len(aliases) == INPUTS and all(2 <= i < 2 + INPUTS + offset for i in aliases)
    assert all(bit.public is None for bit in e.inputs)

    def resolve(bit):
        e.check_bit(bit)
        assert bit.public is None, "a cut must not change public-only folding"
        return aliases[bit.index - 2] if bit.index < 2 + INPUTS else offset + bit.index

    runs = []
    for lane, word in enumerate(boundary.words):
        before = tuple(reversed(e.inputs[64 * lane : 64 * lane + 64]))
        if word == before:
            continue
        start = word[0].index
        assert tuple(bit.index for bit in word) == tuple(range(start, start + 64))
        assert start >= 2 + INPUTS
        runs.append((lane, start))
    output_alias = [resolve(bit) for word in boundary.words for bit in reversed(word)]
    output_alias += [resolve(boundary.active), resolve(boundary.rejected)]
    assert output_alias[-2] == INPUTS
    return output_alias, runs


def part(ordinal, aliases):
    global CURRENT
    poll()
    row = begin(f"G{ordinal:02}", "generation-probe")
    cap = min(450000, 30000000 - S["aggregate_emitted_gates"])
    if cap <= 0:
        raise RuntimeError("aggregate gate budget exhausted")
    S["inflight_gate_reservation"] = cap
    save()
    offset = S["aggregate_emitted_gates"]
    e = Emitter(
        INPUTS,
        limits=Limits(max_gates=cap, max_output_bytes=8388608, max_seconds=9),
        public_data=f"experimental-full-forward-v1;partition={ordinal}".encode(),
    )
    try:
        started = time.perf_counter()
        boundary = build(e, ordinal)
        circuit = e.finish(boundary.output)
        seconds = time.perf_counter() - started
    except BaseException:
        # A signal may arrive between serialisation and the opcode counter update.
        # Keep a conservative reservation when a complete prefix is not available.
        S["aggregate_emitted_gates"] += cap
        S["inflight_gate_reservation"] = 0
        row.update(
            partial_progress=e.progress(),
            complete=False,
            charged_gate_upper_bound=cap,
            exact_emitted_count_known=False,
        )
        save()
        raise
    S["aggregate_emitted_gates"] += circuit.counts.gates
    S["inflight_gate_reservation"] = 0
    S["generation_seconds"] += seconds
    S["peak_retained_trace_bytes"] = max(
        S["peak_retained_trace_bytes"], circuit.retained_trace_bytes
    )
    counts = {k: getattr(circuit.counts, k) for k in ("xor", "and_", "not_")}
    for key, value in counts.items():
        S["counts"][key] += value
    row.update(
        status="pass",
        complete=True,
        gates=circuit.counts.gates,
        generation_seconds=seconds,
        fingerprint=circuit.fingerprint,
    )
    save()
    assert circuit.retained_trace_bytes <= 8388608
    output_alias, runs = compose(e, boundary, aliases, offset)
    for node in boundary.work:
        if len(node) == 7:
            s, g, u, left, right, m, zeta = node
            assert m == (1 << s) + g and left == 2 * (128 >> s) * g + u
            assert right - left == (128 >> s) and zeta == pow(1753, reverse8(m), Q)
    record = {
        "ordinal": ordinal,
        "complete": False,
        "counts": counts,
        "gates": circuit.counts.gates,
        "generation_seconds": seconds,
        "fingerprint": circuit.fingerprint,
        "private_inputs": INPUTS,
        "gate_offset": offset,
        "work": boundary.work,
        "entry_costs": boundary.entry_counts,
        "changed_output_runs": runs,
        "raw_R_local_wire": boundary.rejected.index,
        "trace_output_local_wire": boundary.output.index,
        "input_alias_sha256": hashlib.sha256(ALIAS.pack(*aliases)).hexdigest(),
        "output_alias_sha256": hashlib.sha256(ALIAS.pack(*output_alias)).hexdigest(),
        "retained_trace_bytes": circuit.retained_trace_bytes,
        "observations": [],
        "memory_after_generation": memory(),
    }
    path = D / f"partition-{ordinal:02}.json"
    write(path, record)
    for case in S["case_states"]:
        poll()
        CURRENT = case["id"]
        previous_words = case["words"]
        witness = b"".join(v.to_bytes(8, "big", signed=True) for v in previous_words)
        witness += bytes([(case["active"] << 7) | (case["R"] << 6)])
        value = evaluate(circuit, witness, max_seconds=2, max_wires=2000260)
        S["evaluator_calls"] += 1
        S["evaluation_seconds"] += value.seconds
        started = time.perf_counter()
        words, _, flags = observed(
            circuit,
            witness,
            words=boundary.words,
            flags=(boundary.rejected, boundary.output, boundary.active),
        )
        observer_seconds = time.perf_counter() - started
        S["observer_passes"] += 1
        S["observer_seconds"] += observer_seconds
        assert flags[0] == case["R"] and flags[2] == case["active"]
        assert value.output == flags[1]
        prefix = min(256, (ordinal + 1) * 8)
        assert all(0 <= word < Q for word in words[:prefix])
        if not case["active"] or case["R"]:
            assert not any(words[:prefix])
        if ordinal < 32:
            assert list(words[prefix:]) == previous_words[prefix:]
        if ordinal == 96:
            evidence = read(D / ("case-" + case["id"] + ".json"))
            assert list(words) == evidence["expected_final"]
            assert flags[1] == evidence["expected_valid"]
            evidence.update(
                actual_final=words,
                actual_valid=flags[1],
                status="pass",
                complete_partitions=97,
                final_bytes_hex=b"".join(v.to_bytes(8, "big", signed=True) for v in words).hex(),
            )
            write(D / ("case-" + case["id"] + ".json"), evidence)
            entry(case["id"])["status"] = "pass"
        else:
            assert flags[1] == case["R"]
        case["words"], case["R"] = list(words), flags[0]
        entry(case["id"])["partitions_compared"] += 1
        record["observations"].append(
            {
                "id": case["id"],
                "invariants": True,
                "R": flags[0],
                "output_bit": flags[1],
                "frontier_sha256": digest(words),
                "evaluation_seconds": value.seconds,
                "observer_seconds": observer_seconds,
            }
        )
    record.update(complete=True, memory_after_evaluations=memory())
    write(path, record)
    S["completed_partitions"] += 1
    current = checkpoint(ordinal, output_alias)
    if ordinal == 31:
        check_transport(current)
    # Frame exit releases emitter, byte buffer, trace, observer and all local wires.
    poll()
    return output_alias


def main(batch):
    global S
    if not 0 <= batch < 13:
        raise ValueError("fixed batch ID")
    seal_path = D / "execution-seal.json"
    seal = read(seal_path)
    for name, expected in seal["sha256"].items():
        assert hashlib.sha256((P / name).read_bytes()).hexdigest() == expected, name
    source = hashlib.sha256(seal_path.read_bytes()).hexdigest()
    if batch == 0:
        if (D / "pilot-state.json").exists():
            raise ValueError("no duplicate initialisation")
        aliases = initialise(source)
    else:
        S = read(D / "pilot-state.json")
        if S.get("failure") or S["completed_partitions"] != batch * 8:
            raise ValueError("incomplete/duplicate/out-of-order batch")
        assert source == S["source_seal_sha256"] and S["inflight_gate_reservation"] == 0
        raw = (D / "tmp/frontier.bin").read_bytes()
        assert len(raw) == ALIAS.size
        aliases = list(ALIAS.unpack(raw))
        prior = read(D / "tmp/state.json")
        validate_checkpoint(prior, S["checkpoint_sha256"], hashlib.sha256(raw).hexdigest())
        assert S["case_states"] == prior["cases"]
    for ordinal in range(batch * 8, min(97, batch * 8 + 8)):
        aliases = part(ordinal, aliases)
    if batch == 12:
        assert len(S["invocations"]) == 107 and S["completed_partitions"] == 97
        assert all(row["status"] == "pass" for row in S["invocations"])
        assert S["evaluator_calls"] == S["observer_passes"] == 582
        assert sum(S["counts"].values()) == S["aggregate_emitted_gates"] <= 30000000
        S["passed"] = True
    S["batch_workers"].append({"batch": batch, "seconds": time.monotonic() - START, **memory()})
    save()
    print(
        json.dumps(
            {
                "batch": batch,
                "completed_partitions": S["completed_partitions"],
                "gates": S["aggregate_emitted_gates"],
                "invocations": len(S["invocations"]),
                "worker_seconds": time.monotonic() - START,
            }
        )
    )


if __name__ == "__main__":
    try:
        main(int(sys.argv[1]))
    except BaseException as error:
        if S is not None:
            failure = {
                "type": type(error).__name__,
                "detail": str(error)[:2500],
                "current_invocation": CURRENT,
                "worker_seconds": time.monotonic() - START,
                **memory(),
            }
            S["failure"] = failure
            if CURRENT is not None:
                entry(CURRENT)["status"] = "failed"
            save()
            write(D / "pilot-failure.json", failure)
        raise
