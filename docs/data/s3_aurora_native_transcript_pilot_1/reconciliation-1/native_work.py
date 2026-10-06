"""Build and compare the actual isolated native patch, without running Python EXP2."""

import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import types
from pathlib import Path

R = Path(__file__).resolve().parent
N = R.parent
P = N.parents[2]
A = P / "experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1"
W = A / "work"


def load(path):
    m = types.ModuleType(path.stem)
    m.__file__ = str(path)
    exec(compile(path.read_text(), str(path), "exec"), m.__dict__)
    return m


def read(path):
    return json.loads(path.read_text())


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            h.update(chunk)
    return h.hexdigest()


def save(name, value):
    (R / name).write_text(json.dumps(value, indent=2) + "\n")


def prepare_sources():
    assert read(R / "provision-result.json")["native_admitted"]
    assert not W.exists() and not (A / "overlay").exists()
    src = load(R / "native_sources.py")
    for name in ("libiop", "libff", "libfqfft"):
        shutil.copytree(A / "src" / name, W / name, ignore=shutil.ignore_patterns(".git"))
    base = W / "libiop/libiop"
    changed = []

    def edit(name, replacements):
        path = base / name
        old = path.read_text()
        new = old
        for before, after in replacements:
            assert new.count(before) == 1, (name, before[:100])
            new = new.replace(before, after)
        path.write_text(new)
        changed.extend(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile="a/libiop/" + name,
                tofile="b/libiop/" + name,
            )
        )

    (base / "bcs/hashing/exp2_public_pilot.hpp").write_text(src.FRAMING)
    edit(
        "bcs/hashing/blake2b.hpp",
        [
            ("#include <functional>", '#include "exp2_public_pilot.hpp"\n#include <functional>'),
            (
                "    protected:\n        binary_hash_digest",
                src.MEMBERS + "\n    protected:\n        binary_hash_digest",
            ),
        ],
    )
    guards = []
    tcc = (base / "bcs/hashing/blake2b.tcc").read_text()
    for marker in (
        "::new_hashchain()",
        "::absorb(const hash_data_type new_input)",
        "::absorb(const std::vector<FieldT> &new_input)",
        "::squeeze(\n",
        "::squeeze_query_positions(\n",
    ):
        start = tcc.index(marker)
        end = tcc.index("{", start) + 1
        guards.append((tcc[start:end], tcc[start:end] + "\n    this->exp2_forbid_legacy();"))
    edit("bcs/hashing/blake2b.tcc", guards)
    edit(
        "bcs/bcs_common.hpp",
        [
            (
                "protected:\n    size_t num_index_trees",
                src.BCS_MEMBERS + "\nprotected:\n    size_t num_index_trees",
            )
        ],
    )
    edit(
        "bcs/bcs_common.tcc",
        [
            (
                "    /* Assume the Merkle tree is already created. */",
                src.BCS_ROUND + "\n    /* Assume the Merkle tree is already created. */",
            )
        ],
    )
    (R / "native-exp2.patch").write_text("".join(changed))
    overlay = A / "overlay"
    overlay.mkdir()
    (overlay / "exp2_native.cpp").write_text(src.HARNESS)
    cmake = P / "docs/proposals/s3_aurora_native_dependency_lock_1/minimal-native.cmake.txt"
    shutil.copyfile(cmake, overlay / "CMakeLists.txt")
    # Adapt only the unchanged canonical public-input encoder, never execute EXP2/oracle cases.
    sys.path.insert(0, str(P / "src"))
    fixture = load(P / "experiments/aurora_transcript_regression_1/cases.py")
    pp, x, encoded = fixture.load_public()
    from dataclasses import replace

    from pqdid.statements import encode_auth_statement

    nonce = bytes([x.context.nonce[0] ^ 1]) + x.context.nonce[1:]
    mutated = encode_auth_statement(pp, replace(x, context=replace(x.context, nonce=nonce)))
    (overlay / "canonical.bin").write_bytes(encoded)
    (overlay / "nonce-mutated.bin").write_bytes(mutated)
    plan = read(N / "case-plan.json")
    for row in plan["cases"]:
        assert sha(P / row["retained_expectation"]) == row["retained_sha256"]
    pins = {}
    for path in (base / "bcs").rglob("*"):
        if path.is_file():
            pins[str(path.relative_to(P))] = sha(path)
    for path in overlay.iterdir():
        pins[str(path.relative_to(P))] = sha(path)
    save("native-inputs.json", {"sha256": pins, "expected": plan["cases"]})


def build(name):
    assert name in {"build-1", "build-2"}
    start = time.monotonic()
    save(name + "-attempt.json", {"attempt": int(name[-1]), "status": "admitted"})
    if name == "build-1":
        prepare_sources()
    env = dict(os.environ, CCACHE_DISABLE="1")
    for key in ("CMAKE_PREFIX_PATH", "PKG_CONFIG_PATH", "LD_LIBRARY_PATH"):
        env.pop(key, None)
    args = [
        "cmake",
        "-S",
        str(A / "overlay"),
        "-B",
        str(A / "build"),
        "-G",
        "Ninja",
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0",
        "-DCMAKE_C_FLAGS_RELEASE=-O0 -g0",
        "-DPQ_SOURCE=" + str(W),
        "-DPQ_PREFIX=" + str(A / "prefix"),
        "-DPQ_HARNESS=" + str(A / "overlay/exp2_native.cpp"),
    ]
    commands = [
        args,
        ["cmake", "--build", str(A / "build"), "--target", "exp2_native", "--parallel", "1"],
    ]
    save(
        name + "-commands.json",
        {
            "commands": commands,
            "environment_removed": ["CMAKE_PREFIX_PATH", "PKG_CONFIG_PATH", "LD_LIBRARY_PATH"],
            "CCACHE_DISABLE": "1",
        },
    )
    try:
        for command in commands:
            subprocess.run(
                command, check=True, env=env, timeout=max(0.1, 53 - (time.monotonic() - start))
            )
    except Exception as error:
        save(
            name + "-attempt.json",
            {
                "attempt": int(name[-1]),
                "status": "failed",
                "seconds": time.monotonic() - start,
                "error": str(error),
            },
        )
        raise
    save(
        name + "-attempt.json",
        {
            "attempt": int(name[-1]),
            "status": "pass",
            "seconds": time.monotonic() - start,
            "binary_sha256": sha(A / "build/exp2_native"),
        },
    )


def compare(stdout, expected):
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
        return {
            "exact_states_blocks_lengths_frames_mapped_outputs_counters": True,
            "native_public_record_replay_equal": True,
            "finish": expected["finish"],
        }
    if "prior_digest_retained" in expected:
        assert lines == [
            [
                "X",
                expected["prior_digest_retained"],
                str(expected["counter_retained"]),
                str(expected["trace_entries_retained"]),
            ]
        ], "rejection state"
        return {
            "rejected": True,
            "atomic_state_retained": True,
            "sticky_failure": True,
            "native_reason_text_not_compared": True,
        }
    if "usable_object_returned" in expected:
        assert lines == [["N"]], "initialisation rejection"
        return {"rejected": True, "usable_object_returned": False}
    assert lines == [
        ["L", expected["old_hex"], expected["repair_u_hex"], expected["repair_v_hex"]]
    ], "legacy omission control"
    return {
        "original_native_omission_reproduced": True,
        "length_only_hash_outputs_match": True,
        "forgery_experiment": False,
    }


def cases():
    assert not (R / "native-case-ledger.json").exists()
    inputs = read(R / "native-inputs-v2.json")
    for name, digest in inputs["sha256"].items():
        assert sha(P / name) == digest
    builds = [
        read(R / (name + "-attempt.json"))
        for name in ("build-1", "build-2")
        if (R / (name + "-attempt.json")).exists()
    ]
    assert builds[-1]["status"] == "pass"
    assert sha(A / "build/exp2_native") == builds[-1]["binary_sha256"]
    started = time.monotonic()
    ledger = []
    for n, row in enumerate(inputs["expected"], 1):
        assert time.monotonic() - started + 2 < 34, "command reserve"
        assert sha(P / row["retained_expectation"]) == row["retained_sha256"]
        item = {"id": row["id"], "invocation": 402 + n, "status": "admitted"}
        ledger.append(item)
        save("native-case-ledger.json", ledger)
        start = time.monotonic()
        try:
            command = [
                str(A / "build/exp2_native"),
                str(n),
                str(A / "overlay" / ("nonce-mutated.bin" if n == 3 else "canonical.bin")),
            ]
            run = subprocess.run(command, capture_output=True, timeout=2)
            assert len(run.stdout) + len(run.stderr) < 65536, "case diagnostic capacity"
            raw = R / (row["id"] + ".native.txt")
            raw.write_bytes(run.stdout + run.stderr)
            assert run.returncode == 0, "native exit " + str(run.returncode)
            outcome = compare(run.stdout.decode("ascii"), read(P / row["retained_expectation"]))
            save(
                row["id"] + ".json",
                {
                    "command": command,
                    "exit_code": run.returncode,
                    "expected_sha256": row["retained_sha256"],
                    "outcome": outcome,
                },
            )
            item.update(status="pass", seconds=time.monotonic() - start)
            save("native-case-ledger.json", ledger)
        except Exception as error:
            item.update(status="failed", seconds=time.monotonic() - start, error=str(error))
            save("native-case-ledger.json", ledger)
            raise
    save(
        "native-case-summary.json",
        {
            "passed": 16,
            "invocations": 16,
            "cumulative": 418,
            "seconds": time.monotonic() - started,
            "layer": (
                "patched native libiop hashchain and common BCS caller; "
                "public synthetic record replay"
            ),
        },
    )
    print("16 native comparisons passed; cumulative 418/426")
