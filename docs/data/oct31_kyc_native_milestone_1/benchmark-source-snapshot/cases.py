"""One counted harness validation per CLI call. Fixtures are explicitly synthetic."""

import argparse
import copy
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "benchmarks.kyc_milestone_1"

from .backends import unavailable_operations
from .export import (
    BoundedWriter,
    Exporter,
    nearest_rank,
    readback,
    statistics,
    validate_record,
)
from .measure import Timings
from .run_bench import ExclusiveMeasurement, InvocationClaims
from .scenarios import schedule


def fixture():
    return {
        "version": 1,
        "run_id": "synthetic-validation",
        "attempt_id": "ISSUE-s1-warm-00",
        "invocation_id": "validation-only",
        "session_id": "session-1",
        "scenario_id": "ISSUE",
        "phase": "warm",
        "trial_index": 0,
        "capability": {"private_auth": False},
        "category": "reference_lifecycle",
        "measurement_origin": "synthetic-validation",
        "outcome": "accepted",
        "reason": None,
        "start_monotonic_ns": 100,
        "end_monotonic_ns": 200,
        "duration_ns": 100,
        "stages_ns": {"outer": 100, "inner": 40},
        "stage_parents": {"outer": None, "inner": "outer"},
        "setup_ns": 12,
        "keygen_ns": 10,
        "message_bytes": {"example": {"canonical": 42, "transport": 48}},
        "identities": {"synthetic-input": "a" * 64},
        "fixture_sha256": "b" * 64,
        "instance_sha256": "c" * 64,
        "signing": {"attempts": None, "exhaustion": None, "reason": "schema fixture only"},
        "resources": {"rss_scope": "synthetic fixture; not a measured RSS"},
        "counters": {"reserved": True},
        "environment": {"guard": {"synthetic": True}},
        "unavailable": unavailable_operations(),
        "censoring": None,
        "details": {"synthetic": True},
    }


def must_reject(function, *args):
    try:
        function(*args)
    except ValueError, FileExistsError, BlockingIOError:
        return
    raise AssertionError("invalid input was accepted")


def run_case(case, root):
    root = Path(root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    row = fixture()
    if case == "H-01":
        validate_record(row)
        for field in tuple(row):
            reduced = copy.deepcopy(row)
            del reduced[field]
            must_reject(validate_record, reduced)
    elif case == "H-02":
        row["category"] = "private_auth_measured"
        must_reject(validate_record, row)
    elif case == "H-03":
        row["stages_ns"]["inner"] = -1
        must_reject(validate_record, row)
        row = fixture()
        del row["duration_ns"]
        must_reject(validate_record, row)
    elif case == "H-04":
        timer = Timings()
        with timer.stage("outer"), timer.stage("inner"):
            pass
        assert timer.roots_total() == timer.stages["outer"]
        assert timer.parents["inner"] == "outer"
        assert statistics([row])[2]["median_ns"] == 100
    elif case == "H-05":
        out = Exporter(root / "export")
        out.append(row)
        out.finalise()
        assert readback(out.root)[0]["message_bytes"]["example"] == {
            "canonical": 42,
            "transport": 48,
        }
    elif case == "H-06":
        trials = schedule()
        assert len(trials) == 276
        assert sum(t.phase == "warmup" for t in trials) == 24
        warmup = copy.deepcopy(row)
        warmup["phase"], warmup["duration_ns"], warmup["end_monotonic_ns"] = "warmup", 900, 1000
        stats = statistics([row, warmup])
        assert stats[1]["attempts"] == 1 and not stats[1]["included_in_warm_statistics"]
        assert stats[2]["attempts"] == 1 and stats[2]["median_ns"] == 100
    elif case == "H-07":
        failed = copy.deepcopy(row)
        failed["outcome"] = "unexpected-rejection"
        stats = statistics([row, failed])[2]
        assert stats["attempts"] == 2 and stats["successful_samples"] == 1
        assert stats["failures"] == 1 and stats["missing_attempts"] == 18
    elif case == "H-08":
        row["outcome"] = "resource-abort"
        row["censoring"] = {"observed_complete": False, "deadline_seconds": 20}
        validate_record(row)
        stats = statistics([row])[2]
        assert stats["censored"] == 1 and stats["successful_samples"] == 0
        assert stats["nearest_rank_p95_ns"] is None
    elif case == "H-09":
        validate_record(row)
        row["unavailable"][0]["seconds"] = 0
        must_reject(validate_record, row)
    elif case == "H-10":
        for field in ("environment", "identities"):
            changed = copy.deepcopy(row)
            changed[field] = {}
            must_reject(validate_record, changed)
    elif case == "H-11":
        out = Exporter(root / "export")
        out.append(row)
        must_reject(out.append, row)
        out.finalise()
        must_reject(Exporter, root / "export")
    elif case == "H-12":
        writer = BoundedWriter(root, "test", "jsonl", cap=64)
        writer.append(b"x" * 40)
        writer.append(b"x" * 40)
        must_reject(writer.append, b"x" * 65)
        writer.close()
        assert len(writer.files) == 2
        assert all(path.stat().st_size <= 64 for path in writer.files)
    elif case == "H-13":
        row["category"] = "mldsa_reference_measured"
        must_reject(validate_record, row)
    elif case == "H-14":
        assert nearest_rank(list(range(1, 21))) == 19
        assert nearest_rank(list(range(1, 61))) == 57
        assert nearest_rank([7]) == 7 and nearest_rank([]) is None
    elif case == "H-15":
        with ExclusiveMeasurement(root / "lock"):
            lock = ExclusiveMeasurement(root / "lock")
            must_reject(lock.__enter__)
        with ExclusiveMeasurement(root / "lock"):
            pass
    elif case == "H-16":
        claims = InvocationClaims(root / "claims")
        receipt = {
            "invocation_id": "same",
            "case_id": "H-16",
            "ordinal": 1,
            "cumulative_invocations": 1,
        }

        def attempt(_):
            try:
                claims.claim(receipt)
                return True
            except FileExistsError:
                return False

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(attempt, range(2)))
        assert sorted(results) == [False, True]
        assert len(list(claims.root.iterdir())) == 1
    else:
        raise ValueError("unknown harness case")
    return {
        "case_id": case,
        "passed": True,
        "category": "reference_lifecycle",
        "measurement_origin": "synthetic-validation",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[f"H-{i:02d}" for i in range(1, 17)], required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run_case(args.case, args.root), sort_keys=True))


if __name__ == "__main__":
    main()
