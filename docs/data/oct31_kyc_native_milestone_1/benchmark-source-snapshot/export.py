"""Schema-checked bounded exports and predeclared descriptive statistics."""

import csv
import hashlib
import io
import json
import math
import os
import re
from collections import Counter
from pathlib import Path

from .backends import unavailable_operations
from .scenarios import SCENARIOS

CATEGORIES = {
    "mldsa_reference_measured",
    "reference_lifecycle",
    "native_component",
    "private_auth_unavailable",
}
OUTCOMES = {
    "accepted",
    "expected-rejection",
    "unexpected-rejection",
    "unexpected-acceptance",
    "expired",
    "stale-state",
    "resource-abort",
    "unavailable",
    "incomplete",
}
FIELDS = (
    "version",
    "run_id",
    "attempt_id",
    "invocation_id",
    "session_id",
    "scenario_id",
    "phase",
    "trial_index",
    "capability",
    "category",
    "measurement_origin",
    "outcome",
    "reason",
    "start_monotonic_ns",
    "end_monotonic_ns",
    "duration_ns",
    "stages_ns",
    "stage_parents",
    "setup_ns",
    "keygen_ns",
    "message_bytes",
    "identities",
    "fixture_sha256",
    "instance_sha256",
    "signing",
    "resources",
    "counters",
    "environment",
    "unavailable",
    "censoring",
    "details",
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
MAX_CHUNK = 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def uint(value):
    return type(value) is int and value >= 0


def validate_record(record):
    require(type(record) is dict and set(record) == set(FIELDS), "record fields")
    require(record["version"] == 1, "record version")
    for name in ("run_id", "attempt_id", "session_id"):
        require(type(record[name]) is str and IDENTIFIER.fullmatch(record[name]), name)
    require(record["scenario_id"] in SCENARIOS, "scenario")
    require(record["phase"] in {"cold", "warmup", "warm"}, "phase")
    require(uint(record["trial_index"]), "trial index")
    require(record["category"] in CATEGORIES, "record category")
    require(record["measurement_origin"] in {"actual", "synthetic-validation"}, "origin")
    require(
        not (
            record["category"] == "mldsa_reference_measured"
            and record["measurement_origin"] != "actual"
        ),
        "synthetic measured row",
    )
    require(record["outcome"] in OUTCOMES, "outcome")
    start, end = record["start_monotonic_ns"], record["end_monotonic_ns"]
    require(uint(start) and uint(end) and end >= start, "monotonic bounds")
    require(record["duration_ns"] == end - start, "duration mismatch")
    for field in ("setup_ns", "keygen_ns"):
        require(uint(record[field]), field)
    require(type(record["stages_ns"]) is dict, "stages")
    require(set(record["stage_parents"]) == set(record["stages_ns"]), "stage parents")
    for name, duration in record["stages_ns"].items():
        require(uint(duration) and duration <= end - start, "stage duration")
        parent = record["stage_parents"][name]
        require(parent is None or parent in record["stages_ns"], "stage parent missing")
        visited = {name}
        while parent is not None:
            require(parent not in visited, "timing parent cycle")
            visited.add(parent)
            require(duration <= record["stages_ns"][parent], "nested timing exceeds parent")
            parent = record["stage_parents"][parent]
    require(type(record["message_bytes"]) is dict, "messages")
    for size in record["message_bytes"].values():
        require(
            type(size) is dict and set(size) == {"canonical", "transport"}, "message size fields"
        )
        require(uint(size["canonical"]) and uint(size["transport"]), "message sizes")
    require(type(record["identities"]) is dict and record["identities"], "input identities")
    require(all(HASH.fullmatch(value) for value in record["identities"].values()), "input hashes")
    for name in ("fixture_sha256", "instance_sha256"):
        require(record[name] is None or HASH.fullmatch(record[name]), name)
    if record["outcome"] == "accepted":
        require(record["fixture_sha256"] and record["instance_sha256"], "accepted fixture identity")
    require(
        type(record["environment"]) is dict and record["environment"].get("guard"), "environment"
    )
    require(type(record["resources"]) is dict and "rss_scope" in record["resources"], "RSS scope")
    require(
        type(record["counters"]) is dict and record["counters"].get("reserved") is True,
        "unreserved trial",
    )
    require(record["invocation_id"] is not None, "missing invocation")
    require(record["unavailable"] == unavailable_operations(), "unavailable private proof fields")
    require(type(record["signing"]) is dict, "signing metadata")
    attempts = record["signing"].get("attempts")
    require(attempts is None or uint(attempts), "signing attempts")
    if attempts is None:
        require(bool(record["signing"].get("reason")), "unavailable signing attempts reason")
    if record["censoring"] is not None:
        require(record["outcome"] in {"resource-abort", "incomplete"}, "censored outcome")
        require(record["censoring"].get("observed_complete") is False, "censoring marker")
        require(record["censoring"].get("deadline_seconds", 0) > 0, "censoring deadline")
    # Reject unserialisable/nonfinite values before any output is written.
    json.dumps(record, allow_nan=False)
    return record


def nearest_rank(values, percentile=0.95):
    require(0 < percentile <= 1, "percentile")
    if not values:
        return None
    return sorted(values)[math.ceil(len(values) * percentile) - 1]


def statistics(records):
    rows = list(records)
    results = []
    for scenario in SCENARIOS:
        sessions = sorted({row["session_id"] for row in rows if row["scenario_id"] == scenario})
        for session in [*sessions, "pooled"]:
            for phase in ("cold", "warmup", "warm"):
                selected = [
                    r
                    for r in rows
                    if r["scenario_id"] == scenario
                    and r["phase"] == phase
                    and (session == "pooled" or r["session_id"] == session)
                ]
                values = sorted(
                    r["duration_ns"]
                    for r in selected
                    if r["outcome"] == "accepted" and r["censoring"] is None
                )
                counts = Counter(r["outcome"] for r in selected)
                n = len(values)
                expected = {"cold": 1, "warmup": 2, "warm": 20}[phase]
                if session == "pooled":
                    expected *= 3
                results.append(
                    {
                        "scenario": scenario,
                        "session": session,
                        "phase": phase,
                        "attempts": len(selected),
                        "planned_attempts": expected,
                        "missing_attempts": max(0, expected - len(selected)),
                        "successful_samples": n,
                        "failures": len(selected) - n,
                        "outcomes": dict(counts),
                        "censored": sum(r["censoring"] is not None for r in selected),
                        "included_in_warm_statistics": phase == "warm",
                        "min_ns": values[0] if n else None,
                        "median_ns": (
                            values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2
                        )
                        if n
                        else None,
                        "nearest_rank_p95_ns": nearest_rank(values),
                        "max_ns": values[-1] if n else None,
                    }
                )
    return results


class BoundedWriter:
    def __init__(self, directory, prefix, suffix, *, cap=MAX_CHUNK, header=b""):
        require(0 < cap <= MAX_CHUNK, "chunk cap")
        self.directory, self.prefix, self.suffix = Path(directory), prefix, suffix
        self.cap, self.header, self.files = cap, header, []
        self.stream = None
        self.size = 0

    def append(self, row):
        require(len(row) + len(self.header) <= self.cap, "single row exceeds chunk cap")
        if self.stream is None or self.size + len(row) > self.cap:
            if self.stream:
                self.stream.close()
            path = self.directory / f"{self.prefix}-{len(self.files):04d}.{self.suffix}"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.stream = os.fdopen(descriptor, "wb")
            self.files.append(path)
            self.stream.write(self.header)
            self.size = len(self.header)
        self.stream.write(row)
        self.stream.flush()
        self.size += len(row)

    def close(self):
        if self.stream:
            self.stream.close()


def csv_line(values):
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerow(values)
    return stream.getvalue().encode("utf-8")


class Exporter:
    def __init__(self, output, *, cap=MAX_CHUNK):
        self.root = Path(output)
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.jsonl = BoundedWriter(self.root, "trials", "jsonl", cap=cap)
        self.csv = BoundedWriter(self.root, "trials", "csv", cap=cap, header=csv_line(FIELDS))
        self.records = []

    def append(self, record):
        validate_record(record)
        if any(prior["attempt_id"] == record["attempt_id"] for prior in self.records):
            raise ValueError("duplicate output attempt")
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        values = [
            json.dumps(record[field], sort_keys=True, separators=(",", ":"))
            if isinstance(record[field], (dict, list))
            else record[field]
            for field in FIELDS
        ]
        csv_encoded = csv_line(values)
        # Check both row sizes before writing either representation.
        require(len(encoded.encode()) + 1 <= self.jsonl.cap, "JSONL record too large")
        require(len(csv_encoded) + len(self.csv.header) <= self.csv.cap, "CSV record too large")
        self.jsonl.append(encoded.encode() + b"\n")
        self.csv.append(csv_encoded)
        self.records.append(record)

    def finalise(self):
        self.jsonl.close()
        self.csv.close()
        summary = statistics(self.records)
        lines = [
            "# ML-DSA reference benchmark",
            "",
            "Research workload on this host. Complete attributes, DID/version, persistent "
            "holder key, rid and path are disclosed and linkable. No private-authentication "
            "proof backend is available. No full-scheme overhead ratio is computed.",
            "",
            "Warm-ups remain in the ledger and exports. Latency statistics use successful, "
            "uncensored observations only; failed and missing attempts remain visible. "
            "Cold samples are descriptive. Sample p95 is not a population p95 or SLA.",
            "",
            "| Scenario | Session | Phase | Attempts/planned | Successful | Failed | "
            "Censored | Min ms | Median ms | p95 ms | Max ms |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for row in summary:
            values = [
                "unavailable" if row[name] is None else f"{row[name] / 1e6:.3f}"
                for name in ("min_ns", "median_ns", "nearest_rank_p95_ns", "max_ns")
            ]
            lines.append(
                f"| {row['scenario']} | {row['session']} | {row['phase']} | "
                f"{row['attempts']}/{row['planned_attempts']} | {row['successful_samples']} | "
                f"{row['failures']} | {row['censored']} | " + " | ".join(values) + " |"
            )
        self._exclusive_file("summary.md", ("\n".join(lines) + "\n").encode())
        self._exclusive_file("summary.json", json.dumps(summary, indent=2).encode() + b"\n")
        manifest = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(self.root.iterdir())
            if path.is_file()
        }
        self._exclusive_file("manifest.json", json.dumps(manifest, indent=2).encode() + b"\n")
        return summary

    def _exclusive_file(self, name, contents):
        require(len(contents) <= MAX_CHUNK, "export file cap")
        descriptor = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)


def readback(output):
    root = Path(output)
    manifest = json.loads((root / "manifest.json").read_text())
    for name, expected in manifest.items():
        require(Path(name).name == name, "manifest filename")
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, "export digest")
    rows = []
    for path in sorted(root.glob("trials-*.jsonl")):
        with path.open() as source:
            rows.extend(validate_record(json.loads(line)) for line in source)
    csv_rows = []
    for path in sorted(root.glob("trials-*.csv")):
        with path.open(newline="") as source:
            csv_rows.extend(csv.DictReader(source))
    require(len(rows) == len(csv_rows), "JSONL/CSV row count")
    for row, csv_row in zip(rows, csv_rows, strict=True):
        for field in FIELDS:
            value = row[field]
            if isinstance(value, (dict, list)):
                require(json.loads(csv_row[field]) == value, "CSV structured value")
            else:
                require(csv_row[field] == ("" if value is None else str(value)), "CSV scalar value")
    require(json.loads((root / "summary.json").read_text()) == statistics(rows), "summary readback")
    return rows
