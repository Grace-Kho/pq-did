"""Trusted phase limits and destination-based output roles for isolated tooling."""

import gzip
import hashlib
import json
import math
import os
import re
from pathlib import Path

MIB = 1048576
PHASES = {
    "compatibility/preflight": (1024 * MIB, 5),
    "compatibility/build-3": (1024 * MIB, 55),
    "compatibility/cases": (1024 * MIB, 50),
    "compatibility/quality": (256 * MIB, 3),
    "compatibility/prepare": (256 * MIB, 2),
    "compatibility/full-audit": (256 * MIB, 7),
    "repair/quality": (256 * MIB, 3),
    "repair/quality-2": (256 * MIB, 3),
    "repair/quality-3": (256 * MIB, 3),
    "repair/quality-4": (256 * MIB, 3),
    "repair/quality-5": (256 * MIB, 3),
    "repair/tooling-rerun-1": (256 * MIB, 3),
    "repair/tooling": (256 * MIB, 10),
    "repair/prepare": (256 * MIB, 3),
    "repair/full-audit": (256 * MIB, 7),
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(value):
    need(type(value) is int or type(value) is str and value.isdecimal(), "integer metric")
    result = int(value)
    need(result >= 0, "negative metric")
    return result


def validate_record(record, phase):
    """Caller supplies an identified phase; limits never come from the record."""
    need(phase in PHASES, "unknown phase")
    memory, seconds = PHASES[phase]
    need(record["name"] == phase.split("/")[1], "phase identity mismatch")
    need(record["limit_seconds"] == seconds, "unauthorised deadline")
    need(record["status"] == "pass" and record["exit_code"] == 0, "unsuccessful record")
    need(record["stop"] is None, "recorded resource breach")
    elapsed = record["seconds"]
    need(type(elapsed) in (int, float) and math.isfinite(elapsed), "invalid wall time")
    need(0 <= elapsed < seconds, "wall limit")
    need(integer(record["sampled_tree_RSS_peak"]) <= memory, "RSS excess")
    need(integer(record["temporary_storage_observed_peak"]) <= 8 * MIB, "temporary excess")
    service = record["service"]
    need(service["exit_code"] == service["resource_guard_exit_code"] == 0, "worker failure")
    need(service["resource_guard_passed"] is True, "worker breach")
    cpus = service["allowed_cpus"]
    need(type(cpus) is list and 1 <= len(cpus) <= 2, "CPU affinity")
    need(len(set(cpus)) == len(cpus) and all(type(n) is int and n >= 0 for n in cpus), "CPU IDs")
    for when in ("before", "after"):
        snap = service[when]
        need(integer(snap["memory.max"]) == memory, "unauthorised memory ceiling")
        need(integer(snap["memory.swap.max"]) == 0, "swap ceiling")
        need(snap["cpu.max"] == "200000 100000", "CPU ceiling")
        need(integer(snap["pids.max"]) == 128, "task ceiling")
        need(integer(snap["memory.peak"]) <= memory, "cgroup memory excess")
        need(integer(snap["memory.current"]) <= memory, "current memory excess")
        need(integer(snap["memory.swap.peak"]) == 0, "swap usage")
        entries = [line.split() for line in snap["memory.events"].splitlines()]
        need(all(len(row) == 2 for row in entries), "malformed memory events")
        events = dict(entries)
        need(len(events) == len(entries), "duplicate memory events")
        need(all(integer(events[key]) == 0 for key in ("max", "oom", "oom_kill")), "memory event")
    return {"phase": phase, "authorised_memory_bytes": memory, "passed": True}


def output_slots(next_root):
    """Exact target paths from the sealed CMake target/source list; no glob *.o."""
    root = Path(next_root)
    build = root / "build"
    paths = {build / n for n in ("exp2_native", "exp2_semantics", "libiop_native.a")}
    paths.add(build / "libff-build/libff/libff.a")
    iop = (
        "common/common.cpp",
        "bcs/hashing/blake2b.cpp",
        "protocols/ldt/ldt_reducer.cpp",
        "protocols/ldt/fri/fri_ldt.cpp",
        "protocols/ldt/fri/fri_aux.cpp",
        "relations/sparse_matrix.cpp",
        "iop/utilities/batching.cpp",
        "algebra/utils.cpp",
    )
    for name in iop:
        source = root / "work/libiop/libiop" / name
        paths.add(build / "CMakeFiles/iop_native.dir" / (str(source).lstrip("/") + ".o"))
    for field in ("gf32", "gf64", "gf128", "gf192", "gf256"):
        paths.add(
            build / f"libff-build/libff/CMakeFiles/ff.dir/algebra/fields/binary/{field}.cpp.o"
        )
    for name in ("double", "profiling", "utils"):
        paths.add(build / f"libff-build/libff/CMakeFiles/ff.dir/common/{name}.cpp.o")
    for target, source in (
        ("exp2_native", "exp2_native.cpp"),
        ("exp2_semantics", "semantic_cases.cpp"),
    ):
        path = root / "overlay" / source
        paths.add(build / f"CMakeFiles/{target}.dir" / (str(path).lstrip("/") + ".o"))
    return frozenset(paths)


def compiler_environment(next_root):
    # The launcher owns this output role. No caller-provided TMPDIR is retained.
    return {"TMPDIR": str(Path(next_root) / "scratch"), "CCACHE_DISABLE": "1"}


def classify(path, evidence_root, next_root, *, compiler_active):
    path, evidence_root, next_root = map(Path, (path, evidence_root, next_root))
    need(".." not in path.parts, "noncanonical output path")
    if path.is_relative_to(evidence_root):
        return "evidence", MIB
    need(path.is_relative_to(next_root), "unregistered output destination")
    relative = path.relative_to(next_root)
    # Scratch has a dedicated trusted compiler producer and cannot be selected by a record.
    if (
        compiler_active
        and path.parent == next_root / "scratch"
        and re.fullmatch(r"cc[A-Za-z0-9]{6}\.(s|o|ii|res)", path.name)
    ):
        return "compiler-scratch", 32 * MIB
    if compiler_active and path in output_slots(next_root):
        return "compiled-binary", 32 * MIB
    if relative.parts[0] in {"work", "overlay"}:
        return "ordinary-source", MIB
    # CMake logs/cache/ninja/JSON, diagnostics and unregistered names are evidence,
    # even inside the build tree. Renaming an evidence file to *.o grants nothing.
    return "evidence", MIB


def account(rows, evidence_root, next_root, *, compiler_active=False):
    seen = set()
    evidence = artifacts = scratch = 0
    roles = {}
    for name, size in rows:
        need(name not in seen, "duplicate output")
        seen.add(name)
        size = integer(size)
        role, ceiling = classify(name, evidence_root, next_root, compiler_active=compiler_active)
        need(
            size <= ceiling,
            "artifact per-file limit" if ceiling == 32 * MIB else "ordinary per-file limit",
        )
        if Path(name).is_relative_to(next_root):
            artifacts += size  # Includes metadata: nothing escapes aggregate artifact accounting.
        if role == "evidence":
            evidence += size
        if role == "compiler-scratch":
            scratch += size
        roles[name] = role
    return {"evidence": evidence, "artifacts": artifacts, "scratch": scratch, "roles": roles}


def enforce(totals, *, retained_artifacts=15223375, evidence_appendices=0):
    need(retained_artifacts + totals["artifacts"] <= 128 * MIB, "aggregate artifact limit")
    need(totals["scratch"] <= 8 * MIB, "aggregate temporary limit")
    evidence = totals["evidence"] + evidence_appendices
    need(evidence <= 240000, "repair evidence reservation")
    need(224338 <= 393216, "retained original subpackage reservation")
    need(11879147 + evidence <= 12386485, "cumulative evidence limit")
    need(1262780 + evidence <= 2 * MIB, "native evidence limit")
    return evidence


def walk_outputs(root):
    rows = []
    if not root.exists():
        return rows
    for base, dirs, names in os.walk(root, followlinks=False):
        need(not any((Path(base) / n).is_symlink() for n in dirs), "new directory symlink")
        for name in names:
            path = Path(base) / name
            need(not path.is_symlink() and path.is_file(), "nonregular new output")
            rows.append((str(path), path.stat().st_size))
    return rows


_retained = None


def retained_inventory(r):
    global _retained
    if _retained is not None:
        return _retained
    rows = {}
    for name, seal_digest in (
        ("reconciliation-1", "f3125c0cdbee596222ebf0736a8647afc94d37a02e21511fec2d5dffe3d2bd56"),
        ("compatibility-1", "af7436a168337d025d766756d545790ee5c4734b458b968a61280b58ae61c99d"),
    ):
        old = r.parent / name
        seal = (old / "manifest.json").read_bytes()
        need(hashlib.sha256(seal).hexdigest() == seal_digest, "retained seal mismatch")
        path = old / "artifact-inventory.json.gz"
        expected = json.loads(seal)["sha256"][str(path.relative_to(r.parents[3]))]
        need(
            hashlib.sha256(path.read_bytes()).hexdigest() == expected, "retained inventory mismatch"
        )
        with gzip.open(path, "rt") as stream:
            for row in json.load(stream)["files"]:
                need(row["path"] not in rows, "overlapping artifact inventories")
                rows[row["path"]] = row
    _retained = rows
    return rows


def enforce_live(r, artifact_root, package_bytes):
    """Used by the inherited guard monitor; this package cannot write native outputs."""
    p = r.parents[3]
    known = retained_inventory(r)
    actual = 0
    observed = set()
    for base, dirs, names in os.walk(artifact_root, followlinks=False):
        for name in list(dirs):
            if (Path(base) / name).is_symlink():
                names.append(name)
                dirs.remove(name)
        for name in names:
            path = Path(base) / name
            key = str(path.relative_to(p))
            need(key in known, "unauthorised new artifact in tooling-only phase")
            old = known[key]
            st = path.lstat()
            need(
                st.st_size == old["bytes"] and st.st_mode == old["mode"],
                "retained artifact changed",
            )
            if old["kind"] == "symlink":
                need(
                    path.is_symlink() and os.readlink(path) == old["target"],
                    "retained symlink changed",
                )
            actual += st.st_size
            observed.add(key)
    need(observed == set(known), "retained artifact missing")
    enforce({"artifacts": 0, "scratch": 0, "evidence": package_bytes}, retained_artifacts=actual)
    for _name, size in walk_outputs(r):
        need(size <= MIB, "ordinary evidence per-file limit")
