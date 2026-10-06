"""Bounded diagnostic, NOT a preservation comparison or full audit."""

import gc
import hashlib
import json
import os
import time
from collections import Counter
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
OLD = P / "docs/data/s2_revoke_state_1"
CG = Path("/sys/fs/cgroup") / next(
    line[3:].lstrip("/")
    for line in Path("/proc/self/cgroup").read_text().splitlines()
    if line.startswith("0::")
)
READ_LIMIT = 64 * 1024**2
EARLY_STOP = 160 * 1024**2


def memory():
    stats = dict(line.split() for line in (CG / "memory.stat").read_text().splitlines())
    return {
        "current": int((CG / "memory.current").read_text()),
        "peak": int((CG / "memory.peak").read_text()),
        "categories": {k: int(stats[k]) for k in ("anon", "file", "kernel", "slab", "file_mapped")},
        "events": (CG / "memory.events").read_text().strip(),
    }


def main():
    started = time.monotonic()
    phases = {"start": memory()}
    baseline_path = OLD / "preservation-before.json"
    raw = baseline_path.read_text()
    baseline = json.loads(raw)
    baseline_identity = hashlib.sha256(raw.encode()).hexdigest()
    phases["one_baseline_text_and_dictionary"] = memory()
    duplicate = json.loads(raw)
    phases["two_baseline_dictionaries"] = memory()
    del duplicate, raw
    gc.collect()
    phases["after_duplicate_release"] = memory()
    sizes = [(path.stat().st_size, name) for name in baseline if (path := P / name).is_file()]
    largest = sorted(sizes, reverse=True)[:8]
    # Only a selected <=64 MiB file, not the full inventory or baseline comparisons.
    size, name = max((size, name) for size, name in sizes if 8 * 1024**2 <= size <= READ_LIMIT)
    probe = P / name
    phases["metadata_only_scan"] = memory()
    modes = []
    for release in (False, True):
        with probe.open("rb", buffering=0) as stream:
            # Establish an explicit cold-file condition; cache advice changes no file bytes.
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_RANDOM)
            before = memory()
            hasher = hashlib.sha256()
            buffer = bytearray(2**18)
            offset = 0
            peak = before
            while True:
                count = stream.readinto(buffer)
                if not count:
                    break
                hasher.update(memoryview(buffer)[:count])
                if release:
                    os.posix_fadvise(stream.fileno(), offset, count, os.POSIX_FADV_DONTNEED)
                offset += count
                sample = memory()
                if sample["current"] > peak["current"]:
                    peak = sample
                if sample["current"] >= EARLY_STOP or time.monotonic() - started > 20:
                    raise RuntimeError("diagnostic early stop, not a complete comparison")
            after = memory()
            modes.append(
                {
                    "mode": "release-consumed-pages" if release else "retain-buffered-pages",
                    "bytes": offset,
                    "sha256": hasher.hexdigest(),
                    "before": before,
                    "at_highest_sampled_current": peak,
                    "after": after,
                }
            )
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
    # Inventory names only: locate existing untracked additions without blessing their bytes.
    extra_by_root = {}
    final = json.loads((OLD / "manifest.json").read_text())
    known = set(baseline) | set(final["sha256"]) | {"docs/data/s2_revoke_state_1/manifest.json"}
    for directory in ("src", "tests", "scripts", "configs", "docs"):
        extras = []
        for base, _dirs, files in os.walk(P / directory, followlinks=False):
            for filename in files:
                path = Path(base) / filename
                name = str(path.relative_to(P))
                if name not in known and not name.startswith(str(D.relative_to(P)) + "/"):
                    extras.append(name)
        extra_by_root[directory] = sorted(extras)
    identity = {}
    for path in [baseline_path, OLD / "manifest.json"]:
        with path.open("rb") as stream:
            identity[str(path.relative_to(P))] = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {
        "package": "S2-REVOKE-AUDIT-1",
        "diagnostic_only": True,
        "full_preservation_pass": False,
        "baseline_entries": len(baseline),
        "baseline_bytes": baseline_path.stat().st_size,
        "baseline_sha256": baseline_identity,
        "baseline_identities": identity,
        "top_level_counts": dict(Counter(name.split("/")[0] for name in baseline)),
        "total_protected_file_bytes_metadata_only": sum(size for size, _ in sizes),
        "largest_files": largest,
        "probe_path": str(probe.relative_to(P)),
        "probe_bytes": size,
        "phases": phases,
        "probe_modes": modes,
        "historical_end_manifest_entries": len(final["sha256"]),
        "historical_end_manifest_overlap": len(set(baseline) & set(final["sha256"])),
        "source_directory_additions_not_in_historical_manifests": extra_by_root,
        "prior_report_bytes": (P / "docs/stage2_revocation_state.md").stat().st_size,
        "seconds": time.monotonic() - started,
    }
    with (D / "diagnosis.json").open("w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "diagnostic_only": True,
                "probe": result["probe_path"],
                "probe_bytes": size,
                "phases": phases,
                "modes": modes,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
