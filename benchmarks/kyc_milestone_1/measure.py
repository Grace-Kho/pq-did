"""Timing, local identities and resource observations, without benchmark execution."""

import hashlib
import importlib.metadata
import os
import platform
import resource
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while block := source.read(65536):
            digest.update(block)
    return digest.hexdigest()


def sha256_source_tree(path):
    path = Path(path)
    digest = hashlib.sha256()
    for source in sorted(path.rglob("*.py")):
        digest.update(str(source.relative_to(path)).encode() + b"\0")
        digest.update(bytes.fromhex(sha256_file(source)))
    return digest.hexdigest()


def input_identities():
    files = [
        ROOT / "tests/fixtures/relations_vectors.json",
        ROOT / "uv.lock",
        ROOT / "native/dependencies.json",
        ROOT / "docs/environment.md",
        ROOT / "native/.deps/install/lib/liboqs.so",
    ]
    files.extend(sorted((ROOT / "native/build").rglob("*mldsa*.so")))
    result = {str(path.relative_to(ROOT)): sha256_file(path) for path in files if path.is_file()}
    for directory in (
        ROOT / "experiments/kyc_milestone_1/baseline",
        Path(__file__).parent,
        ROOT / "src/pqdid",
    ):
        result[str(directory.relative_to(ROOT))] = sha256_source_tree(directory)
    return result


def validate_reuse(identities, *, root=ROOT):
    """A stored observation is reusable only while every recorded input still matches."""
    root = Path(root).resolve()
    if not identities:
        raise ValueError("no identities for reuse")
    for relative, expected in identities.items():
        path = root / relative
        if not path.resolve().is_relative_to(root) or not path.exists():
            raise ValueError("reuse input missing or outside root")
        actual = sha256_source_tree(path) if path.is_dir() else sha256_file(path)
        if actual != expected:
            raise ValueError("changed input invalidates reuse")
    return True


def text_or_none(path):
    try:
        return Path(path).read_text(encoding="utf-8")[:32768].strip()
    except OSError:
        return None


def resource_observation():
    group = text_or_none("/proc/self/cgroup")
    group = next((line[3:] for line in (group or "").splitlines() if line.startswith("0::")), None)
    base = Path("/sys/fs/cgroup") / group.lstrip("/") if group else None
    cgroup = {}
    for name in ("memory.current", "memory.peak", "memory.max", "memory.swap.max", "cpu.max"):
        cgroup[name] = text_or_none(base / name) if base else None
    return {
        "rss_peak_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "rss_scope": "process lifetime high-water mark; not a per-operation delta",
        "cgroup_path": group,
        "cgroup": cgroup,
        "cgroup_scope": "current guarded job and descendants; peak includes setup",
    }


def environment(guard):
    if not isinstance(guard, dict) or not guard:
        raise ValueError("effective guard limits must be supplied by the coordinator")
    cpu = text_or_none("/proc/cpuinfo") or ""
    model = next(
        (
            line.split(":", 1)[1].strip()
            for line in cpu.splitlines()
            if line.startswith("model name")
        ),
        "unavailable",
    )
    memory = text_or_none("/proc/meminfo") or ""
    available = next(
        (
            int(line.split()[1]) * 1024
            for line in memory.splitlines()
            if line.startswith("MemAvailable:")
        ),
        None,
    )
    try:
        binding = importlib.metadata.version("liboqs-python")
    except importlib.metadata.PackageNotFoundError:
        binding = None
    return {
        "python": sys.version,
        "python_executable": sys.executable,
        "python_executable_sha256": sha256_file(sys.executable),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "os_release": text_or_none("/etc/os-release"),
        "wsl": "microsoft" in platform.release().lower(),
        "cpu_model": model,
        "cpu_count": os.cpu_count(),
        "affinity": sorted(os.sched_getaffinity(0)),
        "threads": 1,
        "available_memory_bytes": available,
        "liboqs_python": binding,
        "compiler_identity": {
            "recorded_setup": "GCC/G++ 15.2.0; docs/environment.md",
            "binary_sha256": sha256_file("/usr/bin/g++"),
            "version_probe_rerun": False,
        },
        "guard": guard,
        "network": "local only; no WAN measurement",
    }


class Timings:
    """Retain nested observations; only the enclosing operation is an end-to-end sample."""

    def __init__(self):
        self.stages = {}
        self.parents = {}
        self._stack = []

    @contextmanager
    def stage(self, name):
        if name in self.stages:
            raise ValueError("duplicate stage")
        parent = self._stack[-1] if self._stack else None
        self._stack.append(name)
        start = time.monotonic_ns()
        try:
            yield
        finally:
            end = time.monotonic_ns()
            self._stack.pop()
            self.stages[name] = end - start
            self.parents[name] = parent

    def roots_total(self):
        return sum(value for name, value in self.stages.items() if self.parents[name] is None)
