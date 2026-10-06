"""Reuse the historical unprivileged cgroup guard; retain cumulative accounting."""

import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
D = Path(__file__).resolve().parent
E = D.parent
P = E.parents[2]
sys.path.insert(0, str(P / "scripts/isolation_pilot_v2"))
from ledger import elapsed  # noqa: E402

spec = importlib.util.spec_from_file_location("historical_guard", E / "run_checks.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
guard.D = D
guard.__file__ = __file__
guard.CONFIG = json.loads((D / "config.json").read_text())
guard.FILES = [str(p) for p in sorted((P / "scripts/isolation_pilot_v2").glob("*.py"))]
guard.FILES += [str(p) for p in sorted(D.glob("*.py"))]
guard.FILES += [str(P / "tests/unit/test_isolation_corrections.py")]
guard.COMMANDS = {
    "v2-lint-fix": [str(P / ".venv/bin/ruff"), "check", "--fix", "--no-cache", *guard.FILES],
    "v2-format-source": [str(P / ".venv/bin/ruff"), "format", "--no-cache", *guard.FILES],
    "v2-lint": [str(P / ".venv/bin/ruff"), "check", "--no-cache", *guard.FILES],
    "v2-format": [str(P / ".venv/bin/ruff"), "format", "--check", "--no-cache", *guard.FILES],
    "v2-static": [
        str(P / ".venv/bin/python"),
        "-I",
        "-B",
        str(P / "scripts/isolation_pilot_v2/pilotctl.py"),
        "static",
    ],
    "v2-prepare": [str(P / ".venv/bin/python"), "-I", "-B", str(D / "prepare.py")],
    "v2-audit": [str(P / ".venv/bin/python"), "-I", "-B", str(D / "audit.py")],
}
test_args = [
    "-q",
    "-x",
    "--tb=short",
    "-p",
    "no:cacheprovider",
    "-p",
    "budget",
    "tests/unit/test_isolation_corrections.py",
    "--junitxml=" + str(D / "focused.xml"),
]
guard.COMMANDS["v2-focused"] = [
    str(P / ".venv/bin/python"),
    "-I",
    "-B",
    "-c",
    "import sys; sys.path.insert(0,"
    + repr(str(D))
    + "); import pytest; raise SystemExit(pytest.main("
    + repr(test_args)
    + "))",
]

# Four additional, distinct checks close the newly added admission/failure paths.
closure_args = [arg.replace("focused.xml", "focused-closure.xml") for arg in test_args] + [
    "-k",
    "correction_closure",
]
guard.COMMANDS["v2-focused-closure"] = [
    str(P / ".venv/bin/python"),
    "-I",
    "-B",
    "-c",
    "import sys; sys.path.insert(0,"
    + repr(str(D))
    + "); import pytest; raise SystemExit(pytest.main("
    + repr(closure_args)
    + "))",
]
guard.COMMANDS["v2-lint-fix-validation"] = guard.COMMANDS["v2-lint-fix"]
guard.COMMANDS["v2-format-final-source"] = guard.COMMANDS["v2-format-source"]
guard.COMMANDS["v2-lint-final"] = guard.COMMANDS["v2-lint"]
guard.COMMANDS["v2-cleanup"] = [
    str(P / ".venv/bin/python"),
    "-I",
    "-B",
    "-c",
    "from pathlib import Path; import shutil; p=Path(" + repr(str(D / "tmp")) + "); "
    "[shutil.rmtree(x) if x.is_dir() and not x.is_symlink() else x.unlink() for x in p.iterdir()]",
]

guard.COMMANDS["v2-lint-closure"] = guard.COMMANDS["v2-lint"]


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        raise SystemExit(guard.worker(sys.argv[2]))
    assert elapsed() + 60 + 10 <= 300, "shared time budget including emergency reserve"
    raise SystemExit(guard.main(sys.argv[1]))
