"""Reuse the unchanged unprivileged guard for one targeted review and source quality.

This is not an activation controller. The original ledger is not modified; its
elapsed time is included in admission alongside this supplementary ledger.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
D = Path(__file__).resolve().parent
E = D.parent
P = E.parents[2]
path = E / "run_checks.py"
expected = json.loads((E / "manifest.json").read_text())["sha256"][str(path.relative_to(P))]
assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
spec = importlib.util.spec_from_file_location("existing_guard", path)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
guard.D = D
guard.__file__ = __file__
guard.FILES = []
files = [str(D / name) for name in ("review.py", "run_review.py", "host_observer.py")]
guard.COMMANDS = {
    "activation-preflight": [str(P / ".venv/bin/python"), "-I", "-B", str(D / "review.py")],
    "activation-preflight-lint": [str(P / ".venv/bin/ruff"), "check", "--no-cache", *files],
    "activation-preflight-format": [
        str(P / ".venv/bin/ruff"),
        "format",
        "--check",
        "--no-cache",
        *files,
    ],
}

if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        raise SystemExit(guard.worker(sys.argv[2]))
    prior = json.loads((E / "run-ledger.json").read_text())
    current_path = D / "run-ledger.json"
    current = json.loads(current_path.read_text()) if current_path.exists() else []
    assert sum(r.get("seconds", 60) for r in [*prior, *current]) + 60 <= 300
    raise SystemExit(guard.main(sys.argv[1]))
