"""Seal reviewed execution inputs after formatting; no candidate import/probe."""

import hashlib
import json
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
E = P / "experiments/mldsa_full_forward_ntt_1"


def main():
    target = D / "execution-seal.json"
    assert not target.exists() and not (D / "pilot-state.json").exists()
    files = {*D.glob("*.py"), *E.glob("*.py"), D / "config.json", D / "contract.json"}
    pins = json.loads((D / "reviewed-inputs.json").read_text())["sha256"]
    files.update(P / name for name in pins if name.endswith(".py"))
    hashes = {}
    for path in sorted(files):
        assert path.stat().st_size < 1048576
        hashes[str(path.relative_to(P))] = hashlib.sha256(path.read_bytes()).hexdigest()
    target.write_text(
        json.dumps(
            {"kind": "Execution input seal, not a historical baseline", "sha256": hashes}, indent=2
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "files": len(hashes),
                "execution_seal_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
