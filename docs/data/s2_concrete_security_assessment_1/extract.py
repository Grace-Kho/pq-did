"""Bounded local source extraction and provenance; no production/backend execution."""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def main():
    pdf = P / "docs/manuscript/PQ_DID__Implementation.pdf"
    assert digest(pdf) == "d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca"
    raw = D / "tmp/manuscript-layout.txt"
    subprocess.run(["pdftotext", "-layout", str(pdf), str(raw)], check=True, timeout=10)
    assert raw.stat().st_size < 1048576
    value = raw.read_text()
    headings = [
        line.strip() for line in value.splitlines() if re.search(r"\b(?:II|VIII|IX)\.", line)
    ]
    # Record candidate boundaries before any interpretation; section selection is reviewed.
    (D / "manuscript-layout.txt").write_text(value)
    raw.unlink()
    source = {str(p.relative_to(P)): digest(p) for p in sorted((P / "src/pqdid").rglob("*.py"))}
    frozen = [
        "AGENTS.md",
        "PQ_DID_Security_Assessment_Codex_Task.md",
        "configs/suite.json",
        "docs/implementation_spec.md",
        "docs/manuscript/PQ_DID__Implementation.pdf",
        "experiments/r0_credvalid_po17_1/evidence/cumulative_attempt_ledger.json",
        "docs/proposals/s2_authority_isolation_pilot_1/v2/source-manifest.json",
    ]
    source.update({name: digest(P / name) for name in frozen})
    record = {
        "sha256": source,
        "source_revision": "No Git checkout; content-addressed source inventory",
        "inventory_sha256": hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest(),
        "task_filename": "PQ_DID_Security_Assessment_Codex_Task.md",
        "manuscript_authority": "Sections II-VIII only; extraction of other text is not authority",
        "sage_executable": shutil.which("sage"),
        "estimator_local_candidates": [str(p) for p in (P / ".tools").glob("*lattice*")],
        "new_estimator_runs": 0,
    }
    (D / "source-revision.json").write_text(json.dumps(record, indent=2) + "\n")
    prefixes = {}
    for name in (
        "stage2_authority_isolation_pilot.md",
        "status.md",
        "traceability.md",
        "spec_issues.md",
    ):
        path = P / "docs" / name
        prefixes[str(path.relative_to(P))] = {"bytes": path.stat().st_size, "sha256": digest(path)}
    (D / "prior-report-prefixes.json").write_text(json.dumps(prefixes, indent=2) + "\n")
    print(
        json.dumps(
            {
                "headings": headings,
                "revision": record["inventory_sha256"],
                "sage": record["sage_executable"],
            }
        )
    )


if __name__ == "__main__":
    main()
