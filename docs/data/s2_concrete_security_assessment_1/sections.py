"""Separate authoritative sections using column reading order, not PDF page ranges."""

import json
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
raw = D / "tmp/ordered.txt"
subprocess.run(
    ["pdftotext", str(P / "docs/manuscript/PQ_DID__Implementation.pdf"), str(raw)],
    check=True,
    timeout=10,
)
assert raw.stat().st_size < 1048576
text = raw.read_text()
start = text.index("II. R ELATED W ORK")
end = text.index("IX. I MPLEMENTATION AND E VALUATION", start)
selected = text[start:end]
assert "Theorem 11" in selected and "VIII. S ECURITY" in selected
(D / "sections-II-VIII.txt").write_text(selected)
# Only bibliographic locators, never excluded construction/benchmark claims.
references = text[text.index("R EFERENCES", end) :]
rows = []
for number in (30, 31, 32, 33):
    marker = f"[{number}]"
    if marker in references:
        entry = references.split(marker, 1)[1].split(f"[{number + 1}]", 1)[0]
        rows.append({"number": number, "locator": entry[:2500]})
(D / "bibliographic-locators.json").write_text(json.dumps(rows, indent=2) + "\n")
raw.unlink()
print(
    json.dumps(
        {
            "authority_bytes": len(selected.encode()),
            "includes_theorem_11": True,
            "bibliographic_entries": len(rows),
        }
    )
)
