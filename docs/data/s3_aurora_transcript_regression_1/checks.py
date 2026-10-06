"""One bounded lint/format group, no functional execution or test discovery."""

import hashlib
import json
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
E = P / "experiments/aurora_transcript_regression_1"
paths = sorted([*D.glob("*.py"), *E.glob("*.py")])
ruff = str(P / ".venv/bin/ruff")
for args in (
    ["check", "--select", "I", "--fix", "--no-cache"],
    ["format", "--no-cache"],
    ["check", "--no-cache"],
    ["format", "--check", "--no-cache"],
):
    subprocess.run([ruff, *args, *map(str, paths)], check=True, timeout=0.4)
pins = {str(path.relative_to(P)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
(D / "execution-inputs.json").write_text(json.dumps({"sha256": pins}, indent=2) + "\n")
