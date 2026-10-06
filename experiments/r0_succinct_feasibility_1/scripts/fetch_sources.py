"""Bounded primary-source metadata reads; no downloaded code execution."""

import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9"
URLS = {
    "sdk_release.json": "https://api.github.com/repos/risc0/risc0/releases/tags/v3.0.6",
    "sdk_commit.json": f"https://api.github.com/repos/risc0/risc0/commits/{COMMIT}",
    "sdk_advisories.json": "https://api.github.com/repos/risc0/risc0/security-advisories",
    "rust_release.json": "https://api.github.com/repos/risc0/rust/releases/latest",
    "ci.yml": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/.github/workflows/main.yml",
    "rzup_Cargo.toml": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/rzup/Cargo.toml",
    "rzup_lib.rs": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/rzup/src/lib.rs",
    "sdk_Cargo.lock": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/Cargo.lock",
    "sdk_Cargo.toml": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/Cargo.toml",
    "zkvm_Cargo.toml": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/risc0/zkvm/Cargo.toml",
    "security_model.md": f"https://raw.githubusercontent.com/risc0/risc0/{COMMIT}/website/api/security-model.md",
}
out = []
for name, url in URLS.items():
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "PQ-DID-feasibility-source-review"}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read(4 * 1024**2 + 1)
        if len(data) > 4 * 1024**2:
            raise ValueError("source cap")
        (ROOT / "sources" / name).write_bytes(data)
        out.append(
            {
                "file": "sources/" + name,
                "url": url,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    except Exception as error:
        out.append({"file": name, "url": url, "error": str(error)})
(ROOT / "evidence/source_fetch.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps(out, indent=2))
