"""Eight individually counted tooling fixtures; no native or cryptographic execution."""

import json
import tempfile
import time
import types
from pathlib import Path

R = Path(__file__).resolve().parent
policy = types.ModuleType("seal_policy")
policy.__file__ = str(R / "seal_policy.py")
exec(compile(Path(policy.__file__).read_text(), policy.__file__, "exec"), policy.__dict__)


def run():
    name = "docs/status.md"
    prefix, whole = b"history\n", b"history\nappendix\n"
    raw = json.dumps({"sha256": {name: policy.sha(whole)}}).encode()
    pin = policy.sha(raw)
    reports = {
        name: {
            "prefix_bytes": 8,
            "prefix_sha256": policy.sha(prefix),
            "final_bytes": 17,
            "full_sha256": policy.sha(whole),
        }
    }
    cases = (
        ("unchanged immutable", "src/fixed", b"immutable", None, True),
        ("sealed report", name, whole, raw, True),
        ("modified immutable", "src/fixed", b"Immutable", None, False),
        ("modified historical prefix", name, b"History\nappendix\n", raw, False),
        ("modified sealed appendix", name, b"history\nAppendix\n", raw, False),
        ("unsealed tail", name, whole + b"tail", raw, False),
        ("truncated coverage", name, whole[:-1], raw, False),
        ("stale untrusted seal missing report entry", name, whole, b'{"sha256":{}}', False),
    )
    ledger = []
    for number, (label, selected, data, seal, expected) in enumerate(cases, 1):
        row = {"id": f"SEAL-{number:02d}", "invocation": 411 + number, "status": "admitted"}
        ledger.append(row)
        (R / "fixture-ledger.json").write_text(json.dumps(ledger) + "\n")
        start = time.monotonic()
        try:
            with tempfile.TemporaryDirectory(dir=R / "tmp") as temp:
                path = Path(temp) / "input"
                path.write_bytes(data)
                accepted = True
                reason = None
                try:
                    policy.verify_file(
                        path,
                        selected,
                        policy.sha(prefix if selected == name else b"immutable"),
                        reports,
                        seal,
                        pin,
                    )
                except ValueError as error:
                    accepted, reason = False, str(error)
                assert accepted is expected, label
                row.update(status="pass", label=label, accepted=accepted, rejection=reason)
        except Exception as error:
            row.update(status="failed", error=str(error))
            raise
        finally:
            row["seconds"] = time.monotonic() - start
            (R / "fixture-ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
