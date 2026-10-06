"""Count every started focused invocation, including failures and repeats."""

import json
from pathlib import Path

import pytest

D = Path(__file__).resolve().parent
FILE = D / "test-invocations.jsonl"


def pytest_runtest_logstart(nodeid, location):
    rows = FILE.read_text().splitlines() if FILE.exists() else []
    if len(rows) >= 24 or 76 + len(rows) + 1 + 22 > 124:
        pytest.exit("amended cumulative invocation allowance exhausted", returncode=125)
    with FILE.open("a") as stream:
        stream.write(
            json.dumps(
                {
                    "invocation": len(rows) + 1,
                    "nodeid": nodeid,
                    "historical": 76,
                    "pending_identity": 22,
                }
            )
            + "\n"
        )
        stream.flush()
