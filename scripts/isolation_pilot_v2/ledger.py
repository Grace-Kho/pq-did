"""Purpose-specific local command ledger admission; IPC limits remain unchanged."""

import json
import math
import re

from layout import EVIDENCE, PilotError, check, object_pairs, read_bytes

MAX_BYTES = 1048576
MAX_RECORDS = 128
MAX_RECORD_BYTES = 16384
LOCAL_LEDGERS = (
    EVIDENCE / "run-ledger.json",
    EVIDENCE / "activation-preflight/run-ledger.json",
    EVIDENCE / "correction-v2/run-ledger.json",
)
# Conservative charge for the preceding unguarded metadata/formatting observations
# and the present read-only interface query, in addition to measured guard time.
OPERATOR_RESERVE_SECONDS = 5


def validate(rows, *, allow_incomplete=False):
    check(type(rows) is list and len(rows) <= MAX_RECORDS, "ledger-record-count")
    names = set()
    for row in rows:
        check(type(row) is dict, "ledger-record")
        name = row.get("name")
        check(type(name) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", name), "ledger-name")
        check(name not in names, "ledger-duplicate-record")
        names.add(name)
        check(len(json.dumps(row, indent=2).encode()) <= MAX_RECORD_BYTES, "ledger-record-size")
        status = row.get("status")
        check(type(status) is str and status in {"pass", "failed", "launched"}, "ledger-status")
        if status == "launched":
            check(allow_incomplete, "ledger-incomplete")
            check("seconds" not in row, "ledger-incomplete-time")
        else:
            seconds = row.get("seconds")
            check(
                type(seconds) in {int, float} and math.isfinite(seconds) and 0 <= seconds <= 60,
                "ledger-time",
            )
            check(type(row.get("exit_code")) is int and "stop" in row, "ledger-outcome")
            check(
                status != "pass" or (row["exit_code"] == 0 and row["stop"] is None), "ledger-pass"
            )
        # Bound the complete retained structure, including diagnostic fields. Never
        # discard an unknown field or skip a failed row to obtain admission.
        stack = [(row, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            check(nodes <= 2048 and depth <= 16, "ledger-structure")
            if isinstance(value, dict):
                check(all(type(k) is str and len(k) <= 128 for k in value), "ledger-key")
                stack.extend((v, depth + 1) for v in value.values())
            elif isinstance(value, list):
                stack.extend((v, depth + 1) for v in value)
            elif isinstance(value, str):
                check(len(value) <= MAX_RECORD_BYTES, "ledger-string")
            elif type(value) is float:
                check(math.isfinite(value), "ledger-nonfinite")
            else:
                check(value is None or type(value) in {int, bool}, "ledger-value")
    return rows


def read_ledger(path, *, allow_incomplete=False):
    try:
        rows = json.loads(read_bytes(path, MAX_BYTES), object_pairs_hook=object_pairs)
        return validate(rows, allow_incomplete=allow_incomplete)
    except (ValueError, RecursionError, OverflowError) as error:
        raise PilotError("ledger-malformed") from error


def elapsed(paths=LOCAL_LEDGERS, *, allow_incomplete=False):
    return OPERATOR_RESERVE_SECONDS + sum(
        row.get("seconds", 60)
        for path in paths
        for row in read_ledger(path, allow_incomplete=allow_incomplete)
    )


def capacity(paths=LOCAL_LEDGERS, remaining=26):
    rows = [row for path in paths for row in read_ledger(path)]
    # A merged representation is not used operationally, but this conservative
    # projection proves all 22 cases plus provision/verify/shutdown/rollback fit.
    current = len(json.dumps(rows, indent=2).encode())
    projected = current + remaining * (MAX_RECORD_BYTES + 512)
    check(len(rows) + remaining <= MAX_RECORDS and projected <= MAX_BYTES, "ledger-capacity")
    return {
        "existing_records": len(rows),
        "remaining_records": remaining,
        "projected_bytes": projected,
        "maximum_bytes": MAX_BYTES,
    }
