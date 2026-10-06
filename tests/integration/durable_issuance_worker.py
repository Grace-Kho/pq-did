"""TEST ONLY real process interruption at two integrated commit boundaries."""

# ruff: noqa: E402

import hashlib
import json
import resource
import select
import signal
import sys
from pathlib import Path

resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
signal.alarm(12)
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from durable_issuance_cases import ISSUE, Rig, keys

from pqdid.persistence import sqlite_store


def main():
    root, mode = Path(sys.argv[1]), sys.argv[2]
    rig = Rig(root, keys(), existing=True)
    original = sqlite_store.SQLiteStore._write

    def write(store, *args):
        decision = args[6]
        target = b"ALLOCATED" if mode == "reservation" else b"CERTIFIED"
        if decision != target:
            return original(store, *args)

        def barrier(point):
            if point != "commit-before-ack":
                return
            facts = {"barrier": mode, "heads": {}}
            for name, authority in (("manager", rig.manager_store), ("issuer", rig.issuer_store)):
                with authority._connection() as c:
                    c.execute("BEGIN")
                    ticket, _, _, _, ops = authority._load(c)
                    facts["heads"][name] = [
                        ticket.sequence,
                        ticket.digest.hex(),
                        ticket.checkpoint.hex(),
                        ticket.generation,
                    ]
                    if name == "issuer" and mode == "certification":
                        op = rig.flow.stage_operation(ISSUE, b"certify")
                        facts["response_sha256"] = hashlib.sha256(ops[op][2]).hexdigest()
            print(json.dumps(facts), flush=True)
            assert select.select([sys.stdin], [], [], 8)[0], "barrier deadline"
            raise AssertionError("parent must kill; no retry")

        sqlite_store._fault = barrier
        return original(store, *args)

    sqlite_store.SQLiteStore._write = write
    if mode == "reservation":
        rig.flow.begin(ISSUE, rig.h.request, rig.state, b"recipient")
    else:
        submission = rig.h.prepare(rig.flow.challenge(ISSUE))
        rig.flow.finish(ISSUE, submission)
    raise AssertionError("barrier not reached")


if __name__ == "__main__":
    main()
