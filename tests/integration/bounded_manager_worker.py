"""TEST ONLY application barrier; parent SIGKILL, no power/storage failure simulation."""

# ruff: noqa: E402

import hashlib
import json
import resource
import select
import signal
import sys
from pathlib import Path

resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
signal.alarm(10)
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bounded_manager_cases import OP, Material, Policy, store

from pqdid.bounded_manager import BoundedDurableManager
from pqdid.persistence import sqlite_store
from pqdid.persistence.codec import decode
from pqdid.persistence.records import HeadTicket, WriterPermit
from pqdid.revocation_state import RevocationRequest
from pqdid.statements import decode_state


def main():
    root, point = Path(sys.argv[1]), sys.argv[2]
    material = Material()
    authority = store(root, material, Policy())
    ticket = HeadTicket(*decode((root / "ticket.pql").read_bytes()))
    owner = BoundedDurableManager(
        authority,
        WriterPermit(b"writer", ticket.generation),
        ticket,
        signing_key=material.manager_key,
    )
    cp = decode((root / "bootstrap.pql").read_bytes())
    rid, nonce, signature = decode((root / "request.pql").read_bytes())
    request = RevocationRequest(
        rid, decode_state(material.pp, cp.state.state).reference, nonce, signature
    )

    def barrier(label):
        if label != point:
            return
        evidence = {"barrier": label, "committed": label == "commit-before-ack"}
        if evidence["committed"]:
            # TEST coordinator independently retains the exact committed head before
            # killing the worker. Not automatic admission from self-consistency.
            with authority._connection() as c:
                c.execute("BEGIN")
                committed, _, _, _, ops = authority._load(c)
                evidence["ticket"] = [
                    committed.sequence,
                    committed.digest.hex(),
                    committed.checkpoint.hex(),
                    committed.generation,
                ]
                evidence["response_sha256"] = hashlib.sha256(ops[OP][2]).hexdigest()
        print(json.dumps(evidence), flush=True)
        assert select.select([sys.stdin], [], [], 8)[0], "barrier deadline"
        raise AssertionError("parent must kill; no continuation authorised")

    sqlite_store._fault = barrier
    owner.revoke(OP, request)
    raise AssertionError("expected application barrier was not reached")


if __name__ == "__main__":
    main()
