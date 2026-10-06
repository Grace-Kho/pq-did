"""Retain at most 64 KiB per stream and bounded aggregate SDK phase observations."""

import json
import time

MARKERS = {
    "prove_session: exit_code": "execution_complete",
    "segment_preflight": "segment_preflight_start",
    "prove_segment_core": "segment_proof_start",
    "Proving lift:": "lift_start",
    "Proving lift finished:": "lift_complete",
    "Proving join: a.claim": "join_start",
    "Proving join finished:": "join_complete",
    "Proving resolve:": "resolve_start",
    "Proving resolve finished:": "resolve_complete",
    "Running prover": "recursion_prover_start",
}


def capture(stream, output, path):
    start = time.monotonic()
    first = bytearray()
    tail = bytearray()
    total = 0
    events = {}
    last = None
    # Each read is bounded even if a child emits a line without a newline.
    for line in iter(lambda: stream.readline(65536), b""):
        total += len(line)
        remaining = 49152 - len(first)
        if remaining > 0:
            first.extend(line[:remaining])
        tail.extend(line[max(remaining, 0) :])
        del tail[:-16384]
        text = line.decode("utf-8", errors="replace")
        for token, name in MARKERS.items():
            if token in text and ("DEBUG" in text or "INFO" in text):
                elapsed = time.monotonic() - start
                row = events.setdefault(name, {"count": 0, "first_seconds": elapsed})
                row.update(count=row["count"] + 1, last_seconds=elapsed)
                last = name
                tmp = path.with_suffix(".new")
                tmp.write_text(
                    json.dumps(
                        {
                            "events": events,
                            "bytes_seen": total,
                            "last_event": last,
                            "last_event_seconds": elapsed,
                            "note": "SDK log observations; seconds since capture start",
                        },
                        indent=2,
                    )
                    + "\n"
                )
                tmp.replace(path)
    output.write((first + tail).decode("utf-8", errors="replace"))
    output.flush()
    state = json.loads(path.read_text()) if path.exists() else {"events": events}
    state.update(
        bytes_seen=total,
        retained_bytes=len(first) + len(tail),
        middle_omitted_bytes=max(0, total - len(first) - len(tail)),
    )
    path.write_text(json.dumps(state, indent=2) + "\n")
