"""Exactly sixteen individually admitted public regressions, no retries."""

# ruff: noqa: E402

import base64
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = HERE.parents[1]
D = P / "docs/data/s3_aurora_transcript_regression_1"
sys.path.insert(0, str(HERE))
from reference_trace import expected, length_repair_expected
from transcript import BASE, GROUPED, Transcript, TranscriptError, reconstruct

from pqdid.codec import decode_record, encode_record
from pqdid.parameters import decode_parameters, encode_parameters
from pqdid.statements import decode_auth_statement, encode_auth_statement


def check(ok, reason):
    if not ok:
        raise AssertionError(reason)


def write(name, value):
    data = json.dumps(value, separators=(",", ":")) + "\n"
    check(len(data.encode()) < 65536, "result file capacity")
    (D / name).write_text(data)


def unique(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, "duplicate fixture key")
        result[key] = value
    return result


def fixture(name, field):
    path = P / "docs/data/s2_kyc_interoperability_contract_1/examples" / name
    with path.open("rb") as stream:
        data = stream.read(65537)
    check(len(data) <= 65536, "fixture read capacity")
    pins = json.loads((D / "reviewed-inputs.json").read_text())["sha256"]
    check(hashlib.sha256(data).hexdigest() == pins[str(path.relative_to(P))], "fixture pin")
    value = json.loads(data, object_pairs_hook=unique)["body"][field]
    check(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value), "base64url spelling")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    check(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value, "canonical base64url")
    check(len(raw) <= 32768, "canonical fixture capacity")
    return raw


def load_public():
    pp_bytes = fixture("instance.json", "parameters")
    pp = decode_parameters(pp_bytes)
    check(encode_parameters(pp) == pp_bytes, "parameters re-encoding")
    encoded = fixture("presentation-a.json", "statement")
    x = decode_auth_statement(pp, encoded)
    check(encode_auth_statement(pp, x) == encoded, "statement re-encoding")
    return pp, x, encoded


def run_valid(pp, x, *, grouped=False, root=None, message=None, swap=False):
    trusted = GROUPED if grouped else BASE
    t = Transcript.new(trusted, pp, x, 2)
    a = bytes(64) if root is None else root
    v = b"\x02" * 24 if message is None else message
    w = b"\x03" * 24
    messages = (v + w,) if grouped else ((w, v) if swap else (v, w))
    t.commit_round(0, (a, b"\x01" * 64), messages)
    for c in range(3):
        t.challenge(0, c)
    t.commit_round(1, (), (b"",))
    t.challenge(1, 0)
    t.commit_round(2, (), ())
    result = t.finish()
    replay, replay_result = reconstruct(trusted, pp, x, 2, t.records)
    check(replay.trace == t.trace and replay_result == result, "prover/verifier trace")
    check(replay.outputs == t.outputs and replay.state == t.state, "replay counters/values")
    return t, result


def serial(t, result):
    return {
        "states_and_blocks": [
            {"label": k, "value_hex": v.hex(), "input_bytes": len(p)} for k, p, v in t.trace
        ],
        "round_records_hex": [r.hex() for r in t.records],
        "mapped_outputs": [v.hex() if type(v) is bytes else v for v in t.outputs],
        "finish": [result[0].hex(), result[1]],
        "mode": t.mode,
        "all_preimages_equal_independent_oracle": True,
        "all_states_blocks_outputs_counters_equal_oracle": True,
        "prover_verifier_agreement": True,
    }


def valid_case(pp, x, encoded, **kw):
    oracle = expected(encoded, **kw)
    t, result = run_valid(pp, x, **kw)
    check(t.trace == oracle["trace"], "independent full preimages/states/blocks")
    check(t.records == oracle["records"], "independent round frames")
    check(t.outputs == oracle["outputs"] and result == oracle["finish"], "independent values")
    check(t.state.counter == 4 and t.state.next_round == 3 and t.mode == "FINISHED", "final phase")
    check(t.outputs[2] == 0, "zero-width index")
    return serial(t, result)


def rejected(t, operation):
    state, trace, records, outputs = t.state, t.trace, t.records, t.outputs
    try:
        operation()
    except TranscriptError as error:
        reason = str(error)
    else:
        raise AssertionError("unexpected acceptance")
    check(
        (t.state, t.trace, t.records, t.outputs) == (state, trace, records, outputs),
        "failed operation changed state or released partial material",
    )
    check(t.mode == "FAILED", "failure not sticky")
    try:
        t.challenge(0, 0)
    except TranscriptError:
        pass
    else:
        raise AssertionError("poisoned object reused")
    check(t.state == state and t.outputs == outputs and t.trace == trace, "poisoned side effect")
    return {
        "rejected": True,
        "reason": reason,
        "mode": t.mode,
        "prior_digest_retained": state.digest.hex(),
        "counter_retained": state.counter,
        "trace_entries_retained": len(trace),
        "no_partial_output": True,
        "subsequent_challenge_rejected": True,
    }


def run_case(number, shared):
    if number == 1:
        shared["public"] = load_public()
    pp, x, encoded = shared["public"]
    if number in (1, 2, 3, 4, 5, 7, 8):
        kw = {}
        if number == 3:
            nonce = bytes([x.context.nonce[0] ^ 1]) + x.context.nonce[1:]
            x = replace(x, context=replace(x.context, nonce=nonce))
            # Independent expected E: edit only the fourth context field in sealed E.
            parts = list(decode_record(encoded, "auth-statement"))
            context = list(decode_record(parts[2], "context"))
            context[3] = nonce
            parts[2] = encode_record("context", tuple(context))
            encoded = encode_record("auth-statement", tuple(parts))
            check(encode_auth_statement(pp, x) == encoded, "independent nonce-only E mutation")
        if number == 4:
            kw["root"] = bytes(63) + b"\x01"
        if number == 5:
            kw["message"] = b"\x02" * 23 + b"\x03"
        if number == 7:
            kw["swap"] = True
        if number == 8:
            kw["grouped"] = True
        outcome = valid_case(pp, x, encoded, **kw)
        if number == 1:
            shared["baseline"] = outcome
        elif number == 2:
            check(outcome == shared["baseline"], "fresh-session deterministic repeat")
        else:
            before = shared["baseline"]
            initial_same = outcome["states_and_blocks"][2] == before["states_and_blocks"][2]
            check(initial_same == (number in (4, 5, 7)), "initial binding boundary")
            check(outcome["finish"] != before["finish"], "fixed-vector full-state anomaly")
            if number in (4, 5, 7, 8):
                check(
                    outcome["round_records_hex"][0] != before["round_records_hex"][0],
                    "round content/order/boundary distinction",
                )
            outcome["observed_initial_state_equal_baseline"] = initial_same
            outcome["observed_final_state_equal_baseline"] = False
            outcome["mapped_equal_baseline"] = [
                a == b
                for a, b in zip(outcome["mapped_outputs"], before["mapped_outputs"], strict=True)
            ]
        return outcome
    if number in (9, 12):
        try:
            Transcript.new(BASE, pp, b"" if number == 9 else x, 1 if number == 12 else 2)
        except TranscriptError as error:
            return {"rejected": True, "reason": str(error), "usable_object_returned": False}
        raise AssertionError("initialisation unexpectedly accepted")
    if number == 16:
        # Source-faithful negative control, never imported by the EXP2 engine.
        state = b"\x20" * 64
        u, v = bytes(64), b"\x01" * 64
        old_u = hashlib.blake2b((state + u)[:64], digest_size=64).digest()
        old_v = hashlib.blake2b((state + v)[:64], digest_size=64).digest()
        check(old_u == old_v == hashlib.blake2b(state, digest_size=64).digest(), "old omission")
        repaired_u = hashlib.blake2b(state + u, digest_size=64).digest()
        repaired_v = hashlib.blake2b(state + v, digest_size=64).digest()
        check(repaired_u == length_repair_expected(state, u), "full-span independent U")
        check(repaired_v == length_repair_expected(state, v), "full-span independent V")
        check(state + u != state + v and repaired_u != repaired_v, "fixed-vector repair anomaly")
        return {
            "kind": "source-equation negative control; not native execution or forgery",
            "old_equal": True,
            "old_input_bytes": 64,
            "repaired_input_bytes": 128,
            "old_hex": old_u.hex(),
            "repair_u_hex": repaired_u.hex(),
            "repair_v_hex": repaired_v.hex(),
            "independent_incremental_oracle": True,
        }
    if number == 15:
        t, _ = run_valid(pp, x)
        return rejected(t, lambda: t.commit_round(3, (), ()))
    t = Transcript.new(BASE, pp, x, 2)
    roots, messages = (bytes(64), b"\x01" * 64), (b"\x02" * 24, b"\x03" * 24)
    if number == 6:
        return rejected(t, lambda: t.commit_round(1, (), (b"",)))
    if number == 10:
        return rejected(t, lambda: t.commit_round(0, (bytes(63), roots[1]), messages))
    if number == 11:
        return rejected(t, lambda: t.commit_round(0, roots, (b"\x02" * 23, messages[1])))
    t.commit_round(0, roots, messages)
    if number == 13:
        t.challenge(0, 0)
        return rejected(t, lambda: t.commit_round(1, (), (b"",)))
    check(number == 14, "unlisted case")
    return rejected(t, lambda: t.challenge(0, 1))


def main():
    check(os.environ.get("PQDID_PILOT_RUN") == "cases", "guard required")
    check(not (D / "case-ledger.json").exists(), "no repeats")
    config = json.loads((D / "config.json").read_text())
    for name, pin in json.loads((D / "execution-inputs.json").read_text())["sha256"].items():
        check(hashlib.sha256((P / name).read_bytes()).hexdigest() == pin, "execution input pin")
    guard_rows = json.loads((D / "run-ledger.json").read_text())
    opening = guard_rows[-1]["package_charged_before"]
    started = time.monotonic()
    ledger, shared = [], {}
    for number in range(1, 17):
        elapsed = time.monotonic() - started
        check(opening + elapsed + 0.15 + 10 <= 25, "completion reserve")
        check(elapsed + 0.15 < float(os.environ["PQDID_COMMAND_SECONDS"]) - 0.5, "case deadline")
        check(config["prior_test_invocations"] + len(ledger) < 402, "invocation ceiling")
        row = {
            "id": f"TR-{number:02d}",
            "status": "admitted",
            "seconds": None,
            "cumulative_invocation": 386 + number,
        }
        ledger.append(row)
        write("case-ledger.json", ledger)
        case_start = time.monotonic()
        try:
            outcome = run_case(number, shared)
            write(row["id"] + ".json", outcome)
            row.update(
                status="pass", seconds=time.monotonic() - case_start, evidence=row["id"] + ".json"
            )
            write("case-ledger.json", ledger)
        except Exception as error:
            row.update(
                status="failed",
                seconds=time.monotonic() - case_start,
                error_type=type(error).__name__,
                error=str(error)[:2000],
            )
            write("case-ledger.json", ledger)
            raise
    write(
        "case-summary.json",
        {
            "completed": True,
            "passed": 16,
            "admitted": len(ledger),
            "seconds": time.monotonic() - started,
            "implementation_layer": "isolated Python reimplementation",
            "native_patch_executed": False,
            "proofs": 0,
        },
    )
    print(json.dumps({"passed": 16, "cumulative_invocations": 402}))


if __name__ == "__main__":
    main()
