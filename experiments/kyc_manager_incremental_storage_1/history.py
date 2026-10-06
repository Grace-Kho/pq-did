"Public namespace/state pages and atomic holder catch-up; no holder-ID query."

from pqdid.codec import require_uint
from pqdid.parameters import validate_parameters_structure
from pqdid.persistence.codec import CAP, decode, encode, require
from pqdid.public_checks import state_auth
from pqdid.statements import decode_state, encode_state
from pqdid.witness_updates import (
    DEFAULT_UPDATE_LIMITS,
    UPDATE_RECORD_BYTES,
    UpdateLimits,
    decode_update,
)

TAG = b"kyc-public-history-v2"


def page(manager, namespace, after, target, *, limits=DEFAULT_UPDATE_LIMITS):
    """Return ONE bounded encoded local response for a fixed public target state.

    Internal allocation heads never cross this interface. The existing signed
    state and signed update chain authenticate the target and every page endpoint.
    """
    pp = manager.parameters
    require(type(limits) is UpdateLimits, "limits")
    limits.__post_init__()
    require(type(namespace) is bytes and namespace == pp.namespace, "namespace")
    require_uint(after, 64)
    require(state_auth(pp, target), "target-authentication")
    with manager._operation(), manager._admitted(manager.ticket) as (_, _, cp, _, _, _):
        base = decode_state(pp, cp.state.base_state)
        history = cp.state.history
        require(
            base.epoch <= after <= target.epoch <= decode_state(pp, cp.state.state).epoch,
            "epoch-range",
        )
        # The unchanged recovery validator has already authenticated complete stored history.
        states = (base, *(decode_update(pp, r).new_state for r in history))
        start = after - base.epoch
        stop = target.epoch - base.epoch
        require(states[stop].reference == target.reference, "target-state-binding")
        prefix = (TAG, namespace, encode_state(pp, target), encode_state(pp, states[start]))
        empty = encode((*prefix, encode_state(pp, states[start]), ()))
        # PQL1 byte-child framing is five bytes; all encoded states have fixed width.
        count = min(
            stop - start,
            limits.records,
            limits.encoded_bytes // UPDATE_RECORD_BYTES,
            (CAP - len(empty)) // (UPDATE_RECORD_BYTES + 5),
        )
        require(count > 0 or after == target.epoch, "page-limit")
        records = history[start : start + count]
        response = encode((*prefix, encode_state(pp, states[start + count]), records))
        require(
            len(response) <= CAP and sum(map(len, records)) <= limits.encoded_bytes, "response-cap"
        )
        return response


def collect(pp, starting, target, fetch, *, limits=DEFAULT_UPDATE_LIMITS):
    "All-or-nothing bounded collection; fetch receives only public information."
    validate_parameters_structure(pp)
    require(type(limits) is UpdateLimits, "limits")
    limits.__post_init__()
    require(state_auth(pp, starting) and state_auth(pp, target), "state-authentication")
    count = target.epoch - starting.epoch
    require(
        0 <= count <= limits.records and count * UPDATE_RECORD_BYTES <= limits.encoded_bytes,
        "total-admission",
    )
    records = []
    sizes = []
    current = starting
    # At most 16+1 page calls; zero-record response only for equal epochs.
    for _ in range(count + 1):
        raw = fetch(pp.namespace, current.epoch, target, limits=limits)
        require(type(raw) is bytes and len(raw) <= CAP, "response-cap")
        values = decode(raw)
        require(
            type(values) is tuple and len(values) == 6 and values[:2] == (TAG, pp.namespace),
            "page-shape",
        )
        require(encode(values) == raw, "canonical-page")
        _, _, encoded_target, encoded_start, encoded_end, items = values
        require(
            encoded_target == encode_state(pp, target)
            and decode_state(pp, encoded_start).reference == current.reference,
            "page-binding",
        )
        endpoint = decode_state(pp, encoded_end)
        require(
            state_auth(pp, decode_state(pp, encoded_start)) and state_auth(pp, endpoint),
            "transported-state-authentication",
        )
        require(type(items) is tuple and len(items) <= limits.records, "page-records")
        require(
            all(type(r) is bytes and len(r) == UPDATE_RECORD_BYTES for r in items), "record-width"
        )
        require(sum(map(len, items)) <= limits.encoded_bytes, "page-byte-limit")
        require(
            endpoint.epoch - current.epoch == len(items) and endpoint.epoch <= target.epoch,
            "page-progress",
        )
        previous = current
        for record in items:
            update = decode_update(pp, record)
            require(
                update.old_state.reference == previous.reference
                and update.new_state.epoch == previous.epoch + 1,
                "update-order",
            )
            previous = update.new_state
        require(previous.reference == endpoint.reference, "page-endpoint")
        require(len(records) + len(items) <= count, "total-records")
        records.extend(items)
        sizes.append(len(raw))
        current = endpoint
        if current.reference == target.reference:
            require(len(records) == count, "missing-history")
            return tuple(records), tuple(sizes)
        require(bool(items), "no-progress")
    raise ValueError("bounded history incomplete")


def baseline_catch_up(holder, manager, target, *, fetch=None):
    "Reuse the holder's full-batch validation and ONE durable wallet replacement."
    require(holder.checkpoint is not None, "no-holder-checkpoint")
    fetch = (lambda *args, **kw: page(manager, *args, **kw)) if fetch is None else fetch
    records, sizes = collect(holder.pp, holder.checkpoint.state, target, fetch)
    result = holder.apply(target, records)
    return result, sizes, records


def wallet_catch_up(wallet, expected, target, fetch):
    "Existing private PQ-DID reference wallet; no proof generation or verification."
    value = wallet.snapshot(expected)
    records, sizes = collect(wallet.parameters, value.state, target, fetch)
    result, plan = wallet.prepare_update(expected, target, records)
    if plan is not None:
        wallet.commit(plan)
    return result, sizes
