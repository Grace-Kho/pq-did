"""Twenty-two prospective actual-identity cases. Never executed by static validation."""

import os
import socket
import time
from pathlib import Path

from control import admit, bootstrap, client, ctl, finish_client, head, rpc, shutdown, start, stop
from layout import (
    CONFIG,
    RELEASE,
    ROLES,
    RUN,
    STATE,
    atomic_json,
    check,
    json_bytes,
    read_bytes,
    read_json,
    write_new,
)

OP, ISSUE = b"o" * 32, b"i" * 32


def fixture(role):
    from pqdid.persistence.codec import decode

    return decode(read_bytes(STATE / "inputs" / (ROLES[role] + ".fixture")))


def verification(role):
    from pqdid.parameters import decode_parameters
    from pqdid.persistence.codec import decode
    from pqdid.statements import decode_context

    cp = fixture(role)
    values = decode(read_bytes(STATE / "inputs" / (ROLES[role] + ".public")))
    context = cp.state.challenges[0].context
    return (
        decode_context(decode_parameters(cp.parameters), context).session,
        context,
        values[1],
        values[2],
        values[3],
    )


def expected(role):
    from pqdid.persistence.codec import decode

    return decode(bytes.fromhex(read_json(STATE / "evidence/heads.json")[role]))


def remember(role, ticket):
    from pqdid.persistence.codec import encode

    path = STATE / "evidence/heads.json"
    rows = read_json(path) if path.exists() else {}
    rows[role] = encode(ticket).hex()
    atomic_json(path, rows)


def activate(role, *, fresh=False):
    from pqdid.persistence.codec import decode

    if fresh:
        bootstrap(role)
        remember(
            role,
            decode(read_bytes(STATE / "clients" / ("pqiso-o-" + role) / "bootstrap-result.bin")),
        )
    start(role)
    check(head(role) == expected(role), "retained-external-head-mismatch")
    remember(role, admit(role, expected(role)))


def refresh(role):
    # Called only after a deliberately successful authorised operation in this case.
    remember(role, head(role))


def private_paths(role):
    return [
        str(STATE / "stores" / role / "authority.sqlite3"),
        str(CONFIG / "owners" / role / "policy.json"),
        str(RUN / role / "owner.sock"),
    ]


def denied(account, paths):
    # Disposable leaves exercise actual unlink denial without risking retained DB history.
    leaves = []
    try:
        for name in paths:
            path = Path(name).parent / ".denial-probe"
            if path not in leaves:
                write_new(path, b"synthetic-permission-probe", mode=0o600)
                leaves.append(path)
        rows, _ = client(account, {"mode": "probe", "paths": paths})
        check(
            rows and all(row[2] != b"UNEXPECTED-ACCESS" for row in rows),
            "unexpected-cross-boundary-access",
        )
    finally:
        for path in leaves:
            if path.exists():
                path.unlink()


def permission_checks(role):
    for account in ("pqiso-w-" + role, "pqiso-admin", "pqiso-observer"):
        denied(account, private_paths(role))
    check(
        rpc(role, "replace", (OP, head(role)))[0:2] == (b"ERROR", b"denied"),
        "writer-admin-escalation",
    )
    check(rpc(role, "status", account="pqiso-observer")[0] == b"STATUS", "observer-status")
    check(
        rpc(role, "replace", (OP, head(role)), account="pqiso-observer")[1] == b"denied",
        "observer-escalation",
    )
    # Runtime/configuration denial is also checked by real UID open/access in ISO-RUNTIME.


def issue():
    from pqdid.persistence.codec import decode

    activate("m")
    activate("i", fresh=True)
    approved, issued = decode(read_bytes(STATE / "inputs/issued.fixture"))
    result = rpc(
        "i", "intent", (ISSUE, head("i"), b"pilot-session", approved, fixture("m").state.state)
    )
    check(result[:2] == (b"OUTCOME", b"INTENT"), "issuer-intent")
    for method, operation, extra in [
        ("attach", b"a" * 32, ()),
        ("pending", b"p" * 32, (b"n" * 32,)),
        ("claim", b"s" * 32, ()),
    ]:
        result = rpc("i", method, (operation, head("i"), ISSUE, *extra))
        check(result[0] in {b"OUTCOME", b"SIGNING"}, "issuer-transition")
    ticket = result[1]
    check(
        rpc("i", "certify", (b"c" * 32, ticket, ISSUE, issued, ticket))[:3]
        == (b"OUTCOME", b"CERTIFIED", b""),
        "issuer-certification",
    )
    refresh("i")
    return issued


def case(identifier):
    from pqdid.persistence.codec import decode, encode

    if identifier == "ISO-RUNTIME":
        for account in read_json(CONFIG / "creation.json")["identities"]:
            result, _ = client(account, {"mode": "runtime"})
            check(result[0] == b"RUNTIME", "runtime-failure")
        return
    if identifier.startswith("ISO-ROLE-"):
        role = identifier.removeprefix("ISO-ROLE-")
        if role == "i":
            issue()
        else:
            activate(role, fresh=True)
            if role == "m":
                result = rpc(role, "reserve", (OP, head(role), ISSUE, fixture(role).state.state))
                check(result[1] == b"ALLOCATED", "manager-allocation")
                check(rpc(role, "allocation-count") == (b"COUNT", 43), "manager-count")
            else:
                args = verification(role)
                check(
                    rpc(role, "verify", args)[1] == b"reference-model-accepted",
                    "verifier-acceptance",
                )
                check(rpc(role, "verify", args)[1] == b"unknown-challenge", "one-time-consumption")
            refresh(role)
        permission_checks(role)
        return
    if identifier.startswith("ISO-CROSS-"):
        source = identifier.removeprefix("ISO-CROSS-")
        target = "vb" if source == "va" else "va"
        activate(target)
        for kind in ("o", "w"):
            denied("pqiso-" + kind + "-" + source, private_paths(target))
            result, _ = client("pqiso-" + kind + "-" + source, {"mode": "raw", "role": target})
            check(result == (b"DAC-DENIED",), "verifier-channel-separation")
        return
    if identifier == "ISO-RECIPIENT":
        activate("m")
        activate("i")
        issued = decode(read_bytes(STATE / "inputs/issued.fixture"))[1]
        for account in ("pqiso-admin", "pqiso-w-i", "pqiso-observer"):
            check(
                rpc("i", "retrieve", (b"c" * 32,), account=account)[1] == b"denied",
                "recipient-permissions",
            )
        check(
            rpc("i", "retrieve", (b"c" * 32,), account="pqiso-rec-b")[1] == b"wrong-recipient",
            "recipient-binding",
        )
        check(
            rpc("i", "retrieve", (b"c" * 32, b"recipient-A"), account="pqiso-rec-b")[1]
            == b"bad-request",
            "recipient-field-substitution",
        )
        client(
            "pqiso-rec-a",
            {
                "mode": "drop",
                "role": "i",
                "token": "i:recipient-a",
                "operation": "retrieve",
                "arguments": encode((b"c" * 32,)).hex(),
            },
        )
        check(
            rpc("i", "retrieve", (b"c" * 32,), account="pqiso-rec-a") == issued, "exact-redelivery"
        )
        return
    if identifier in {"ISO-DAC-DENIED", "ISO-ACL-DENIED"}:
        activate("m")
        if identifier == "ISO-DAC-DENIED":
            check(
                client("pqiso-denied", {"mode": "raw", "role": "m"})[0] == (b"DAC-DENIED",),
                "transport-denial",
            )
            denied("pqiso-denied", private_paths("m"))
        else:
            stolen = read_json(CONFIG / "credentials/client-pqiso-admin.bin")["tokens"]["m:admin"]
            for value in ("00" * 32, stolen):
                for operation, args in [("status", ()), ("replace", (OP, head("m")))]:
                    check(
                        rpc("m", operation, args, injected_token=value)[1] == b"denied",
                        "capability-peer-denial",
                    )
        return
    if identifier == "ISO-FENCING":
        activate("m")
        start("m", replacement=True)
        request = {
            "mode": "connected",
            "role": "m",
            "token": "m:writer",
            "operation": "reserve",
            "arguments": encode((b"z" * 32, head("m"), b"j" * 32, fixture("m").state.state)).hex(),
        }
        client("pqiso-w-m", request, asynchronous=True)
        until = time.monotonic() + 0.3
        while not (STATE / "clients/pqiso-w-m/connected").exists():
            check(time.monotonic() < until, "fencing-barrier")
            time.sleep(0.001)
        ticket = admit("m", expected("m"), replacement=True)
        remember("m", ticket)
        write_new(
            CONFIG / "clients/pqiso-w-m/go",
            b"go",
            gid=read_json(CONFIG / "clients/pqiso-w-m/policy.json")["identity"]["gid"],
            mode=0o640,
        )
        check(finish_client("pqiso-w-m")[0][1] == b"fenced-writer", "connected-writer-not-fenced")
        check(
            rpc("m", "reserve", (b"z" * 32, ticket, b"j" * 32, fixture("m").state.state))[1]
            == b"fenced-writer",
            "old-owner-not-fenced",
        )
        return
    if identifier == "ISO-ROTATION":
        # Quiesce every affected owner/client before replacing immutable loaded bundles.
        activate("m")
        activate("i")
        account = "pqiso-rec-a"
        client(
            account,
            {
                "mode": "connected",
                "role": "i",
                "token": "i:recipient-a",
                "operation": "retrieve",
                "arguments": encode((b"c" * 32,)).hex(),
            },
            asynchronous=True,
        )
        stop("pqiso-client@pqiso-rec-a.service")
        stop("pqiso-owner@i.service")
        token = "i:recipient-a"
        old = read_json(CONFIG / "credentials/client-pqiso-rec-a.bin")["tokens"][token]
        new = os.urandom(32).hex()
        for name in ("owner-i.bin", "client-pqiso-rec-a.bin"):
            path = CONFIG / "credentials" / name
            value = read_json(path)
            value["tokens"][token] = new
            temporary = path.with_suffix(".rotation")
            write_new(temporary, json_bytes(value), mode=0o400)
            os.replace(temporary, path)
        activate("i")
        check(
            rpc("i", "retrieve", (b"c" * 32,), account=account, injected_token=old)[1] == b"denied",
            "old-token-not-revoked",
        )
        check(
            rpc("i", "retrieve", (b"c" * 32,), account=account)
            == decode(read_bytes(STATE / "inputs/issued.fixture"))[1],
            "rotated-redelivery",
        )
        return
    if identifier == "ISO-HOLDER":
        ids = read_json(CONFIG / "creation.json")["identities"]
        for account in ("pqiso-rec-a", "pqiso-rec-b"):
            path = STATE / "clients" / account / "wallet.fixture"
            write_new(
                path, b"synthetic-private-wallet", uid=ids[account]["uid"], gid=ids[account]["gid"]
            )
        denied("pqiso-rec-a", [str(STATE / "clients/pqiso-rec-b/wallet.fixture")])
        for role in ("va", "vb"):
            for kind in ("o", "w"):
                denied(
                    "pqiso-" + kind + "-" + role,
                    [
                        str(STATE / "clients/pqiso-rec-a/wallet.fixture"),
                        str(STATE / "clients/pqiso-rec-b/wallet.fixture"),
                    ],
                )
            check(len(verification(role)) == 5, "anonymous-request-shape")
        return
    if identifier == "ISO-FD":
        activate("m")
        check(client("pqiso-w-m", {"mode": "fds"})[0], "descriptor-inventory")
        result, _ = client("pqiso-w-m", {"mode": "rights", "role": "m", "token": "m:writer"})
        check(result[0] == b"ERROR", "ancillary-rights-not-refused")
        pid = (
            ctl("show", "pqiso-owner@m.service", "-p", "MainPID", "--value").stdout.strip().decode()
        )
        result, _ = client("pqiso-w-m", {"mode": "probe", "paths": ["/proc/" + pid + "/fd/0"]})
        check(all(r[2] != b"UNEXPECTED-ACCESS" for r in result), "cross-uid-fd-access")
        return
    if identifier.startswith("ISO-MISCONFIG-"):
        kind = identifier.removeprefix("ISO-MISCONFIG-")
        target = (
            CONFIG / "owners/m/policy.json"
            if kind == "peer-identity"
            else RUN / "m"
            if kind in {"socket-mode", "writable-parent"}
            else RELEASE / "owner_entry.py"
        )
        original = read_bytes(target) if kind == "peer-identity" else None
        mode = target.stat().st_mode & 0o7777
        fake = None
        try:
            if original is not None:
                cfg = read_json(target)
                cfg["identity"]["uid"] += 1
                target.write_bytes(json_bytes(cfg))
            elif kind == "socket-mode":
                fake = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                fake.bind(str(RUN / "m/owner.sock"))
                cfg = read_json(CONFIG / "owners/m/policy.json")
                os.chown(RUN / "m/owner.sock", cfg["identity"]["uid"], cfg["transport_gid"])
                os.chmod(RUN / "m/owner.sock", 0o600)
            else:
                os.chmod(target, mode | 0o002)
            result = ctl("start", "pqiso-owner@m.service", ok=False)
            check(result.returncode != 0, "misconfiguration-started")
            check(
                ctl("show", "pqiso-owner@m.service", "-p", "MainPID", "--value").stdout.strip()
                == b"0",
                "misconfiguration-listener",
            )
        finally:
            if fake is not None:
                fake.close()
                (RUN / "m/owner.sock").unlink()
            if original is not None:
                target.write_bytes(original)
            os.chmod(target, mode)
            ctl("reset-failed", "pqiso-owner@m.service", ok=False)
        return
    if identifier.startswith("ISO-RESTART-"):
        role = identifier.removeprefix("ISO-RESTART-")
        if role == "i":
            activate("m")
        start(role)
        check(head(role) == expected(role), "restart-external-head")
        op, args = (
            ("allocation-count", ())
            if role == "m"
            else ("retrieve", (b"c" * 32,))
            if role == "i"
            else ("verify", verification(role))
        )
        account = "pqiso-rec-a" if role == "i" else None
        check(
            rpc(role, op, args, account=account)[1] == b"not-admitted",
            "restart-active-without-admission",
        )
        remember(role, admit(role, expected(role)))
        result = rpc(role, op, args, account=account)
        if role == "m":
            check(result == (b"COUNT", 43), "restart-allocation")
        elif role == "i":
            check(
                result == decode(read_bytes(STATE / "inputs/issued.fixture"))[1], "restart-delivery"
            )
        else:
            check(result[1] == b"unknown-challenge", "restart-second-acceptance")
        permission_checks(role)
        return
    raise ValueError("unknown-case")


def run_case(identifier):
    from control import EVENTS, verify

    verify()
    result = {
        "case": identifier,
        "status": "incomplete",
        "actual_identities": True,
        "proofs": False,
        "zkvm_executions": False,
    }
    path = STATE / "evidence" / (identifier + ".json")
    check(not path.exists(), "case-already-executed-no-retry")
    atomic_json(path, result)
    try:
        case(identifier)
        shutdown()
        result["status"] = "comparisons-complete-outer-guard-pending"
    except Exception as error:
        result["failure_type"] = type(error).__name__
        raise
    finally:
        result["identity_observations"] = EVENTS
        atomic_json(path, result)
