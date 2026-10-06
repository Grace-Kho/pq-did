"""Transport faults preserve complete wallet state; no hidden-identifier requests."""

import shutil
from dataclasses import replace

from experiments.kyc_issuer_incremental_storage_1.cases import rejected
from experiments.kyc_manager_incremental_storage_1 import history
from experiments.kyc_manager_incremental_storage_1.integration import create
from experiments.kyc_milestone_1.baseline.holder import Holder
from experiments.kyc_milestone_1.baseline.verifier import Verdict
from pqdid.holder_wallet import Wallet
from pqdid.persistence.codec import decode, encode
from pqdid.statements import decode_state, encode_state
from pqdid.witness_updates import UpdateLimits, UpdateStatus


def fixture(root):
    app = create(root)
    app.issue()
    s = app.scenario
    for _ in range(8):
        holder = s.add_holder()
        s.revoke(holder.credential.identifier)
    return app


def copy_holder(source, path):
    path.mkdir(mode=0o700)
    for name in ("holder.key", "wallet.bin"):
        shutil.copyfile(source.path / name, path / name)
        (path / name).chmod(0o600)
    return Holder(source.pp, path, source.clock, source.request_keys, source.approved_policy)


def run(i, path, app, cache):
    s = app.scenario
    if i in (12, 13):
        from experiments.kyc_testbed_execution_1.fixtures import WalletFixture

        if "pq" not in cache:
            cache["pq"] = WalletFixture()
        f = cache["pq"]
        path.mkdir(mode=0o700)
        wallet = Wallet.create(f.pp, path / "wallet.sqlite3", b"H" * 32, f.accepted, f.secret)
        before = wallet.head
        original = wallet.snapshot()

        # Existing independent fixture supplies genuinely signed public states/update.
        # This is an explicitly synthetic transport, not a proof or manager-store test.
        def fetch(namespace, epoch, target, *, limits):
            assert (
                namespace == f.pp.namespace and epoch == f.states[0].epoch and target == f.states[1]
            )
            return encode(
                (
                    history.TAG,
                    namespace,
                    encode_state(f.pp, target),
                    encode_state(f.pp, f.states[0]),
                    encode_state(f.pp, target),
                    f.records,
                )
            )

        if i == 12:
            result, sizes = history.wallet_catch_up(wallet, before, f.states[1], fetch)
            assert (
                result.status is UpdateStatus.UPDATED
                and wallet.snapshot().witness.path == f.expected_path
            )
            assert (
                wallet.snapshot().credential == original.credential
                and wallet.head.sequence == before.sequence + 1
            )
        else:
            records, _ = history.collect(f.pp, f.states[0], f.states[1], fetch)
            _, plan = wallet.prepare_update(before, f.states[1], records)
            other = Wallet(f.pp, path / "wallet.sqlite3", b"H" * 32)
            recovery = other.prepare_recovery(before, f.states[0])
            other.commit(recovery)
            rejected(lambda: wallet.commit(plan))
            assert other.snapshot() == original
        return dict(
            private_reference_wallet=True,
            records=1,
            transport="synthetic bounded public response with genuine signed fixture",
            proof="unavailable",
            all_or_nothing=True,
        )
    source = s._other_holders[0] if i == 11 else s.holder
    holder = copy_holder(source, path)
    before = (holder.credential, holder.checkpoint, (path / "wallet.bin").read_bytes())
    target = decode_state(s.pp, s.manager.snapshot()[1].state.state)
    requests = []
    saved = []

    def fetch(namespace, epoch, state, *, limits):
        requests.append((namespace.hex(), epoch, state.epoch))
        raw = history.page(s.manager, namespace, epoch, state, limits=limits)
        values = list(decode(raw))
        saved.append(raw)
        if i == 2 and len(saved) == 2:
            raise OSError("missing second page")
        if i == 3 and len(saved) == 2:
            return saved[0]
        if i == 4:
            values[5] = tuple(reversed(values[5]))
        if i == 5:
            values[2] = values[3]
        if i == 6:
            values[1] = b"wrong"
        if i == 7:
            return bytes(65537)
        if i == 8:
            return raw[:-1]
        if i == 9:
            values[4] = values[3]
        if i == 10:
            values[4] = values[3]
            values[5] = ()
        return encode(tuple(values))

    if i == 17:
        from experiments.kyc_milestone_1.baseline.scenario import _OwnerGate
        from pqdid.signing_adapters import ManagerSigningAdapter

        key = s.trusted[b"M"]
        signer = ManagerSigningAdapter(key, authorisation=_OwnerGate(key))

        def signed(state):
            sig = signer.state(s.pp, replace(state, signature=bytes(3309)))
            return replace(state, signature=sig.signature)

        alternate = signed(holder.checkpoint.state)
        assert alternate.reference == holder.checkpoint.state.reference
        assert alternate.signature != holder.checkpoint.state.signature
        holder._commit(holder.credential, replace(holder.checkpoint, state=alternate))
        target = signed(target)
    if i in (1, 11, 15, 16, 17):
        result, sizes, records = history.baseline_catch_up(holder, s.manager, target, fetch=fetch)
        if i == 11:
            assert result.status is UpdateStatus.REVOKED
            assert (
                holder.credential,
                holder.checkpoint,
                (path / "wallet.bin").read_bytes(),
            ) == before
        else:
            assert result.status is UpdateStatus.UPDATED and holder.checkpoint.state == target
            assert len(records) == 8 and len(sizes) == 2 and max(sizes) <= 65536
            restored = Holder(
                holder.pp, path, holder.clock, holder.request_keys, holder.approved_policy
            )
            assert restored.checkpoint == holder.checkpoint and restored.credential == before[0]
            if i in (15, 16):
                audience = "A" if i == 15 else "B"
                request = s.request(audience)
                holder.approved_policy = request.context.policy
                presentation = holder.present(request)
                assert s.verify(request, presentation) is Verdict.ACCEPTED
        return dict(
            status=result.status.value,
            page_bytes=sizes,
            records=len(records),
            public_requests=requests,
            holder_identifier_transmitted=False,
            atomic_wallet=True,
        )
    elif i == 14:
        raw = history.page(s.manager, s.pp.namespace, 0, target, limits=UpdateLimits(1, 11162))
        assert len(decode(raw)[5]) == 1 and len(raw) <= 65536
        rejected(
            lambda: history.page(
                s.manager, s.pp.namespace, 0, target, limits=UpdateLimits(1, 11161)
            )
        )
    else:
        try:
            history.baseline_catch_up(holder, s.manager, target, fetch=fetch)
        except (OSError, ValueError) as error:
            reason = type(error).__name__
        except Exception as error:
            from pqdid.persistence.codec import Unavailable

            assert isinstance(error, Unavailable)
            reason = str(error)
        else:
            raise AssertionError("corrupt page accepted")
        assert (holder.credential, holder.checkpoint, (path / "wallet.bin").read_bytes()) == before
        return dict(
            expected_rejection=reason, public_requests=requests, wallet_bytes_unchanged=True
        )
    assert (holder.credential, holder.checkpoint, (path / "wallet.bin").read_bytes()) == before
    return dict(lowered_limits_preserved=True)
