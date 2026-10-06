"""Genuine disclosed baseline orchestration; no private-proof acceptance."""

from experiments.kyc_issuer_incremental_storage_1.journal import IssuerJournal
from experiments.kyc_manager_incremental_storage_1 import history
from experiments.kyc_manager_incremental_storage_1.integration import create
from experiments.kyc_milestone_1.baseline.holder import Holder
from experiments.kyc_milestone_1.baseline.verifier import Verdict
from pqdid.did_state import DIDStatus
from pqdid.statements import decode_state
from pqdid.verifier_state import ProofVerdict, UnsupportedProofVerifier
from pqdid.witness_updates import UpdateStatus


class Demo:
    def __init__(self, root):
        self.root, self.app, self.cache = root, None, {}

    def run(self, number):
        if self.app is None:
            assert number == 1
            self.app = create(self.root)
        app, cache = self.app, self.cache
        s = app.scenario
        if number == 1:
            cache["delivery"] = app.issue()
            assert s.holder.credential == cache["delivery"].credential
            assert app.resolver.resolve(s.pp, app.did).status is DIDStatus.ACTIVE
        elif number == 2:
            before = s.snapshot()
            j = s.issuer.journal
            # Retain the trusted ticket BEFORE reopen; never adopt a database's own head.
            s.issuer = s._issuer(IssuerJournal(j.path, j.identity, j.ticket, j.ticket[1]))
            h = s.holder
            s.holder = Holder(h.pp, h.path, h.clock, h.request_keys, h.approved_policy)
            assert s.issuer.retrieve(s.last_operation, b"holder") == cache["delivery"]
            assert s.snapshot() == before
        elif number in (3, 4):
            audience = "A" if number == 3 else "B"
            before = s.snapshot()
            req = s.request(audience)
            pres = s.present(req)
            assert s.verify(req, pres) is Verdict.ACCEPTED
            cache[audience] = req, pres
            after = s.snapshot()
            other = "B" if audience == "A" else "A"
            assert after["verifiers"][other] == before["verifiers"][other]
            assert (
                after["verifiers"][audience]["consumed"]
                == before["verifiers"][audience]["consumed"] + 1
            )
        elif number in (5, 6):
            before = s.snapshot()
            req, pres = cache["A"]
            result = s.verify(req, pres) if number == 5 else s.verifiers["B"].verify(req, pres)
            assert result is (Verdict.REPLAY if number == 5 else Verdict.MISMATCH)
            assert s.snapshot() == before
        elif number == 7:
            # Seven other revocations permit two pages, then own revocation is update eight.
            for _ in range(7):
                holder = s.add_holder()
                s.revoke(holder.credential.identifier)
            cache["target"] = decode_state(s.pp, s.manager.snapshot()[1].state.state)
            before = (s.holder.path / "wallet.bin").read_bytes()
            calls = []

            def fetch(namespace, epoch, target, *, limits):
                calls.append((namespace.hex(), epoch, target.epoch))
                if len(calls) == 2:
                    raise OSError("declared interrupted second public page")
                return history.page(s.manager, namespace, epoch, target, limits=limits)

            try:
                history.baseline_catch_up(s.holder, s.manager, cache["target"], fetch=fetch)
            except OSError:
                pass
            else:
                raise AssertionError("interruption not observed")
            assert len(calls) == 2 and (s.holder.path / "wallet.bin").read_bytes() == before
            cache["public_queries"] = calls
        elif number == 8:
            result, sizes, records = history.baseline_catch_up(s.holder, s.manager, cache["target"])
            assert result.status is UpdateStatus.UPDATED and len(records) == 7
            assert len(sizes) == 2 and max(sizes) <= 65536
            h = s.holder
            restored = Holder(h.pp, h.path, h.clock, h.request_keys, h.approved_policy)
            assert restored.credential == h.credential and restored.checkpoint == h.checkpoint
            cache["pages"] = sizes
        elif number == 9:
            before = (s.holder.path / "wallet.bin").read_bytes()
            target = s.revoke(s.holder.credential.identifier)
            result, sizes, records = history.baseline_catch_up(s.holder, s.manager, target)
            assert result.status is UpdateStatus.REVOKED and target.epoch == 8
            assert (s.holder.path / "wallet.bin").read_bytes() == before
        elif number == 10:
            before = s.snapshot()
            assert (
                UnsupportedProofVerifier().verify(None, b"not-a-proof") is ProofVerdict.UNSUPPORTED
            )
            assert not s.capabilities()["prove_auth"] and not s.capabilities()["verify_auth_proof"]
            assert s.snapshot() == before
        else:
            raise ValueError("unregistered demonstration case")
        return {
            "state": s.snapshot(),
            "pages": cache.get("pages", []),
            "public_queries": cache.get("public_queries", []),
            "signatures": "genuine bounded ML-DSA-65",
            "private_proofs": "unavailable",
            "store_versions": {"issuer": 2, "manager": 2},
            "storage": s.storage_inventory(),
        }
