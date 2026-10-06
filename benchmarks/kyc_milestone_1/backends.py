"""Adapter to the real isolated baseline. Private proof operations intentionally absent."""

import time

BACKEND = "pqdid-mldsa-reference-1"
UNAVAILABLE_REASON = "complete private authentication backend not implemented"


def unavailable_operations():
    return [
        {
            "operation": name,
            "available": False,
            "seconds": None,
            "bytes": None,
            "reason": UNAVAILABLE_REASON,
        }
        for name in ("prove_auth", "verify_auth_proof")
    ]


class ReferenceBackend:
    def __init__(self, *, epoch_base):
        # Lazy loading lets schema checks execute without native library initialisation.
        from experiments.kyc_milestone_1.baseline.scenario import Scenario

        self._scenario_class = Scenario
        self.epoch_base = epoch_base
        start = time.monotonic_ns()
        self.material = Scenario.material(epoch_base)
        self.keygen_ns = time.monotonic_ns() - start
        self.scenario = None

    def capabilities(self):
        return {
            "backend": BACKEND,
            "issue": True,
            "present": True,
            "verify": True,
            "revoke_update": True,
            "private_auth": False,
            "disclosure": "complete attributes, DID/version, holder key, rid and path",
        }

    def setup(self, root, scenario):
        start = time.monotonic_ns()
        self.scenario = self._scenario_class.create(
            root, epoch_base=self.epoch_base, material=self.material
        )
        self.scenario.setup_for(scenario)
        return time.monotonic_ns() - start

    def issue(self):
        return self.scenario.run("ISSUE")

    def present(self, audience):
        if audience not in {"A", "B"}:
            raise ValueError("unknown verifier")
        return self.scenario.run("PRESENT-" + audience)

    def verify(self, request, presentation, *, audience="A"):
        if request.context.audience != self.scenario.verifiers[audience].audience:
            raise ValueError("wrong configured verifier audience")
        return self.scenario.verify(request, presentation)

    def revoke_update(self):
        return self.scenario.run("REVOKE-UPDATE")

    def storage_inventory(self):
        return self.scenario.storage_inventory()

    def cleanup(self):
        return self.scenario.cleanup()
