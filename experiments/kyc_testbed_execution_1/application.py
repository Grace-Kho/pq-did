"""Connected local disclosed baseline. No anonymous proof or network service.

The DID registry is the existing in-memory reference service. Durable authority and
baseline stores retain their original admission contracts. This coordinator supplies
trusted issuer policy; it does not change signed messages or claim cross-store ACID.
"""

import hashlib
from dataclasses import replace

from experiments.kyc_milestone_1.baseline.records import require
from experiments.kyc_milestone_1.baseline.scenario import Scenario, _OwnerGate
from experiments.kyc_milestone_1.baseline.signing import Key
from pqdid.did_state import (
    DIDConfiguration,
    DIDStatus,
    ReferenceDIDController,
    ReferenceDIDRegistry,
    ReferenceDIDResolver,
)
from pqdid.recovery_records import Role
from pqdid.schema import decode_attributes, encode_attributes
from pqdid.signing_adapters import (
    ControllerSigningAdapter,
    RegistrySigningAdapter,
    TrustedSigningKey,
)


class Application:
    @classmethod
    def create(cls, root):
        self = cls()
        material = Scenario.material()
        self.material = material
        pp = material.pp
        pair = Key.generate()
        config = DIDConfiguration(pp, b"G" * 32, pair.public)
        key = TrustedSigningKey(pp, b"G" * 32, Role.REGISTRY, b"G", pair.public, pair.secret)
        adapter = RegistrySigningAdapter(key, config=config, authorisation=_OwnerGate(key))
        self.registry = ReferenceDIDRegistry(config, signer=adapter._bridge())
        self.resolver = ReferenceDIDResolver(config, self.registry)

        def current(did):
            return next(
                (chain[-1] for name, chain in self.registry.snapshot() if name == did), None
            )

        self.controllers = []
        for i in (4, 5):
            pair = material.keys[i]
            key = TrustedSigningKey(
                pp, bytes([i]) * 32, Role.CONTROLLER, b"C" + bytes([i]), pair.public, pair.secret
            )
            self.controllers.append(
                ControllerSigningAdapter(
                    key,
                    config=config,
                    expected_public_key=pair.public,
                    current_record=current,
                    authorisation=_OwnerGate(key),
                )
            )
        self.controller = ReferenceDIDController(
            self.resolver, material.keys[4].public, b"S" * 32, signer=self.controllers[0]._bridge()
        )
        require(self.controller.publish() is DIDStatus.CONFIRMED, "did-bootstrap")
        initial = self.controller.snapshot()
        answer = self.resolver.resolve(pp, initial.did)
        require(answer.status is DIDStatus.ACTIVE, "did-resolution")
        values = list(decode_attributes(pp.schema, material.attributes))
        values[pp.schema.did_index - 1] = initial.did
        values[pp.schema.version_index - 1] = initial.version
        attributes = encode_attributes(pp.schema, tuple(values))
        material = replace(
            material,
            attributes=attributes,
            fixture_sha256=hashlib.sha256(
                attributes + bytes.fromhex(material.fixture_sha256)
            ).hexdigest(),
        )
        self.scenario = Scenario.create(root, material=material)
        self.did, self.version = initial.did, initial.version
        return self

    def issue(self):
        """Trusted application admission, before reservation and certification.

        There is no caller-selectable DID/key/instance. Existing baseline enrolment
        proves possession of the pinned controller/holder key. Rotation requires a
        new explicit approved issuer intent; old attributes are never silently changed.
        """
        answer = self.resolver.resolve(self.scenario.pp, self.did)
        require(answer.status is DIDStatus.ACTIVE and bool(answer.chain), "did-not-active")
        record = answer.chain[-1]
        require(record.version == self.version, "did-version-changed")
        require(
            record.body.controller_key == self.scenario.holder.public_key,
            "holder-controller-binding",
        )
        values = decode_attributes(self.scenario.pp.schema, self.scenario.data.attributes)
        require(
            values[self.scenario.pp.schema.did_index - 1] == self.did
            and values[self.scenario.pp.schema.version_index - 1] == record.version,
            "certified-did-binding",
        )
        return self.scenario.issue()

    def rotate(self):
        return self.controller.publish(
            (1, 1),
            new_public_key=self.material.keys[5].public,
            new_signer=self.controllers[1]._bridge(),
        )

    def deactivate(self):
        return self.controller.publish((0, 0))
