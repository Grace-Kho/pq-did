"""Synthetic DID fixtures: ordinary native test signing, NOT bounded production signing.

Private inputs stay in this harness. Controlled proof tokens remain labelled
reference verdicts; all new method signatures use the real bounded verifier.
"""

from dataclasses import replace

from pqdid.backend import load_backend
from pqdid.did_state import (
    DEFAULT_DID_LIMITS,
    READ_CONTEXT,
    RECORD_CONTEXT,
    ZERO_DIGEST,
    DIDBody,
    DIDConfiguration,
    DIDLifecycleProvider,
    DIDRecord,
    DIDStatus,
    IssuanceDIDAdapter,
    ReferenceDIDController,
    ReferenceDIDRegistry,
    ReferenceDIDResolver,
    RegistryReply,
    encode_body,
    make_did,
)
from pqdid.schema import decode_attributes, encode_attributes

from .issuance_cases import IssuanceAuthority, IssuanceHarness
from .revocation_state_cases import RecordingSigner
from .verifier_state_cases import NativeTestSigner, TestNonces


class DIDAuthority(IssuanceAuthority):
    def __init__(self):
        super().__init__()
        self.registry = NativeTestSigner(load_backend())
        self.rotated = NativeTestSigner(load_backend())
        self.config = DIDConfiguration(self.pp, b"G" * 32, self.registry.public_key)

    def close(self):
        self.registry.close()
        self.rotated.close()
        super().close()


class RecordingTransport:
    def __init__(self, registry):
        self.registry = registry
        self.reads, self.writes = [], []
        self.transform = lambda value: value

    def read(self, did, selector, nonce):
        self.reads.append((did, selector, nonce))
        return self.transform(self.registry.read(did, selector, nonce))

    def append(self, encoded, expected):
        self.writes.append((encoded, expected))
        return self.registry.append(encoded, expected)


class DIDHarness:
    def __init__(self, authority, *, limits=DEFAULT_DID_LIMITS):
        self.authority, self.config, self.pp = authority, authority.config, authority.pp
        self.signer = RecordingSigner(authority.registry)
        self.registry = ReferenceDIDRegistry(self.config, signer=self.signer, limits=limits)
        self.transport = RecordingTransport(self.registry)
        self.resolver = ReferenceDIDResolver(
            self.config, self.transport, nonces=TestNonces(), limits=limits
        )
        self.controller = ReferenceDIDController(
            self.resolver,
            authority.controller.public_key,
            b"s" * 32,
            signer=RecordingSigner(authority.controller),
        )
        self.did = self.controller.snapshot().did

    def record(self, previous=None, *, key=None, active=1, salt=b"s" * 32, signer=None):
        public_key = self.authority.controller.public_key if key is None else key
        did = make_did(self.config, public_key, salt) if previous is None else previous.body.did
        body = DIDBody(
            self.config.registry_id,
            did,
            0 if previous is None else previous.body.index + 1,
            ZERO_DIGEST if previous is None else previous.version[8:],
            public_key,
            active,
            salt,
        )
        return self.signed(body, signer)

    def signed(self, body, signer=None):
        signer = self.authority.controller if signer is None else signer
        return DIDRecord(body, signer.sign(encode_body(body), RECORD_CONTEXT))

    def reply(self, message):
        return RegistryReply(message, self.authority.registry.sign(message, READ_CONTEXT))

    def publish(self):
        assert self.controller.publish() is DIDStatus.CONFIRMED
        return self.registry.snapshot()[0][1][-1]

    def rotate(self):
        return self.controller.publish(
            (1, 1),
            new_public_key=self.authority.rotated.public_key,
            new_signer=RecordingSigner(self.authority.rotated),
        )

    def issuance(self):
        record = self.publish()
        h = IssuanceHarness(self.authority)
        values = list(decode_attributes(h.pp.schema, h.attributes))
        values[h.pp.schema.did_index - 1] = self.did
        values[h.pp.schema.version_index - 1] = record.version
        h.attributes = encode_attributes(h.pp.schema, values)
        h.request = replace(
            h.request,
            did=self.did,
            version=record.version,
            attributes=h.attributes,
            holder_approval=h.attributes,
        )
        h.authorisation.attributes = h.attributes
        h.issuer.resolver = IssuanceDIDAdapter(self.resolver)
        return h, DIDLifecycleProvider(self.resolver, h.manager)
