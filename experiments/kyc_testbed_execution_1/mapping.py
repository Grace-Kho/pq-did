"""Approved project-local research projections; not a VC/DID cryptosuite.

All incoming metadata is matched to a projection of separately trusted canonical
objects. This is transport binding, never a cryptographic verification verdict.
The anonymous view contains only the existing public statement/disclosed fields.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from experiments.kyc_milestone_1.baseline.records import encode_credential
from pqdid.containers import ContainerError, _encode64, _json
from pqdid.did_state import DIDStatus, encode_did_record
from pqdid.parameters import encode_parameters
from pqdid.schema import decode_attributes, decode_disclosed_attributes, encode_schema
from pqdid.statements import encode_auth_statement

PROFILE = "pqdid-local-kyc-projection/1"
ISSUER = "https://issuer.kyc.example/"
VOCAB = "https://vocab.kyc.example/pqdid/v1#"
FIELDS = {
    "kycPassed": ("kycPassed", 1),
    "assuranceLevel": ("assuranceLevel", 2),
    "countryOfResidence": ("countryOctets", 0),
    "validUntil": ("validUntil", 2),
}


def need(value, code):
    if not value:
        raise ContainerError(code)


def date_time(seconds):
    need(type(seconds) is int and 0 <= seconds <= 253402300799, "date-range")
    return (
        (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


class LocalMapping:
    def __init__(self, parameters):
        self.pp = parameters
        self.instance = _encode64(encode_parameters(parameters))
        self.schema = hashlib.sha256(encode_schema(parameters.schema)).hexdigest()
        # Trusted exact field table: no caller-selected index or vocabulary.
        self.fields = {}
        for i, f in enumerate(parameters.schema.fields, 1):
            if i in (parameters.schema.did_index, parameters.schema.version_index):
                continue
            need(f.name in FIELDS and f.type_code == FIELDS[f.name][1], "unsupported-schema")
            self.fields[i] = FIELDS[f.name][0]

    def _base(self, kind):
        return dict(
            profile=PROFILE,
            kind=kind,
            status="local-unsecured-projection",
            issuer=ISSUER,
            vocabulary=VOCAB,
            instance=self.instance,
            schemaSha256=self.schema,
            issuerKey=_encode64(self.pp.issuer_public_key),
            issuerReference=_encode64(self.pp.issuer_reference),
        )

    def _claims(self, values):
        claims = []
        for i, value in sorted(values.items()):
            if i not in self.fields:
                # DID/version only if already explicitly disclosed; no extra holder key/id.
                name = "disclosedCanonicalField"
            else:
                name = self.fields[i]
            encoded = (
                _encode64(value)
                if type(value) is bytes
                else str(value)
                if type(value) is int
                else value
            )
            row = dict(index=str(i), term=VOCAB + name, value=encoded)
            if name == "validUntil":
                row["dateTime"] = date_time(value)
            claims.append(row)
        return claims

    def baseline(self, credential):
        raw = encode_credential(self.pp, credential)
        result = self._base("disclosed-baseline-credential")
        result.update(
            canonical=_encode64(raw),
            claims=self._claims(
                dict(enumerate(decode_attributes(self.pp.schema, credential.attributes), 1))
            ),
        )
        return result

    def anonymous(self, statement):
        need(statement.parameters == self.pp, "instance")
        raw = encode_auth_statement(self.pp, statement)
        result = self._base("anonymous-public-statement")
        result.update(
            canonical=_encode64(raw),
            claims=self._claims(
                decode_disclosed_attributes(
                    self.pp.schema, statement.disclosed, statement.disclosed_attributes
                )
            ),
            sessionExpiresAtSeconds=str(statement.context.expires_at),
        )
        return result

    def did(self, answer):
        """Only use an answer obtained by the trusted authenticated resolver."""
        need(
            answer.status
            in {DIDStatus.ACTIVE, DIDStatus.DEACTIVATED, DIDStatus.UNKNOWN, DIDStatus.UNAVAILABLE},
            "resolver-status",
        )
        result = dict(
            profile=PROFILE,
            kind="local-did-resolution",
            status=answer.status.value,
            document=None,
            localKey=None,
        )
        if answer.status is DIDStatus.ACTIVE:
            need(bool(answer.chain) and answer.document is not None, "resolver-shape")
            record = answer.chain[-1]
            result["document"] = {"id": record.body.did.decode("ascii")}
            result["localKey"] = dict(
                encoding="local-raw-ML-DSA-65/base64url",
                publicKey=_encode64(record.body.controller_key),
                version=_encode64(record.version),
                recordSha256=hashlib.sha256(encode_did_record(record)).hexdigest(),
            )
        return result

    def validate_baseline(self, data, credential):
        return self._validate(data, self.baseline(credential))

    def validate_anonymous(self, data, statement):
        return self._validate(data, self.anonymous(statement))

    def validate_did(self, data, answer):
        return self._validate(data, self.did(answer))

    def _validate(self, data, expected):
        """Expected is computed by trusted application from its canonical object.

        No network fetch, dynamic key lookup, proof deserialisation or acceptance flag.
        Existing bounded duplicate/type/nesting JSON parser is reused.
        """
        actual = _json(data, "local-projection")
        # Exact canonical JSON equality also distinguishes bool/string types. Numeric JSON
        # tokens are already forbidden by the bounded parser, including bool-as-integer.
        need(
            json.dumps(actual, sort_keys=True, separators=(",", ":"))
            == json.dumps(expected, sort_keys=True, separators=(",", ":")),
            "projection-binding",
        )
        return expected


def encode_view(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
