"""Write synthetic container examples once; no signing, proof or lifecycle execution."""

# ruff: noqa: E402

import base64
import json
import sys
from dataclasses import replace
from pathlib import Path

D = Path(__file__).resolve().parent
P = D.parents[2]
sys.path.insert(0, str(P))
from pqdid.credentials import Certificate, Credential, encode_credential
from pqdid.parameters import encode_parameters
from pqdid.schema import decode_attributes, decode_disclosed_attributes, encode_disclosure_mask
from pqdid.statements import (
    encode_auth_statement,
    encode_context,
    encode_enrol_statement,
    encode_state,
)
from pqdid.witnesses import encode_auth_witness
from tests.unit.relation_cases import auth_case, enrol_case

PROFILE = "pqdid-application-container-draft-1"


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def claims(pp, statement):
    values = decode_disclosed_attributes(
        pp.schema, statement.disclosed, statement.disclosed_attributes
    )
    return [
        {
            "index": str(index),
            "name": pp.schema.field(index).name,
            "type": {0: "bytes", 1: "boolean", 2: "uint64"}[pp.schema.field(index).type_code],
            "value": b64(value)
            if type(value) is bytes
            else str(value)
            if type(value) is int
            else value,
        }
        for index, value in values.items()
    ]


def write(name, kind, exposure, body, status):
    obj = {
        "profile": PROFILE,
        "kind": kind,
        "synthetic": True,
        "exposure": exposure,
        "evidenceStatus": status,
        "body": body,
    }
    with (D / "examples" / (name + ".json")).open("x") as stream:
        stream.write(json.dumps(obj, indent=2) + "\n")


def main():
    pp, statement, witness = auth_case()
    _, enrol, _ = enrol_case()
    credential = Credential(
        Certificate(enrol.binding, witness.signature),
        witness.attributes,
        witness.revocation_identifier,
        b"",
        pp.metadata,
    )
    attrs = decode_attributes(pp.schema, witness.attributes)
    did, version = attrs[pp.schema.did_index - 1], attrs[pp.schema.version_index - 1]
    parameters, state = b64(encode_parameters(pp)), b64(encode_state(pp, statement.state))
    write(
        "instance",
        "instance",
        "public-trusted-configuration",
        {"parameters": parameters},
        "Existing synthetic vector; obtain expected parameters independently",
    )
    write(
        "private-holder",
        "private-holder",
        "private-holder-only",
        {
            "credential": b64(encode_credential(pp, credential)),
            "authenticationWitness": b64(encode_auth_witness(pp.schema, witness)),
            "state": state,
        },
        "Private synthetic fixture, not a wallet storage format or secured W3C VC",
    )
    write(
        "issuance-request",
        "issuance-request",
        "private-issuer-holder-channel",
        {
            "session": b64(b"issue-example"),
            "did": b64(did),
            "version": b64(version),
            "attributes": b64(witness.attributes),
            "holderApproval": b64(witness.attributes),
            "evidence": b64(b"SYNTHETIC-EVIDENCE-NOT-AUTHORISED"),
        },
        "Example inputs only; no evidence or controller authorisation performed",
    )
    write(
        "enrolment-challenge",
        "enrolment-challenge",
        "private-issuer-holder-channel",
        {
            "parameters": parameters,
            "approvedAttributes": b64(enrol.approved_attributes),
            "identifier": str(enrol.revocation_identifier),
            "nonce": b64(enrol.issuer_nonce),
            "state": b64(encode_state(pp, enrol.state)),
        },
        "Existing vector, not a newly registered pending issuer challenge",
    )
    write(
        "enrolment-submission",
        "enrolment-submission",
        "private-issuer-holder-channel",
        {
            "statement": b64(encode_enrol_statement(pp, enrol)),
            "proof": None,
            "controllerSignature": None,
        },
        "NON-VERIFYING: missing enrolment proof and controller signature",
    )
    write(
        "issuance-delivery",
        "issuance-delivery",
        "private-original-recipient",
        {
            "credential": b64(encode_credential(pp, credential)),
            "identifier": str(witness.revocation_identifier),
            "path": b64(witness.path),
            "state": state,
        },
        "Fixture content only; no committed recipient outcome is claimed by this file",
    )
    for label in ("a", "b"):
        context = replace(
            statement.context,
            audience=("verifier-" + label).encode(),
            session=("session-" + label).encode(),
            nonce=label.encode() * 32,
        )
        current = replace(statement, context=context)
        write(
            "request-" + label,
            "presentation-request",
            "public-request",
            {
                "context": b64(encode_context(pp, context)),
                "state": state,
                "requestSignature": None,
                "sessionExpiresAtSeconds": str(context.expires_at),
            },
            "NON-VERIFYING: distinct illustrative context, no request signature",
        )
        write(
            "presentation-" + label,
            "presentation-submission",
            "public-disclosed",
            {
                "statement": b64(encode_auth_statement(pp, current)),
                "proof": None,
                "disclosedClaims": claims(pp, current),
            },
            "NON-VERIFYING: proof is null; ordinary adapter must reject before verification",
        )
    write(
        "verification-result",
        "verification-result",
        "private-verifier-application-channel",
        {
            "decision": "unsupported-proof-backend",
            "accepted": False,
            "challengeConsumed": False,
            "businessAction": "not-authorised",
        },
        "Illustrative result mapping, not a service response or cryptographic receipt",
    )
    write(
        "did-resolution",
        "did-resolution",
        "public-method-result",
        {
            "did": did.decode("ascii"),
            "selector": b64(b"\x01" + version),
            "document": b64(b'{"id":"' + did + b'"}'),
            "version": b64(version),
            "contentType": "application/did+json",
            "registryReply": None,
            "registrySignature": None,
        },
        "NON-VERIFYING: exact document shape only; authenticated method chain absent",
    )
    write(
        "revocation-state",
        "revocation-state",
        "public-authenticated-state",
        {"state": state, "currentNonce": None, "currentSignature": None},
        "Existing signed synthetic state; not a fresh nonce-bound current-state reply",
    )
    write(
        "updates-request",
        "updates-request",
        "public-namespace-epochs",
        {
            "namespace": b64(pp.namespace),
            "afterEpoch": str(statement.state.epoch),
            "targetEpoch": str(statement.state.epoch),
        },
        "Public same-epoch history request; no private rid or path argument",
    )
    write(
        "updates-response",
        "updates-response",
        "public-authenticated-history",
        {
            "status": "public-update-page",
            "startingState": state,
            "endpointState": state,
            "records": [],
            "requestedEpoch": str(statement.state.epoch),
            "nextEpoch": str(statement.state.epoch),
            "complete": True,
        },
        "Empty same-state page illustration; no claim of advancing or proving non-revocation",
    )
    summary = {
        "examples": 15,
        "generation_only": True,
        "new_signatures": 0,
        "proofs": 0,
        "lifecycle_executions": 0,
        "fixture": "tests/fixtures/relations_vectors.json",
        "auth_vector": "alpha-42-old-002c",
        "enrol_vector": "alpha-42",
        "schema": [
            {"index": i, "name": f.name, "type_code": f.type_code, "capacity": f.capacity}
            for i, f in enumerate(pp.schema.fields, 1)
        ],
        "disclosed_indices": list(statement.disclosed),
        "disclosure_mask": b64(encode_disclosure_mask(statement.disclosed, len(pp.schema.fields))),
        "session_expiry": str(statement.context.expires_at),
    }
    (D / "example-provenance.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
