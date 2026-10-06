"""Read-only access to independently framed and signed relation fixtures."""

import json
from pathlib import Path

from pqdid.parameters import decode_parameters
from pqdid.statements import decode_auth_statement, decode_enrol_statement, decode_state
from pqdid.witnesses import decode_auth_witness, decode_enrol_witness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / "tests/fixtures/relations_vectors.json").read_text())
INSTANCES = {item["name"]: item for item in FIXTURE["instances"]}
CREDENTIALS = {item["name"]: item for item in FIXTURE["credentials"]}


def parameters(name="alpha"):
    return decode_parameters(bytes.fromhex(INSTANCES[name]["parameters"]))


def auth_case(name="alpha-42-old-002c"):
    item = next(item for item in FIXTURE["authentication"] if item["name"] == name)
    pp = parameters(CREDENTIALS[item["credential"]]["instance"])
    return (
        pp,
        decode_auth_statement(pp, bytes.fromhex(item["statement"])),
        decode_auth_witness(pp.schema, bytes.fromhex(item["witness"])),
    )


def enrol_case(name="alpha-42"):
    item = next(item for item in FIXTURE["enrolment"] if item["credential"] == name)
    pp = parameters(CREDENTIALS[name]["instance"])
    return (
        pp,
        decode_enrol_statement(pp, bytes.fromhex(item["statement"])),
        decode_enrol_witness(bytes.fromhex(item["witness"])),
    )


def state(name="old", instance="alpha"):
    return decode_state(
        parameters(instance), bytes.fromhex(INSTANCES[instance]["states"][name]["encoded"])
    )


def path(identifier, tree="old", instance="alpha"):
    return bytes.fromhex(INSTANCES[instance]["states"][tree]["paths"][str(identifier)])
