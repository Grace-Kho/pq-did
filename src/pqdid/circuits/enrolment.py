"""Complete local enrolment relation circuit, provisional BC-1 recipe (SPEC-003).

No prover, state freshness or issuance authorisation is implemented here.
"""

from typing import BinaryIO

from pqdid.circuits.control import Scope
from pqdid.circuits.emitter import Circuit, Emitter, Limits
from pqdid.circuits.keccak import sha3_384
from pqdid.circuits.parsing import equal_bytes, holder_message, parse_enrolment_public, public_bytes
from pqdid.parameters import PublicParameters
from pqdid.statements import EnrolmentStatement, encode_enrol_statement


def compile_enrolment(
    pp: PublicParameters,
    statement: EnrolmentStatement,
    *,
    limits: Limits,
    mode: str = "materialised",
    sink: BinaryIO | None = None,
) -> Circuit:
    """Construct solely from public pp/X; exactly 256 private input positions.

    Public domain errors raise EncodingError; resource failure propagates. False
    public attribute equality is retained as a required check without skipping the
    private hash construction. All 32-byte secrets have a valid representation.
    """
    encoded = encode_enrol_statement(pp, statement)
    e = Emitter(256, limits=limits, mode=mode, sink=sink, public_data=encoded)
    scope = Scope(e)
    digest = sha3_384(e, holder_message(e, pp.domain, e.inputs))
    holder_ok = equal_bytes(e, digest, public_bytes(e, statement.binding.holder_value))
    attributes_ok = equal_bytes(
        e,
        public_bytes(e, statement.binding.attributes),
        public_bytes(e, statement.approved_attributes),
    )
    return e.finish(scope.output((holder_ok, attributes_ok)))


def compile_encoded_enrolment(
    pp: PublicParameters,
    encoded: bytes,
    *,
    limits: Limits,
    mode: str = "materialised",
    sink: BinaryIO | None = None,
) -> Circuit:
    statement, _ = parse_enrolment_public(pp, encoded)
    return compile_enrolment(pp, statement, limits=limits, mode=mode, sink=sink)
