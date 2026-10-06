"""Complete same-witness experimental Rauth source; never a proof verifier.

Every hidden check is emitted. A gate/resource exception propagates without a
completed relation. No component's host reference result can become acceptance.
"""

from dataclasses import dataclass

from experiments.auth_relation_integration_1.merkle import non_revocation
from experiments.auth_relation_integration_1.mldsa_verify import verify_signature
from experiments.auth_relation_integration_1.statement import validate_prepared
from experiments.auth_relation_integration_1.stream import CountedEmitter
from pqdid.circuits.auth_parsing import link_disclosure, parse_auth_witness
from pqdid.circuits.control import Scope
from pqdid.circuits.signature_inputs import certified_message
from pqdid.witnesses import AUTH_WITNESS_BITS


@dataclass(frozen=True, repr=False)
class RelationOutputs:
    acceptance: object
    holder_value: tuple
    certified_message: tuple
    signature_valid: object
    non_revocation_root: tuple
    components: tuple


def emit_private(prepared, emitter, *, phase=None) -> RelationOutputs:
    """Use one parsed xH/m/rid/sigma/path throughout the complete conjunction."""
    validate_prepared(prepared)
    if len(emitter.inputs) != AUTH_WITNESS_BITS:
        raise ValueError("exactly 42,632 raw private witness bits required")
    scope = Scope(emitter)
    components = []

    def mark(name, before):
        components.append((name, before, emitter.counts.gates))
        if phase is not None:
            phase({"completed_components": tuple(components), "gates": emitter.counts.gates})

    before = emitter.counts.gates
    parsed = parse_auth_witness(scope, prepared.parameters.schema, emitter.inputs)
    link_disclosure(
        scope,
        prepared.parameters.schema,
        parsed,
        prepared.statement.disclosed,
        prepared.statement.disclosed_attributes,
    )
    mark("private-layout-and-same-attributes-disclosure", before)
    before = emitter.counts.gates
    message = certified_message(scope, prepared.parameters, prepared.statement.metadata, parsed)
    mark("same-holder-secret-and-certified-body", before)
    before = emitter.counts.gates
    signature = verify_signature(scope, prepared, parsed.signature, message.formatted_message)
    mark("complete-bounded-ML-DSA-65", before)
    before = emitter.counts.gates
    root, _matches = non_revocation(scope, prepared, parsed.identifier, parsed.siblings)
    mark("same-certified-rid-non-revocation", before)
    before = emitter.counts.gates
    acceptance = scope.output(())
    mark("joint-final-rejection", before)
    return RelationOutputs(
        acceptance,
        message.holder_value,
        message.certified_message,
        signature.valid,
        root,
        tuple(components),
    )


def compile_private(prepared, sink, limits):
    """Complete streamed Boolean boundary; the sink owns R1CS accounting.

    The full E(X) enters public_data. Public validation and policy have already
    passed independently and are rechecked by emit_private. A sink footer is
    written only when all private checks finish. Native memory admission remains
    separate and this function never creates an Aurora instance or proof.
    """
    sink.relation_progress = {"completed_components": (), "gates": 0}
    try:
        emitter = CountedEmitter(
            AUTH_WITNESS_BITS,
            limits=limits,
            sink=sink,
            public_data=prepared.encoded_statement,
        )
        result = emit_private(
            prepared,
            emitter,
            phase=lambda progress: setattr(sink, "relation_progress", progress),
        )
        circuit = emitter.finish(result.acceptance)
        return circuit, result
    except BaseException:
        sink.state = "incomplete"
        sink.descriptor = None
        raise
