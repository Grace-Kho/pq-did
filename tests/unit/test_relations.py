"""Complete composition, targeted failures, and explicit public/lifecycle boundaries."""

import inspect
from dataclasses import replace

import pytest

from pqdid import bounded_mldsa as mldsa
from pqdid.binding import create_binding
from pqdid.credentials import Certificate, Credential, cred_valid
from pqdid.expiry import is_unexpired
from pqdid.merkle import path_root, verify_non_revocation_path
from pqdid.policy import Equality, Policy, Range, make_policy
from pqdid.public_checks import enrol_public_ok, pub_ok, public_policy_ok, state_auth
from pqdid.relations import auth, auth_private, enrol
from pqdid.schema import decode_attributes, encode_attributes, project_attributes
from pqdid.statements import encode_auth_statement, encode_enrol_statement, validate_auth_statement
from pqdid.witnesses import EnrolmentWitness, encode_auth_witness

from .relation_cases import FIXTURE, INSTANCES, auth_case, enrol_case, parameters, path, state
from .sampler_streams import CountingReader, ball_stream, ntt_stream


def credential_for(pp, statement, witness):
    """Expose intermediate checks in tests so negatives fail the intended conjunct."""
    return Credential(
        Certificate(
            create_binding(pp.domain, witness.holder_secret, witness.attributes), witness.signature
        ),
        witness.attributes,
        witness.revocation_identifier,
        b"",
        statement.metadata,
    )


def with_state(statement, replacement):
    return replace(
        statement,
        state=replacement,
        context=replace(statement.context, state_reference=replacement.reference),
    )


@pytest.mark.parametrize("item", FIXTURE["authentication"], ids=lambda item: item["name"])
def test_full_relation_matches_independent_outcome(item):
    pp, statement, witness = auth_case(item["name"])
    assert pub_ok(pp, statement)
    assert public_policy_ok(pp, statement)
    assert cred_valid(pp, credential_for(pp, statement, witness), witness.holder_secret)
    assert auth(pp, statement, witness) is item["expected"]


@pytest.mark.parametrize("name", ["alpha-42", "alpha-43", "beta-42"])
def test_enrolment_and_stateless_public_checks(name):
    pp, statement, witness = enrol_case(name)
    assert enrol_public_ok(pp, statement, statement.approved_attributes)
    assert enrol(pp, statement, witness)
    assert not enrol(pp, statement, EnrolmentWitness(bytes(reversed(witness.holder_secret))))
    altered = replace(statement, binding=replace(statement.binding, holder_value=bytes(48)))
    assert enrol_public_ok(pp, altered, statement.approved_attributes)
    assert not enrol(pp, altered, witness)


def test_enrolment_approved_vector_is_checked_at_both_required_boundaries():
    pp, statement, witness = enrol_case()
    _, other, _ = enrol_case("alpha-43")
    # Existing B does not open to the changed public mapp.
    altered = replace(statement, approved_attributes=other.approved_attributes)
    assert not enrol(pp, altered, witness)
    assert not enrol_public_ok(pp, altered, other.approved_attributes)
    # A coherent B/mapp opens locally but does not match the issuer's external approval.
    altered = replace(
        altered, binding=create_binding(pp.domain, witness.holder_secret, other.approved_attributes)
    )
    assert enrol(pp, altered, witness)
    assert not enrol_public_ok(pp, altered, statement.approved_attributes)
    assert enrol_public_ok(pp, altered, other.approved_attributes)


@pytest.mark.parametrize("field", ["issuer_nonce", "revocation_identifier", "state"])
def test_enrolment_transcript_fields_are_not_extra_holder_secret_conditions(field):
    pp, statement, witness = enrol_case()
    value = {"issuer_nonce": b"Z" * 32, "revocation_identifier": 999, "state": state("updated")}[
        field
    ]
    changed = replace(statement, **{field: value})
    assert enrol(pp, changed, witness)
    assert enrol_public_ok(pp, changed, changed.approved_attributes)
    assert encode_enrol_statement(pp, changed) != encode_enrol_statement(pp, statement)
    # No allocation, pending-nonce or latest-state service was consulted.


def test_enrolment_state_authenticity_is_a_separate_public_check():
    pp, statement, witness = enrol_case()
    invalid_state = replace(statement.state, signature=bytes(3309))
    changed = replace(statement, state=invalid_state)
    assert enrol(pp, changed, witness)
    assert not enrol_public_ok(pp, changed, changed.approved_attributes)


@pytest.mark.parametrize("mask", range(64))
def test_all_disclosure_patterns_for_six_field_schema(mask):
    pp, statement, witness = auth_case()
    disclosed = tuple(i for i in range(1, 7) if mask & (1 << (i - 1)))
    # Independently slice the canonical fixed fields, not production projection.
    chunks, offset = [], 0
    for index, capacity in enumerate((171, 56, 1, 8, 2, 8), 1):
        if index in disclosed:
            chunks.append(witness.attributes[offset : offset + 2 + capacity])
        offset += 2 + capacity
    changed = replace(
        statement,
        disclosed=disclosed,
        disclosed_attributes=b"".join(chunks),
        context=replace(statement.context, policy=Policy(disclosed, ())),
    )
    assert auth(pp, changed, witness)


@pytest.mark.parametrize(
    "field", ["holder_secret", "attributes", "revocation_identifier", "signature"]
)
def test_mixed_credential_component_fails_signature_with_other_conjuncts_satisfied(field):
    pp, statement, witness = auth_case()
    _, _, other = auth_case("alpha-43-old-002c")
    mixed = replace(witness, **{field: getattr(other, field)})
    mixed = replace(mixed, path=path(mixed.revocation_identifier))
    changed = replace(
        statement,
        disclosed_attributes=project_attributes(pp.schema, mixed.attributes, statement.disclosed),
    )
    assert pub_ok(pp, changed) and public_policy_ok(pp, changed)
    assert verify_non_revocation_path(
        pp.domain, mixed.revocation_identifier, mixed.path, changed.state.root
    )
    assert not cred_valid(pp, credential_for(pp, changed, mixed), mixed.holder_secret)
    assert not auth(pp, changed, mixed)


def test_signature_for_other_issuer_fails_with_same_metadata_and_valid_path():
    pp, statement, witness = auth_case()
    _, _, other = auth_case("beta-42-old-002c")
    mixed = replace(witness, signature=other.signature)
    assert pub_ok(pp, statement) and public_policy_ok(pp, statement)
    assert verify_non_revocation_path(
        pp.domain, mixed.revocation_identifier, mixed.path, statement.state.root
    )
    assert not auth(pp, statement, mixed)


@pytest.mark.parametrize("damage", ["challenge", "zeros"])
def test_invalid_credential_signature_rejects_a_well_formed_witness(damage):
    pp, statement, witness = auth_case()
    signature = (
        bytes([witness.signature[0] ^ 1]) + witness.signature[1:]
        if damage == "challenge"
        else bytes(3309)
    )
    changed = replace(witness, signature=signature)
    assert len(encode_auth_witness(pp.schema, changed)) == 5329
    assert pub_ok(pp, statement) and public_policy_ok(pp, statement)
    assert verify_non_revocation_path(
        pp.domain, changed.revocation_identifier, changed.path, statement.state.root
    )
    assert not auth(pp, statement, changed)


def test_whole_genuine_other_credential_is_valid_but_partial_splices_are_not():
    pp, statement, witness = auth_case("alpha-43-old-0034")
    _, _, other = auth_case("alpha-42-old-0034")
    changed = replace(
        statement,
        disclosed_attributes=project_attributes(pp.schema, other.attributes, statement.disclosed),
    )
    # Country changes from GB to SG. This policy only requires the disclosed Boolean.
    assert auth(pp, changed, other)
    assert not auth(pp, statement, other)
    assert not auth(pp, changed, witness)


@pytest.mark.parametrize("kind", ["issuer_key", "manager_key", "metadata", "expected_instance"])
def test_expected_issuer_instance_and_state_key(kind):
    pp, statement, witness = auth_case()
    other = parameters("beta")
    if kind == "issuer_key":
        changed_pp = replace(pp, issuer_public_key=other.issuer_public_key)
        statement = replace(statement, parameters=changed_pp)
        assert pub_ok(changed_pp, statement)  # State remains valid; credential key is wrong.
        assert not auth(changed_pp, statement, witness)
    elif kind == "manager_key":
        changed_pp = replace(pp, revocation_public_key=other.revocation_public_key)
        statement = replace(statement, parameters=changed_pp)
        assert auth_private(changed_pp, statement, witness)
        assert not pub_ok(changed_pp, statement)
        assert not auth(changed_pp, statement, witness)
    elif kind == "metadata":
        assert not auth(pp, replace(statement, metadata=other.metadata), witness)
    else:
        assert not auth(other, statement, witness)


def test_nonuniform_path_substitution_reaches_path_check():
    pp, statement, witness = auth_case()
    substituted = path(0)
    assert path(0) != path(2)
    assert path_root(pp.domain, 2, 0, path(0)) != statement.state.root
    assert (
        path_root(pp.domain, witness.revocation_identifier, 0, substituted) != statement.state.root
    )
    mixed = replace(witness, path=substituted)
    assert pub_ok(pp, statement) and public_policy_ok(pp, statement)
    assert cred_valid(pp, credential_for(pp, statement, mixed), mixed.holder_secret)
    assert not auth(pp, statement, mixed)


def test_equal_paths_in_uniform_subtrees_are_legitimate():
    pp, statement, witness = auth_case("alpha-42-empty-0000")
    assert path(42, "empty") == path(43, "empty")
    assert auth(pp, statement, replace(witness, path=path(43, "empty")))


def test_revocation_reuses_surviving_credential_and_rejects_revoked_zero_leaf():
    pp, old, survivor = auth_case("alpha-43-old-002c")
    updated = with_state(old, state("updated"))
    updated_survivor = replace(survivor, path=path(43, "updated"))
    assert survivor.signature == updated_survivor.signature
    assert survivor.attributes == updated_survivor.attributes
    assert (
        encode_auth_witness(pp.schema, survivor)[:-960]
        == encode_auth_witness(pp.schema, updated_survivor)[:-960]
    )
    assert survivor.path != updated_survivor.path
    assert auth(pp, old, survivor)
    assert auth(pp, updated, updated_survivor)
    assert not auth(pp, updated, survivor)
    _, old_revoked, revoked = auth_case()
    current = with_state(old_revoked, state("updated"))
    revoked = replace(revoked, path=path(42, "updated"))
    assert pub_ok(pp, current) and public_policy_ok(pp, current)
    assert cred_valid(pp, credential_for(pp, current, revoked), revoked.holder_secret)
    assert path_root(pp.domain, 42, 1, revoked.path) == current.state.root
    assert path_root(pp.domain, 42, 0, revoked.path) != current.state.root
    assert not auth(pp, current, revoked)
    # Old correctly signed root remains mathematically valid even after this update.
    _, _, original = auth_case()
    assert auth(pp, old_revoked, original)


def test_disclosure_mismatch_fails_even_when_the_public_policy_is_satisfied():
    pp, statement, witness = auth_case()
    values = list(decode_attributes(pp.schema, witness.attributes))
    values[3] = 4  # The fixture public range is 2..4, while certified value is 3.
    false_values = encode_attributes(pp.schema, values)
    changed = replace(
        statement,
        disclosed_attributes=project_attributes(pp.schema, false_values, statement.disclosed),
    )
    assert pub_ok(pp, changed) and public_policy_ok(pp, changed)
    assert cred_valid(pp, credential_for(pp, changed, witness), witness.holder_secret)
    assert verify_non_revocation_path(
        pp.domain, witness.revocation_identifier, witness.path, changed.state.root
    )
    assert not auth(pp, changed, witness)


def test_unsatisfied_public_policy_does_not_change_private_predicate():
    pp, statement, witness = auth_case()
    policy = make_policy(pp.schema, statement.disclosed, (Equality(3, False),))
    changed = replace(statement, context=replace(statement.context, policy=policy))
    assert pub_ok(pp, changed)
    assert auth_private(pp, changed, witness)
    assert not public_policy_ok(pp, changed)
    assert not auth(pp, changed, witness)


@pytest.mark.parametrize(
    "field,value",
    [
        ("audience", b"different-audience"),
        ("session", b"different-session"),
        ("nonce", b"!" * 32),
        ("expires_at", 0),
        ("expires_at", (1 << 64) - 1),
    ],
)
def test_transcript_only_context_fields_change_encoding_without_relation_rejection(field, value):
    pp, statement, witness = auth_case()
    changed = replace(statement, context=replace(statement.context, **{field: value}))
    assert auth(pp, changed, witness)
    assert encode_auth_statement(pp, changed) != encode_auth_statement(pp, statement)
    # A stateless reference call does not register/consume this context.
    assert auth(pp, changed, witness)
    if field == "expires_at" and value == 0:
        assert not is_unexpired(value, now=0)


def test_satisfied_policy_mutation_changes_statement_and_stays_at_public_layer():
    pp, statement, witness = auth_case()
    policy = make_policy(pp.schema, statement.disclosed, (Range(4, 1, 5),))
    changed = replace(statement, context=replace(statement.context, policy=policy))
    assert auth(pp, changed, witness)
    assert encode_auth_statement(pp, changed) != encode_auth_statement(pp, statement)


@pytest.mark.parametrize("damage", ["signature", "wrong_role", "epoch", "root"])
def test_state_auth_failure_is_public_and_cannot_be_skipped(damage):
    pp, statement, witness = auth_case()
    state_value = statement.state
    if damage == "signature":
        state_value = replace(state_value, signature=bytes(3309))
    elif damage == "wrong_role":
        state_value = replace(
            state_value,
            signature=bytes.fromhex(INSTANCES["alpha"]["states"]["old"]["wrong_role_signature"]),
        )
    elif damage == "epoch":
        state_value = replace(state_value, epoch=state_value.epoch + 1)
    else:
        state_value = replace(state_value, root=bytes(48))
    changed = with_state(statement, state_value)
    assert validate_auth_statement(pp, changed) is None
    assert not state_auth(pp, state_value)
    assert not pub_ok(pp, changed)
    if damage != "root":
        assert auth_private(pp, changed, witness)
    assert not auth(pp, changed, witness)


@pytest.mark.parametrize(
    "field,value",
    [
        ("holder_secret", bytes(31)),
        ("attributes", bytes(1023)),
        ("attributes", b"\xff" * 1024),
        ("revocation_identifier", 1 << 20),
        ("revocation_identifier", True),
        ("signature", bytes(3308)),
        ("path", bytes(959)),
    ],
)
def test_malformed_witness_returns_false_at_reference_boundary(field, value):
    pp, statement, witness = auth_case()
    assert pub_ok(pp, statement)
    assert not auth(pp, statement, replace(witness, **{field: value}))


@pytest.mark.parametrize("value", [None, {}, b"", (), False])
def test_bad_record_types_are_rejections(value):
    pp, statement, witness = auth_case()
    assert not auth(pp, statement, value)
    assert not auth(pp, value, witness)
    assert not auth(value, statement, witness)
    pp, statement, witness = enrol_case()
    assert not enrol(pp, statement, value)
    assert not enrol(pp, value, witness)
    assert not enrol(value, statement, witness)


@pytest.mark.parametrize("target", ["credential", "state"])
@pytest.mark.parametrize(
    "bits,data,budget", [(128, ntt_stream(87), 1026), (256, ball_stream(200), 256)]
)
def test_actual_bounded_exhaustion_reaches_complete_authentication(
    monkeypatch, target, bits, data, budget
):
    pp, statement, witness = auth_case()
    assert auth(pp, statement, witness)
    real_reader = mldsa._shake_reader
    seed_prefix = (pp.issuer_public_key if target == "credential" else pp.revocation_public_key)[
        :32
    ]
    challenge = (witness.signature if target == "credential" else statement.state.signature)[:48]
    streams = []

    def reader(kind, seed):
        matching = seed[:32] == seed_prefix if kind == 128 else seed == challenge
        if kind == bits and matching:
            result = CountingReader(data)
            streams.append(result)
            return result
        return real_reader(kind, seed)

    monkeypatch.setattr(mldsa, "_shake_reader", reader)
    if target == "credential":
        assert pub_ok(pp, statement)  # Exhaustion is in CredValid, not the state precheck.
    assert not auth(pp, statement, witness)
    assert len(streams) == 1  # No restart/retry/uncapped fallback.
    assert streams[0].consumed == budget


def test_runtime_failure_propagates_without_acceptance(monkeypatch):
    pp, statement, witness = auth_case()

    def fail(*args):
        raise MemoryError("synthetic resource failure")

    monkeypatch.setattr(mldsa, "_shake_reader", fail)
    with pytest.raises(MemoryError):
        auth(pp, statement, witness)


def test_public_apis_do_not_receive_witness_and_full_relation_has_no_skip_mode():
    assert list(inspect.signature(auth).parameters) == [
        "expected_parameters",
        "statement",
        "witness",
    ]
    assert list(inspect.signature(pub_ok).parameters) == ["expected_parameters", "statement"]
    assert list(inspect.signature(public_policy_ok).parameters) == [
        "expected_parameters",
        "statement",
    ]
    assert list(inspect.signature(enrol).parameters) == [
        "expected_parameters",
        "statement",
        "witness",
    ]
