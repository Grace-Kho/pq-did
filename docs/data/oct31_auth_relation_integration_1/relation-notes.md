# Complete authentication relation: source mapping for OCT31-AUTH-RELATION-INTEGRATION-1

Source inspection only, 29 September 2026. No relation, circuit, build, test or
proof was executed. This note supplements the coordinator's proposal; it grants
no execution allowance. Authority is manuscript Sections II–VIII, the agreed
clarifications and `docs/implementation_spec.md` R-024–R-037. The completed native
masking report's final dated appendix supersedes its retained earlier blocked
checkpoint; those native component results do not implement this relation.

## Exact relation and byte contracts

`src/pqdid/relations.py:auth` is the complete reference target:
`pub_ok(pp,X) AND auth_private(pp,X,w) AND public_policy_ok(pp,X)`.
`auth_private` reconstructs exactly one credential from the witness, invokes
`cred_valid`, checks a zero-leaf path for its certified identifier, and compares
the projection of its attributes with the disclosed attributes. There is no
proof, clock, current-state access, trust decision or challenge consumption inside
this timeless predicate.

Public `X = (pp, metadata, context, state, disclosed, disclosed_attributes)` uses
the existing `statements.encode_auth_statement`. Its six framed fields are
`E(pp), E(metadata), E(context), E(state), E(D), mD`. Context is the existing
eight-field record containing suite, audience, session, nonce, policy, issuer
reference, state reference and expiry. Parameters contain the suite, issuer
reference, namespace, issuer and revocation public keys, and schema. Repeated
schema, metadata, issuer, namespace, disclosure and state references must agree
exactly. Preserve `PQ-DID-MITH-1` inside all these existing objects; an experimental
proof identifier is a separate proof-layer identifier.

Private input is exactly the existing 5,329-byte `AuthenticationWitness`, with
no new credential field or externally supplied verification token:

| Bytes [start,end) | Meaning | Private input bit positions |
| --- | --- | --- |
| [0,32) | holder secret | [0,256) |
| [32,1056) | canonical 1,024-byte attributes | [256,8448) |
| [1056,1060) | unsigned big-endian rid, required below 2^20 | [8448,8480) |
| [1060,4369) | 3,309-byte ML-DSA-65 signature | [8480,34952) |
| [4369,5329) | twenty consecutive 48-byte siblings, bottom upwards | [34952,42632) |

`witnesses.witness_bits` is MSB-first within bytes. Arithmetic words are LSB-first;
FIPS packed polynomials use little-endian bit interpretation. These are explicit
rewirings, not changed external encodings. Existing protocol framing is
length-prefixed ASCII tag, u32 field count and u32-prefixed fields; use existing
encoders rather than introducing a new signing format.

## Required component coverage

| Obligation | Reusable implementation | New isolated integration required |
| --- | --- | --- |
| Trusted public structure and policy | `parameters.validate_parameters_structure(expected=pp)`, `statements.validate_auth_statement`, `public_checks.pub_ok/public_policy_ok`, `policy.evaluate_policy` | Verifier wrapper independently reconstructs X from trusted configuration and pending challenge; never accepts supplied truth flags. These entirely public checks remain outside the private core as already specified. |
| Canonical private attributes and rid | `circuits/auth_parsing.py:parse_auth_witness`, `parse_attributes`, `link_disclosure`; reference `schema.py`, `witnesses.py` | Reuse all length/type/padding checks. BYTES length <= capacity; BOOLEAN exact one byte 0/1; UINT64 exact eight bytes; zero field/tail padding. Same attribute wires feed message and disclosure, same rid wires feed message and Merkle selection. |
| Holder binding and exact credential body | `circuits/signature_inputs.py:certified_message`; `binding.py`, `credentials.build_mcred` | Constrain SHA3-384 of existing holder preimage, then B=(Y,m) and existing `cred` framing with suite, metadata, B and rid. Do not accept B, Y, Mcred or FIPS mu as independent advice. Y and B remain private. |
| FIPS framing/key/message preparation | `signature_inputs.decode_expected_public_key`, `message_representative`, `prepare_verifier_inputs` | Preserve pure ML-DSA prefix `0 || len(context) || context`, fixed `PQ-DID/credential/v1`, `tr=SHAKE256(pkI,64)`, `mu=SHAKE256(tr||formatted_message,64)`. Presentation context is not added to issuer Mcred. |
| Signature decoding/hints/norm | `circuits/signature.py:decode_responses`, `decode_hints`, `response_norm`; isolated approved hint candidate, subject to explicit profile choice | Keep c-tilde 48 bytes, five packed z polynomials, 55 index bytes plus six endpoints; monotone endpoints 0..55, strictly increasing positions within each row, zero unused padding. Strict norm is abs(z)<524092, distinct from valid 20-bit decoding. |
| Public matrix/key expansion | `bounded_mldsa._decode_public_key`, `_expand_a`, `_ntt`; verified public inputs only | All 30 SHAKE128(rho||column||row) samplers preserve separate 1,026-byte budgets and rejected-byte consumption. No invented rejection of valid 10-bit t1 values. Public preprocessing must be independently recomputed/checked by the verifier, never supplied as unconstrained prover constants. |
| Private challenge sampling | `bounded_mldsa._sample_in_ball` is the reference, no complete circuit exists | Constrain SHAKE256(private c-tilde) prefix and fixed masked Algorithm 29. One 256-byte budget includes eight signs plus at most 248 index bytes; rejected j>i consumes bytes. Constrain counters, indexed reads/writes, termination and exhaustion. This cannot be public preprocessing. |
| Complete polynomial verification | Reference `_ntt`, `_matrix_vector_product`, `_inverse_ntt`, `_decompose`, `_use_hint`, `_encode_w1`; partial `circuits/scalar_ring.py`; experimental forward-NTT kernels | Five private z forward transforms and one private challenge transform; six public t1 transforms; 30 pointwise matrix/vector products with accumulation, six c-hat/t1-hat products/subtractions, six inverse transforms, all 1,536 hint/decomposition operations, 768-byte w1 encoding. Inverse transform and complete joined verifier are not established by the forward pilot. |
| Final issuer verification | `_verify_internal`, `bounded_verify_mldsa65` | Constrain SHAKE256(mu||w1Encode,48), byte equality to the same c-tilde and strict z norm, together with every active rejection bit. Neither a host signature check nor a reconstructed challenge alone is the private relation. |
| Non-revocation | `merkle.path_root`, `verify_non_revocation_path`, existing SHA3 gadgets | Starting at the public zero-leaf hash, perform all twenty level-tagged SHA3-384 hashes with private siblings and private rid bit j selecting left/right at level j+1. Compare final root to the authenticated public state root. No host-created root or unrelated identifier. |
| Full result | `relations.auth`, `Scope.output` | Output acceptance only when all private checks and no active rejection hold; wrapper also requires PubOK and Ppub. Public state-auth exhaustion and private challenge exhaustion reject; unexpected runtime/resource failure means incomplete execution, never acceptance. |

The bounded verifier uses q=8380417,n=256,k=6,l=5,d=13,tau=49,
omega=55,gamma1=2^19,gamma2=(q-1)/32,beta=196. Its twiddles are ordinary
residues `1753^bitreverse8(i) mod q`, not Montgomery values. The inverse uses
descending twiddles with a minus sign and final multiplication by 8347681.
Publicly precomputable objects are matrix A, decoded pk/t1, NTT(2^13 t1), tr,
metadata encodings and zero leaf; every such value must derive from the exact
trusted X. Public preprocessing must reject bounded expansion exhaustion. It may
change measured work distribution, not accepted inputs or signature semantics.

512-byte RejBoundedPoly and 1,024 signing attempts belong to key generation/signing;
do not invent them as verification loops. Existing `_verify_diagnostic` distinguishes
INVALID and EXHAUSTED, while the public bounded verifier maps both to False.

## Concrete isolated source boundary

Propose new files only under `experiments/auth_relation_integration_1/`:

- `statement.py`: typed/canonical X admission and trusted public preprocessing,
  with immutable source/profile/parameter and preprocessing identities.
- `private_relation.py`: compose existing parsing/message/hash gadgets, complete
  new bounded ML-DSA and Merkle gadgets, and the final private acceptance bit.
- `mldsa_verify.py`: exact bounded challenge, matrix/vector, inverse transform,
  decomposition/hints, norm and hash comparison. Reuse approved experimental
  kernels only with their entry/output invariants and explicit profile labels.
- `r1cs.py` and `native/relation_adapter.cpp`: deterministic streamed conversion,
  witness assignment, checked native loading and actual libiop satisfaction.
- `cases.py`: individually enumerated relation, malformed-input, composition and
  native-loading comparisons; no synthetic accepted proof objects.

Exact public entry points should separate construction from assignment:
`prepare_public(expected_pp, X) -> PreparedPublic`,
`compile_private(prepared, sink, limits) -> CompletedRelationDescriptor`,
`assign_private(descriptor, raw_witness, limits) -> PrivateAssignment`,
`check_native(descriptor, expected_public_input, assignment) -> satisfaction`.
An aborted descriptor or partial assignment is never a completed relation.
Public data may select shape and public folding; witness values must never select
the emitted topology. Joined intermediates are identical variables or constrained
equalities, including range and validity state. Partitioning is only a storage or
evaluation technique unless all joined wires are represented in the final matrix.

For minimal reuse of today's constant-public Boolean gadgets, recommend a
**statement-specific** experimental matrix: derive all public constants from
the verifier's exact X; derive the matrix and its identifier independently on both
sides; bind complete E(X) as well as PID/RID in EXP2. Use one explicit public
acceptance variable fixed by the verifier to 1 and constrain private output to it
(primary input count one satisfies native K+1 being a power of two). Public X
need not be silently reclassified as private advice. This is not one reusable
universal matrix for all statements. A reusable shape-only matrix with symbolic
public X would require extra public-input plumbing absent from the current
Emitter; select that deliberately only if its added implementation is included.

## Binary-field R1CS and identity obligations

The selected experimental field is the already checked native `libff::gf192`,
polynomial basis modulo T^192+T^7+T^2+T+1, with 24-byte little-endian coefficient
encoding. Every private/free input bit needs `b*(b+1)=0`; AND is `a*b=c`, XOR
`(a+b)*1=c`, NOT `(1+a)*1=c`. Derived outputs are Boolean by induction; extra
free auxiliary bits need their own Booleanity rows. An acceptance equality and
fixed public value are required. A field element is not a 64-bit integer word or
an ML-DSA residue: carry, reduction, signed representative, quotient/remainder,
range and invalidity constraints remain necessary.

Map native column 0 to constant one (the libiop convention); Boolean Emitter wire
0 is constant zero, wire 1 constant one. Do not copy wire indices directly.
Number primary variables, raw private witness bits, derived wires and padding
deterministically. Encode matrices with sorted unique columns, combine terms in F,
remove zero terms and retain exact row/variable/public sizes, nnz and padding.
PID binds field, algorithms, contexts, caps and finite profile. RID binds compiler
revision, semantic/public shape, complete ordered matrices, counts, conversions
and padding, using the previously proposed proof-layer Fr/BLAKE2b identifiers.
Full E(X) enters transcript initialisation independently. Never use the internal
BC-1 development trace SHA-256 as though it were an adopted protocol commitment.

Native interfaces are
`libiop/relations/r1cs.hpp:r1cs_constraint_system<gf192>`,
`r1cs_constraint`, `linear_combination`, `is_satisfied`, and
`create_Az_Bz_Cz_from_variable_assignment`; later IOP consumption is through
`aurora_iop` and its existing encoded protocol, not a mock. Current native public
masking tests used zero matrices; they do not establish nontrivial full-relation
loading or assignment correspondence.

Source-visible admission traps must be handled explicitly: native
`linear_combination::is_valid` dereferences the last term of an empty sum and uses
`>=num_variables` on the final column; `is_satisfied(primary,aux)` depends on
asserts for lengths; A/B/C conversion uses `map.insert` rather than combining
duplicates. A new bounded loader must check exact lengths, inclusive column range
0..n, canonical sorted unique nonzero coefficients and empty sums before invoking
native arithmetic. Do not use that native validity routine as the sole validator,
rely on Release assertions, or feed duplicates into matrix conversion. Empty sums
are mathematically zero. Record these source limitations; this proposal does not
silently patch the pinned library.

## Service integration and security boundary

The eventual experimental proof adapter must reconstruct X from the existing
pending challenge and trusted pp, call PubOK/Ppub, validate the configured PID/RID,
and call a real admitted proof verifier. `verifier_state.UnsupportedProofVerifier`
continues to fail closed until that exists. A local native `is_satisfied` result
inspects private assignment and is not a presentation proof or service API.

Outside the timeless relation remain request signature, holder approval, issuer
trust, expected audience/session, strict trusted-time `now < expires_at`, current
state read, configured disclosed DID/version check and atomic single consumption.
Use the existing `verifier_state`/durable authority contracts unchanged. Credential
validity is a certified/disclosed application policy claim; generic Rauth does not
invent a hidden validUntil predicate or conflate it with session expiry. StateAuth
authenticates a supplied root but cannot make it current. The baseline's persistent
holder-key presentation signature is a separate reference profile and must not
replace the original private xH binding in this relation.

All-gate bit constraints give an equivalence route, not feasibility. Approved
23-bit/hint lowering is experimental, not BC-1. The measured 27,044,356-gate
forward transform is not a whole verifier, inverse-transform count, R1CS row
count or proof estimate. No complete authentication matrix, private proof or
finite secure Aurora profile currently follows from those measurements.

## Finite validation suggestions for the coordinator's counted matrix

Require distinct complete positive local comparisons for at least two statements
and disclosure policies; each compares reference `auth`, generated assignment and
actual native R1CS satisfaction. Include one changed context producing a new
statement/matrix/transcript identity while preserving the underlying credential.
Mutate independently xH, certified attributes, signature, rid and sibling path;
include a path from another valid credential to detect missing same-rid linkage.
Exercise attribute field/tail padding, BOOLEAN, UINT64 endpoints, rid high bits,
hint backward endpoint/duplicate index/nonzero padding, strict norm endpoint,
challenge mismatch and capped sampler exhaustion with test-only stream injection.
Count every distinct injected case. Sampler fixtures establish the gadget boundary,
not existence of an actual SHAKE seed giving the injected stream.

Add explicit malformed X, state-signature/context-reference/policy/disclosure
mismatches at the public wrapper; resource abort must return incomplete with no
relation acceptance. Challenge expiry/replay and stale state belong to distinct
service checks rather than being disguised as R1CS negatives. R1CS negatives
must include one non-Boolean free field value, changed intermediate, changed
acceptance, wrong public/private lengths, out-of-range/duplicate columns,
truncation, and a splice at a partition boundary. Reference expectations must not
call the lowering under test. Full accepted/rejected comparisons are needed in
addition to component fixtures; none of this finite coverage is a universal
compiler-equivalence or proof-security theorem.

Unresolved after successful relation integration: finite query/masking/security
parameters, private commitment/opening transformation, extraction/privacy,
concrete-hash composition, adaptive Delta_tail and production security. Native
correspondence or local satisfaction alone cannot close AURORA-BRIDGE-001.
