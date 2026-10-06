# S3-AURORA-TRANSCRIPT-CORRECTION-CONTRACT-1

**Proposed, not implemented or validated.** This contract is complete enough for
the narrowly scoped **S3-AURORA-TRANSCRIPT-REGRESSION-1** proposed below, after
explicit execution authorisation. It does not require another general review
before that public-input harness. It does not admit a private Aurora prototype,
apply an upstream patch or close **AURORA-BRIDGE-001**.

The two corrections are (1) absorbing the entire intended byte sequence, and
(2) explicitly binding the trusted protocol/profile, parameters, relation and
canonical public statement before challenges. These have different status: the
first repairs an input-length omission; the second, together with canonical
framing, is a separately identified transcript construction change. The broader
masking, commitment and security-transformation gaps are preserved.

## Authority and opening resources

Only manuscript Sections II–VIII and agreed SPEC-001–004 clarifications are
authoritative. The [bridge review](stage3_aurora_transcript_bridge.md), its pinned
source snapshot and the [construction contract](stage3_aurora_auth_construction_contract.md)
are reused. No broader literature review was repeated. Only the BCS construction
definition and the already selected BLAKE2b specification were revisited.

The [preflight](data/s3_aurora_transcript_correction_contract_1/preflight-evidence.json)
verifies the preceding 71-file seal
`ddfbc1f1b5fc3953eec5ead4e317f692efafea2b05c4d7e9e876a8cd66b906ce`,
all 53 assessed source identities, and manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The earlier source-access diagnostic, results and pending obligations remain sealed.

| Opening ledger | Treatment |
| --- | --- |
| Analysis | 80.00599182222504/300 s charged; **219.99400817777496 s available** |
| This package | Retain the proposed 20 charged seconds, ten-second reserve, measured documentation jobs plus five bookkeeping seconds |
| Implementation | **41.82321833795868 s untouched**, 332.1767816620413/374 s used |
| Invocations | **386/386**, no new tests, probes, builds or computed transcript vectors |
| Isolation | Safely stopped/unactivated; 22 original cases and 250.22 s untouched |
| Proofs | **Two attempts used, one unused**; CPU proving and raw-view integration paused |

Existing 256 MiB cgroup memory, zero swap, one worker, two CPUs, four controlled
processes, 60 s command/55 s child ceilings, 8 MiB temporary space, cumulative
10 MiB evidence, 1 MiB/file, 60 KiB command diagnostics and the 9 GiB storage stop
remain unchanged. Job reservations are smaller. The final section records actual
analysis consumption; no implementation or isolation allowance is borrowed.

## Confirmed data flow and scope of the findings

Base commit: **`a2ed2ec2f3e85f29b6035951553b02cb737c817a`**.
Source byte identities are retained in the bridge's
[main inventory](data/s3_aurora_transcript_bridge_1/sources.json) and
[supplement](data/s3_aurora_transcript_bridge_1/sources-supplement.json).
All paths below are under `libiop/` at that commit. The selected path is
non-holographic Aurora, native ZK, additive binary field and **BLAKE2b binary
digest hash chain**, rather than a custom caller-provided hash-chain class.
The draft proposes proven FRI/reducer analysis, binary localisation and no PoW;
the unchanged upstream default still contains PoW. No such configuration was run.

| Step / source function | Prover data flow | Verifier data flow and dependence |
| --- | --- | --- |
| `snark/aurora_snark.tcc:aurora_snark_prover/verifier` | Constructs BCS with BCS parameters; constructs/registers R1CS protocol; supplies primary and auxiliary input to `produce_proof` | Constructs BCS from parameters and transcript; registers same R1CS; calls transcript validity and `verifier_predicate(primary_input)` |
| `bcs/bcs_common.tcc:bcs_protocol`, lines 400–406 | Calls `parameters.hashchain_->new_hashchain()` | Same factory call; full public statement is not an argument |
| `bcs/hashing/blake2b.tcc:new_hashchain`, constructor | Constructs a fresh object using only `security_parameter`; state becomes D space bytes | Same; it does not copy an externally pre-seeded chain. `blake2b.hpp` initialises squeeze counter to zero |
| `bcs/bcs_prover.tcc:signal_prover_round_done/run_hashchain_for_round` | Commits current oracle tables; passes roots and all direct prover-message vectors to common round function | `bcs_verifier.tcc:seal_interaction_registrations` passes roots and direct vectors from the supplied transcript to that same common function |
| `bcs/bcs_common.tcc:run_hashchain_for_round/absorb_prover_messages` | Absorbs each current root, then hash of one zero field followed by current message fields concatenated together | Reconstructs this same sequence. Even a round with no direct messages absorbs a zero-field vector. Message boundaries are lost in the concatenation |
| `bcs/hashing/blake2b.tcc:absorb_hash_digest`, lines 51–65 | Builds state plus digest, passes only D input bytes to BLAKE2b | Same erroneous input length. Vector absorption first hashes native field bytes, then calls this function |
| `blake2b.tcc:squeeze/squeeze_query_positions` and `blake2b.cpp` | Increments counter; derives field values from state plus native counter, keyed by native element index; index extraction is keyed by counter | Same state/counters; field and index widths differ. Squeezing does not update the stored hash state |
| `bcs_common.tcc:squeeze_verifier_random_messages/obtain_random_query_position` | Calls the foregoing extractors in registration/query-handle order | Same ordering. PoW adds a root-type squeeze, but its answer is not absorbed in these callers |

For D-byte state S and D-byte digest u, the source's effective update is

`OLD(S,u) = BLAKE2b_D((S||u)[0:D]) = BLAKE2b_D(S)`.

That omission is **confirmed by source**. For fixed public registration shape,
number/order of absorptions and squeeze calls, varying the root or direct-message
contents cannot affect the chain through these absorptions. This conclusion is
independent of collision assumptions. It does not say that changing shape or
calling order leaves every challenge unchanged.

The minimal intended-behaviour repair is to retain output length D, pass
`hash_input.size()` as the input length, validate widths/length addition, compute
into a temporary digest and publish state only on success. It yields
`H_D(S||u)`, not the entire corrected transcript defined below. No edit has been
applied. [Pinned absorption source](https://raw.githubusercontent.com/scipr-lab/libiop/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/bcs/hashing/blake2b.tcc).

### Does another active path bind the statement?

The reviewed non-holographic call graph has no second statement-to-hash-chain
path: the fresh BLAKE2b factory retains only its security argument; BCS common
absorbs roots and message hashes; the prover/verifier wrappers do not pass primary
input or matrices to an initialisation absorption. The generic `iop.tcc` handles
registration, round counters and query dependencies, not BLAKE2b seeding. Its
shape-dependent registration is not byte-exact binding of statement values.
An externally seeded BLAKE2b instance would be replaced by the factory's fresh
object. Holographic indexes and alternative/custom hash-chain implementations
are outside this finding and must not be silently substituted.

**There is nevertheless an algebraic primary-input path.**
`aurora_iop::verifier_predicate(primary_input)` calls
`encoded_aurora_protocol::construct_verifier_state`, which calls
`fz_oracle_->set_primary_input(primary_input)` and constructs lincheck state.
The prover's witness/codeword computation also uses primary input. Matrices and
dimensions affect the relation and registrations. Thus the verifier's overall
decision is not established to be statement-independent. After the length repair,
statement-dependent commitments might also create indirect dependencies, but
that is not the explicit statement binding of the chosen BCS construction.

Accordingly, the precise second finding is **absence of explicit initial full
statement/relation binding in this selected hash-chain path**, not absence of
every form of statement binding in the whole protocol. Existing PQ-DID public
checks and canonical instance/context agreement still matter. No complete Aurora
authentication relation has been built, so there is no basis to assert that its
context is already constrained by some unimplemented arithmetic path.

The inferred consequence is failure to match the desired Fiat–Shamir/BCS
challenge-dependency contract. A transferable proof, forged credential or
successful malicious statement substitution is an **unexecuted attack hypothesis**,
not a result of this package. The report narrows the earlier shorthand without
rewriting historical evidence.

## Corrected transcript identity and exact encodings

Name the inactive variant **`PQDID-AURORA-TRANSCRIPT-EXP2`**, transcript version
**2**, with protocol identifier ASCII `PQDID-AURORA-AUTH`. This is a transcript
harness identity, not a new accepted proof family or a replacement for the signed
suite `PQ-DID-MITH-1`. No version-1 fallback is permitted. Normal proof adapters
are unchanged and fail closed; the future harness never returns a proof object.

Keep the draft's **unkeyed sequential BLAKE2b-512**, exactly 64 output bytes,
fanout/depth one and zero salt/personalisation parameters. This preserves the
selected primitive, but canonical unkeyed challenge expansion differs from
upstream's native-memory/keyed, variable-output extractors. It is an explicit
construction change, not a claim of byte compatibility. BLAKE2b internal word
order remains its specified order; application integers below are big-endian.
[RFC 7693, §§2–3](https://datatracker.ietf.org/doc/html/rfc7693).

Define `U_k(n)` as an unsigned integer in exactly k big-endian bytes. Reject
nonintegers, booleans, negatives and overflow. Define

`F(label;parts) = U_2(len(tag)) || tag || U_4(len(parts)) ||`
`concat(U_8(len(part)) || part)`,

where `tag=ASCII("PQDID-AURORA-TRANSCRIPT-EXP2/")+ASCII(label)`.
No NUL terminator, Unicode normalisation, varint or implicit string conversion.
Labels are exactly `profile`, `relation`, `statement`, `init`, `round`, `absorb`,
`challenge`. Each is used with only the arity specified below. Prefix/count/length
checks make component boundaries unambiguous; they do not make hashing injective.

The **trusted descriptor** contains nonempty parameter bytes P, nonempty relation
bytes A and a finite round/challenge plan. It is selected locally, never from proof
metadata. A future full profile's P must identify all adopted algorithm/field/domain,
repetition/masking/commitment selectors; A must identify the canonical relation,
compiler and ordered matrices. Those full-profile selectors remain unresolved.
The public harness uses the complete fixed synthetic descriptors below and makes
no claim to instantiate them. The engine hashes bytes verbatim; no JSON
serialisation or library default supplies their canonical form.

The plan encoding is:

`PLAN=U_4(R) || concat_r[U_4(r)||U_4(C_r)||U_4(J_r)||`
`concat_j U_4(n_rj)||U_4(K_r)||`
`concat_c(U_4(c)||U_1(kind_rc)||U_2(width_rc))]`.

Rounds and challenge IDs are consecutive from zero. C counts roots, J separate
direct-message vectors, n_j fields in each vector, K challenge **blocks**, one
per result. Kind 1 has width 192 and returns the first 24 block bytes as
little-endian polynomial-basis bits. Kind 2 has width h, `0<=h<=63`, and returns
`LE_integer(block) mod 2^h`; h=0 returns zero. No prime-field sampler, arbitrary
non-power-of-two domain, public challenge-width override or spare-byte pooling
is supported. The h range is the bounded harness's supported capacity, not a
new accepted authentication domain or a replacement for a full profile table.

`ROOTS=U_4(C)||root_0[64]||...||root_(C−1)[64]`.
`MSGS=U_4(J)||concat_j(U_4(n_j)||fields_j[24*n_j])`.
`RR=F("round";[U_4(r),ROOTS,MSGS])`.
Root order is oracle-registration order; messages and their fields retain exact
registration/coefficient order. An empty list encodes as four zero bytes. One
empty message encodes J=1,n_0=0 and is distinct from no messages. Empty lists and
vectors are accepted only where the trusted schedule declares them. An empty
scheduled round still changes the input to absorption; it must not be skipped.

The future Python interface takes `roots: tuple[bytes,...]` and
`message_vectors: tuple[bytes,...]`; each message byte string packs exactly its
declared n_j field elements, rather than native field objects. Reject lists,
mutable buffers and implicit conversions. Thus the baseline messages are
`(v0,v1)`, one empty vector is `(b"",)`, and no messages is `()`.
`replay_public_rounds(trusted,expected_pp,X,version,records)` accepts an immutable
tuple of canonical RR byte strings and returns only the diagnostic finish pair
after exact schedule and end-of-input checks. It cannot return proof acceptance.

### Public input and trusted selection

Use `E=encode_auth_statement(expected_pp,typed_X)` from the existing
[statements module](../src/pqdid/statements.py), with its validators and canonical
[codec](../src/pqdid/codec.py). E contains parameters, metadata, context, signed
revocation state, disclosure mask and disclosed attribute bytes. Context contains
the existing suite, audience, session, nonce, policy, issuer reference, state
reference and expiry. Instance, disclosure/policy and state-reference agreement
are checked against trusted expected parameters. Binding these bytes does not
authenticate state, enforce current freshness or replace the final expiry check.

Do not append hidden attributes, hidden identifier, credential signature, holder
secret/opening or sibling path. Public state signatures are already part of E;
private issuer credential signatures are not. Do not use an enrolment encoding,
container metadata or a caller-supplied Xtag as a replacement for E.

Derive `PID=H(F("profile";[U_2(2),PROTO,P,PLAN]))` and
`RID=H(F("relation";[A]))` from trusted bytes. Then
`XDOM=F("statement";[U_2(2),PROTO,PID,RID,E])`.
This binds parameters through their trusted content-derived PID, conditional on
the hash assumption; it is not permission for a caller to choose a new descriptor.
XDOM, including full E, enters both initialisation and challenge derivation.

The existing maximum encoded E length is `2^32−1`; it is not changed. A bounded
harness capacity refusal is separate from invalid credential semantics. Its
fixture files and E are checked against small public bounds before parsing or
copying. Current `encode_auth_statement` allocates its output; this contract does
not claim it streams arbitrarily large statements. The harness has fixed expected
parameters and bounded context/schema fields, not a general hostile-object API.

## Replacement pseudocode and state machine

The full [pseudocode](data/s3_aurora_transcript_correction_contract_1/transcript-pseudocode.txt)
also gives exact list encodings and failure semantics. Its operative equations are:

```text
new(trusted, expected_pp, X, version):
    require version == 2; validate trusted plan, public X and resource bounds
    derive PID, RID, E, XDOM as above
    S = H(F("init"; [XDOM]))
    next_round = 0; pending = none; next_challenge = 0; g = 0; mode = LIVE

commit_round(r, roots, message_vectors):
    require LIVE, r == next_round < R
    require every scheduled challenge of previous round consumed (vacuous initially)
    require exact trusted counts, lengths and ordering
    RR = F("round"; [U_4(r), ROOTS, MSGS])
    T = H(F("absorb"; [S, U_4(r), U_8(g), RR]))
    atomically set S = T, pending = r, next_challenge = 0, next_round = r+1

challenge(r, c):
    require LIVE, pending == r, c == next_challenge < K_r, g < 2^64-1
    (kind,width) = trusted.plan[r].challenge[c]
    B = H(F("challenge"; [XDOM,S,U_4(r),U_4(c),U_8(g),U_1(kind),U_2(width)]))
    value = B[0:24] if kind == 1 else LE_integer(B) mod 2^width
    atomically increment g and next_challenge; leave S unchanged
    return value

finish():
    require LIVE, all R rounds committed, final scheduled challenges consumed
    mode = FINISHED
    return diagnostic pair (S,g), never proof acceptance
```

No hash call uses a guessed digest length as its **input** length: feed every
frame byte in the displayed order, with the true input length or equivalent
streaming updates into a fresh H context. Do not finalise/restart hashing between
components. Finalise to exactly 64 bytes and check success before changing state.
The framing's checked length arithmetic precedes construction/allocation.

Squeezing advances explicit counters, not S. This deliberately avoids an extra
hash ratchet not present in the selected BCS-style state model. The next absorption
includes S and the consumed global counter g. Absorb-after-squeeze is permitted
only after the round's complete scheduled challenge list; a partial list cannot
be silently discarded. No reset, alternate label, challenge replay, clone to a
different statement or wraparound interface is exported. Identical fresh sessions
with identical public inputs intentionally yield identical transcripts.

On malformed input, unsupported version/kind, wrong phase, overrun, I/O failure,
hash failure or resource limit: publish no partial value/state; fail the operation
and poison the object. Prior state/counters may be retained in the **public
synthetic diagnostic** trace, but all subsequent operations fail. If initialisation
fails, there is no usable transcript. A finished object also refuses extra calls.
There is no automatic retry or old-version compatibility path.

The verifier uses its independently selected trusted descriptor, expected_pp and
typed X, and reconstructs the same round records. A future public-only replay
adapter decodes the F round frame with the fixed label/arity, exact counts/widths,
checked lengths and exact end of input; re-encoding must equal the input. It then
uses the same commit/challenge schedule. In a future IOP adapter, query-position
challenges must follow all required final direct messages. The synthetic plan
below uses a generic bounded index port to test mapping; its round-zero indices
are not Aurora query positions. Missing/extra rounds or bytes are errors, not
ignored metadata. The harness compares reconstructed states and blocks; a real
verifier would additionally need all unimplemented commitment and algebraic checks.

## Concrete edit list and theorem correspondence

The [explicit pseudo-diff](data/s3_aurora_transcript_correction_contract_1/proposed-edits.diff.txt)
separates the length-only diagnostic correction from EXP2 and from later IOP
integration. The pinned snapshot is never edited.

| Site / proposed interface | Required edit and classification |
| --- | --- |
| `blake2b.tcc:absorb_hash_digest` | Correct input span to the complete concatenation, widths/overflow checked, atomic output; restores intended local behaviour only |
| New isolated `Transcript.new/commit_round/challenge/finish` | Implement exact EXP2 bytes/state machine; replaces native-memory/vector-concatenation/keyed-counter conventions for this experiment; explicit version change |
| Future BCS common round adapter | Replace per-root/unframed vector calls with one ordered round record; preserve separate vectors and empty rounds; bind trusted registration plan. **Not part of the regression implementation** |
| Future Aurora wrapper | Initialise from trusted descriptor and validated full public X before any challenge; retain the existing algebraic primary-input path. **Not part of the regression implementation** |
| Future prover/verifier final phase | No PoW nonce, verification, solve or dummy squeeze; no work credit; recalculate IOP parameters before eventual integration. The narrow harness has no PoW interface |
| Normal PQ-DID proof backend | No edit, no registration and no new success object; EXP2 is unsupported there |

The selected primary construction is [BCS §6, construction T](https://eprint.iacr.org/2016/116.pdf):
it uses distinct randomness/hash oracle ports, initialises from x, hashes each
commitment with previous state, and derives verifier randomness from x and state.
Its verifier reconstructs this sequence. EXP2 restores those **dependencies**, with
the first Aurora prover round preceding its dependent challenge; it is not the
literal bit-oracle T byte format. BCS's initial verifier move may be empty for that
schedule; a future protocol with a nonempty pre-prover challenge needs an explicit
schedule extension, which EXP2 here does not silently invent.

| Question | What this correction establishes / still needs |
| --- | --- |
| Intended upstream update | Full-span correction includes u in H's input. It does not establish statement binding by itself |
| Prefix-free encoding | Tags, arities, fixed widths and component lengths give a unique parse; exact counts identify message boundaries. This is an encoding argument, not hash collision resistance |
| BCS-style initial/state/challenge dependency | XDOM enters initial state and every challenge; full roots/messages enter next state before dependent challenges; counters/plan identify requests |
| Exact transformation lemma | Still needed: map grouped roots and direct messages, labelled oracle ports, block expansion and schedule to T with explicit query costs and error terms. Hashing larger frames is not that lemma |
| Knowledge / privacy | Restricted state-restoration and round-by-round knowledge, joint masking/query simulation, commitments and adaptive application composition remain separate premises |
| Concrete primitive | BLAKE2b-512 remains concrete; no random-oracle instantiation theorem is established by deterministic regression traces |

The proposed framing can model disjoint labelled ports of one ideal oracle, but
the tuple/message compilation and challenge-expansion correspondence must still be
shown for the chosen protocol. Counters and labels prevent accidental identical
**preimages** for distinct scheduled requests; finite hash outputs can collide.
No numerical loss, overall bit-security or new extraction/privacy theorem is
claimed. BCS Theorem 7.1 and the bridge's separate CMS IOP route retain all their
premises. Query/masking, selective/grouped commitments, adaptive extraction/privacy,
concrete hash, component reduction budgets and adaptive Delta_tail remain open.

## Regression contract — executable only after authorisation

The future harness uses Python standard-library hashing and existing canonical
public-object modules; it does not import/build libiop/libff, sign, generate keys,
evaluate an authentication relation or construct a proof. Public roots/fields are
synthetic byte strings, not genuine commitments. The sealed snapshot supplies
provenance for a small **source-equation model** of the old omission.

Exact files proposed under `experiments/aurora_transcript_regression_1/`:

- `transcript.py`: EXP2 engine, strict public round-frame replay and typed-public-X
  adapter; no generic raw-message signing or proof-verification endpoint.
- `reference_trace.py`: independent straight-line framing/hash recipe and old
  span-equation model; no imports from the candidate engine/framer/scheduler.
- `cases.py`: exactly TR-01 through TR-16, sequential, one recorded case at a time.
- `README.md`: provenance, inactive-profile boundary and commands; bounded evidence
  and guard/audit helpers live under the matching `docs/data/` package directory.

Normal proof configuration cannot select this engine. Any eventual upstream fork
would require its own identified patch/release; this harness needs no checkout,
native ABI harness, dependency install or active profile edit.

### Fixed public inputs and independently reproducible expected traces

Use `body.parameters` from the historical synthetic
[instance example](data/s2_kyc_interoperability_contract_1/examples/instance.json)
as separately trusted expected_pp, and `body.statement` from
[presentation A](data/s2_kyc_interoperability_contract_1/examples/presentation-a.json)
as E. Their byte identities are in this package's
[reviewed inputs](data/s3_aurora_transcript_correction_contract_1/reviewed-inputs.json).
Bound file reads before JSON parsing; strictly decode canonical unpadded base64url,
decode using existing typed modules and require byte-exact canonical re-encoding.
Do not pass the surrounding null-proof container through as a proof. Its
`synthetic` or status flags confer no verification authority.

Trusted synthetic P is ASCII
`PUBLIC-HARNESS;F=2^192;rho=1/8;eta=1;pow=0;not-an-IOP`.
Trusted synthetic A is ASCII `PUBLIC-TRANSCRIPT-HARNESS-NOT-AUTHENTICATION`.
These literal descriptors are **not an authentication parameter/relation manifest**.
Use roots `A0=00^64`, `A1=01^64`, fields `v0=02^24`, `v1=03^24` (notation means
repeated bytes, not integer exponentiation). Plan:

| Round | Roots | Separate messages | Scheduled `(kind,width)` |
| --- | --- | --- | --- |
| 0 | A0, A1 | [v0], [v1] | (1,192), (2,8), (2,0) |
| 1 | none | one empty vector | (1,192) |
| 2 | none | no vectors | none |

The independently reproducible **expected trace is this exact straight-line
recipe**, not a digest guessed or evaluated in this source-only package:

```text
Compute PLAN, PID, RID, XDOM from the fixed inputs above using direct byte writes.
S_init = H(F("init"; [XDOM]))
RR0 = F("round"; [U4(0), U4(2)||00^64||01^64,
                  U4(2)||U4(1)||02^24||U4(1)||03^24])
S0 = H(F("absorb"; [S_init,U4(0),U8(0),RR0]))
B00 = H(F("challenge"; [XDOM,S0,U4(0),U4(0),U8(0),U1(1),U2(192)]))
B01 = H(F("challenge"; [XDOM,S0,U4(0),U4(1),U8(1),U1(2),U2(8)]))
B02 = H(F("challenge"; [XDOM,S0,U4(0),U4(2),U8(2),U1(2),U2(0)]))
RR1 = F("round"; [U4(1), U4(0), U4(1)||U4(0)])
S1 = H(F("absorb"; [S0,U4(1),U8(3),RR1]))
B10 = H(F("challenge"; [XDOM,S1,U4(1),U4(0),U8(3),U1(1),U2(192)]))
RR2 = F("round"; [U4(2), U4(0), U4(0)])
S2 = H(F("absorb"; [S1,U4(2),U8(4),RR2]))
finish = (S2,4)
```

`U4/U8/U1/U2` in this recipe mean U_k above. The independent oracle uses explicit
length-prefix concatenation and `hashlib.blake2b(...,digest_size=64)` with the
specified default sequential parameters. It may reuse the established primitive,
but **not** candidate framing, plan encoding, round transitions or mapping helpers.
Expected E uses sealed existing bytes, rather than a second shared new encoder.
Compare exact complete preimages in memory, all 64-byte states/blocks, counters,
mapped results and final status. Save full states/blocks plus fixture references
and preimage-comparison outcomes, not sixteen copies of large public X preimages.
This preserves reproducibility within the output cap without truncating results.

No expected digest has been computed here. TR-01 must compute and seal the oracle
trace inside its counted invocation, not via an uncounted vector-generation probe.
Mutation cases derive their oracle trace inside that case. TR-02 is the explicit
counted repeat, not an automatic retry. Candidate/replay/oracle comparisons within
one case are one documented case, not extra undisclosed parameter combinations.

| Counted ID | Exact case | Required outcome |
| --- | --- | --- |
| TR-01 | Complete baseline above | Candidate and independently reconstructed verifier trace equal the straight-line oracle at every stage; includes four challenges and valid absorb-after-squeeze, one empty vector and an empty round |
| TR-02 | Fresh second baseline invocation | Byte-identical full trace to TR-01; no timestamp, entropy or mutable counter leakage between instances |
| TR-03 | Flip bit 0 of first byte of typed context nonce, re-encode X | Exact new oracle trace; initial public input/frame changes; other typed fields unchanged |
| TR-04 | Flip bit 0 of last byte of A0 | S_init unchanged; first changed frame is RR0; all later states match oracle |
| TR-05 | Flip bit 0 of last byte of v0 | Same dependency assertion for prover-message contents |
| TR-06 | Submit round 1 first | Reject before hash/state publication; poisoned object; no challenge returned |
| TR-07 | Swap the two one-field message vectors | Shape remains valid; order-sensitive frame and expected trace match independent oracle |
| TR-08 | Second trusted synthetic descriptor uses one two-field R0 message | Same raw field concatenation, different J/n boundaries, PLAN/PID and exact trace. Compare RR bytes themselves to isolate the framing distinction |
| TR-09 | Supply empty bytes where typed public X is required | Structural/type rejection before initialisation; no usable state |
| TR-10 | A0 has 63 bytes | Width rejection before R0 update; no output |
| TR-11 | v0 has 23 bytes | Field/message-length rejection before R0 update; no output |
| TR-12 | Request transcript version 1 | Reject before initialisation, no fallback |
| TR-13 | Commit R1 after only challenge 0 of R0 | Reject; state/counters unchanged except FAILED status; cannot skip scheduled challenges |
| TR-14 | Request challenge 1 before challenge 0 | Reject before hashing; no out-of-order block |
| TR-15 | Append another round after baseline finish | Reject extra round and further processing; no conversion to proof success |
| TR-16 | Old equation versus length-only repair, S=20^64, u=00^64 and 01^64 | Old states both equal H(S). Repaired preimages are distinct full 128-byte strings and match independent H(S||u). This is a source-equation diagnostic, not a native execution or forgery |

For these fixed changed-input vectors, compare full states with the independent
oracle and report the observed equality/divergence; an unexpected full-state
collision/anomaly stops the package, without searching for replacements. Do not
assert that every input change must change every challenge. In particular the
scheduled width-zero index is **always zero** and must agree across mutations;
an 8-bit index can coincide as well. Counter/preimage/state correctness is the
relevant regression property. Finite examples are not a security theorem.

## Inactive implementation proposal and admission criteria

Propose **S3-AURORA-TRANSCRIPT-REGRESSION-1**, exactly the files and sixteen
individually counted cases above. Request an additional **16 invocations**,
ceiling **386 → 402**. Every attempted case, failure and explicitly authorised
repeat counts; no extra vector probes or parameterised batches. Execute cases
once in order, stopping on the first unexpected result. A batch launcher must
write an admission/outcome row for each case before advancing; it cannot report
sixteen passes when an inner case failed or was skipped.

No implementation-time increase is proposed: cap this package at **25 seconds**
from the existing **41.82321833795868 s**, leaving at least **16.82321833795868 s**
if fully charged. Preserve a **ten-second cleanup/evidence reserve**. Tentative
admission envelope: one second preflight, three seconds for the sequential case
group, one second total lint/format, one second scope preparation, four seconds
single preservation audit, five seconds bookkeeping, ten seconds reserve.
These are reservations/estimates, not measured harness performance; actual ledger
balance and headroom govern admission. No time is borrowed from analysis/isolation.

Use the same 256 MiB cgroup ceiling, zero swap, one worker/two CPUs/four controlled
processes, 60/55 s command/child maxima and existing disk limits. Smaller case
reservations apply; no worker/process hidden outside the guard. Within existing
ceilings, propose fixed fixture reads at most 64 KiB/file, E at most 32 KiB,
at most four rounds/four roots/four messages/four fields per message/four challenges
per round, and at most **256 KiB newly retained package evidence**. This bounds
the harness workload only. Continue the cumulative 10 MiB evidence ledger; if
the remaining capacity cannot fit, stop rather than dropping states or baselines.
No gate or circuit allowance is requested or consumed.

Acceptance is exact transcript behaviour, no partial output on failures and
source snapshot/production preservation. Preserve all discrepancies and stop on
resource exhaustion, incomplete trace, unexpected acceptance, wrong state/block,
version fallback, or insufficient reserve. No automatic reruns, budget transfers,
allowance increases or narrower hidden test substitutes. An uncompleted case is
not a pass. Lint/format and the single corrected preservation audit remain required.

This proposal is **inactive**. It is patch-ready for the public transcript harness
without another general review, but it does not authorise IOP integration, PoW
changes in libiop, a serializer for real proofs or private data processing. Passing
it would validate proposed corrections locally; AURORA-BRIDGE-001 would still
require the joint masking/commitment/compiler and adaptive security arguments.

## Preserved obligations and deliverables

New evidence comprises [correction metadata](data/s3_aurora_transcript_correction_contract_1/correction.json),
[pseudocode](data/s3_aurora_transcript_correction_contract_1/transcript-pseudocode.txt),
[pseudo-diff](data/s3_aurora_transcript_correction_contract_1/proposed-edits.diff.txt),
[sixteen inactive cases](data/s3_aurora_transcript_correction_contract_1/regressions.json)
and [resource proposal](data/s3_aurora_transcript_correction_contract_1/proposal.json).
No implementation, trace vector, proof or challenge result was generated.

Production source, active BC-1/proof profile, parameters, dependencies, manuscript,
canonical signed messages and historical results are preserved. The ordinary
authentication relation still requires its existing issuer signature, holder
binding and same-identifier disclosure/non-revocation linkage; public transcript
hashing cannot replace any check. RISC Zero evidence and forecasts are untouched.

Stages 2–3 remain open. Complete proof knowledge/privacy, concrete-hash/adaptive
composition, adaptive Delta_tail, component advantages at reduction budgets and
production custody/entropy/erasure/side-channel obligations remain unresolved.
Isolation stays safely stopped and unactivated; raw-view integration and CPU
proving remain paused; proof ledger remains **two attempts used, one unused**.
Recommend only the bounded transcript regression package above, without starting it.


## Measured documentation and preservation closure

The correction contract is complete, **proposed, not implemented or validated**.
AURORA-BRIDGE-001 remains open; only the specified isolated public transcript
regression package is recommended for future authorisation, with no general review
prerequisite. No private prototype or profile is admitted.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_aurora_transcript_correction_contract_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: 10,856 disjoint content paths;
10,890 identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.632140150 s |
| Audit cgroup-v2 memory.peak | 23,830,528 bytes |
| Audit sampled process-tree RSS | 41,525,248 bytes |
| Maximum guarded-job cgroup peak | 23,830,528 bytes |
| Maximum separately sampled tree RSS | 41,525,248 bytes |
| Guarded commands | 7, 3.480552636 s |
| New analysis charge, including five bookkeeping seconds | 8.480552636 s |
| Cumulative analysis charge | 88.486544458/300 s |
| Analysis remaining | **211.513455542 s** |
| Implementation unchanged | **41.823218338 s**, **386/386 tests** |
| Temporary disk observed peak | 0 bytes; zero retained |
| Evidence bytes at audit completion | 394,201 |

No new validation failures, retries or resource breaches. Historical source-access
diagnostics remain sealed. No transcript hash values or test traces were evaluated.
The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_aurora_transcript_correction_contract_1/validation-closure.json)
and [additive seal](data/s3_aurora_transcript_correction_contract_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
