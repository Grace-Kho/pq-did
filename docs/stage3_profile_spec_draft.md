# Draft amendments: PQDID-R0S-EXP1

19 September 2026. **Unadopted specification proposal.** This document is separate
from the active [implementation specification](implementation_spec.md), manuscript
and [suite manifest](../configs/suite.json). “Shall” below expresses proposed rules
for review, not current implemented behaviour. No new tags, profiles, image IDs,
dependencies or vectors are activated. The
[proposal and security-impact analysis](stage3_profile_change_proposal.md) controls
the interpretation of this draft. Security admission is unresolved.

## DRAFT-01 — Profile identity and scope

The proposed proof profile shall be ASCII `PQDID-R0S-EXP1` (P). It shall use RISC Zero
v3.0.6 at commit `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`, native **Succinct STARK**
receipts with `poseidon2`, local proving and development mode disabled. Groth16,
Composite and Fake receipts shall not be accepted under P.

P shall be distinct from the credential suite `PQ-DID-MITH-1`. Existing credential,
issuer-key, application hash, tree, statement, state/update and context bytes retain
their original suite value. This explicit separation is a material specification
change requiring review: the original suite name alone shall no longer imply the
only admissible proof backend in an experimental application using P. No old
signature shall be reinterpreted over renamed bytes.

The application shall pin a single expected proof profile in trusted configuration
and in each pending session record, and preserve it through final atomic acceptance.
It shall reject unsolicited profile negotiation, fallback or profile changes during
a session. P is additionally bound inside the proved journal. Supporting multiple
profiles/negotiation would require a further authenticated selection design; this
draft does not add unauthenticated negotiation to the existing context.

Kinds shall be one byte: `00` for enrolment, `01` for complete authentication. A
trusted profile registry shall pin, separately per kind, the reproducibly compiled
guest image ID, source/ELF/compiler/lockfile digests, verifier-parameter digest,
control root/allowed control set, proof-system/circuit information strings, hash
suite, expected terminal control metadata schedule and admission limits. The
terminal control ID/path and allowed seal-length pattern shall depend only on
public kind/X, never on private witness-dependent execution length. A fixed public
schedule or reviewed normalisation is required; this draft does not claim it is
provided automatically by Succinct mode. It shall not accept those values merely because a
prover supplies them. **No registry/image entries exist yet.** Source revisions or
security parameter changes require a newly reviewed profile revision.

Diagnostic fragments shall use distinct programme IDs and a distinct profile/tag
namespace, e.g. `PQDID-R0S-DIAG1` with a fragment-specific journal. They shall never
be registered as the complete enrol/auth kind or described as an authentication
proof. This applies to the next credential-verification fragment experiment.

## DRAFT-02 — Programme and relation

The guest shall take canonical E(X) plus exactly the existing private witness bytes:
32 for enrolment; 5,329 for authentication. It shall reject malformed/trailing
private data, inconsistent public parameters, noncanonical fields, ranges and
padding. It shall implement the same relation as the reference module, preserving
private/public/lifecycle placement from R-025. The host shall independently perform
all specified public checks against the same expected E(X).

For authentication, the proved guest shall reconstruct the holder hash, B and
Mcred from one xH/m/rid; perform the complete bounded FIPS ML-DSA-65 credential
verification inside the proved computation; verify the depth-20 zero-leaf path at
that same rid; and match the disclosed fields from that same canonical m. It shall
bind the complete public statement even if a particular field is used only by the
public verifier or lifecycle layer. It shall not trust a supplied B, message digest,
decoded signature, polynomial result, Merkle result or success Boolean without
proving the corresponding computation/consistency.

The programme shall preserve FIPS byte order/context formatting, SHA3/SHAKE domain
separation, exact sampler byte caps, consumed rejected bytes and deterministic
failure on exhaustion. Machine arithmetic shall preserve specified mathematical
results and overflow rejection using explicit checked widths/wider temporaries;
field equality alone shall not replace integer range checks. Any faster arithmetic
or memory access implementation requires semantic equivalence evidence. The new
profile does not claim BC-1 gate-order conformance: SPEC-003/004 and their canonical
circuits remain intact for the original profile.

Success shall mean a zero guest exit code after all required private checks and
exactly the journal below. Failure shall yield no accepted success receipt. Cycle,
memory or implementation failures shall be distinguished from false predicates,
shall fail closed and shall not trigger an unrecorded retry. Prover hints or
coprocessors shall not bypass proved checks. The initial feasibility port shall use
software SHA3/SHAKE; acceleration is later reviewed work.

## DRAFT-03 — Exact application framing and public journal

Define `U32BE(n)` as an unsigned four-byte big-endian integer and
`LP(b)=U32BE(len(b)) || b`. For literal ASCII tag a and k byte-string fields,

```text
enc_a(s1,...,sk) = LP(a) || U32BE(k) || LP(s1) || ... || LP(sk).
J = enc_proof-result(P, kind, E(X)).                 # exactly 3 fields
input = enc_proof-input(P, kind, E(X), xi).          # exactly 4 fields
```

These **new literal tags** shall be confined to the new profile's codec; they are
not added to the active codec by this draft. E(X) and xi are inserted once, not
decoded/re-encoded differently by the host and guest. The guest shall write J as
raw bytes, without an extra vendor serializer layer, and no other public journal
data. The verifier shall reconstruct J from its expected P/kind/X and require exact
bytes through full receipt verification. It shall not accept arbitrary prover-supplied
journal bytes or only an asserted relation-result Boolean.

The public journal exposes existing public E(X) only. It shall not contain xH,
hidden attributes, B for authentication, sigma, rid, a witness digest, secret-derived
cache key, cycle/segment count or diagnostic output. Existing enrolment-public B/rid
remain public for enrolment only. Local execution/trace information shall stay local;
host-side timing and storage privacy need separate operational treatment.

## DRAFT-04 — Raw proof bytes and transport

To avoid accepting arbitrary vendor object serializations, propose a fixed
application wire adapter for the inspected SuccinctReceipt fields:

```text
pi = enc_proof-r0s(P, kind, I, V, C, H, Q, Bctl, S). # exactly 9 fields
```

| Field | Proposed exact representation |
|---|---|
| P/kind | Literal profile bytes / exactly one allowed byte as above |
| I | Expected image ID, 32 bytes |
| V | Expected Succinct verifier-parameter digest, 32 bytes |
| C | Recursion control ID, 32 bytes; match the expected public terminal schedule and verify membership under the expected control root |
| H | Exactly the nine ASCII bytes `poseidon2` |
| Q | Pruned ReceiptClaim digest, 32 bytes; never a serialized open claim |
| Bctl | `U32BE(index) \|\| sibling0 \|\| ... \|\| sibling7`, exactly 260 bytes; index<256; eight 32-byte digests, leaf-to-root order |
| S | Nonempty seal vector: each u32 serialized in little-endian order, concatenated; length divisible by 4. LP supplies its byte length, so no second vector length is present |

Each RISC Zero 32-byte digest shall be encoded as its eight numeric u32 words in
order, each little-endian, independently of host endianness; no ASCII hex or host
memory casting. Conversion vectors must confirm this convention before use.
The eight-level control tree is the vendor control-ID tree, **not** the application's
depth-20 SHA3 revocation tree. Its
[pinned source layout](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/receipt/merkle.rs)
and [SuccinctReceipt fields](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/receipt/succinct.rs)
are the basis for this proposed adapter; this adapter is not implemented/tested yet.

The verifier shall construct a SuccinctReceipt with `claim=MaybePruned::Pruned(Q)`,
the expected hash/parameters and decoded seal/control inclusion proof, and construct
the outer Receipt with reconstructed J and matching metadata. It shall invoke the
pinned `verify_with_context` with expected image ID and trusted verifier parameters.
The expected claim shall be the vendor successful-halt claim with no unresolved
assumptions and journal J. This precludes accepting a valid proof of another image,
guest failure, an assumed unproved subcomputation or different public output.
An integrity-only API shall not be used as the acceptance predicate.

The proposed binary presentations are

```text
auth presentation = enc_presentation-r0s(P, D, mD, pi)  # exactly 4 fields
enrol proof carrier = enc_enrol-proof-r0s(P, pi)        # exactly 2 fields
```

D and mD retain their existing canonical encodings. All other public statement
inputs come from the expected authenticated session, not substituted receipt data.
A W3C/JSON adapter is separate future work and must carry these same claims and
count its encoding overhead. No signature/hidden certificate is added to a public
carrier. Raw proof size means the **whole pi**, not just S. Changing these formats
invalidates old proof-transcript vectors only for the new profile; existing
credential/statement/BC-1 vectors remain unchanged.

## DRAFT-05 — Admission, lifecycle and security gates

For the first experimental profile, propose practical admission caps of 64 KiB for
E(X), 10 MiB for pi and 12 MiB for the encoded authentication presentation. These
are new experimental limits, distinct from the manuscript's L=2^32−1 framing bound
and subject to target review. Every length/count shall be checked against remaining
input and its field-specific maximum **before allocation**; reject unknown tags,
wrong arity, bad widths, nonzero surplus data, trailing bytes, other profiles/hash
suites and inconsistent repeated fields. Require canonical re-encoding equality.
Seal and parser bounds include adversarial rejection paths and memory/time limits.

Complete acceptance shall retain PubOK/StateAuth, Ppub, disclosure-controlled DID
checks, expected audience/session/context, final ordered current-state read and
atomic pending-context/profile/expiry recheck and consumption. Strict now<texp
remains mandatory. A valid receipt shall not override an expired, consumed or
stale/inconsistent state request. No hidden identifier shall be sent to a service.

Before activation, supply source/compiler/guest equivalence evidence, positive and
adversarial format vectors, complete enrol/auth proofs, resource admission tests,
and a reviewed quantum security contract for VM integrity/knowledge, recursion,
hashes/Fiat–Shamir, simulation and actual-history composition. Existing Section
VIII raw-view loss expressions shall not be applied to this profile. The documented
RISC Zero ZK qualifications and 96/99-bit component estimates leave this gate
unresolved; no 128-bit or fully proved privacy claim is authorised by the draft.

The [bounded feasibility envelope](stage3_profile_change_proposal.md#next-bounded-work-package)
is a separate future experiment proposal, not an active configuration change.
All remaining original Stage 2/3 obligations and DEP-001/002 remain recorded.
