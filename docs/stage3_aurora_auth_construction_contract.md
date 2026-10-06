# S3-AURORA-AUTH-CONSTRUCTION-CONTRACT-1

26 September 2026. **Construction decision: retain Aurora–BCS as the approved
research direction, but do not admit an Aurora authentication-proof prototype
yet. AURORA-BRIDGE-001 must first be resolved:** produce a version-pinned
correspondence between the proposed committed-oracle transcript below, its
complete opening/masking budget, and the applicable IOP/BCS knowledge and privacy
hypotheses. The inspected sources do not establish that correspondence for this
contract. This is a missing argument and parameterisation, not an attack.

This report specifies a proposed construction and a bounded wire design, including
the exact unresolved selectors. It is not an adopted profile, a completed compiler,
or evidence that the library's default prover implements this design. No execution
or installation is admitted. The endpoint is a named prerequisite, not another
candidate survey. See [acceptance criteria](#acceptance-criteria-and-next-action).

## Authority, preserved evidence and opening allowance

Only manuscript **Sections II–VIII**, SPEC-001–004 and the
[current specification](implementation_spec.md) are authoritative. The
[preflight](data/s3_aurora_auth_construction_contract_1/preflight-evidence.json)
verified manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`,
the previous 62-file seal
`bc8367d59a3c6e8cab7405fb79b61748f14a3534f2294e368b567285ac76bbad`,
and all 53 assessed source identities. Historical evidence is not regenerated.

Reuse the [compact-proof review](stage3_compact_auth_proof_profile_review.md),
[security assessment](stage2_concrete_security_assessment.md),
[outer-oracle decision](stage3_outer_oracle_composition.md),
[authentication plan](stage3_auth_proof_feasibility_plan.md), and
[complete forward-NTT evidence](stage3_mldsa_full_forward_ntt_pilot.md).
The assessment's older implementation-status snapshot remains historical;
subsequent signing and lifecycle achievements are preserved.

| Ledger at admission | Treatment |
| --- | --- |
| Analysis | 63.32524994877167/300 s used; **236.67475005122833 s available** |
| This source-only package | Conservatively retain the proposed 30 charged seconds, including checks/audit; ten-second cleanup/evidence reserve |
| Implementation | **41.82321833795868 s unchanged**; 332.1767816620413/374 used |
| Counted invocations | **386/386**, no new tests, probes, builds or circuit evaluations |
| Isolation | Existing safe-stopped/unactivated evidence reused; 100 historical invocations, 22 pending original cases, 250.22 s untouched |
| Proofs | **Two attempts used, one unused**; CPU proving paused |

The same 256 MiB cgroup ceiling, zero swap, one worker, two CPUs, four controlled
processes, 60 s command/55 s child maximum, 8 MiB temporary storage, cumulative
10 MiB evidence, 1 MiB/file, 60 KiB diagnostic stop and 9 GiB experimental-storage
stop apply. Documentation jobs use smaller reservations inside those maxima.
Source reading and writing follow the established operator/bookkeeping allowance;
guarded checks are charged by measured wall time. No implementation or isolation
allowance is borrowed.

## Construction contract — proposed, not active

Name the proposed family **PQDID-AURORA-AUTH-DRAFT1**, wire version 1. This identifier
is a proof-layer identifier only. It must never replace `PQ-DID-MITH-1` inside an
existing signed credential, hash domain or request. No service currently admits
this family. The normal proof adapter remains fail-closed.

**Variant:** non-holographic Aurora R1CS, native algebraic zero knowledge, additive
binary-field domains, FRI proximity testing, followed by a BCS-style
commit/challenge/query transformation. No recursion, preprocessing SNARK, pairing
wrapper, grinding, heuristic FRI mode or proof-friendly replacement of relation
hashes. These are proposed requirements, not inferred library defaults.

| Primary source / implementation identity | What was actually available |
| --- | --- |
| [Aurora 2018/828](https://eprint.iacr.org/2018/828.pdf), 8 May 2019, 64 pages | §9, Theorem 9.2, Figures 4–5 are the normative IOP target; §10.2 describes its BCS implementation |
| [BCS 2016/116](https://eprint.iacr.org/2016/116.pdf), 10 February 2016, 48 pages | §6 transformation, Theorem 7.1 and §3 commitments inspected |
| [CMS TCC 2019 proceedings](https://www.iacr.org/archive/tcc2019/11891143/11891143.pdf), 29 pages | Theorem 3 is explicitly informal; §2.9 sketches the BCS argument. The [14 January 2020 full-version metadata](https://eprint.iacr.org/2019/834) was checked, but its PDF fetch was denied. No unseen formal theorem number or constant is asserted |
| [libiop target commit](https://github.com/scipr-lab/libiop/tree/a2ed2ec2f3e85f29b6035951553b02cb737c817a) `a2ed2ec2f3e85f29b6035951553b02cb737c817a` | Commit-addressed root readable; immutable implementation files/submodule tree unavailable. Readable branch files are source observations, not a byte-verified checkout at that commit |
| [libff binary-field description](https://github.com/scipr-lab/libff/tree/master/libff/algebra/fields/binary) | Degree-specific lexicographically least irreducible-polynomial convention and coefficient encoding documented; no checked submodule revision or compiled arithmetic |

Before a build, pin every transitive source/submodule, compiler option and ABI,
match the inspected files to that inventory, and review entropy interfaces. In
particular, libff/libfqfft identities are not supplied by the root commit alone.
No dependency pin, download into the project, install or build occurred here.

### Algebra and parameter dependencies

Propose `F = GF(2)[T]/P192(T)`, where `P192` is the monic irreducible degree-192
polynomial with the smallest unsigned coefficient bitmask, lower coefficients
ordered from bit 0 upwards. This uniquely defines the field independently of a
library default. Basis `e_i=T^i`, `0<=i<192`; encode `sum b_i e_i` as the **24-byte
little-endian coefficient bitmask**. All 24-byte strings are field elements;
integer residues and Boolean wire values have additional constraints. The exact
coefficient mask and an independently checkable irreducibility certificate must
be included in the future release manifest and matched to the pinned field code.
They have not been computed or certified in this package. The degree follows the
previous binary-field comparison; it is not a 192-bit or 128-bit security claim.

For one admitted public statement shape, let `m` be R1CS rows, `n` nonconstant
variables, `k` public variables, and `s=nnz(A)+nnz(B)+nnz(C)`. Let `M,N` be the
next powers of two at least `m,n+1`; pad constraints with `0*0=0`, and unused
variables with a fixed zero assignment. Pad only after accounting for the complete
relation. The matrix/shape identifier binds actual and padded sizes.

Set `H1=span(e_0,...,e_(log2(M)-1))`, `H2` analogously using `N`,
`t=max(M,N)`. Propose code rate `rho=1/8` and
`L=e_d + span(e_0,...,e_(d-1))`, with the least `d` satisfying
`2t+2b <= 2^d/8` and all selected degree/localisation requirements; require
`d<192`. Thus the evaluation coset is disjoint from both systematic subspaces.
Domain enumeration uses ascending coefficient bitmasks in the displayed basis.
FRI quotient-domain order must be derived from this basis using its prescribed
localiser polynomials, not ordinary integer division of field elements.

Propose binary FRI folding (localisation dimension one at each step), stopping
only at the profile's explicit final degree bound. The stopping round and final
coefficient count must be materialised in the profile table. They are not a
library-selected optimisation. Final-domain descriptions, query schedules and
all repetitions remain symbolic until dimensions and the security contract are
known. Request the proven FRI/reducer analysis, never a heuristic enum or unsafe
security override. The [FRI interface](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/protocols/ldt/fri/fri_ldt.hpp)
distinguishes these modes; an enum name itself is not proof of its bound.

| Selector | Required input / decision; missing evidence |
| --- | --- |
| `m,n,k,s`, exact matrix encoding | Complete lowering and sparsity inventory for each supported public shape; no full authentication R1CS exists |
| `b` | Upper bound for the joint disclosed information from **all** actual oracle openings, virtual-oracle dependencies, FRI cosets and terminal messages; not simply a user-entered query count |
| `a,a',a_F,q_F` | Lincheck, reduction, FRI interaction and query repetitions; derive from the selected proven bounds and adversary/reduction budgets |
| `d`, tested degrees, FRI rounds/final degree | Solve the masking/query/domain dependency, including integer rounding; stop if no finite admitted solution |
| `epsilon_rbr,kappa_rbr,z_IOP` | Round-by-round soundness, knowledge and privacy claims for that exact schedule; not automatically the library's printed bit value |
| `Q_red,T_red,M_red,N_presentations` | Application reductions, simulator/extractor and complete proof-system hashing, including statement processing and all sessions |
| Concrete release descriptor | Full integer table, field mask, oracle/message register, query dependency table, hashes and decoder maxima; **currently not instantiated** |

The [parameter implementation](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/protocols/aurora_iop.tcc)
requires power-of-two padding, adds ZK domain dimensions, and iterates a query/degree
dependency that may enlarge the domain. Its internal soundness target and query
budget do not discharge the rows above. Its adaptive parameter search is not a
bounded online verifier operation in this proposal. Solve and review a finite table
offline, then reject mismatches. The [BCS default parameters](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/common_bcs_parameters.tcc)
also select proof-of-work credit: this proposal sets that credit to zero and omits
the nonce, so an unchanged default invocation would not implement the contract.

### Transcript schedule and zero-knowledge requirements

The normative algebra is Aurora Figures 4–5, with these ordered dependencies:

| Phase | Oracle/message dependency |
| --- | --- |
| A0 | Randomised witness and `Az,Bz,Cz` encodings; sumcheck masks and their sums; LDT masks must precede their mixing challenges |
| A1 | Lincheck challenges; corresponding quotient messages/oracles |
| A2 | LDT combination challenges after all combined commitments |
| A3 | Each FRI commitment before its fold challenge; final bounded coefficients before query randomness |
| A4 | Query answers and authentication paths only |

For Theorem 9.2, require `2t+2b<=rho|L|`, and `b>=q_pi` for honest-verifier privacy.
Its errors are
`epsilon_i=((M+1)/|F|)^a+(|L|/|F|)^a'+epsilon_FRI_i^a_F` and
`epsilon_q=epsilon_FRI_q^q_F`, with the theorem's proximity parameter. Random
extensions on `L` must agree on the systematic domains; sumcheck and LDT masks
are separate. Use the exact degree bounds and joint distribution in Figures 4–5,
not independently invented masking of each derived oracle.
[Aurora, Theorem 9.2 and Figures 4–5](https://eprint.iacr.org/2018/828.pdf).

The table is a protocol dependency specification, **not a claim to have recovered
the pinned library's complete registration order**. Before execution, expand it
to an ordered manifest: for each message/oracle, its ID, producer phase, domain,
degree, exact length, ZK class, challenge dependencies and query closure. Include
virtual oracles without transmitting them as unconstrained advice. Do not let
runtime registration order, unordered C++ containers or a prover choose this list.
Reconciling that manifest with the selected theorem is the named blocker.

Randomness must be fresh per proof, independent across required masks/leaves and
never supplied by an untrusted proof caller as a deterministic seed. Failure to
obtain all required randomness aborts without partial proof release. No unchanged
mask, leaf salt or private oracle is reused across presentations or retries. This
is a protocol requirement; reliable entropy, erasure and process-level leakage are
separate unresolved production obligations.

## Same-witness lowering and complete acceptance

Keep `X=(pp,mu,ctx,rstate,D,mD)` and the sole
[`encode_auth_statement`](../src/pqdid/statements.py). Trusted local configuration
selects `pp`, the proof family and relation version. A supplied profile/key/context
cannot override them. Private input remains exactly
`xH[32] || Esch(m)[1024] || rid[4] || sigma[3309] || path[960]`:
5,329 bytes, 42,632 bits. Auxiliary wires are additional *constrained* private
variables, not an alternative witness interface.

The whole acceptance predicate remains
`PubOK(pp,X) AND VerifyAurora(R_private,X,pi) AND Ppub(X)` followed by the existing
service checks. As in VII-A.6, `PubOK` and `Ppub` operate on public data; they are
not new offloading of hidden predicates. Public Boolean/range/policy constraints
can be constant-checked or public-only R1CS rows with the same truth value; retain
their independent checks in the verifier wrapper. A private-core proof by itself
does not certify complete authentication. No prover-supplied result bit substitutes
for either check.

| Reference operation | Public / private / auxiliary constraint obligation |
| --- | --- |
| Holder opening, `binding.py` | Public suite/metadata; private xH and attributes. Constrain all 24 SHA3-384 rounds, canonical holder preimage and `Y`; construct the same B. Y/B are not extra public presentation identifiers |
| `credentials.build_mcred`, `cred_valid` | Constrain precisely `Enc(cred;suite,E(mu),E(B),u32(rid))`; pure-FIPS `0 || len(ctx) || ctx || Mcred`, context `PQ-DID/credential/v1`; trusted public pkI and private sigma |
| `bounded_mldsa._verify_internal` | Public-key decode/expansion, private signature decode, bounded challenge, NTTs, matrix product, inverse NTT, hint/decomposition, strict norm and challenge equality. All intermediates constrained; no assumed host verification token |
| `schema.py`, disclosure | Entire 1,024-byte canonical block, tags/types/lengths/padding and same m; D equals policy's D; `proj_D(m)=mD`. Public policy evaluated on exactly mD, not an auxiliary copy |
| `merkle.verify_non_revocation_path` | Same certified rid, 20-bit range inside four-byte encoding; zero leaf, 20 private siblings, level tags/left-right order and SHA3-384 root equality to public state |
| `statements.py`, `public_checks.py` | Exact expected pp/mu/schema, full ctx and state reference agreement; bounded StateAuth under pkR and `PQ-DID/state/v1`; policy truth. All public data bound to the same E(X) |
| Lifecycle verifier | Authenticated request/holder consent/current-state read, trusted strict final `now < texp`, atomic single consumption. This remains outside the timeless proof relation. Session expiry is not credential validity |

**Conservative R1CS translation:** in characteristic two, constrain every free
bit `u` by `u(u+1)=0`; AND by `ab=c`, XOR by `(a+b)*1=c`, NOT by `(1+a)*1=c`.
With Boolean inputs these imply Boolean outputs inductively. A free auxiliary
bit requires its own Booleanity row. Each wire definition has one producer;
constants, public inputs and final acceptance `1` are fixed independently of the
prover. This gives an elementary relation-preserving baseline, not an efficient
full compiler already implemented. Replacing XOR chains with affine expressions
would change row counts and matrix sparsity and needs separate accounting.

Never use field addition for a 64-bit integer sum, or field multiplication for
ML-DSA integer multiplication modulo 8,380,417. Use explicit bit/carry constraints
and checked signed64 semantics, 65-bit additions and 128-bit products; retain
SPEC-003/004 overflow and division rules until an authorised equivalent lowering
is substituted. Ranges, sign conversion, high unused bits, integer quotients and
remainders must be constrained. A quotient supplied by the witness generator is
not justified just because that generator used correct Python arithmetic.

Parsing is a fixed-shape relation for the admitted public shape. FIPS bit ordering
and public serialization ordering are distinct and explicitly rewired. Compile
both private branches, cap each sampling loop, constrain counters/termination
masks, and propagate sticky active-path rejection. Invalid reads yield the
established unusable value; invalid writes do nothing; inactive paths do not add
spurious rejection. Final acceptance requires no active parsing, indexing,
arithmetic or exhaustion failure. All SHA3/SHAKE padding and output lengths stay
unchanged. Public-only folding may depend on X, never on witness values.

ML-DSA-65 remains `n=256,k=6,l=5,q=8380417`, signature 3,309 bytes, pk 1,952 bytes,
strict `||z||<524092`, canonical hint ordering/count/padding and original
decomposition representatives. Retain the 1,026-byte matrix samplers and
256-byte SampleInBall budget (8 sign plus 248 index bytes), without retry/fallback.
The 512-byte secret sampler and 1,024 signing-attempt cap remain unchanged in
their own operations; they are not fictitious loops to add to signature
verification. Adaptive **Delta_tail** remains open.

Experimental canonical-23-bit multiplication, butterflies, forward NTT and hint
decoding may later supply subgraphs only with their entry guards, conversions,
canonical/centred boundaries and invalidity semantics. The 97-partition forward
result does not cover inverse NTT or full FIPS verification. Each joined private
boundary must be the same constrained variable, or an enforced equality, not a
host assertion. Behavioural agreement does not make this compiler canonical BC-1.
The previous 10,679,298 AND / 27,044,356 total-gate transform measurements are
not R1CS counts. No full-relation row, sparsity or time figure is asserted.

The existing statement encoder admits lengths up to `L_codec=2^32-1`, not an
invented small JSON cap. Parameterised public-shape lowering must preserve the
existing admitted semantic domain. A future machine/resource refusal is an
explicit unsupported-capacity outcome, not evidence of an invalid credential.
No narrowing to convenient metadata lengths is authorised here. Full X can be
streamed into hashing; this report does not claim current encoders already stream.

## Wire format and commitment contract

This is a **new, proposed application wire format**, not libiop's serialization.
Every integer is unsigned big-endian with the stated fixed width. No varints,
JSON, floats, platform `size_t`, optional extensions or alternate encodings.
Field elements alone use the 24-byte polynomial encoding above. Propose a raw
proof limit `B_pi=10,485,760` bytes, matching the provisional KYC target rather
than authorising a file/process limit increase. A selected finite profile must
prove its worst-case wire length fits; none is selected yet. Oversize proofs are
unsupported/rejected, never truncated. Ordinary research evidence keeps 1 MiB/file.

Define `Fr(tag,parts)=u16(len(tag))||tag||u32(number_of_parts)||`
the sequence `u64(len(part))||part`, with ASCII tags and byte-exact parts. Tags
below include prefix `PQDID-AURORA-AUTH-DRAFT1/`; no C-string terminators. Bounds
for every framing use follow from the selected finite profile before allocation.
Reject overflows when adding lengths, multiplication by field width, and short
reads. This framing is confined to the new proof layer.

Propose **unkeyed sequential BLAKE2b-512**, 64-byte digest, key length zero,
fanout/depth one, zero salt/personalisation parameters; application domain tags
are bytes in `Fr`. This fixes all hash parameters. It follows the algorithm in
[RFC 7693, §§2–3](https://datatracker.ietf.org/doc/html/rfc7693), not a new hash
design or a claim that BLAKE2b is an ideal oracle. Internal credential, ML-DSA,
holder and revocation hashes remain SHA3/SHAKE. No length-extension/XOF API or
variable digest setting is silently substituted.

Let `PID` identify the exact parameter/algorithm manifest, and `RID` the canonical
R1CS compiler version, public shape, ordered matrices and dimensions, each using
64-byte `H(Fr(...))` digests. Matrix rows are ordered; terms are combined in F,
zero terms removed, column indices increasing, with exact counts and field
coefficients. IDs are computed or checked against an independently trusted local
inventory; a proof cannot supply arbitrary matrices and call them authentication.
Binding to IDs is conditional on the new hash assumption. Full E(X) also enters
the initial transcript, so a statement tag is not a substitute for reconstructing X.

Commit **one field element per leaf**, one tree per actual oracle, power-of-two
length `L_j`, no column batching or path pruning in this draft. A leaf uses fresh
**128 random bytes** and
`H(Fr(leaf;PID,RID,u32(j),u64(L_j),u64(index),fe24,salt128))`.
An internal node uses
`H(Fr(node;PID,RID,u32(j),u32(level),left64,right64))`, level 0 above leaves.
Children have fixed order. This conservatively separates value openings from
unqueried oracle contents. It requires a packed-alphabet/tagged-commitment
privacy/extraction bridge to the original BCS bit-leaf construction; neither
salt length nor collision resistance alone supplies that bridge. The 128-byte
salt is a deliberate `2*512`-bit design choice, not the library default.

Initial state `S0=H(Fr(init;PID,RID,E(X)))`. Each phase appends its exact round ID,
ordered commitment roots and direct public prover-message bytes to
`S_next=H(Fr(absorb;S_previous,round_record))` **before** deriving dependent
challenges. Challenge blocks are
`H(Fr(challenge;S_next,round_id,challenge_id,u64(block_counter)))`.
Consume a fresh, labelled block for each field challenge, taking its first 24
bytes as a uniform F element in the ideal model. A query into a power-of-two
domain of size `2^h` takes h low coefficient-order bits of its separately labelled
block; no modulo bias or rejection-resampling loop. Distinct challenge IDs and
counters prevent accidental reuse. Profiles demanding nonuniform, nonzero or
excluded-set challenges must supply that distribution explicitly and cannot use
this field sampler unchanged. Unused bytes are discarded, not a hidden shared
randomness pool. No grinding/search nonce exists.

This deterministic expansion is a specified proposed transformation wrapper. Its
domain separation, multiple oracle ports, packed symbols and expanded randomness
must be included in AURORA-BRIDGE-001; it is not declared identical to BCS §6 or
CMS merely because both use Merkle commitments and Fiat–Shamir challenges.

| Binary field, in order | Exact meaning and bound |
| --- | --- |
| `magic[8]` | ASCII `PQDAUR01` |
| `version:u16, kind:u8, flags:u8` | Exactly `1,1,0`; authentication only, no proof-mode/privacy toggle |
| `PID[64], RID[64], Xtag[64]` | Match trusted/derived IDs and `H(Fr(statement;E(X)))` |
| `body_len:u32` | Exact remaining length, total including header at most B_pi |
| For each scheduled round: `r:u32, C:u32, M:u32` | Must equal profile's round ID, number of roots, number of direct field elements; roots `[64]*C`, then fields `[24]*M` in manifest order |
| Opening section: `Q:u32` | Must equal deterministic query dependency closure count, not a prover-chosen count |
| Each opening slot: `fe[24], salt[128], path[64*h_j]` | Oracle/index/height inferred from schedule; path bottom-up, order from index. No direction bits or transmitted query positions |
| End | Exact exhaustion of body; reject trailing bytes, missing rounds, extra roots/fields/openings and any malformed frame |

Duplicates in the required query sequence reuse the same logical leaf; if a slot
is repeated its bytes must agree. Do not add a second independent opening, omit a
required slot, or transmit a prover-selected query list. Virtual queries expand
to their real-oracle dependency slots in manifest order. The selected schedule
must allow all required indices to be determined at that point; any adaptive
response-dependent query needs an explicit sequential decoding rule, not sorting
that changes the IOP. The current manifest gap means this decoder is specified
parametrically, not implemented or ready to interoperate.

The fixed header is 208 bytes. For `R` rounds, `C` roots, `M_dir` direct field
elements and `Q` opening slots, the proposed exact length is

`B_wire = 208 + 12R + 64C + 24M_dir + 4 + sum_slots(152 + 64h_j)`.

The selected descriptor bounds R,C,M_dir,Q,h_j and every sum before allocation;
all must also fit their u32/u64 representation. Use a streaming bounded decoder,
with independent trusted X and no recursive container structure. A malformed
proof, resource failure or unknown profile never yields acceptance. There are no
acceptance flags, witness fields, raw polynomial coefficient tables, optional
debug buffers or synthetic tokens in this format. Zero-knowledge mode is mandatory.

Prover memory contains the witness, constraints, mask coefficients, encoded oracle
tables, salts and Merkle trees; these are not transmitted. Only specifically
declared terminal/direct messages and query openings may leave the prover. An
unmasked terminal polynomial would be a privacy failure even if verification
succeeds. Inspect its dependencies and include its information in the masking
argument, not just the Q leaf count. For every execution transcript establish a
bound on the actual information revealed from each correlated masked object,
including virtual-oracle reconstruction and FRI coset openings. A conservative
sum of field symbols can upper-bound queries, but it does not by itself prove
that all terminal messages are simulated by the theorem. Require a joint simulator
for the transmitted object, not separate privacy claims per buffer.

The inspected [transcript serializer](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/bcs_common.tcc)
has a binary/non-algebraic stub and a non-ZK-only membership helper. Its size
method is not this wire size. The [Merkle implementation](https://raw.githubusercontent.com/scipr-lab/libiop/master/libiop/bcs/merkle_tree.tcc)
retains leaf randomness and returns it for opened leaves; that randomness must
survive any serializer. This draft intentionally forgoes the code's batching and
pruning conveniences. A later compacting change requires a new descriptor and
query/privacy/byte audit, rather than treating omitted transmitted bytes as free.

## Theorem applicability and unresolved application arguments

Symbols here are property-specific, not an asserted overall bit-security level.
`q_H` is the complete reduction's oracle budget, `p` the IOP proof-length quantity
in BCS's encoding, and `ell` its oracle output bits. They are **not** automatically
the existing outer SHAKE output length, NTT gate count or original Q rows.

| Intended claim | Exact source / hypotheses and loss | Applicability to this proposed contract |
| --- | --- | --- |
| Lowering completeness and witness correspondence | Direct bit-gate argument above, canonical validators and bounded reference relation; both directions required | Baseline expressibility established; complete compiler, auxiliary constraints and accepted-domain equivalence unimplemented |
| Interactive algebraic knowledge/privacy | Aurora Theorem 9.2, with its field/domain/repetition/query conditions above | Conditional IOP basis; ordinary knowledge does not alone establish round-by-round extraction for the selected FRI variant |
| Classical non-interactive soundness/knowledge | BCS Theorem 7.1: public-coin IOP with restricted state-restoration soundness/knowledge; respective error `s_sr`/`kappa_sr` plus `3(q_H^2+1)2^-ell` | Only after matching the transformation and state-restoration premises; not an automatic bound for this tagged field-leaf wrapper |
| Classical statistical ZK | Same theorem: honest-verifier statistical ZK `z` gives `z+p*2^(-ell/4+2)` in its programmable-oracle model | Requires exact commitment privacy/encoding correspondence; not a concrete-hash or repeated-session guarantee |
| Quantum soundness, knowledge, privacy | CMS proceedings Theorem 3 (informal), §2.9: public-coin round-by-round soundness gives `O(q_H^2*epsilon_rbr+q_H^3/2^ell)`; round-by-round knowledge and HVZK are separate premises | Relevant QROM route. No finite constants, complete extractor resource bound or library-to-theorem correspondence established here |
| Adaptive terminal extraction | Manuscript VI-B4/VIII-C and OC-EXT require the selected terminal X, event and retained history, with the adversary's residual state and permitted services | Need a history-preserving theorem-level reduction; do not rewind real service commits or replace external outcomes |
| Repeated adaptive privacy | VI-C/VIII-D and OC-PRIV require online simulation from public X, continuing oracle state, post-cutoff revocation and allowed background corruption | Fresh masks are necessary, insufficient. Need one continuing public-only simulator; never reveal protected holders or assume known future updates |
| Concrete hashes/shared interfaces | ROM/QROM theorems model ideal functions; RFC 7693 specifies BLAKE2b, not an instantiation theorem | New BLAKE2b modelling obligation. Internal fixed Keccak relation unchanged; old shared-Keccak outer composition claims do not transfer or close automatically |

[BCS Theorem 7.1](https://eprint.iacr.org/2016/116.pdf) supplies the classical
expressions, and [CMS Theorem 3/§2.9](https://www.iacr.org/archive/tcc2019/11891143/11891143.pdf)
supplies only the stated quantum route at the inspected precision. A selected
backend must identify the formal full-version statements and finite constants
before numerical assurance. Literature existence results are not an implementation
certificate. None of these rows establishes simulation extractability or a
universal-composability claim.

In particular, even a literal substitution `ell=512` in the *original* BCS
privacy expression gives `z+p*2^-126`, not a demonstrated 128-bit privacy bound.
That algebra illustrates why choosing the largest BLAKE2b output cannot certify
all properties. It is not a lower bound on attacks or the privacy of this unproved
variant. Likewise illustrative `q_H=2^80` would amplify the CMS IOP term by
`2^160`; an unqualified library target of 128 does not pay that reduction loss.
Unspecified big-O constants prevent extracting an exact numerical guarantee.
No new probability/estimator campaign was run; these are symbolic substitutions.

The [assessment](stage2_concrete_security_assessment.md) records **no adopted
overall security threshold**. Its example lifetime/query rows cannot silently
become this profile's budgets. Before numerical selection, fix a property,
classical/quantum/adaptive model, resource units, lifetime targets and maximum
advantage. Price oracle queries from all commitment nodes, expansion blocks,
proofs, simulators, extractors and reductions. Field size and hash output width
play different roles. Neither is interchangeable with sponge capacity.

Keep OC-REL (fixed relation versus oracle-relative relation), OC-EXT, OC-PRIV and
OC-BUDGET explicit. The proposal's outer BLAKE2b avoids deliberately reusing the
Keccak permutation for outer and internal hashing, but does not prove independent
ideal oracles for concrete primitives. Do not append an unexplained
`epsilon_inst` to knowledge/privacy: first define the games, access permissions,
oracle history and composition reduction. No ACMT sponge theorem is invoked for
BLAKE2b. Component ML-DSA/SHA3 advantages at enlarged reduction budgets,
adaptive Delta_tail, production custody/entropy/erasure/side channels and complete
proof knowledge/privacy remain unresolved.

## Engineering acceptance and feasibility accounting

The descriptor must price the **entire** relation, not one multiplication or NTT.
Inventory Booleanity and parsing, every hash permutation/squeeze, capped sampling,
all transforms and matrix products, disclosure/path constraints, masks, and final
acceptance. Record row/variable/nnz counts before and after padding, rather than
assuming one AND equals one R1CS row. The verifier also pays for public StateAuth,
public validation/policy, hashing E(X), and service work. Keep those costs separate
from proof verification, as well as from circuit generation and witness generation.

For the proposed simple storage design, if all oracle tables and trees coexist,
their payload alone is

`24*sum_j L_j + 128*sum_j L_j + 64*sum_j(2L_j-1)` bytes.

This excludes field-object overhead, witness and mask coefficients, FFT scratch,
matrix storage (at least row/column indices and 24-byte nonzero coefficients),
allocator overhead, transcript copies and the verifier's matrices. At run-time,
measure the maximum *simultaneous* live set. Streaming an oracle's construction
does not permit forgetting data needed for later challenges/queries without a
documented recomputation/storage strategy. None is implemented here. Salt storage
and unpruned paths cost more than the earlier library benchmark encoding.

For example, one `2^20`-element field table alone is 24 MiB. A complete workload
contains several correlated tables, trees and matrix data. This arithmetic is a
storage illustration, not a measured peak or chosen full-relation dimension.
The selected construction has verifier work depending on the matrices, not just
the short transmitted proof. Padding and masking can change L abruptly, so
extrapolating linearly from a kernel is unjustified. Existing published timings
in the compact review are not repeated as forecasts for this workload.

Retain the [provisional KYC targets](benchmark_targets.md): raw proof 10 MiB,
presentation 12 MiB, generation p95 30 s, verification p95 2 s, end-to-end p95
45 s and prover/verifier process-tree RSS 4/1 GiB. These are evaluation targets,
not activated allowances or measurements. The exploratory 1 MiB/10 s scenario
is distinct. Current audit/analysis memory remains 256 MiB. A small prototype
cannot establish percentiles or complete authentication feasibility. The old
raw-view conditional 2,568,395,104-byte projection and RISC Zero forecast remain
unchanged; no Aurora number is inferred from either.

## Acceptance criteria and next action

**Before a private Aurora prototype:** close AURORA-BRIDGE-001 for one *small,
explicit* public shape: pin source identities/field representation; supply the
complete ordered oracle/message manifest and deterministic query closure;
establish the masking/terminal-message exposure bound; instantiate the finite
degree/domain/FRI table without heuristic/grinding credit; and map the packed,
tagged commitment and challenge expansion to the required transformation premises.
A deliberately insecure diagnostic may be useful later, but it must not be
mislabelled as this private-proof prototype. No such diagnostic is authorised now.

**Before adoption additionally:** full-relation bidirectional lowering and
malformed/exhausted rejection evidence; independently checked parser/wire vectors;
actual local proof verification, resource/size measurements and a privately masked
transcript audit; finite property/workload security selection; adaptive terminal
extraction and joint-view simulation arguments; concrete hash assumptions and
component reduction budgets; operational custody/entropy/erasure/side-channel and
lifecycle trust obligations. Enrolment's proof path needs its own relation/profile
contract. Authentication alone cannot complete Stage 3 or make issuance production
ready.

**One next package proposed, not started:**
**S3-AURORA-TRANSCRIPT-BRIDGE-1**, a targeted source/mathematical prerequisite,
at most 20 charged analysis seconds including checks/audit, ten-second reserve,
unchanged limits, zero implementation invocations, installations or executions.
It must either deliver the exact pinned oracle/query/mask manifest and the
commitment/transformation correspondence for a small synthetic R1CS shape, or
close with a precise no-go for this draft. It must not reset the research question
to another broad survey or introduce a new backend to avoid the obligation.
Full application security gaps can remain explicitly open; missing privacy for
the prototype's own transmitted object cannot.

After that prerequisite, the **smallest material experiment**, still inactive,
would be a bounded synthetic R1CS-to-IOP transcript adapter: two fixed shapes,
one Boolean/hash-like and one carry/range-like, each no more than 1,024 rows,
with masks, one-field leaves and this serializer. Measure actual wire bytes,
query exposure and simultaneous tables/tree memory independently of proof size.
Plan separately counted cases for valid round trips and corrupted commitments,
openings, statement/profile binding and excessive/missing fields. A future task
must price its build/dependency requirements, invocations and time against the
then-current ledgers; none can run under **386/386** or this analysis approval.
This would settle adapter/privacy-accounting overhead, not full authentication
cost. Do not claim native proofs until an authorised real prover/verifier exists.

## Proposed eventual manuscript and specification changes

| Location | Change requiring later adoption |
| --- | --- |
| VII-A.1/.5/.6/.7 | Separate proof-profile registration from immutable credential suite/context domains; define the full relation wrapper, compiler/matrix identity, field, finite domains and failure behaviour |
| VII proof construction | Replace raw tapes/views and 480-repetition format only in the new profile with native-ZK IOP/BCS algorithms, exact transcript/wire and bounded entropy/query contracts |
| VIII-A/C/D and dependent results | Supply the selected finite IOP/BCS premises, classical/quantum knowledge/privacy reductions and oracle composition; do not reuse the old raw-view error expression or label |
| VIII component/correctness analysis | Preserve bounded ML-DSA, SHA3 binding/tree, same rid/attributes, Delta_tail and service ordering; reprice actual reduction budgets |

The manuscript, active BC-1, existing parameters and production code are unchanged.
Raw-view integration and CPU proving remain paused. Isolation remains safely
stopped and unactivated. Stages 2–3 remain open.

## Documentation validation and preservation

Only this report, package evidence, and append-only status/traceability/issues
updates are authorised. The first preflight passed historical seal and budget
checks, then failed because this package's review list named nonexistent
`src/pqdid/context.py`; Context is in `statements.py`. The old input list, failure,
STOP evidence and charged time are retained. A manually diagnosed documentation
correction and explicitly named recheck passed; no experimental test or automatic
retry occurred. No full audit had run at that point.

The final guarded lint/format, static document/JSON/link checks, original-baseline
content/inventory comparisons, outer resource result and measured balances are
recorded below and in the
[evidence closure](data/s3_aurora_auth_construction_contract_1/validation-closure.json).
No report-completion claim is made from a comparison alone.


## Measured documentation and preservation closure

The construction review is complete. AURORA-BRIDGE-001 remains a prerequisite
for a private Aurora prototype: pinned transcript/query/mask and transformation
correspondence. No profile is adopted and no experiment is admitted.
Helper lint/format and documentation/static consistency checks pass. No test,
circuit generation, arithmetic probe, build, estimator or cryptographic execution ran.
The single [preservation audit](data/s3_aurora_auth_construction_contract_1/result.json)
completed content/inventory comparison, report readback and outer guard, exit 0.
Coverage: 10,739 disjoint content paths;
10,771 identity-inclusive paths.
Original baselines and historical document prefixes are preserved.

| Measurement | Result |
| --- | --- |
| Audit wall time | 2.510384024 s |
| Audit cgroup-v2 memory.peak | 23,289,856 bytes |
| Audit sampled process-tree RSS | 41,353,216 bytes |
| Maximum guarded-job cgroup peak | 23,289,856 bytes |
| Maximum separately sampled tree RSS | 41,353,216 bytes |
| Guarded commands | 8, 3.385644324 s |
| New analysis charge, including five bookkeeping seconds | 8.385644324 s |
| Cumulative analysis charge | 71.710894273/300 s |
| Analysis remaining | **228.289105727 s** |
| Implementation unchanged | **41.823218338 s**, **386/386 tests** |
| Temporary disk observed peak | 0 bytes; zero retained |
| Evidence bytes at audit completion | 390,263 |

One diagnosed documentation-inventory preflight failure is retained and charged;
the explicit corrected preflight passed. No test/probe, audit retry or resource breach.
The unchanged 256 MiB cgroup guard
covers the worker and descendants, including charged file-cache/kernel memory;
swap is zero. Sampled RSS is a separate metric. Final bounded bookkeeping uses
256 MiB address space, five-second CPU/alarm, two CPUs and 1 MiB/file inside the
five-second charge; it does not repeat content comparisons.
The [closure](data/s3_aurora_auth_construction_contract_1/validation-closure.json)
and [additive seal](data/s3_aurora_auth_construction_contract_1/manifest.json)
record the exact balances. Isolation remains safely stopped/unactivated with
250.22 s and 22 original cases pending. Stages 2–3 remain open; proof ledger
**two attempts used, one unused**, CPU proving paused.
