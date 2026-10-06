# Stage 3 hash and enrolment circuits

## Contract and agreed SPEC-003

Only manuscript Sections II–VIII are authoritative; the PDF identity was verified
as `d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
VII-A.6, printed p. 16, prescribes equality left-folding XNORs and magnitude
multiplication by summing shifted partial products in increasing bit order. It does
not explicitly choose the fold initialisers. Equality can start from public 1 or
its first XNOR; multiplication can start from full-width zero or its first partial
product. Both agree mathematically, including overflow validity, but the mandated
retention of private/constant gates makes their counts, order and identity differ.

**SPEC-003 is agreed by the user (17 September 2026):**

> Initialise equality with public 1. Initialise magnitude multiplication with a public 128-bit zero accumulator; add all 64 shifted partial products in increasing order using full-width ripple addition, retaining terminal carry operations.

This is an implementation clarification, not existing manuscript wording. VII-A.6's
equality and multiplication paragraph needs that sentence added later; the PDF is
unchanged. Existing gate/operand order, checked arithmetic and public-only folding
are preserved. The production source already follows this convention and exposes no
alternative switch; diagnostic first-term variants remain test-only. The earlier,
broader proposal is retained in [SPEC-003](spec_issues.md#spec-003--fold-initialisers-and-derived-gadget-recipes-affect-gate-identity)
as historical rationale, without treating every derived detail as user-approved.

Agreement settles these initialisers; it does not establish full BC-1 conformance.
The latest execution evidence is in
[confirmed convention and extended validation](#confirmed-convention-and-extended-validation).

Explicit FIPS XOR expressions
retain their written operands: theta's five-term expression emits four left-associated
XORs, chi emits XOR-with-1 (not a substituted NOT), iota XORs all 64 positions, and
absorption XORs all 1600 state bits including the capacity's public zeros.

FIPS 202 (August 2015), Algorithms 1–9 and §§3.1, 5–6, supplies the hash function.
Implementation traversal is lexicographic `(x,y,z)` for its state arrays; conversion
uses string index `64*(5*y+x)+z`. Bytes enter the emitter MSB-first but Keccak uses
LSB-first bits within each byte, converted only by rewiring. All 24 rounds, preceding-
state updates and explicit step order theta/rho/pi/chi/iota are retained. Lengths
are public, byte-aligned; no private-length sponge interface is introduced.

Enrolment (V-B/C, p. 8; VII-A.5/.6, pp. 15–16) has exactly 256 private bits, the raw
32-byte xH. Public inputs are the complete existing EnrolmentStatement and expected
parameters. The relation checks SHA3-384(enc_holder(suite,E(mu),xH))=B.Y and
B.attributes=mapp. Every 32-byte string is a valid secret representation: no private
tag, length, scalar-range or nonzero-secret constraint exists. Canonical public
record/schema/instance/rid domains are validated outside private gates, as in the
Stage 2 reference; required public attribute equality can fold to a constant. State
signature verification, issuer-approved vector comparison, controller authority,
nonce/current-state/allocation/holder-approval checks remain their separate boundaries.

The new hash gadgets may serve holder/Merkle SHA3-384, ML-DSA SHAKE128/SHAKE256 and
the outer proof SHAKE256 with 128 output bytes. The latter is not called inside
enrolment. No complete authentication circuit or privacy-preserving proof is added.
Construction uses the agreed initialisers; complete canonical BC-1 conformance
remains unverified independently of functional tests. Results, resource profiles, parsing scope and evidence follow below.


## Historical alternative comparison evidence

The [comparison record](data/spec003_comparison.json) pins the test source, counts,
trace lengths and fingerprints. Equality exhaustively compares all operand pairs at
widths 1, 2, 3 and 4. Multiplication covers all signed2/signed3 pairs and signed64
zero, maximum, minimum, MIN×(-1), MAX×2 and MIN×MIN, checking both low result and
representability; wrong expected validity rejects under both interpretations.

| Comparison predicate | Current gates / AND | First-term gates / AND | Behaviour |
|---|---:|---:|---|
| equality, 1 bit | 3 / 1 | 2 / 0 | identical truth table |
| equality, 2 bits | 6 / 2 | 5 / 1 | identical truth table |
| equality, 4 bits | 12 / 4 | 11 / 3 | identical truth table |
| multiply, 2 bits plus expected value/validity | 146 / 53 | 128 / 46 | identical values/overflow acceptance |
| multiply, 3 bits plus expected value/validity | 241 / 91 | 213 / 80 | identical values/overflow acceptance |
| multiply, 64 bits plus expected value/validity | 47638 / 21319 | 47000 / 21064 | identical tested boundary outcomes |

The multiply figures include a comparison harness and differ from the operation-only
counts in the foundation report. Omitting the first zero-accumulator ripple also
leaves high bits public for the next addition, allowing extra entirely-public folds.
For width n the observed/audited difference is 10n−2 gates and 4n−1 ANDs, rather than
only the first ripple. No optimising rewrite was added to the production emitter.
Enrolment is affected through equality/final conjunction identity; it has no multiply.
All six recorded circuit pairs have different fingerprints. Functional equivalence
therefore cannot resolve the missing canonical construction convention.

## Source-to-gadget mapping and interfaces

Functional authority is [FIPS 202 (August 2015)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
not an optimised implementation's gate schedule. No dependency or standard edition
was upgraded. Relevant manuscript requirements are R-010, R-020, R-032 and R-034–037;
R-041 supplies the general proof-size arithmetic.

| Source | Implementation | Construction details |
|---|---|---|
| FIPS 202 §3.1, Algorithms 1–7, pp. 7–17 | [keccak.py](../src/pqdid/circuits/keccak.py): `keccak_f1600`, internal `_round` | 200-byte permutation, all 24 rounds; each step reads the preceding state; fixed x/y/z order, no reassociation/CSE or private-identity folding |
| FIPS 202 Algorithms 8–9, §§5–6 and B.2 | `sha3_384`, `shake128`, `shake256` | Full-state absorb XOR, domain suffix, pad10*1, all required squeeze permutations; input/output lengths are public byte counts |
| VII opening encoding, VII-A.5 holder binding | [parsing.py](../src/pqdid/circuits/parsing.py): `public_bytes`, `reverse_byte_bits`, `equal_bytes`, `holder_message` | MSB byte positions, reversible per-byte FIPS bit permutation, 1-seeded XNOR/AND comparison, exact public LP/tag prefix plus symbolic xH |
| VII-A.5/.6; V-B/C enrolment relation | [enrolment.py](../src/pqdid/circuits/enrolment.py): `compile_enrolment`, `compile_encoded_enrolment` | Public expected-pp/domain validation, 256 private input positions, holder digest comparison AND public attribute equality AND no rejection |
| VII closing formula, p. 17 | [enrolment_accounting.py](../src/pqdid/circuits/enrolment_accounting.py) | View/proof byte calculation with d=256; encoding-bound helper only; no proof creation |

All byte interfaces are immutable flattened tuples of symbolic bits, serialised
MSB-first per byte. `reverse_byte_bits` maps to/from Keccak string bit order; it is
not a change to the protocol's big-endian integer encodings. State storage is nested
A[x][y][z], while its serialised/FIPS string uses z+64*(x+5*y). Copies/rho/pi are
rewiring only. Round constants are generated entirely publicly by FIPS Algorithm 5;
a separate literal table and independent lane oracle check them.

SHA3-384 has 104-byte rate, 48-byte output and suffix/padding byte 0x06. SHAKE128 and
SHAKE256 have 168-/136-byte rates and suffix/padding byte 0x1f; all append the final
0x80 padding bit, including the shared suffix/final byte at rate−1. Exact-rate input
requires a new padding block. Zero output still performs absorption. Message/output
lengths are limited to 65536 bytes by an explicit development guard; the emitter's
separate default cap is 65536 private bits. Practical gate/time limits can terminate
much earlier. No private length controls loops or indexing.

Roles remain distinct: holder and future Merkle nodes use SHA3-384; future ML-DSA
uses SHAKE128/SHAKE256 with its prescribed output/capped-stream lengths. The outer
proof HRO uses SHAKE256 with 128 output bytes; that capability is tested separately
and is never invoked by the enrolment compiler. ML-DSA sampler integration and an
outer proof transcript are not implemented by these standalone gadgets.

## Exact parsing and enrolment boundary

`parse_enrolment_public` calls the existing strict statement decoder and re-encoder.
`compile_enrolment` validates/re-encodes a typed public statement; the encoded entry
point first parses then compiles. Public failures raise `EncodingError` before a
circuit is returned. These checks include tag/count/LP/trailing bytes, fixed lengths,
canonical schema attributes/padding, rid range below 2^20, expected-parameter equality,
namespace/metadata agreement, nonce length and state structure. Existing schema/codecs
remain unchanged. Public range validation stays at this boundary; adding a private
integer parser would introduce checks not present in the enrolment witness.

| Data/condition | Boundary |
|---|---|
| pp, metadata, mapp, rid, B, issuer nonce, state encodings/domains | Host-side public parsing/validation before construction |
| B.attributes equals mapp | Required relation check, constructed from public bits and folded; a false value does not skip the holder hash |
| xH bytes | Exactly 32 bytes / 256 private positions; all byte strings are valid representations |
| SHA3-384(holder prefix concatenated with xH) equals B.Y | Emitted private computation and comparison |
| Wrong witness byte length | Evaluator rejects the call; there is no variable private-length input |
| Well-sized zero/ff/wrong xH | Ordinary relation evaluation; rejects only when the opening equation fails |
| State signature and externally issuer-approved mapp | Separate `enrol_public_ok`; structure alone is not authenticity |
| Controller/holder approval, allocation, pending nonce, current state and atomic issuance | Surrounding unimplemented services, outside this circuit |

The local comparison boundary is `public domains valid AND evaluate(derived circuit,
raw xH)` versus `relations.enrol(pp,X,EnrolmentWitness(xH))`. For the stateless
surrounding helper, compare `enrol_public_ok AND circuit` with `enrol_public_ok AND
reference`. There is no public API accepting the witness as a privacy-preserving proof.
Resource exceptions propagate as inability to finish, not a false relation result.

Canonical holder framing is LP("holder") || [3]4 || LP(suite) || LP(E(mu)) || [32]4
|| xH. The alpha fixture has 10629 public E(X) bytes, a 425-byte public holder prefix
and 32 private bytes: 457 bytes total. At rate 104 it absorbs four wholly public blocks
and a fifth mixed block; xH starts at byte 9 of that last block. Public-only operations
are evaluated through the same emitter; no native hash substitutes for private gates.
The beta fixture uses a 423-byte prefix and a 455-byte total. Other valid public
layouts may place xH across two blocks and exceed the original development budget;
that is resource non-completion, not a reduced-round or different relation circuit.

E(X) enters the existing development fingerprint header via SHA-256, independent of
witness values. This is only a development circuit identity. Nonce/rid/well-formed
state mutations can leave enrolment acceptance true while changing E(X)/fingerprint;
actual proof transcript binding remains unimplemented. Inconsistent instances fail
public validation; coherent other instances with an old binding target fail the
holder comparison. An invalid state signature can still satisfy the private relation
but fails `enrol_public_ok`, preserving the confirmed Stage 2 boundary.

## Independent validation and original coverage limits

The new [CAVP fixture](../tests/fixtures/fips202_circuit_vectors.json) contains 15
selected official records: SHA3-384 short inputs at 0,1,103,104 bytes plus its first
209-byte long record; SHAKE128 at 0,1,167,168,169; SHAKE256 at 0,1,135,136,137. The
SHA3-384 ShortMsg file ends at 104 bytes, so a nonexistent 105-byte official record
was not invented. Separate hashlib tests specify rate+1 for each algorithm.

Provenance: [NIST secure-hashing vectors page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing),
CAVS 19.0 response files generated January 2016. The standalone
[extractor](../tests/reference/extract_fips202_vectors.py) has no production imports
and copies outputs verbatim, selecting only by public input length. Archive URLs,
archive/member SHA-256 hashes, original headers and extractor digest are recorded in
the fixture. Original empty-message `Msg=00` is retained as provenance but decoded
as zero bytes because Len=0. This is informal checking, not NIST/CAVP validation.

| Archive | SHA-256 |
|---|---|
| sha-3bytetestvectors.zip | cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c |
| shakebytetestvectors.zip | debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7 |

Nonempty hash tests use private input wires, assert over 35000 AND gates, and evaluate
both the official message and a changed message on the same completed circuit. Empty
input has no private message bits and legitimately folds entirely publicly; it is not
counted as private-hashing evidence. Hashlib/OpenSSL supplies independent short/hash/
XOF expectations; [the independent word oracle](../tests/reference/keccak_reference.py)
uses row-major integer lanes, fixed tables and an independent rotate/permutation
implementation for zero/dense full-state tests. Hand traces check the first theta
XORs, literal chi operation order, full iota and exact 24-round gate counts.

Passed coverage at the original budget includes all nine below-rate official cases,
private complete permutations, output lengths up to one squeeze block (including
SHAKE256's 128-byte proof-hash length), mixed public-prefix/private-input absorption
across several blocks, wrong openings/targets/attributes/instances, public parser
malformations, context mutations, mode agreement and resource non-completion.

**At the original package boundary, seventeen larger-profile tests were skipped.**
The later approved run and all outcomes appear in the validation section below.
They cover the six official cases requiring additional private permutations, six
native rate+1/two-rate+1 inputs and five SHAKE outputs crossing a squeeze boundary
(including 1026/256/512-byte call-site lengths). They are implemented but have not run
under the original 200000-gate cap, and are not claimed as functional validation.
At that boundary, the prepared opt-in profile was awaiting approval. The historical
measurement record contains only original-budget runs and is preserved unchanged.
The approved operational profile and additional evidence are recorded separately below.

## Historical original-budget resource measurements

The [measurement record](data/stage3_hash_enrolment_measurements.json) includes the
initial WSL host snapshot: 8126111744 total RAM bytes, 5469507584 available, 2 GiB
free swap; workspace and /tmp available bytes 1021613772800 and 4002656256. One worker
was used with fresh sequential child processes, the unchanged 200000-gate/8 MiB
output/10 s generation/5 s evaluation limits and 256 MiB RLIMIT_AS. Each child has a
30 s wall timeout. The default evaluator wire bound is explicitly sized to gate cap
plus input-position cap (265538 for these probes). Rounds were never reduced.

Each row measures a predicate comparing component output with an independent public
target, so the permutation row includes 4800 comparison gates beyond its 193536
permutation gates. The parsing row includes public validation/holder framing and a
256-private-bit equality test; framing alone emits zero gates. Enrolment includes
its actual required relation checks. Layouts are 200 private bytes for permutation,
32 for successful hash/XOF/parsing/enrolment probes, and 209 for the aborted multiblock
SHA3 probe. Outputs/targets and public prefixes are public; only enrolment is a full
relation circuit. Materialised runs evaluate one valid witness; enrolment additionally
reuses that same completed circuit with a wrong opening, without reconstructing it.

| Component | Gates | AND | Wires | Serialised bytes |
|---|---:|---:|---:|---:|
| permutation | 198336 | 40000 | 199938 | 3371801 |
| sha3-short | 194688 | 38784 | 194946 | 3309785 |
| shake128-short | 194304 | 38656 | 194562 | 3303257 |
| shake256-128 | 196608 | 39424 | 196866 | 3342425 |
| parsing | 768 | 256 | 1026 | 13145 |
| enrolment | 194691 | 38787 | 194949 | 3309836 |

| Component | Mode | Generation s | Evaluation s | Peak RSS MiB | Retained trace bytes | Traced generation retained / peak bytes |
|---|---|---:|---:|---:|---:|---:|
| permutation | materialised | 0.674716 | 0.644075 | 32.008 | 3371834 | 3380924 / 7230974 |
| permutation | count | 0.644449 | — | 25.648 | 0 | 9314 / 709721 |
| permutation | stream | 0.703378 | — | 25.719 | 0 | 9346 / 709753 |
| sha3-short | materialised | 0.723426 | 0.785012 | 31.363 | 3309818 | 3318828 / 6926190 |
| sha3-short | count | 0.657355 | — | 25.316 | 0 | 8978 / 623402 |
| sha3-short | stream | 0.722074 | — | 25.441 | 0 | 9010 / 623434 |
| shake128-short | materialised | 0.722978 | 0.774340 | 31.582 | 3303290 | 3312268 / 6907374 |
| shake128-short | count | 0.661123 | — | 25.504 | 0 | 8946 / 627562 |
| shake128-short | stream | 0.714801 | — | 25.461 | 0 | 8978 / 627594 |
| shake256-128 | materialised | 0.725853 | 0.807619 | 31.633 | 3342458 | 3351468 / 7020270 |
| shake256-128 | count | 0.658780 | — | 25.555 | 0 | 8978 / 625482 |
| shake256-128 | stream | 0.723792 | — | 25.438 | 0 | 9010 / 625514 |
| parsing | materialised | 0.012355 | 0.000339 | 25.098 | 13178 | 13876 / 105170 |
| parsing | count | 0.012155 | — | 25.105 | 0 | 698 / 105057 |
| parsing | stream | 0.011469 | — | 25.141 | 0 | 698 / 105057 |
| enrolment | materialised | 1.038508 | 0.617258 | 32.637 | 3309869 | 3319015 / 6937391 |
| enrolment | count | 0.969948 | — | 25.508 | 0 | 9114 / 690471 |
| enrolment | stream | 1.038963 | — | 25.305 | 0 | 9146 / 690503 |

Timings are single instrumented runs with tracemalloc overhead. RSS is process
high-water RSS including imports/interpreter/native allocation. Count/stream modes
retain no trace history; input handles, live lane/step tuples and public byte tuples
still consume memory. Counting's serialised bytes are logical; its stored trace bytes
are zero. Streaming was checked by independent file hashing, and unit tests compare
actual stream/materialised bytes. Each materialised finalisation temporarily copies
its bytearray. These measurements do not establish a bound for future compiler ASTs,
sampler state or complete authentication. Traced retained memory excludes allocations
before tracing and some native memory; the JSON records those limits explicitly.

Enrolment's fresh whole-construction timer additionally includes public validation;
its emitter generation timer begins after public encoding. Reusing its materialised
circuit with an incorrect 32-byte opening returned 0 in 0.620766 s. No circuit cache,
no skipped rounds and no witness-dependent construction path was used.

All three modes of the 209-byte private SHA3, SHAKE128→1026 and SHAKE256→512 probes
hit **gate-count limit at 200000**, returned `complete: false`, and produced no
completed circuit/fingerprint. Materialised/stream partial output was 3400056 bytes;
counting stored zero bytes. Partial wires were 201674 for SHA3 and 200258 for SHAKE.
Thus 18 probes completed and nine terminated cleanly; none of the nine partial runs
is counted as a working multiblock/XOF circuit. Original-limit failure is also tested
with a private SHA3 input exactly at its 104-byte rate.

## Enrolment size calculation and proof boundary

For the measured provisional enrolment circuit only, d=256 and g=38787:

```text
V = ceil((256 + 2*38787)/8) = 9729 bytes
projected_proof_bytes = 64 + 480*(515 + 2*9729) = 9587104 bytes
```

The general enrolment expression is `277984 + 960*((g+3)//4)`. Tests cover rounding
and huge integer counts without allocating a view/tape/proof buffer. This is a
calculated size based on the complete provisional enrolment circuit's AND count,
not an actual proof, final approved BC-1 size or authentication estimate. In particular
no enrolment count was inserted into the authentication d=42632 formula. Trace size
3309836 bytes, calculated proof size 9587104 bytes and generated proof (absent) are
separate facts. The helper's V<=L check is only an encoding-capacity condition.

## Historical implementation commands and results

Executed using the established environment:

```bash
.venv/bin/python tests/reference/extract_fips202_vectors.py /tmp tests/fixtures/fips202_circuit_vectors.json
.venv/bin/python -m pytest tests/unit/test_keccak_circuit.py tests/unit/test_enrolment_circuit.py tests/unit/test_spec003_alternatives.py -q
.venv/bin/python scripts/measure_hash_enrolment.py --suite --host-snapshot /tmp/pqdid-hash-host.json --output docs/data/stage3_hash_enrolment_measurements.json
.venv/bin/python -m pytest tests/unit tests/integration tests/smoke/test_hashes.py -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Original results: **57 focused passed, 17 skipped (15.10 s); 1082 regression passed,
17 skipped (19.33 s)**; lint passed and all **89 Python files** passed format checking.
The skips are the explicit larger-profile tests described above, not hidden successes.
The source-preservation and final documentation audits are recorded with project status.

The final audit checked 6816 protected pre-existing files: 6815 outside the suite
manifest match their original hashes. Only implementation evidence changed in that
manifest; confirmed parameters, SPEC-001/002, native/dependency/editor files, previous
source/tests/vectors and the manuscript remain unchanged. Current/prior source and
new fixture-extractor hashes match. All 52 main requirement rows, 119 local links and
22 Markdown tables across the five updated overview/report documents pass checks.
The audit also confirms 18 completed probes, nine clean non-completions, mode equality
and exact count/trace arithmetic. No dependency installation or native rebuild occurred.

The implementation contains full SHA3/SHAKE operation schedules and complete enrolment
logic; functional evidence currently establishes the successfully bounded cases only.
Full canonical BC-1 conformance remains unverified; SPEC-003 initialisers are now agreed. Authentication still needs
canonical private attribute/signature/rid/path parsing, constant division/reduction,
centred ring arithmetic, full bounded ML-DSA/sampler lowering, Merkle traversal and
complete same-witness circuit composition. Proof sharing/commitment/challenge/transcript/
checking and full-circuit feasibility are not implemented.

Stage 2 bounded key generation/signing, setup/import, production revocation/witness
updates, DEP-001 signing-tail validation and remaining DEP-002 release obligations
remain separate and open. SPEC-001/002 and all confirmed suite parameters are unchanged.

The original implementation package stopped here. The later validation-only package
is recorded below; it does not start authentication implementation.

## Confirmed convention and extended validation

This validation-only package adopts exactly the SPEC-003 wording at the start of
this report. All pre-existing production code, tests, vectors and measurement JSON
are preserved. The source was already fixed to public-1 equality and zero-seeded
magnitude accumulation; there is no selectable alternative in the canonical path.
Historical source comments/measurement labels describing the recipe as provisional
are retained as provenance, not as an unresolved initialiser choice. Full BC-1
conformance remains unverified.

**Results:** 17/17 previously deferred tests passed; 9/9 diagnostic probes completed;
both historical stability cases passed. No deferred case was skipped, failed an
assertion or stopped at a resource limit. Six counting/streaming probes establish
construction/digest agreement, not witness evaluation. The three materialised probes
also evaluated their intended predicates successfully. The full regression passed
**1106 tests, no skips**, including seven new trace/supervision checks. The earlier
nine gate-limit results remain valid historical non-completions; they are not
retrospectively counted as correctness passes.

### Approved profile, host inspection and enforcement

[validation_profiles.json](../configs/validation_profiles.json) is separate from
cryptographic suite parameters and unchanged routine `Limits()` defaults. The
[sequential runner](../scripts/validate_hash_enrolment.py) launches one test/probe
worker at a time; [supervision](../scripts/validation_support.py) also kills its
process group on a watchdog limit and waits for exit before continuing. Profile
selection changes operational limits only, never the fingerprint/public header.

The pre-run `/proc/meminfo`/filesystem snapshot records WSL2 total usable RAM
8126111744 bytes (7.57 GiB), available RAM 5438423040 bytes (5.07 GiB), and 2147483648
bytes free swap. The actual process cgroup is `/init.scope`; its `memory.max`,
`memory.high` and `memory.swap.max` report `max`, while inspected current usage was
2661437440 bytes. No additional numeric cgroup ceiling is exposed. The WSL guest
RAM allocation still applies; this is not a claim of unlimited host memory or a
new Windows configuration. The setup inspection had found no `.wslconfig`; it was
not changed. Workspace filesystem available bytes were 1021612490752; RAM-backed
`/tmp` had 3996323840 available bytes. These are guest filesystem measurements,
not guarantees about future physical Windows disk capacity. Full snapshots and
inspection times are embedded in the new JSON records.

| Control | Effective value and enforcement |
|---|---|
| Emitted gates per extended construction | 2000000; emitter checks before another gate |
| Serialised trace output per construction | 41943040 bytes (40 MiB); checked on writes in materialised/stream modes. Count mode stores no trace; the gate cap bounds its logical length to 34000089 bytes, also below 40 MiB |
| Private inputs | Existing 65536-bit emitter maximum; actual cases are smaller |
| Generation | Existing 10 seconds per construction, cooperative emitter polling |
| Evaluation | Existing 5 seconds per evaluation, cooperative evaluator polling; official/probe wire ceiling 2065538, native multiblock/squeeze tests retain 2100000, stability fixtures use existing 300000 |
| Process address space | Existing stricter 268435456 bytes (256 MiB), kernel `RLIMIT_AS` soft/hard in each worker |
| Process RSS | Separate 134217728-byte (128 MiB) parent watchdog, sampled every 0.01 seconds; transient overshoot can escape sampling, so this is not a kernel hard RSS bound |
| Case wall clock | Existing 30 seconds; regression resets the watchdog at each pytest case, so its whole-suite time can exceed 30 seconds |
| Logs and temporary files | 2097152-byte sampled per-process log ceiling; one streamed trace at a time under its output cap; temporary directory/file cleanup on completion/termination |
| Concurrency | One active test/probe worker; no xdist. Small subprocesses in supervision unit tests exercise control failures only |

The RSS ceiling is below both 1 GiB and the retained 256 MiB address-space bound,
and comfortably below a quarter of inspected available RAM. The runner can reduce
it for lower headroom and rejects inadequate headroom; it never automatically raises
any cap. A fresh host snapshot must precede future use; the stored snapshot is evidence
of this run, not a permanent resource reservation. Resource exceptions report unfinished
work rather than predicate false/success. RSS/time/log watchdog termination is covered
by three deliberately small-limit control tests; emitter/evaluator limit tests remain
in regression. A normal-exit control test also passes. Memory exhaustion under
`RLIMIT_AS` is classified separately from mathematical rejection.

Process RSS below is measured `ru_maxrss`, including imports/interpreter; the JSON
also records independently sampled RSS. Neither value is an allocation allowance.
Tests/stability runs have lightweight timing/hash observation without tracemalloc;
probes retain the historical tracemalloc instrumentation. Timings are single runs,
not benchmark averages or full-circuit feasibility bounds. Peak RSS across the
17 individual tests was 87.484 MiB; across nine probes 72.859 MiB; full regression
109.934 MiB. The largest trace was 23449481 bytes, distinct from RSS and from the
calculated enrolment proof size.

### All 17 previously skipped tests

Every identifier below has the exact prefix
`tests/unit/test_keccak_circuit.py::`. These are the existing tests with their original
assertions unchanged. `G/A` means total emitted gates / AND gates. `Gen/eval` lists
seconds for generation and every actual evaluation (official cases include valid=1
and changed-message=0). RSS is MiB. All rows passed under the same profile; none has
an unfinished check. Remaining scope limits are finite public lengths/test vectors,
byte-aligned messages and no full authentication/proof composition.

| Test identifier | Functionality (private input bytes → output bytes) | Outcome | G/A | Wires | Trace bytes | Gen/eval s | RSS MiB |
|---|---|---|---:|---:|---:|---|---:|
| `test_official_vectors_with_private_messages[SHA3_384-832]` | SHA3_384 official 104 → 48; positive/negative | pass | 390656/77184 | 391490 | 6641241 | 0.473335/0.085410/0.083556 | 54.797 |
| `test_official_vectors_with_private_messages[SHA3_384-1672]` | SHA3_384 official 209 → 48; positive/negative | pass | 585792/115584 | 587466 | 9958553 | 0.694551/0.122997/0.125003 | 61.176 |
| `test_official_vectors_with_private_messages[SHAKE128-1344]` | SHAKE128 official 168 → 16; positive/negative | pass | 390400/76928 | 391746 | 6636889 | 0.458812/0.083547/0.086356 | 54.828 |
| `test_official_vectors_with_private_messages[SHAKE128-1352]` | SHAKE128 official 169 → 16; positive/negative | pass | 390400/76928 | 391754 | 6636889 | 0.471959/0.082654/0.084597 | 54.676 |
| `test_official_vectors_with_private_messages[SHAKE256-1088]` | SHAKE256 official 136 → 32; positive/negative | pass | 390528/77056 | 391618 | 6639065 | 0.461748/0.083743/0.083914 | 54.836 |
| `test_official_vectors_with_private_messages[SHAKE256-1096]` | SHAKE256 official 137 → 32; positive/negative | pass | 390528/77056 | 391626 | 6639065 | 0.463204/0.084726/0.087136 | 54.836 |
| `test_multiple_absorption_blocks_private[SHA3_384-1]` | SHA3_384 105 → 48; 2 absorption blocks | pass | 390656/77184 | 391498 | 6641241 | 0.466920/0.083522 | 54.824 |
| `test_multiple_absorption_blocks_private[SHA3_384-2]` | SHA3_384 209 → 48; 3 absorption blocks | pass | 585792/115584 | 587466 | 9958553 | 0.687550/0.129837 | 61.328 |
| `test_multiple_absorption_blocks_private[SHAKE128-1]` | SHAKE128 169 → 48; 2 absorption blocks | pass | 391168/77184 | 392522 | 6649945 | 0.461656/0.086140 | 54.988 |
| `test_multiple_absorption_blocks_private[SHAKE128-2]` | SHAKE128 337 → 48; 3 absorption blocks | pass | 586304/115584 | 589002 | 9967257 | 0.698961/0.127816 | 60.926 |
| `test_multiple_absorption_blocks_private[SHAKE256-1]` | SHAKE256 137 → 48; 2 absorption blocks | pass | 390912/77184 | 392010 | 6645593 | 0.459940/0.083125 | 54.539 |
| `test_multiple_absorption_blocks_private[SHAKE256-2]` | SHAKE256 273 → 48; 3 absorption blocks | pass | 586048/115584 | 588234 | 9962905 | 0.686144/0.127487 | 61.539 |
| `test_squeeze_boundaries_and_callsite_lengths[SHAKE128-169]` | SHAKE128 32 → 169; multiple squeeze blocks | pass | 391128/78152 | 391386 | 6649265 | 0.456073/0.086765 | 54.887 |
| `test_squeeze_boundaries_and_callsite_lengths[SHAKE128-1026]` | SHAKE128 32 → 1026; multiple squeeze blocks | pass | 1379376/277008 | 1379634 | 23449481 | 1.608060/0.303554 | 87.484 |
| `test_squeeze_boundaries_and_callsite_lengths[SHAKE256-137]` | SHAKE256 32 → 137; multiple squeeze blocks | pass | 390360/77896 | 390618 | 6636209 | 0.456954/0.082976 | 54.914 |
| `test_squeeze_boundaries_and_callsite_lengths[SHAKE256-256]` | SHAKE256 32 → 256; multiple squeeze blocks | pass | 393216/78848 | 393474 | 6684761 | 0.457433/0.085079 | 55.074 |
| `test_squeeze_boundaries_and_callsite_lengths[SHAKE256-512]` | SHAKE256 32 → 512; multiple squeeze blocks | pass | 786432/157696 | 786690 | 13369433 | 0.912010/0.167609 | 68.074 |

### All nine originally capped diagnostic probes

Identifiers are `component/mode`, passed to the existing probe implementation.
`sha3-multiple` exercises SHA3-384 with 209 private bytes → 48 bytes (three absorption
blocks). `shake128-1026` and `shake256-512` each use 32 private bytes → the named
output length (seven and four squeeze blocks respectively). Targets come from hashlib.
All three modes agree on counts, trace lengths, folds and complete fingerprints;
stream files are independently hashed. Count/stream rows deliberately have no
Boolean evaluation, so “pass” means their construction/digest checks completed.
No remaining resource termination affects these nine rows; finite-input and full
compiler/proof scope limitations still apply.

| Probe identifier | Outcome | G/A | Wires | Serialised bytes | Gen/eval s | RSS MiB | Traced peak bytes |
|---|---|---:|---:|---:|---|---:|---:|
| `sha3-multiple/materialised` | pass | 585792/115584 | 587466 | 9958553 | 1.992440/1.856970 | 45.742 | 20411781 |
| `sha3-multiple/count` | pass | 585792/115584 | 587466 | 9958553 | 1.797648/— | 27.082 | 890953 |
| `sha3-multiple/stream` | pass | 585792/115584 | 587466 | 9958553 | 1.990709/— | 26.832 | 890985 |
| `shake128-1026/materialised` | pass | 1379376/277008 | 1379634 | 23449481 | 4.701255/4.393355 | 72.859 | 50579351 |
| `shake128-1026/count` | pass | 1379376/277008 | 1379634 | 23449481 | 4.235264/— | 28.027 | 1403394 |
| `shake128-1026/stream` | pass | 1379376/277008 | 1379634 | 23449481 | 4.737118/— | 27.980 | 1403426 |
| `shake256-512/materialised` | pass | 786432/157696 | 786690 | 13369433 | 2.661619/2.486934 | 52.223 | 28391847 |
| `shake256-512/count` | pass | 786432/157696 | 786690 | 13369433 | 2.453305/— | 26.926 | 963042 |
| `shake256-512/stream` | pass | 786432/157696 | 786690 | 13369433 | 2.667790/— | 27.117 | 963074 |

Counting retains zero trace bytes; streaming stores exactly the listed bytes in a
file but retains no full trace in Python. Materialised Python trace objects add 33
bytes to the listed serialised length; finalisation can temporarily retain both the
bytearray and its immutable copy. Traced peaks include instrumentation and are not
RSS. The slowest instrumented evaluation took 4.393355 seconds under the unchanged
5-second limit; another host/load may legitimately terminate. Budgets were not
increased and instrumentation was not removed to force completion.

### Historical construction stability and independent fold audit

The exact foundation `build("mul64", ...)` demonstration checks checked multiplication
against public 6, plus required rejection checks, using witness (2,3). It is distinct
from the operation-only and alternative-comparison harnesses. The enrolment case is
the unchanged `sample()` alpha-42 fixture, with 10629-byte E(X), 457-byte holder input
and 256 private positions. Fresh original-default and extended materialised traces
are compared literally; extended stream bytes also compare literally, and counting
has identical counts/fingerprint. Both predicates evaluate to 1 under both budgets.

Historical JSON retained fingerprints/counts/lengths, not full trace files. Historical
comparison is therefore digest/count/length equality, not a claimed literal comparison
with an unavailable old file. Literal byte equality applies to the fresh reproductions.
There are **no count, wire, operation-order or fingerprint differences**: approval
adopted the already implemented initialisers. Operational metadata never enters the
trace identity. Gate-record-only digests are also recorded for the fresh materialised
traces, separate from the complete development fingerprint.

| Exact predicate | XOR / AND / NOT | Gates | Wires | Trace bytes | Extended gen/eval s | Worker peak RSS MiB |
|---|---|---:|---:|---:|---|---:|
| mul64 | 25933 / 21322 / 388 | 47643 | 47773 | 810020 | 0.051947/0.010351 | 25.672 |
| enrolment | 155520 / 38787 / 384 | 194691 | 194949 | 3309836 | 0.467895/0.041785 | 34.770 |

mul64 complete development fingerprint: `88d78f60c37cc7223662e64f2a6bd8cb9e257125dd0377412e4f3faeb3afd19b`.

enrolment complete development fingerprint: `57712c0fdb2e6ace69c7cc2ddda40028eef8b97b192766aee30efcb624b1c0e2`.

These RSS figures cover the whole stability worker holding the comparison traces,
not a single fresh component; tracemalloc is off, unlike the old timings. Historical
measurements remain unchanged and are not overwritten by these new timings.

[test_confirmed_bc1.py](../tests/unit/test_confirmed_bc1.py) supplies three additional
checks: literal two-bit equality records retain AND(public 1, first private XNOR);
a hand-expanded two-bit multiplication slice retains the first zero-accumulator
full-width ripple and its unused terminal carry; and an observed actual-width call
schedule contains two signed65 magnitude preparations, exactly 64 full-128-bit
accumulations in increasing shift order, then the sign-negation ripple. The small
trace verifies operand order, permitted all-public folds and the final carry operation;
existing exhaustive arithmetic/overflow and exact ripple tests complement it.
Source inspection confirms the same public-1 seed in byte equality and no production
imports of diagnostic first-XNOR/first-partial alternatives. New checks test this
specific agreement; they do not certify all derived recipes.

### Coverage assessment and readiness

| Claim | Completed evidence | Remaining boundary |
|---|---|---|
| Functional hashing | All 15 selected official vectors now run; 12 have actual private message inputs and three are public empty-message cases. All six newly executed official cases reuse a completed circuit with a changed message and reject. Independent hashlib and integer-lane oracle checks remain | Informal finite tests, not CAVP certification or all-length proof |
| Absorb/squeeze boundaries | Rate−1, exact rate with new padding block, rate+1 and two-rate+1; mixed public prefix/private tail; squeeze at rate and rate+1, SHAKE128 1026 bytes and SHAKE256 137/256/512, plus original 0/32/48/64/128/136 cases | Only public byte-aligned lengths; no private-length sponge or integrated ML-DSA samplers |
| Enrolment parsing/reference relation | Complete 256-position raw secret; strict public decoder/re-encoder and domains; three fixtures, valid/wrong/zero/ff openings, wrong target/attributes, coherent/incoherent instances, malformed public framing, fixed witness-length errors; `enrol_public_ok AND circuit` agrees with the same public checks plus reference | Public StateAuth/approval boundaries remain separate; no authentication private parser or controller/current-state/issuance service |
| Deterministic agreed construction | Literal small traces, 64-partial schedule, unchanged historical multiplication/enrolment digests/counts, literal fresh budget/mode equality, repeated/witness-independent construction | Development SHA-256 fingerprint is not HRO/proof commitment; agreement is not an independent full CGen implementation |
| Full canonical BC-1 conformance | Explicit basis/order/folding, selected ripple/Keccak traces and agreed initialisers audited | Complete independent lowering/conformance audit, byte/conjunction traversal and remaining derived recipes, full authentication/sampler/Merkle lowering, complete canonical circuit admission and feasibility remain unverified |
| Privacy-preserving proofs | Enrolment d=256/g=38787 yields V=9729 and **9587104 calculated proof bytes** | No proof generated or verified; shares/raw tapes, 480 repetitions, commitments, challenge, transcript, checking, erasure and complete resource feasibility are absent |

**Readiness: ready to begin the next bounded package of authentication private parsing
and checked positive-constant division/reduction/ring gadgets.** No required deferred
validation gap remains in this package. Subsequent work must preserve the agreed
construction rules, add independent traces/reference checks for each new lowering,
and keep full BC-1 conformance open until independently established. Stage 2 bounded
key generation/signing, setup/import, production revocation/witness updates, DEP-001
tail validation and remaining DEP-002 release obligations remain open. Full Stage 3
proof-feasibility requirements remain open. This package stops here.

### Complete commands and evidence

Executed with the established environment; `/tmp/pqdid-confirmed-host.json` contains
the inspected host snapshot embedded verbatim in both records. To reproduce a run,
capture a fresh snapshot in that shape before launch; do not reuse an old available-
memory measurement. Do not overwrite the historical records when choosing an output.
The runner's regression child invokes pytest with
`tests/unit tests/integration tests/smoke/test_hashes.py -q --tb=short`, setting
`PQDID_HASH_EXTENDED_BUDGET=1` inside the supervised process. Every actual subprocess
command, per-case pytest report, timing, limit and source digest is recorded in JSON.

```bash
.venv/bin/python -m pytest tests/unit/test_confirmed_bc1.py tests/unit/test_validation_support.py -q
.venv/bin/python scripts/validate_hash_enrolment.py --host-snapshot /tmp/pqdid-confirmed-host.json --output docs/data/stage3_hash_enrolment_validation.json
.venv/bin/python scripts/validate_hash_enrolment.py --regression --host-snapshot /tmp/pqdid-confirmed-host.json --output docs/data/stage3_hash_enrolment_regression.json
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Results: seven focused audit/control tests passed in 0.13 s; 17 tests, nine diagnostic
probes and two stability cases passed sequentially; **1106 regression tests passed in
31.91 s** (1083 unit, 19 integration, four fixed hash), no skips. Regression worker
wall time was 32.01 s, governed by the per-case 30-second watchdog. Ruff reports
“All checks passed!” and “93 files already formatted”. No environment/native rebuild
or dependency update was performed.

New evidence: [per-case validation](data/stage3_hash_enrolment_validation.json),
[regression](data/stage3_hash_enrolment_regression.json), and
[preservation/consistency audit](data/stage3_validation_audit.json).
The old [foundation measurements](data/stage3_bc1_measurements.json),
[hash/enrolment measurements](data/stage3_hash_enrolment_measurements.json),
[alternative comparison](data/spec003_comparison.json) and all previous fixtures
retain their original hashes.
