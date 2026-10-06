# S3-AURORA-COMPILER-COMPATIBILITY-CONTRACT-1

Decision: **a functional correction requires the eight specified semantic checks**,
then the unchanged TR-01–TR-16 comparisons. The intended member selection is supported
by pinned declarations and constructors; this is not merely a printing fix or a
validated compatibility-only change. One further native build is proposed, inactive.
No source in the acquired checkout, experimental work tree or overlay was modified.
No configuration, compilation (including syntax-only), native case, proof or zkVM
execution occurred. Both historical build attempts remain consumed.

Only manuscript Sections II–VIII and agreed clarifications are authoritative. This
is a source/toolchain contract, not a construction change. The agreed EXP2 framing,
canonical statement encoder, role/parameter choices and active BC-1 remain unchanged.

## Evidence, authority and opening balances

The preceding [native closure](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/validation-closure.json)
and seal `f3125c0cdbee596222ebf0736a8647afc94d37a02e21511fec2d5dffe3d2bd56`
establish complete preservation and a stopped build, not native correspondence.
The latest completed analysis ledger is the dependency-lock continuation:
120.20447600178886/300 seconds charged; **179.79552399821114 seconds available**.
This package may charge at most 30 seconds, reserving ten for completion. The existing
accounting convention charges five conservative seconds for source review/editing/
bookkeeping plus actual guarded check durations. Analysis is separate from the
unchanged native, implementation and isolation allowances.

[Opening accounting](data/s3_aurora_compiler_compatibility_contract_1/opening-ledger.json)
records 11,510,011 retained cumulative evidence bytes and **876,474 bytes headroom**
below 12,386,485. The present package reserves 262,144 bytes, including 131,072 for
finalisation. The proposed future native continuation reserves another 393,216;
together these conservative reservations leave 221,114 bytes. All retained outputs
remain counted. No baseline, seal, failure log or original inventory was regenerated.

Pinned libiop remains `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, root tree
`2e2588ccb085242dd2237875c3b9adf1a0fc958c`. Reuse the verified libff/libfqfft revisions,
package artifacts and [corrected lock](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/dependency-lock-v2.json).
Source and log SHA-256 identities are in
[reviewed inputs](data/s3_aurora_compiler_compatibility_contract_1/reviewed-inputs.json).

## Exact diagnoses and intended objects

The second [compiler log](data/s3_aurora_native_transcript_pilot_1/reconciliation-1/build-2.log)
contains ten member-lookup errors in four definitions of `libiop/relations/variable.tcc`.
There is no base class, alias or accessor named `index` or `coeff` in either type.
`var_index_t` is `size_t`; `variable<FieldT>` declares public `index_` (header line 52)
and its non-explicit constructor sets `index_(index)` (line 54).
`linear_term<FieldT>` declares `index_` and `FieldT coeff_` (lines 95–96).
Its constructors (TCC 103–118) copy `var.index_` and initialise `coeff_` to one,
`FieldT(int_coeff)`, or the supplied field coefficient. The formal expressions in
the same header are `x_index` and `coeff * x_index`.

| Definition and original lines | Logged errors and intended member | Required meaning and callers |
| --- | --- | --- |
| `variable<F>::operator==(const variable<F>&)`, 61–64 | Two: `this->index`, `other.index` select the respective variables' `index_` | Equal formal variables iff indices match; direct equality API. No coefficient exists on a variable. |
| `linear_term<F>::operator*(const F&)`, 127–130 | Two: current term's `this->index`, `this->coeff` must be `index_`, `coeff_` | Return `(same index, field_coeff * old coefficient)`. Preserve operand order. Integer member overload delegates here (121–123); combination member scaling calls `lt * field_coeff` (271–279). |
| `linear_term<F>::operator-()`, 169–172 | Two: current term's `this->index`, `this->coeff` must be `index_`, `coeff_` | Return `(same index, -old coefficient)` without mutating the input. Direct unary-term API; do not confuse with combination negation, which uses scaling. |
| `linear_term<F>::operator==(const linear_term<F>&)`, 175–179 | Four: `this->index`, `other.index`, `this->coeff`, `other.coeff` select each term's corresponding suffixed members | Compare index AND coefficient. Vector term equality underlies combination equality (337–340), then R1CS constraint equality (`r1cs.tcc` 57–62) and system equality. |

The resulting `linear_term(index_, coefficient)` calls retain the existing implicit
conversion through `variable<F>(var_index_t)`; the term constructor copies that
same index. No new constructor, cast, storage layout, arithmetic primitive,
short-circuit order, index transformation, zero filtering or field conversion is
introduced. The source supports these intended formulas; the currently ill-formed
specialisations supply no successful executable baseline against which to claim
observed behavioural equivalence.

This is not a missing `this->` qualification problem: six logged expressions
already have it. Adding qualifications alone cannot select non-existent members.
Deleting the operators or removing `sparse_matrix.cpp` would evade the known
failure without validating their required semantics and is not proposed.

The observed include route is `sparse_matrix.cpp` → `sparse_matrix.hpp:15` →
`r1cs.hpp:27` → `variable.hpp:208` → `variable.tcc`. The CPP defines only the
`all_r1cs_sparse_matrix_types` list; the log does not show these four operators
being instantiated or called by that translation unit. GCC 15 diagnosed their
template bodies during compilation. Compile-time reachability is established;
runtime reachability is not. The retained public EXP2 driver constructs `gf192`
values and common BCS round calls, and has no variable/linear-term/R1CS operations.
Therefore the 16 transcript cases alone would not exercise this correction.

The broader library does use these representations: `linear_combination::evaluate`
(TCC 260–267) reads the already correct `index_`/`coeff_`, treating index zero as the
constant one and index `i>0` as assignment slot `i-1`; `r1cs_constraint_system::is_satisfied`
uses that evaluation for A/B/C. `r1cs_sparse_matrix::get_row` returns those
combinations. Restoring scaled or negated terms can therefore affect downstream
constraint construction and evaluation in real consumers, although the evaluator
itself is not edited.

## Smallest patch and limits of its semantics

[variable-members.patch](data/s3_aurora_compiler_compatibility_contract_1/variable-members.patch)
is the entire proposed library edit: four definitions in three diff hunks, ten identifier substitutions,
one file. The source under both `src/libiop` and `work/libiop` remains unchanged.
Textual applicability is checked against both, with a separately recorded virtual
postimage digest. No C++ parser, compiler or native execution is used by that check.

| Effect category | Classification |
| --- | --- |
| Diagnostics/printing | No printing, logging or error-handling body changes. `print` and `print_with_assignment` already use suffixed members and are unchanged. |
| Indices/coefficients | Functional restoration of access to stored indices and coefficients. No caller-controlled remapping, narrowing, sentinel change or layout change. |
| Arithmetic/constraints/evaluation | Two repaired arithmetic operators plus two equalities. Source-supported formulas retained; eight explicit native cases required. No claim of general R1CS validation. |
| Serialisation/transcript | No encoder, stream operator, field representation, EXP2 frame/hash/counter or challenge mapping change. Indirect effects in other R1CS consumers remain possible. Transcript regression is still required after a successful build. |

The inspection also finds **unpatched latent stale accesses** in the same file:
non-member `F * linear_term` (188–191), sorted combination addition (293–306), and
vector-term constructor sorting/coalescing (453–460). These use `lt.index/coeff`,
iterator `index/coeff`, or lambda `a.index/b.index`. They are not the ten logged
errors and are not required by the proposed eight direct-operator checks or the
public transcript driver. No code is deleted to avoid them. If another instantiation
or the proposed build diagnoses them, stop and preserve that result; no automatic
patch expansion. General combination arithmetic needs a separate contract, including
ordering/coalescing and zero-coefficient policy. The existing empty-combination
`is_valid` dereference and range convention (343–363) also remain unreviewed and
unchanged; the proposed tests do not call it. There is no claim that the whole
relations module is correct after this minimal patch.

## Complete experimental patch stack

1. Unchanged acquired libiop/libff/libfqfft and verified local sodium/GMP artifacts.
   Original source origin, commits, gitlinks and hashes remain as reconciled.
2. Existing isolated EXP2 native patch to `bcs/hashing/blake2b.hpp/.tcc`,
   `bcs/bcs_common.hpp/.tcc`, and added `bcs/hashing/exp2_public_pilot.hpp`.
   Its harness is `overlay/exp2_native.cpp`. The agreed construction is frozen.
   Canonical statement preparation is still in the existing typed Python adapter;
   the native path receives public prevalidated bytes. No claim of native PQ-DID decoding.
3. Existing overlay libff target selection. Before/after CMake SHA-256:
   `24f4ae5a0fba323204099cb5e699d02c704f4dee877d8037511df1c583dbc2b8` →
   `fb72c9eb78bb7103f8968214e3d116f1744d6a57b54c12186cdf2cc5a7e21c3f`.
   It retains the five binary-field CPP files (`gf32`, `gf64`, `gf128`, `gf192`,
   `gf256`) and three common files (`double`, `profiling`, `utils`). It leaves
   the actual sources and eight libiop compilation units unchanged.
4. Proposed ten-member-token patch above, plus a separate public-only semantic
   driver and [CMake test-target addition](data/s3_aurora_compiler_compatibility_contract_1/semantic-target.patch).
   These last artifacts are inactive and would be used only in a fresh clone of
   the retained experimental work/overlay, never by modifying the sealed copies.

The first log's failure is **prime-field stream output**, not EXP2 hashing:
BLS12-381 G1 printing instantiates `operator<<(ostream&, const Fp_model<6,...>&)`;
`fp.tcc:812` calls private `bigint_repr()` (declared `fp.hpp:146`). There are already
friend declarations at `fp.hpp:141–142`. Source inspection does not establish why
this compiler/template combination fails to recognise the intended access, nor
justify changing that representation helper's visibility or replacing its output.
The retained target-selection correction avoids unneeded curve implementations;
it does not repair or validate that prime-field serialisation path. All GMP/sodium
link dependencies, checks and binary-field code remain selected. No permissive
flag, error suppression, mocked field or fake caller is proposed.

**Historical reporting clarification:** the previous report says build 2 “built
that target”. Its log establishes that the eight binary-field/common translation
units compiled, then compilation stopped in libiop. The sealed artifact inventory
contains **no build-produced `.a` archive** and no native executable. A complete
`ff` link or native target build is therefore not established. Preserve the earlier
wording as history and use this narrower finding going forward.

## Proposed validation and single build admission

The [inactive runbook](data/s3_aurora_compiler_compatibility_contract_1/runbook.md)
and [machine-readable request](data/s3_aurora_compiler_compatibility_contract_1/proposal.json)
pin the exact patch, semantic driver, CMake addition, commands and budget. Proposed
next package: **S3-AURORA-NATIVE-COMPATIBILITY-VALIDATION-1**. Request only **one**
additional build attempt (cumulative 2 → 3), including configuration/probes and both
native targets. No retry or build-only correction after that attempt is included.

The eight proposed public native cases instantiate the four edited operators using
real pinned `libff::gf192`, without mocks. Each row is one counted process invocation;
checks of its output and unchanged input/evaluation are consequences of that same
operation, not hidden parameterised examples.

| ID | One operation/input | Independent expected result |
| --- | --- | --- |
| SEM-01 | `variable(0) == variable(0)` | true; zero is the same formal constant variable |
| SEM-02 | `variable(3) == variable(4)` | false |
| SEM-03 | term `(index=3, coefficient=0x2)` multiplied on the right by field `0x3` | `(3,0x6)`; unchanged input; evaluation at slot 3 = 1 gives `0x6` |
| SEM-04 | term `(0,0x2)` multiplied by field zero | `(0,0)`; unchanged input; evaluation with no assignments gives zero |
| SEM-05 | unary negative of term `(3,0x2)` | `(3,0x2)` in characteristic two; unchanged input; evaluation at slot 3 = 1 gives `0x2` |
| SEM-06 | equality of `(3,0x2)` and `(3,0x2)` | true |
| SEM-07 | equality of `(3,0x2)` and `(4,0x2)` | false |
| SEM-08 | equality of `(3,0x2)` and `(3,0x3)` | false |

Expected arithmetic is literal polynomial-bit arithmetic: `x*(x+1)=x²+x`, with
no reduction in SEM-03, and `-a=a` in GF(2^192). These expected values are not obtained
by calling the patched operators. This does not validate odd-characteristic negation,
all indices/coefficient values, generic FieldT instantiations or full R1CS semantics.
The proposed [driver source](data/s3_aurora_compiler_compatibility_contract_1/semantic_cases.cpp)
is review text only, not syntax-checked or compiled in this package.

If and only if the build and SEM-01–SEM-08 pass, run all original **TR-01–TR-16** once
in the original order, with retained independent expectations and the existing
public case inputs. TR-02 remains a counted repeat; TR-16 remains the labelled
native omission negative control, not a forgery. Retain statement-binding
qualification: algebraic primary-input checks exist, even though the selected old
hash chain lacked explicit statement initialisation. Do not infer universal hash
security from finite comparisons or demand distinct finite-range challenges for
every mutation. Native common BCS replay is not full Aurora prover/verifier coverage.

Eight semantic + sixteen transcript cases = **24/24 currently unused invocations**;
402 → 426 if all admitted. No invocation-ceiling increase is needed. A failure
consumes its invocation and stops the sequence; no reserve invocation is left for a
retry. Run only public synthetic values; no private witness or full proof.

## Resources, estimates and stop criteria

The retained incomplete builds measured 1.371514156 s and 3.603540356 s. They do not
predict completion time. Largest native cgroup memory peak was 258,568,192 bytes;
retained artifacts are 11,228,057 bytes. Both are lower evidence points for the
future build, not a bound on its unfinished compilation/link stages.

Propose a **150-second subcap** against existing native/implementation balances:
55 s for the sole configure/build attempt, 24 × 2 s case deadlines, 17 s for input
checking, fresh-copy/patch preparation, static checks and bookkeeping, and the final
30 s for audit/reporting/cleanup. These are admission reservations, not runtime
estimates. Individual command/child limits remain 60/55 s; one worker, two CPUs,
zero swap, 1 GiB native memory, 256 MiB audit memory and the existing process limit.
No third build is admitted by unused time alone. The 150-second reservation fits
native 264.371873684 s and implementation 268.929253343 s without increasing either.
Provisioning is complete; its 41.843650440 s balance is not used for compilation.

Reserve 32 MiB additional artifacts inside the existing designated artifact root;
11,228,057 + 33,554,432 = 44,782,489 bytes, below 128 MiB. This is an allowance
reservation, not a demonstrated link-size estimate. Keep the existing 32 MiB
binary/Git/build per-file exception, 1 MiB ordinary-file limit, 8 MiB temporary
limit and 60 KiB diagnostic limit. Reserve 393,216 new native evidence bytes
(262,144 for build/case records, 131,072 for finalisation); check actual cumulative
and native 2 MiB evidence headroom again before admission. No artifact deletion or
evidence truncation is proposed to create room.

Stop on a pin, patch-context or inventory mismatch, a new compiler error, incomplete
build, first semantic/transcript discrepancy, resource breach, or insufficient
remaining completion reserve. Preserve failure records and exact invocation/build
counts. No automatic source expansion, retry, dependency substitution, installation,
profile change or limit amendment is part of the request.

## Completion and remaining obligations

Required checks are Python-helper lint/format, three textual patch-applicability
checks (not native tests), reviewed-input hashes, original-baseline comparisons,
final inventory, report readback and the outer 256 MiB guard. Results and actual
analysis/output balances are appended after the single preservation audit.

Native correspondence, full prover/verifier caller coverage, query/masking,
commitment transformation, extraction/privacy, concrete-hash composition, adaptive
Delta_tail, production security and complete authentication remain open.
AURORA-BRIDGE-001 and Stages 2–3 remain open. Isolation is safely stopped/unactivated;
CPU proving remains paused; proof ledger two used/one unused. No further package
is started by this proposal.


Completed source-only contract: lint/format and all three textual patch-applicability
checks passed; no source mutation, compiler invocation or native test. The complete
preservation audit passed, exit 0, with 10,901 disjoint content comparisons,
10,936 identity-inclusive paths and 4,915 inventory entries at audit time. Final
inventory, reporting/readback and outer guard passed. Audit 3.020466007 s,
30,470,144 bytes cgroup peak under 256 MiB; sampled tree RSS 48,529,408 bytes.
Largest analysis-worker cgroup peak was 36,962,304 bytes. No resource breach or
retained temporary data. Historical build failures, original seals and native
source/artifacts remain preserved.

Analysis charge 8.535517291/30 s, including existing five-second bookkeeping
accounting; package residual 21.464482709 s and analysis balance 171.260006707 s.
Native 264.371873684 s, implementation 268.929253343 s, provisioning 41.843650440 s,
isolation 250.22 s, builds 2/2 consumed and invocations 402/426 remain unchanged.
Exact final byte accounting and the additive seal are in
[the contract closure](data/s3_aurora_compiler_compatibility_contract_1/validation-closure.json)
and [manifest](data/s3_aurora_compiler_compatibility_contract_1/manifest.json).

The functional patch's SHA-256 is
`8a28d44432c4dfd2ff41a07bb4affd1a154b52ae781289210410586b43e4c357`.
It remains unapplied. One extra build plus eight semantic cases and TR-01–TR-16
is an inactive request requiring approval; no broader resource increase is requested.
Stages 2–3 and AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.


### Native functional-correction continuation: build 3 guard stop

The approved ten-reference patch and semantic target were applied only in the
fresh isolated `dependency-prefix-v1/compatibility-v1` subtree after seal checks.
Build 3 configured successfully, then stopped at 2.299439995 seconds under the
new-output guard: compiler temporary files were included in evidence accounting
(569,344 sampled temporary bytes versus the 393,216-byte reservation). The log
contains no compiler diagnostic; neither executable linked. No SEM-01–SEM-08 or
TR-01–TR-16 case ran. Builds are 3/3 used; invocations remain 402/426. No further
build or correction is automatic. Containment and the empty temporary directory
are recorded; the partial build and every earlier failure are retained.

See [the native report](stage3_aurora_native_transcript_pilot.md) and its
`docs/data/s3_aurora_native_transcript_pilot_1/compatibility-1` evidence. Required
preservation finalisation is recorded separately below; a passing audit cannot
establish compilation, operator semantics or native correspondence. Recommended
next work is a source-only compiler-scratch/evidence accounting correction
contract before a new build request. Stages 2–3 and AURORA-BRIDGE-001 remain
open, with query/masking, commitment transformation, extraction/privacy,
concrete-hash and complete-authentication obligations unresolved. Isolation
remains stopped/unactivated and CPU proving paused; proof attempts remain two
used and one unused. Analysis/provisioning allowances are unchanged.


### Final outcome of the third-build continuation: incomplete, stopped

Formatting/lint passed. Preparation passed over **5,907 inventory entries** with
no missing or unexpected paths. The sole full preservation audit exited **1**
after **3.082952 seconds**, at **29,663,232 bytes** cgroup peak
(**47,603,712 bytes** sampled tree RSS), under the unchanged **256 MiB** ceiling.
It completed **8,759 original + 2,142 supplemental = 10,901** disjoint baseline
comparisons, report-prefix checks and assessed/sealed input checks. These remain
partial evidence: final inventory, final documentation checks and complete report
readback were not reached.

The failure is `changed prior resource controls`: this continuation's
`checks.py::current_checks` included the authorised **1 GiB native preflight** in
the legacy `check_runs` list, whose resource validator requires **256 MiB**.
This is an integration error in the new audit wrapper, not a measured audit
memory breach or a demonstrated protected-content mismatch. The error, phases,
outer result and STOP record are preserved. No audit was repeated and no
comparison requirement was removed. **The package is not complete.**

**AURORA-NATIVE-GUARD-001 remains open:** review the compiler scratch/evidence
accounting boundary and make phase-specific validation explicit while retaining
all ceilings. This is the one recommended bounded next contract; neither a repair
execution nor another build begins here. Build attempt three remains consumed,
with no complete linking and **zero** semantic/transcript invocations. Each
SEM-01–SEM-08 and TR-01–TR-16 outcome is recorded as not run. The previous Python
results do not establish native correspondence or proof security.

Accounting: **11.543774/150 seconds** charged (five conservative bookkeeping
seconds plus **6.543774** measured guarded seconds); **138.456226**
remain under this stopped subcap. Native balance **252.828099 s**;
implementation **257.385479 s**. Analysis remains
**171.260006707 s**, provisioning **41.843650440 s**. Builds **3/3** used;
invocations **402/426**, all **24** native cases unused. The guarded workload
terminated; cleanup retained the empty assembler artifact and left no temporary
entries. New artifacts: **3,995,318 bytes / 956 entries**, aggregate artifacts
**15,223,375/134,217,728 bytes**.

Final retained new evidence and document appendices: **000000224338 bytes**;
cumulative **000011879147/12,386,485 bytes**, headroom
**000000507338 bytes**; native package evidence
**000001262780/2,097,152 bytes**. These retained totals do not erase the
build-time guard exceedance caused by temporary-file accounting. Exact records
are in `docs/data/s3_aurora_native_transcript_pilot_1/compatibility-1/validation-closure.json`.
The new manifest seals this incomplete outcome; it does not replace old seals or
claim a successful audit. No final inventory is claimed after the failure.

Stages 2–3, AURORA-BRIDGE-001, query/masking, commitment transformation,
extraction/privacy, concrete-hash and complete-authentication obligations stay
open. Isolation remains stopped/unactivated, CPU proving paused, and the proof
ledger two used/one unused. No proof, zkVM execution, installation or activation
occurred. Stop after this report.


S3-AURORA-RESOURCE-GUARD-REPAIR-1: eight tooling cases and one targeted rerun
passed (411/438); complete preservation pending. See the native transcript report.
Builds remain 3/3; all 24 native cases remain unexecuted.


Resource-guard repair complete: audit passed; 411/438 invocations, builds 3/3. See native report.

Fourth-build approval did not reach execution: sealed patch/targets verified,
but retained build metadata/evidence totals 344,971 bytes under the tested policy,
above the 200,000-byte reservation and 267,653-byte opening headroom. Exact paths
and hashes: native-pilot `build-4-admission-1/admission-result.json`. No compiler
or native operator/caller was executed; all eight SEM and sixteen TR cases remain
not run. Builds 3/4 consumed; no functional edit, revised dependency or retry.
AURORA-NATIVE-ADMISSION-001 is open. The proposed correction's semantic validation
and AURORA-BRIDGE-001 remain outstanding; see the native report for finalisation.


Fourth-build admission finalised: preservation passed (10,901 comparisons; final inventory 6008; report/readback complete), no build or cases launched. Charged 9.005019 s; native 233.290628 s, implementation 237.848007 s remain. Builds 3/4; ledger 411/438. Evidence-budget blocker and AURORA-BRIDGE-001 remain open; see native report.


Fourth-build storage resumption: 784,736 historically artifact-only bytes now
additionally charged once as evidence; 16 MiB cumulative/4 MiB native/2 MiB new
reservation reconciled without altering old ledgers. Preflight E501 stopped native
admission before copying/configuring/building. Formatting-only correction and
completion lint passed; no preflight retry. Builds 3/4, ledger 411/438; every SEM/TR
case not run. See native report and `build-4-resumption-1/` evidence. Storage gap
addressed; static-stop resumption remains pending. Stages 2–3/AURORA-BRIDGE-001 open.


Stopped preflight finalised: audit exit 0; 10,901 comparisons, final inventory 6041, reporting/readback complete. Charged 8.976094 s; subcap 82.018887 s, native 224.314534 s, implementation 228.871913 s remain. Builds 3/4, ledger 411/438; all native cases not run. Unchanged 55+30-second build/completion reservation no longer fits; resolve admission before resumption. Historical failures remain failures. See native report; Stages 2–3/AURORA-BRIDGE-001 open.


Fourth-build total amended prospectively to 120 s; 17.981113 s retained as consumed.
Source admission then found AURORA-NATIVE-SEAL-001: unchanged preflight uses older
full-file hashes for five legitimately appended reports. Current hashes match the
latest seal and historical prefixes are intact. Stop before preflight/build;
non-formatting validation correction is not authorised here. Native launcher and
worker unchanged; all SEM/TR cases not run, builds 3/4, ledger 411/438. See native
report and `build-4-time-admission-1/`. Stages 2–3/AURORA-BRIDGE-001 remain open.


Time-admission finalisation complete: audit passed, 10,901 comparisons, 6066 final inventory entries and report readback complete. Charged 9.044320 s; fourth-build 92.974568 s, native 215.270214 s, implementation 219.827594 s remain. No preflight/build/case launched. Builds 3/4; ledger 411/438. AURORA-NATIVE-SEAL-001 needs the explicit non-formatting preflight correction described in the native report. Stages 2–3/AURORA-BRIDGE-001 remain open.


AURORA-NATIVE-SEAL-001 corrected: explicit five-report allowlist, protected prefix
checks and pinned complete seals/lengths. Eight fixtures passed once; stable-snapshot
preflight passed. The authorised fourth build configured then failed compiling
`libiop/algebra/utils.cpp`: `utils.hpp:40` has undeclared `size_t`. No functional fix
or fifth build; AURORA-NATIVE-COMPILE-002 open for a bounded source-only correction
review. No native SEM/TR case ran; builds 4/4, ledger 419/448. All 24 native cases,
two new fixture reruns and three older tooling reruns remain unused. Historical
failures preserved; see native report and `seal-repair-1/` evidence. Stages 2–3 and
AURORA-BRIDGE-001 remain open; proof ledger two used/one unused.


Seal repair/fourth-build finalisation: preservation passed, 10,901 comparisons, 7073 final inventory entries, complete reporting/readback. Charged 18.074351 s; native 197.195863 s, implementation 201.753243 s, fourth-build subcap 124.900217 s remain. Eight seal fixtures/preflight passed; fourth build failed at utils.hpp undeclared size_t, all native cases unrun. Builds 4/4, ledger 419/448. AURORA-NATIVE-SEAL-001 resolved at this layer; AURORA-NATIVE-COMPILE-002 and AURORA-BRIDGE-001 remain open. See native report.


### Fifth-build patch-stack outcome

The authorised utils.hpp/utils.cpp/utils.tcc declaration overlay adds `<cstddef>` and 19 `std::size_t` qualifications. It preserves underlying types and algorithms; full before/after hashes and patch are in `header-correction-1/overlay-amendment.json`. Both native targets link with the prior ten-reference functional correction and unchanged libff target selection. Functional SEM/TR validation remains unexecuted due to the outer storage-accounting stop.


Fifth-build continuation: the exact approved standard-size correction compiled and both targets linked; the outer monitor failed on an unregistered 1,387,120-byte CMake harness object. This is an incomplete guarded run. SEM-01–SEM-08 and TR-01–TR-16 are all not run; builds 5/5, ledger 419/448, all 24 native invocations retained. AURORA-NATIVE-COMPILE-002 is resolved at declaration/compilation level. AURORA-NATIVE-ARTIFACT-001 is open: exact CMake target-local object registration and exception-safe monitor termination/reporting need a bounded correction; no such correction was made here. Full preservation admission exited 1 before a worker, with zero fresh baseline comparisons. The previous 10,901 comparisons remain historical only. Final name inventory passed (8078 entries); failure reports/readback completed, not a successful audit.

Measured compiler body 6.052475 s; worker 6.115275 s and cgroup-v2 memory.peak 450,625,536 bytes under 1 GiB. Outer wall/RSS completion metrics are unavailable. Conservative charge 73.345883 s comprises preflight 1.345883, existing unfinished-run fallback 60, failed-audit reservation 7 and bookkeeping 5; it is not a measured 60-second build. Remaining: build continuation 51.554334 s; parent 59.478106 s; native 123.849980 s; implementation 128.407360 s. Analysis/provisioning unchanged.

Stages 2–3 and AURORA-BRIDGE-001 remain open: query/masking, commitment transformation, extraction/privacy, concrete-hash and complete authentication remain unestablished. Isolation remains stopped/unactivated; CPU proving paused; proof ledger two used/one unused. No native comparison, proof, zkVM execution, installation or activation occurred. Evidence and additive failure seal: `docs/data/s3_aurora_native_transcript_pilot_1/header-correction-1/`.

Final retained-byte accounting: new evidence 000002002278 bytes; combined reservation 000003622250/4,194,304, remaining 000000572054; cumulative 000015845249/18,874,368; native 000005228882/6,291,456. No bytes removed from prior charges. Aggregate artifacts 27,839,915/134,217,728 bytes, including all 8,253,592 new bytes; the existing per-file classification breach remains unresolved. See the additive failure seal and validation-closure.json; package is **not complete**.


### Output registration/monitor repair and retained native execution

The consolidated continuation passed five tooling fixtures, then a complete pre-native preservation audit, then SEM-01–SEM-08 and TR-01–TR-16 once each. Native binaries were reused without rebuilding. Cumulative ledger is **448/450** (419 opening + 5 tooling + 24 native); two targeted tooling reruns remain unused and are not native retries. Builds remain **5/5**, with no new attempt. The first tooling command failed lint before admitting any fixture (two unused imports and an unbound loop-variable warning); the log and source snapshot are retained, the narrow correction passed lint/format, and no test was rerun.

The 22 retained compiler/linker output identities, target rules, dependencies, source overlays and successful link records were verified against the retained failure seal before execution. Exactly two CMake target-local harness object paths were added to the prospective registration. Logs/textual metadata and unregistered paths retain their evidence/fallback roles. All historical charges, including 1,844,237 bytes of build-tree evidence and the prior 73.345883-second charge, remain paid. The failed fifth-build outer guard is not retroactively marked successful.

The existing monitor now preserves a primary fatal error before containment, attempts bounded termination/reaping of its exact workload, and records cleanup/reporting errors separately. Unavailable timing/memory remains explicit; the established missing-time fallback remains 60 seconds. GUARD-04 exercised the shared fatal handler with an active harmless child, killed/reaped with exit -9; GUARD-05 exercised it after termination, retaining null measurements and a failed result. These are focused handler fixtures, not exhaustive transport/persistence fault injection or validation of the separate isolation controller.

Native results establish only the demonstrated patched-library public transcript correspondence and eight tested GF(2^192) operator behaviours. The common BCS caller, EXP2 state/round/challenge/finish paths, native public-record replay and original absorbed-digest omission control were exercised. Full Aurora proving/verifying, complete authentication, other field families and unrelated latent R1CS defects were not tested. TR-16 reproduces the original omission; it is not a forgery experiment. Existing algebraic primary-input checks remain distinct from the historical missing explicit hash-chain initialisation.

Stages 2–3 and **AURORA-BRIDGE-001 remain open**: query/masking, commitment transformation, extraction/privacy, concrete-hash composition, complete authentication and production-security obligations are unchanged. Isolation stays stopped/unactivated; CPU proving paused; proof ledger two used/one unused. No installation, configuration, compilation, proof or zkVM execution occurred in this continuation. Final preservation and exact balances are appended below after its single final audit.


Finalisation complete: the final audit exited 0 after **3.982068 seconds**, with **49,991,680 bytes** cgroup-v2 memory.peak under 256 MiB; sampled tree RSS 70,905,856 bytes. It repeated the complete 10,901 disjoint baseline content comparisons and 10,936 identity-inclusive paths with all frozen inputs/artifacts, without replacing them with prior partial evidence. Final audit inventory 8188; closure inventory 8193, no missing or unexpected paths. Both audit reporting/readback and outer guards passed. New report appendices are covered by the additive completion seal.

Charge **16.585722 seconds** = 11.585722 measured guarded wall seconds (including the retained initial static failure) + five conservative bookkeeping seconds. Remaining: continuation **94.968612 s**; parent **102.892385 s**; native **107.264258 s**; implementation **111.821638 s**. Analysis 171.260007 s and provisioning 41.843650 s remain unchanged. The old 73.345883-second conservative charge remains intact. No build reservation remains; builds 5/5 unchanged. All five tooling and 24 native cases passed once, ledger **448/450**, two narrowly reserved tooling reruns unused. The retained audit template's generic test fields are unpopulated; the individual fixture/native ledgers and closure record the actual 29 invocations.

This completes the isolated native public-input transcript pilot and its preservation continuation, not Aurora as a whole, complete authentication or proof security. AURORA-NATIVE-ARTIFACT-001 is resolved at the demonstrated repair layer; AURORA-BRIDGE-001 and Stages 2–3 stay open. No further work starts here.

Final exact evidence accounting: new 000000349206 bytes; retained-plus-new reservation 000003971456/6,291,456, remaining 000002320000; cumulative 000016194455/18,874,368; native 000005578088/8,388,608. No historic charges reclaimed. Artifacts remain 27,839,915/134,217,728 bytes; no new artifacts. Closure and additive seal: `output-guard-repair-1/validation-closure.json` and `manifest.json`.
