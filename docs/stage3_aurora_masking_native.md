# Native masking component — OCT31-KYC-NATIVE-MILESTONE-1

The isolated branch compiled, and 24 public component cases passed on build 2.
**Final native validation is incomplete.** A reviewed harness-only N04 improvement
compiled on build 3 but its revalidation and the 16 rebuilt EXP2 cases are pending
an automatic approval-review block. No current-build correspondence or private-proof
admission is claimed from the earlier binary's results.

## Source and patch identity

Pinned libiop commit `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, root tree
`2e2588ccb085242dd2237875c3b9adf1a0fc958c`. Source copies are isolated in
[the experiment](../experiments/aurora_masking_milestone_1/); 919 original files,
3,163,710 bytes, were copied without Git/build/cache directories. Original pinned
sources and the prior EXP2/libff/ten-reference/size-type corrections remain unchanged.

The prospective library patch SHA-256 is
`cb88c8a4df6ee669525175be677bc166e50ff3c07def1d0302cacb2ef48e0420`.
The build-3 harness SHA-256 is
`ab3c66696547b4a221bc0b3a7922e49adb09dcfbce7d0425710e2ba698109b94`.
The prospective patch manifest is
`99bc11390fcd100995ff2d81e68fc8075caaf88793743dec4f1ad94a477f1ce9`.
[Build commands and input hashes](data/oct31_kyc_native_milestone_1/native-build-3-commands.json)
and earlier attempt records retain the complete stack. Dispatcher formatting/call
labels are separately captured by final preservation; native source hashes are not
silently regenerated to match unapproved changes.

## Implemented public branch

Fourteen isolated native files carry sumcheck/lincheck/Aurora registration,
unit-pad LDT reduction and FRI folded degree bounds. The branch retains unrestricted
mask coefficients, early one-field beta = xi*u[t−1], fixed unit mask coefficients,
prover/verifier beta agreement, exact 2J reducer coins and the final unit pad.
Both equal-degree reducer terms remain present. FRI updates intermediate degree
bounds at the proper fold boundary and rejects non-divisible configurations.
No generic field, FFT or IOP-engine replacement was introduced.

The otherwise missing Google Test header was used only for two FRIEND_TEST
friend declarations. Their literal friend-class expansions are preserved in the
isolated header; no Google Test mock or operator replacement is supplied.
Build 1 failed on three public-fixture lvalue/rvalue polynomial-constructor calls.
Explicit vector copy temporaries fixed only those fixture branches. Build 2 linked
both targets. Later source review found N04's zero-triple case initially tested the
zero polynomial at sumcheck, rather than passing the zero triple through actual
lincheck. The narrow harness addition retains that assertion and also calls the
real lincheck path with (0,0,0). Build 3 linked; tests of that new binary remain pending.
Previous patches/manifests and the successful build-2 harness are retained in overlay.

Configuration uses the approved local prefix, GNU++14, Release overridden to
`-O0 -g0`, existing non-ASM/non-multicore libff selection, Ninja and one compiler
worker. Targets are `aurora_masking_native` and `exp2_native`; no full Aurora prover,
private witness, installed dependency or zkVM guest is built or run.

## Executed paths and independent expectations

N01 uses exact GF(2) polynomial arithmetic to check the degree-192 modulus, the
Frobenius identity and gcd tests at 96/64, plus native word/basis products. Sumcheck
uses independently specified schoolbook coefficients/division/evaluation, including
non-unit xi, nonzero quotient/remainder, shifted domains and a wrong-beta degree
condition. Reducer comparisons cover all 256 public evaluation points, actual pad
submission, both mappings and malformed counts. FRI checks D20→10→5 and
D24→12→6→3; N18 compares actual folds and the complete terminal coefficient vector
with independent two-point interpolation and all 64 terminal-domain evaluations.

Actual lincheck uses zero R1CS matrices with prescribed public challenges. Aurora
coverage reaches native constructors/registration and early beta-message layout,
not complete `produce_proof`. The fixture uses M=N=8,K=2,b=2,L=256 and deliberately
small public test parameters; it is not a deployed security profile. Test-only
coefficient injection is compiled only for the public harness. A wrong-beta degree
violation is not an executed forgery or a full proof-verifier rejection.

| ID | Contract case | Recorded invocations | Result |
| --- | --- | --- | --- |
| N-01 | independent-field-modulus-basis-certificate | M1-0019: pass | passed at recorded inputs |
| N-02 | unrestricted-mask-coefficient-map | M1-0020: pass | passed at recorded inputs |
| N-03 | nonunit-xi-sum | M1-0021: pass | passed at recorded inputs |
| N-04 | zero-lincheck-triple | M1-0022: pass | passed at recorded inputs |
| N-05 | nonzero-quotient-remainder | M1-0023: pass | passed at recorded inputs |
| N-06 | prover-verifier-point-agreement | M1-0024: pass | passed at recorded inputs |
| N-07 | shifted-vector-point-agreement | M1-0025: pass | passed at recorded inputs |
| N-08 | tampered-beta-degree-condition | M1-0026: pass | passed at recorded inputs |
| N-09 | wrong-beta-message-length | M1-0027: pass | passed at recorded inputs |
| N-10 | zero-reducer-coins-retain-pad | M1-0028: pass | passed at recorded inputs |
| N-11 | mixed-reducer-degrees | M1-0029: pass | passed at recorded inputs |
| N-12 | bump-coefficient-index | M1-0030: pass | passed at recorded inputs |
| N-13 | shifted-reducer-vector-point | M1-0031: pass | passed at recorded inputs |
| N-14 | wrong-reducer-coin-count | M1-0032: pass | passed at recorded inputs |
| N-15 | missing-reducer-pad | M1-0033: pass | passed at recorded inputs |
| N-16 | two-fold-degree-registration | M1-0034: pass | passed at recorded inputs |
| N-17 | longer-fold-degree-sequence | M1-0035: pass | passed at recorded inputs |
| N-18 | independent-fold-terminal-coefficients | M1-0036: pass | passed at recorded inputs |
| N-19 | nondivisible-bound-rejection | M1-0037: pass | passed at recorded inputs |
| N-20 | actual-lincheck-paths | M1-0038: pass | passed at recorded inputs |
| N-21 | aurora-early-mask-beta-registration | M1-0039: pass | passed at recorded inputs |
| N-22 | dependent-challenge-order | M1-0040: pass | passed at recorded inputs |
| N-23 | unsupported-branch | M1-0041: pass | passed at recorded inputs |
| N-24 | invalid-attached-claim | M1-0042: pass | passed at recorded inputs |

Every row above refers to build 2. N04's stronger actual zero-triple caller coverage
is compiled but not executed in build 3. To avoid whole-binary reuse ambiguity,
24 N cases should be rerun against the delivered build-3 binary from the approved
correction pool, then the 16 EXP2 cases once. The EXP2 expectations remain the
retained independent vectors; the legacy omission control is not a forgery test.

| ID | Contract case | Recorded invocations | Result |
| --- | --- | --- | --- |
| TR-01 | baseline complete trace, including empty scheduled records, four challenges and legal absorb after squeeze | none | not run; blocked |
| TR-02 | fresh second baseline run, counted repeat | none | not run; blocked |
| TR-03 | typed public context nonce first byte XOR1, re-encode unchanged remaining fields | none | not run; blocked |
| TR-04 | root_a last byte XOR1 | none | not run; blocked |
| TR-05 | field_a last byte XOR1 | none | not run; blocked |
| TR-06 | submit round1 before round0 | none | not run; blocked |
| TR-07 | swap the two one-field R0 messages | none | not run; blocked |
| TR-08 | second trusted harness plan uses one two-field R0 message rather than two one-field messages | none | not run; blocked |
| TR-09 | empty canonical statement byte input to typed adapter | none | not run; blocked |
| TR-10 | root_a truncated to63 bytes | none | not run; blocked |
| TR-11 | field_a truncated to23 bytes | none | not run; blocked |
| TR-12 | request transcript version1 | none | not run; blocked |
| TR-13 | after R0 challenge0, attempt R1 before remaining two R0 challenges | none | not run; blocked |
| TR-14 | request challenge1 before challenge0 | none | not run; blocked |
| TR-15 | append a fourth round after valid finish | none | not run; blocked |
| TR-16 | isolated old omission equation and length-only repair for two64-byte digests | none | not run; blocked |

## Admission block and remaining security work

Automatic approval review rejected the unchanged TR command twice, applying the old
24-native-case ceiling despite the milestone plan's 40 initial native cases and
600-slot allocation. Neither rejected command launched. A direct confirmation was
requested; no workaround or additional native case was attempted. The evidence
records both review outcomes. C09 correctly remains pending because current native
source/binary identities lack the corresponding final case matrix.

Query/masking soundness, general nontrivial R1CS correspondence, generic challenge
access, commitment/private-opening transformation, extraction/privacy, concrete-hash
composition, adaptive Delta_tail and complete authentication remain unresolved.
The generic IOP-engine boundary comparison noted in source review is unchanged;
these cases do not claim universal challenge-API hardening. No security target or
proof-size claim follows from these component tests. AURORA-BRIDGE-001 and Stages
2–3 remain open, CPU proving is paused, isolation remains stopped/unactivated,
and the proof ledger is two used/one unused.

## Final preservation checkpoint

The complete audit passed with exit status 0: 8,759 original and 2,142 disjoint
supplemental content comparisons (10,901 total; 10,936 identity-inclusive historical
paths), protected immutable inputs and report prefixes, and a 10,625-entry inventory.
There were no unexpected or missing paths. All 841 local documentation links passed.
The worker completed report generation and readback; its outer guard also passed.
Guarded elapsed time was 6.058319 seconds (audit child 4.163477 seconds). Peak
cgroup-v2 memory was 51,773,440 bytes under the unchanged 268,435,456-byte cap,
including charged worker descendants, file cache and kernel memory; swap and memory
events were zero. Independently sampled summed tree RSS peaked at 62,828,544 bytes;
shared mappings can be counted more than once in that separate metric.

The first preparation failed at the auditor's 10,000-entry traversal admission.
Its helper, new-output inventory and failure remain in `corrections/` and `jobs/`.
The correction partitions the same inventory by its 16 disjoint original roots,
retains the 10,000-entry limit per partition and requires full expected-path union
with no overlap. Corrected preparation and final lint/format checks passed. No
historical baseline, expected entry, digest, permitted-content boundary or file
limit was changed. This is preservation completion; it does not clear the native
admission blocker or establish proof security. Final accounting and post-report
inventory/readback are recorded in the [closure](data/oct31_kyc_native_milestone_1/validation-closure.json).

## Final-binary validation — 29 September 2026

This dated completion supersedes the earlier admission-blocked checkpoint above;
its failed approval attempts and earlier-binary evidence are retained unchanged.
The user's direct confirmation admitted the unchanged commands through normal
automatic approval review. All 24 strengthened-final-binary cases, the 16 pending
transcript cases and C-09 passed once: 41 new invocations, no new build or functional
correction. Baseline, harness, other integrations and all 276 measurements were
reused without rerunning.

Preflight verified the 2,347-entry completed-checkpoint seal, all 919 native source
files against their retained origin/approved patch, every build-3 input, and the
16 independent retained expectations. The final masking binary SHA-256 is
`52e210b488f7ccf0df4aa477aa7f66c65764f511b5532403a02ef322df94e827`;
EXP2 is `65c24a731b68a58ba903abf0de9e64b576087e0df056cfcc354028407e1b4af2`.
Their identities match the previously sealed build artifacts. Neither executable,
its library inputs nor the agreed expectations changed.

The executed commands, each wrapped by the existing coordinator, were:

```sh
.venv/bin/python -I -B experiments/kyc_milestone_1/run.py job native-final-cases native 60 -- .venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases N 1 24
.venv/bin/python -I -B experiments/kyc_milestone_1/run.py job native-final-transcripts native 60 -- .venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases TR 1 16
.venv/bin/python -I -B experiments/kyc_milestone_1/run.py job native-final-c09 python 30 -- .venv/bin/python -I -B experiments/kyc_milestone_1/tasks.py cases C 9 9
```

| ID | Contract case | Final invocation | Result |
| --- | --- | --- | --- |
| N-01 | independent-field-modulus-basis-certificate | M1-0379 | pass |
| N-02 | unrestricted-mask-coefficient-map | M1-0380 | pass |
| N-03 | nonunit-xi-sum | M1-0381 | pass |
| N-04 | zero-lincheck-triple | M1-0382 | pass |
| N-05 | nonzero-quotient-remainder | M1-0383 | pass |
| N-06 | prover-verifier-point-agreement | M1-0384 | pass |
| N-07 | shifted-vector-point-agreement | M1-0385 | pass |
| N-08 | tampered-beta-degree-condition | M1-0386 | pass |
| N-09 | wrong-beta-message-length | M1-0387 | pass |
| N-10 | zero-reducer-coins-retain-pad | M1-0388 | pass |
| N-11 | mixed-reducer-degrees | M1-0389 | pass |
| N-12 | bump-coefficient-index | M1-0390 | pass |
| N-13 | shifted-reducer-vector-point | M1-0391 | pass |
| N-14 | wrong-reducer-coin-count | M1-0392 | pass |
| N-15 | missing-reducer-pad | M1-0393 | pass |
| N-16 | two-fold-degree-registration | M1-0394 | pass |
| N-17 | longer-fold-degree-sequence | M1-0395 | pass |
| N-18 | independent-fold-terminal-coefficients | M1-0396 | pass |
| N-19 | nondivisible-bound-rejection | M1-0397 | pass |
| N-20 | actual-lincheck-paths | M1-0398 | pass |
| N-21 | aurora-early-mask-beta-registration | M1-0399 | pass |
| N-22 | dependent-challenge-order | M1-0400 | pass |
| N-23 | unsupported-branch | M1-0401 | pass |
| N-24 | invalid-attached-claim | M1-0402 | pass |
| TR-01 | baseline complete trace, including empty scheduled records, four challenges and legal absorb after squeeze | M1-0403 | pass |
| TR-02 | fresh second baseline run, counted repeat | M1-0404 | pass |
| TR-03 | typed public context nonce first byte XOR1, re-encode unchanged remaining fields | M1-0405 | pass |
| TR-04 | root_a last byte XOR1 | M1-0406 | pass |
| TR-05 | field_a last byte XOR1 | M1-0407 | pass |
| TR-06 | submit round1 before round0 | M1-0408 | pass |
| TR-07 | swap the two one-field R0 messages | M1-0409 | pass |
| TR-08 | second trusted harness plan uses one two-field R0 message rather than two one-field messages | M1-0410 | pass |
| TR-09 | empty canonical statement byte input to typed adapter | M1-0411 | pass |
| TR-10 | root_a truncated to63 bytes | M1-0412 | pass |
| TR-11 | field_a truncated to23 bytes | M1-0413 | pass |
| TR-12 | request transcript version1 | M1-0414 | pass |
| TR-13 | after R0 challenge0, attempt R1 before remaining two R0 challenges | M1-0415 | pass |
| TR-14 | request challenge1 before challenge0 | M1-0416 | pass |
| TR-15 | append a fourth round after valid finish | M1-0417 | pass |
| TR-16 | isolated old omission equation and length-only repair for two64-byte digests | M1-0418 | pass |
| C-09 | native-caller-coverage-export | M1-0419 | pass |

N04 now demonstrates the actual zero-triple lincheck caller on the strengthened
binary, while N20 retains the nonzero challenge fixture. C-09 checks the actual
case-qualified sumcheck, reducer, FRI, lincheck and Aurora registration paths against
current binary/patch identities, without substituting earlier-binary passes.
TR-01–TR-15 execute the retained native EXP2 common caller/hash chain and compare
exact frames/states/challenges or specified atomic/sticky rejection with independent
expectations. TR-16 reproduces the original omission through the native negative
control; it is not a forgery or a proof-security experiment. Explicit transcript
initialisation is now demonstrated, while algebraic primary-input checks remain a
separate existing property.

The N and TR jobs took 1.067412 s and 2.085879 s, with cgroup memory peaks
27,074,560 B and 28,680,192 B under the unchanged 1 GiB native ceiling. C-09 took
0.649100 s, peaking at 34,275,328 B under 256 MiB. These are validation job resources,
not proof generation or authentication performance. The final cumulative count is
867/1,050 (419 milestone invocations; 181 milestone slots and two separate historical
tooling slots unused); builds remain 8/13.

[Individual machine-readable outcomes](data/oct31_kyc_native_milestone_1/native-finalisation-1/outcomes.json)
and [verified identities](data/oct31_kyc_native_milestone_1/native-finalisation-1/confirmed-inputs.json)
retain exact commands, actual paths and expectation provenance. The final continuation
audit/closure is recorded separately from the preserved earlier checkpoint.

This demonstrates only the tested public native components and EXP2 correspondence.
It does not establish full Aurora correctness, nontrivial complete R1CS relation
coverage, private authentication, query/masking security, commitment transformation,
extraction/privacy, concrete-hash composition, adaptive Delta_tail or production
security. AURORA-BRIDGE-001 and Stages 2–3 remain open. CPU proving stays paused;
isolation stays stopped/unactivated; proof ledger two used/one unused.

## Final milestone closure — 29 September 2026

**OCT31-KYC-NATIVE-MILESTONE-1 is complete at its approved reference/component
validation scope.** All originally planned 392 distinct cases/trials are covered,
including all 41 pending final-binary/transcript/C-09 checks. There were no native
failures or new builds in this continuation. Baseline and all 276 benchmark results
were reused unchanged; earlier-binary results, failures and rejected admissions
remain separately preserved.

The continuation's complete preservation audit exited 0: 8,759 original plus
2,142 disjoint supplemental comparisons, 10,936 identity-inclusive historical paths,
complete prior seals/report prefixes and a 10,732-entry inventory with no missing
or unexpected names. Audit worker reporting/readback and outer guard passed.
Elapsed guard time was 4.872552 s (worker 4.203994 s); cgroup memory peak was
46,354,432 B under the unchanged 256 MiB ceiling, with no memory-event breach or
swap. Separately sampled summed process-tree RSS was 63,078,400 B; shared mappings
can be counted repeatedly in that metric. All 1,520 local link checks passed.

The first preparation reported the already-sealed `benchmarks/README.md` outside
its traversal root. Content matched its historical seal. Its helper, snapshots and
failure are retained in `native-finalisation-1/failed-preparation-1`; the correction
traverses `benchmarks` in place of its existing testbed subdirectory and retains all
expected names and hashes. Corrected preparation and affected lint/format passed.
No baseline or expected digest was regenerated, no content permission broadened,
and no functional test was repeated for this tooling correction.

Final report seals, final inventory/readback, exact-unit shutdown and all time and
storage accounting are recorded in the [completed continuation closure](data/oct31_kyc_native_milestone_1/native-finalisation-1/validation-closure.json).
The invocation ledger is 867/1,050 (419 milestone invocations; 181 milestone slots
plus two separate historical tooling slots remain). Builds remain 8/13. Analysis
and isolation allowances are unchanged; completion reserves remain inside unused
implementation/evidence balances.

The next bounded native validation target is a nontrivial public R1CS fixture
through the corrected components before considering private integration; no such
work is started here. Complete Aurora correctness, authentication/private-proof
feasibility, query/masking and commitment-transformation arguments, extraction/privacy,
concrete-hash composition, adaptive Delta_tail and production security remain open.
Stages 2–3/AURORA-BRIDGE-001 remain open; isolation stopped/unactivated and CPU
proving paused. No proof or zkVM execution occurred; proof ledger two used/one unused.
