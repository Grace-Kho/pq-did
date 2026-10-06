# Compact representation contract — before candidate execution

Selected experiment: **AFFINE-GF192-1**, isolated in
`experiments/compact_auth_representation_1`. No active profile, dependency, signed
encoding or cryptographic parameter changes. The backend field remains the pinned
GF(2^192), polynomial x^192+x^7+x^2+x+1, 24-byte native elements. Integer addition
and reduction are **not** replaced by this characteristic-two field's operations.

The candidate consumes the exact existing Boolean HEADER/GATE/FOOTER graph.
Constants are empty form (zero) and column0 (one). Column1 is the independently
fixed public acceptance bit. All original private input bits receive b(b+1)=0.
XOR is symmetric difference of canonical 0/1-coefficient linear forms; NOT toggles
column0. Every original emitted AND creates a fresh auxiliary column and the
exact equation A*B=C, even if its affine operands simplify to constants/equality.
This deliberate rule gives a sound original-AND count lower bound. No cross-AND
optimisation, probabilistic check, unconstrained advice or free packed bit product.

A deterministic support cut (default64 terms) may emit one exact linear link
A*1=y before retaining the singleton y. No truncation of a form is permitted.
The temporary merged form has at most twice the support cap plus one; retained
wire/term/column/row limits are checked before committing storage. Exhaustion
poisons completion, not a cryptographic rejection or smaller accepted set.
Terminal constraints require the original acceptance expression=public1 and
public1=constant1. Missing footer, bad producer/order/opcode, noncanonical field
values, malformed assignments, or a capacity exception cannot complete a descriptor.

Completeness: assign each original input its bit, each AND column its Boolean
product, and each spill column its affine expression. Induction over graph order
satisfies all equations, including the two acceptance equations when the source
accepts. Soundness: in a field, b(b+1)=0 forces b in{0,1}; affine combinations with
coefficients0/1 are Boolean because characteristic2 preserves the prime subfield.
An AND row uniquely forces the next value, and a spill row uniquely forces its
linear value. Thus every satisfying assignment reconstructs every original wire
and forces the source's acceptance bit1. This establishes both directions for
the existing Boolean graph. It is not, by itself, a formal machine proof that the
whole experimental source implements the reference relation; that source-level
map and its remaining unexecuted obligations stay explicit.

All checked signed64, overflow, SPEC-004 quotient/remainder and canonical mod-q
checks remain in that same graph. Its 23-bit residues and exact46-bit public
products retain the earlier guarded conversion/reduction rules. No alternative
integer encoding or unconstrained quotient is introduced: a wrong quotient or
remainder still violates its original bit equations/guards. Non-Boolean or
inconsistent AND/spill auxiliaries must fail. The field polynomial reduction is
exact GF arithmetic, not integer wraparound or reduction modulo8,380,417.

The full graph continues to use one5329-byte private witness (42,632bits) for
credential signature, holder secret, attributes/disclosure, certified rid and its
20-level Merkle path. Public preprocessing and Ppub/PubOK are unchanged, checked
against trusted instance and canonical X. Hidden checks remain private. SHA-256
stream/matrix hashes are engineering identities, not adopted commitments/RIDs.
No full relation RID, finite Aurora parameter profile or private-proof parser
admission is issued by a component test. Ordinary proof acceptance stays closed.

## Early whole-workload model and conditional decision

Let I=42632, A=all emitted original ANDs, X/N=original XOR/NOTs, S=deterministic
linear spills. Exact complete-graph compact formulas are R=I+A+S+2 and
V=I+A+S+1 (excluding constant); 0<=S<=X+N. Nnz is measured only for completed
fixtures; it is not assumed to remain equal to the conservative translation.
Each AND column contributes a nonzero C coefficient, regardless of affine inputs.

Whole relation coverage includes all canonical parsing/disclosure, holder SHA3,
mu SHAKE, bounded challenge SHAKE and248 private sampling steps, six forward NTTs,
7680 public A/z coefficient products/accumulations,1536 public t1/challenge
products/subtractions, six inverse NTTs,1536 final inverse scalings,1536
UseHint/decomposition/encoding checks,1280 z norm checks, final challenge SHAKE,
20 level-framed Merkle hashes/directions/root equality and sticky final rejection.
The subsequent machine-readable model labels exact cardinalities separately from
unmeasured graph costs. Unknown residuals remain nonnegative symbols, not zero.

The retained full-forward pilot measured every twiddle assignment: its eight
internal stages have904192 ANDs each (7233536 total). The current verifier calls
the same canonical producer kernel and ordinary twiddle schedule with symbolic
private operands; original public-only folding cannot turn those operands public.
Entry/final wrappers differ, so the complete prior10679298 AND count is NOT claimed
as an exact embedded subgraph. One core alone forces M>=2^23. With minimum b=1,
Dconstraint>=2M+1, power-of-two |L|>=8Dconstraint, one24-byte codeword needs>=6GiB.
Six source-identical cores yield at least43401216 AND rows, M>=2^26 and |L|>=2^31,
so one codeword needs>=48GiB. Both bounds are conditional on this exact AND-row-
preserving mapping, not universal lower bounds on arithmetic circuits.

These already exceed the1GiB native/2GiB aggregate limits before assignment,
constraint/sparse-matrix copies, masks, interpolation, FFT scratch, simultaneous
codewords, Merkle commitments/openings and retained artifacts. No full native
instance/generation is admitted. Bounded candidate components remain useful for
exact encoding and adversarial/native interface correspondence; implement those
only. A different integer/field strategy would need new range/bit-linkage and
finite-domain/masking arguments. Merely dropping XOR rows cannot admit this route.

The preceding joint count used an explicit local Limits(max_gates=2000000) in
count_case.py, in count mode with zero stored trace bytes. The outer experiment's
2M materialised-trace ceiling did not force that choice;32M count-only partitions
were available. That smaller declared probe cap was honoured. Neither allowance
is raised here, and aggregate2^32 events is not a per-instance memory exemption.
The previous stopped prefix is retained; no complete count is inferred from it.

## Validation and stopping contract

Root dispatches individually recorded C fixtures and small native comparisons;
independent Boolean/integer oracles and explicit full-field adversarial assignments
must agree. Reuse the previous native binary; no build is planned. Unknown phases,
resource breaches, integrity failures and incomplete case output stop affected
work. Preserve routine corrections and charge retries as new invocations. Do not
rerun the previous21 unrun full-relation cases unless complete admission changes.
Here the early no-go means they remain unrun; no repeated oversized route.

All current balances are reconciled in opening.json/policy.json. Preserve the
300-second completion reserve,2MiB evidence completion reserve, accumulated
27379838 work events, zero proof attempts and independent analysis/isolation ledgers.
