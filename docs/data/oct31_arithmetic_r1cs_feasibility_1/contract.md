# INT-R1CS-FR254-1 — exact candidate specification, not an admitted profile

Only manuscript Sections II–VIII and SPEC-001–004 govern the relation. The
SHA-256 of the selected manuscript remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The affine candidate is closed unsuccessfully for resource admission and retained
unchanged. This document selects **one** replacement for feasibility analysis.
It does not install a field, compile a gadget or change the active construction.

## Field and complete predicate

Use the existing pinned libff `alt_bn128_Fr` field definition, with prime modulus

`p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.

The retained `alt_bn128_fields.cpp` declares 254 bits and 2-adicity 28. This is a
prime **scalar field**, not the curve's different base field. No elliptic-curve
proof assumption is introduced. Reusing its field definition neither proves its
native integration nor establishes post-quantum soundness. Elements require at
least 32 bytes in the existing non-packed vector model. Native sizeof/compatibility
in this new profile has not been measured; that cannot make the payload smaller
than 32 bytes per element.

The target remains the exact joint `emit_private` predicate: one parsed secret,
attributes, certified identifier, signature and twenty siblings, with the trusted
public statement/parameters/state/context and existing canonical bytes. `PubOK`,
public policy, independently derived A/t1/tr/zero leaf and statement binding retain
their existing trust boundary. No hidden check moves into preprocessing. Session
freshness/atomic consumption remain lifecycle obligations. Profile and relation
IDs would bind this field, all ranges, schedules, encodings, matrices and admission
parameters; the existing GF192 proof parser must reject this unadopted profile.

## Integer representation and constraints

All equations below are over Fp; their interpretation as integers is justified
by bounds, not by replacing integer operations with field operations.

* `U_n(x)`, n <= 128: fresh bits bi satisfy bi(bi-1)=0 and
  x = sum(2^i bi). This costs n Boolean rows and one linking row if x is a
  distinct column. Because 2^n < p, the representation is unique.
* `S_n(x)`: the same n bits with
  x = sum(i<n-1,2^i bi) - 2^(n-1) b[n-1]. This represents exactly
  [-2^(n-1),2^(n-1)-1], including INT64_MIN. Wire-to-byte links preserve
  existing bit order; a field value with unrelated bytes is not admissible.
* `C_q(x)`, q=8,380,417: U23(x), U23(t), x+t=q-1. The entire sum is below
  2^24 < p. Thus x is canonical [0,q), not merely a 23-bit value. Cost with
  separate packed columns: 49 rows. t is uniquely constrained; it is not advice.
* Public c in [0,q), modular product: Cq(x), Cq(r), U23(k),
  `(c*x)*1 = q*k+r`. The difference of the two integer sides has absolute
  value <2^47 < p, so equality cannot hide wraparound. This forces
  k=floor(c*x/q), r=c*x mod q. All canonical inputs have this witness,
  including c=0; noncanonical x cannot be normalised into acceptance. Fully
  guarded specification cost is 49+49+24+1=123 rows, before boundary validity
  or byte links. This is a **symbolic row formula**, not a generated measurement.
  Public twiddles are ordinary residues; inverse negative twiddles use the
  signed path below. No Montgomery scaling or new transform convention.
* Private canonical multiplication, where actually required: x*y=q*k+r with
  both inputs Cq, output Cq, k U23. Both sides <2^47, same uniqueness argument.
  This is a proposed formula, not extrapolated validation of the public kernel.
* Signed64 Euclidean division by an existing legal positive public divisor d:
  S64(x), S64(k), U63(r), U63(t), r+t=d-1, x=d*k+r. With d<=2^63-1,
  the absolute difference is <2^127 < p. Both Q and R are constructed and
  linked, preserving SPEC-004, even if only R is requested. Zero divisor
  constructs the rejection outcome; it never admits this positive-d relation.
  Negative/private/out-of-range public divisors remain construction errors.
  For d=q, Cq(r) is the tighter equivalent remainder constraint. Neither
  quotient nor remainder can be freely supplied or aliased across operations.
* Checked add/sub: construct the exact S65 sum/difference; constrain its low
  64 bits to the output, and validity to equality of its two high sign bits.
  Checked multiply: construct exact S128 product, link all low 64 output bits,
  and validity to sign extension of bit63 through bits64..127. Products have
  absolute value <=2^126; differences used in the equality stay <2^128 < p.
  Overflow must reject the active path; replacing the operation by mod q before
  that test is forbidden. Wrap outputs after invalidity remain unusable.
* Canonical add/sub: use x+y=q*k+r with k Boolean, or x-y+q*b=r with b
  Boolean, together with Cq inputs/output. Bounds <2^25 justify integer
  equality. These replace checked paths only at proven canonical boundaries.
  NTT entry still accepts **every signed64** value by exact normalisation.
  All eight forward/inverse schedules, twiddles, factor 8,347,681 and output
  representatives remain those in the executable reference.

Every range check, conversion and link contributes rows, columns and nonzeros.
Already established input bits may be reused only by literal shared columns and
their retained constraints. Packing a field value does not confer a range proof.
The 123-row formula cannot be multiplied into a full-verifier count: input
conversions, signed paths, additions, shared checks, control and matrix density
must be counted separately. A 64-bit packing row can contain 65 nonzero terms.

Norm tests use the original strict bound abs(z)<524092, including signedness.
Decomposition/UseHint retain their existing Boolean definitions at first; a
quotient formula without the original boundary/equality cases is not a substitute.
The 61-byte hint canonicality, ordered indices/count/padding, 1,280 response
coefficients, 1,536 w1 nibbles and their byte links remain constrained.

## Boolean, control and hash relation in this field

Free bits satisfy b(b-1)=0. AND is x*y=z. XOR is
`(2*x)*y = x+y-z`; NOT is the affine form 1-x. With Boolean inputs these
uniquely force Boolean outputs. NOT and constant-operand Boolean expressions may
be represented by affine forms; XOR of two unknown bits costs a multiplication
row in odd characteristic. It is **not** a free GF(2) sum. Every private Keccak
chi product is retained as one row; this candidate does not add hash-specific
lookups, custom gates, cross-round algebra or probabilistic bit checks.

Rotations/permutations rewire; SHA3/SHAKE rounds, padding, suffixes, byte order and
absorption/squeezing are unchanged. At least the 268,800 chi products in the
seven-permutation final SHAKE256 remain. Additional XOR/range/input/equality rows
are positive unknown residuals for the admission lower bound, not zero costs.
The retained M-16 measurement specialised mu publicly, which is **not permitted**
in the joint candidate; making it private cannot remove a chi row under this
mapping. No stored digest is substituted for hashing a hidden witness.

The bounded 256-byte SampleInBall stream and 248 scanned candidates are retained
with fixed control flow, exact sequential read/write, exhaustion rejection and
masked unusable outputs. Public ExpandA retains each 1,026-byte cap. Arithmetic
optimisation does not remove either cap. Active-path conditions, comparisons,
validity and sticky rejection remain Boolean circuit constraints, not free flags.
To gate a quadratic equation, introduce its constrained product first and then
constrain g*(product-result)=0; do not accidentally introduce degree-three R1CS.
Inactive advice/outputs are fixed to zero when the reference masks them; any
remaining auxiliary is linked to its defining equation and range. On accepted
paths all required equations and ranges are active. No host witness-dependent
branch changes the circuit, constraint count or rejection relation.

Completeness of these specified kernels follows by assigning reference integers,
their unique bits and Euclidean quotient/remainder. Soundness follows inductively
from Booleanity, canonical ranges, the stated no-wrap bounds, unique quotient
and deterministic control. A forged remainder, negative/oversized quotient,
non-Boolean range bit, inconsistent byte encoding, altered carry, free validity
or unlinked output cannot satisfy the specified equations. This is a mathematical
kernel specification, **not a claim that an unimplemented full compiler has been
proved equivalent**. Full relation coverage would still require independent
comparisons and adversarial assignments; none are claimed performed here.

## Degree, domain and admission

All scalar constraints remain degree <=2 after explicit intermediate products.
Keeping R1CS degree two does not preserve a masking theorem across field changes.
Fp uses multiplicative power-of-two subgroups (available only through 2^28 in
this pinned field); it cannot use the binary additive-subspace FFT construction.
The corrected native `encoded_aurora_parameters` explicitly rejects
`paper_masking=true` unless the domain is additive, non-holographic and ZK.
Turning that flag off or lowering masking/security/query budgets is not allowed.
A corresponding multiplicative-domain masking implementation and applicable
simulation argument are missing. No such port is attempted by this package.

Even granting such a port optimistically, retain the existing degree/rate envelope:
M,N are rounded row/variable domains, t=max(M,N), b>=1 is only a lower-bound
parameter, Dconstraint=max(2t+b-1,2M+2b-1), and |L|>=8*max(D,Dconstraint), rounded
to a power of two. The real b, repetitions and all other degree terms stay
unresolved/unchanged; using b=1 in a lower bound is **not** setting b=1 for a
protocol. The required chi rows alone give M,N>=2^19 and |L|>=2^24. A 32-byte
codeword costs >=512 MiB; four simultaneously retained codewords cost >=2 GiB.
This already exceeds a 1 GiB native worker and fills the entire 2 GiB aggregate
before positive matrix, witness, FFT, mask and commitment storage. A single
spilled codeword also exceeds the complete 128 MiB artifact allowance.

The decision therefore precedes arithmetic-gadget implementation. No complete
constraint count, witness, matrix, native instance, codeword or proof is built.
This is a no-go for this exact arithmetic-only replacement and resident backend,
not a universal lower bound for all hash arithmetisations or proof systems.
