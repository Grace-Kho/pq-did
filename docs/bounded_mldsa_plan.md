# Bounded ML-DSA-65 integration specification

17 September 2026. **The separate Python bounded reference verifier and complete
local CredValid are implemented and tested.** [Implementation evidence](stage2_bounded_mldsa.md)
records the source, API, exact budgets and results. The pinned ordinary backend has
not been modified or rebuilt. Key generation, signing, all-role release integration,
complete relations and circuit/proof work remain pending.

Authority: selected manuscript SHA-256
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`,
Sections VII-A.1/.5/.6, pp. 14–16, and VIII-A, pp. 17–18; requirements
R-009/R-021/R-023/R-032/R-033. Only Sections II–VIII supply protocol requirements.
The referenced August 2024 FIPS 204 Algorithms 3/8 and invoked FIPS 202 algorithms
remain the computation contract. DEP-001's recorded algorithm/editorial dispositions
apply; its quantitative signing-tail claim remains separate and unvalidated.

## Inspected source and build

All source was available locally. Paths below use these exact roots:

- `OQS = native/.deps/src/liboqs-5a1a854b0dc9f2141bdc771c555ee60c37950183`
- `PY = native/.deps/src/liboqs-python-c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061`
- `M = OQS/src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src`
- `I = OQS/src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/integration/liboqs`

[Pinned dependency manifest](../native/dependencies.json) records liboqs and
liboqs-python 0.16.0, the above commits, and the vendored mldsa-native commit
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`. Inspection also covered the equivalent
`ml-dsa-65_x86_64` and `ml-dsa-65_aarch64` source directories.

`native/build/liboqs/compile_commands.json` compiles both portable C and x86-64
ML-DSA-65, with `MLD_CONFIG_PARAMETER_SET=65` and the respective `config_c.h` /
`config_x86_64.h`. The generated `include/oqs/oqsconfig.h` enables distribution
dispatch and x86-64, disables aarch64 and OpenSSL. The wrapper at
`OQS/src/sig/ml_dsa/sig_ml_dsa_65.c:154` dispatches to x86-64 only when AVX2, BMI2
and POPCNT are present, otherwise portable C. This inspection does not claim to
have traced which branch each earlier smoke invocation took.

The following core files are byte-identical across all three architecture copies:

| File relative to M | SHA-256 |
|---|---|
| `sign.c` | `a18fd65dea26403448ed08dabe5db5117ad1cd7559637fc1e3aa3302aaaf8c25` |
| `poly.c` | `3038aebf65a435b3e1ead7432028618316cbc595dac389c06bc1b805c0eb667a` |
| `poly_kl.c` | `0e5bedc2269d8398611635ef1a58b7fcc87fa24a641819ede69364caf474e316` |
| `polyvec_lazy.c` | `e1de3ea478f017b83eb67544e404fe1997c6d2dc8a9d70853c49e2ad00ab3a30` |
| `packing.c` | `5a3cd24d2243e17e33371ea708d5a64deb08cb3fd8be297e8adae7772bce7a80` |

Identical core files do not imply identical arithmetic dispatch. The x86-64 config
enables native arithmetic, including vector rejection sampling. The bounded reference
instead uses one separate Python integer path; no native dispatch enters verification.

## Verification entry and context contract

The existing ordinary route is
`PY/oqs/oqs.py:815 Signature.verify_with_ctx_str(message, signature, context, public_key)`
→ `OQS_SIG_verify_with_ctx_str` → `OQS_SIG_ml_dsa_65_verify_with_ctx_str`
→ the selected `PQCP_MLDSA_NATIVE_MLDSA65_{C,X86_64}_verify`
→ `M/sign.c:1222 mld_sign_verify`
→ `M/sign.c:1089 mld_sign_verify_internal` with `externalmu=0`.

`mld_prepare_domain_separation_prefix` (`sign.c:1512`) rejects contexts longer than
255 bytes and constructs `00 || [len(context)]1 || context` for pure ML-DSA.
`mld_H` (`sign.c:447`) absorbs its three inputs in order. Verification computes
`tr=SHAKE256(pk,64)` and `mu=SHAKE256(tr || prefix || message,64)`, then later
the 48-byte challenge from `mu || w1Encode(w1)`.

The implemented separately named entry in `pqdid.bounded_mldsa` is
`bounded_verify_mldsa65(public_key, message, signature, *, context) -> bool`.
It checks exact immutable bytes, 1952-byte keys, 3309-byte signatures and at most
255 context bytes before decoding. It does not call the signature FFI. The ordinary
Python binding constructs a fixed-size public-key buffer, which can pad a short key,
and the native entry receives no public-key length; its checks are not used here.

For credentials, pass the caller's pinned `pp.pkI`, the exact result of
[`credentials.build_mcred`](../src/pqdid/credentials.py), and the separate
`CREDENTIAL_SIGNING_CONTEXT = b"PQ-DID/credential/v1"`. Signing before a certificate
exists and verification after structural validation must call that same constructor.
No context prefix is added by application code. Do not call the `extmu`, prehash or
no-context APIs as substitutes. The other eight roles use their recorded contexts
when integrated; role selection must not come from an untrusted claimed context.

Malformed input, signature mismatch and sampler exhaustion reject. Missing adapter,
allocation/resource failure or unsupported version must produce explicit failure or
non-completion and never acceptance; distinguish these internally without secret
diagnostics. The implementation returns False for invalid input/signatures or exhaustion,
distinguishes those outcomes internally, and propagates unexpected resource/runtime
errors. There is no fallback to ordinary verification.

## Required verification computation and backend mapping

`M/params.h:32–44` fixes ML-DSA-65: k=6, l=5, eta=4, tau=49, beta=196,
gamma1=2^19, gamma2=(q−1)/32, omega=55, c-tilde length 48. Each polynomial has
256 coefficients and q=8380417. The table retains the original upstream gap analysis.
Its verification requirements are now implemented in the separate Python reference,
as mapped in [stage2_bounded_mldsa.md](stage2_bounded_mldsa.md); per-round hash traces
and BC-1 circuit execution remain future work. Source inspection and ordinary test
success alone are not a bounded conformance proof.

| Required operation | Actual pinned functions/evidence | Original integration requirement |
|---|---|---|
| FIPS 204 Algorithm 3 context preparation and Algorithm 8 verification | `sign.c:1222`, `:1512`, `:1089`; pure context prefix and internal verifier present | Preserve complete algorithms and input checks; expose no external-mu shortcut; freeze reference operation order |
| Decode public key `(rho,t1)` and hash exact pk | `sign.c:1135`, `packing.c:mld_unpack_pk_t1`, `poly.c:777 mld_polyt1_unpack`; 32-byte seed plus six packed 10-bit coefficient polynomials | Explicit boundary length check; bounded expansion of every matrix entry; test packed extremes and FIPS byte order; key trust/provenance is separate |
| Decode c-tilde/z and enforce `\|\|z\|\|∞ < gamma1−beta` | `sign.c:1114–1129`, `polyvec.c:475 mld_polyvecl_unpack_z`, `poly_kl.c:803/:871 mld_polyz_unpack`, `polyvec.c:213 mld_polyvecl_chknorm`, `poly.c:914/:969 mld_poly_chknorm` | Retain all checks; norm threshold 524092 is strict; test both signs at boundary |
| ExpandA: 30 distinct RejNTTPoly invocations, each ≤1026 bytes | `polyvec_lazy.c:59 mld_polyvec_matrix_expand_eager`; seeds are `rho \|\| column \|\| row`; `poly.c:648 mld_poly_uniform`, `:682 mld_poly_uniform_4x`, `:543 mld_rej_uniform_c` | **Cap absent.** Add per-polynomial counters, failure returns and propagation. Preserve 23-bit little-endian candidates, rejection at t≥q and coefficient order |
| SampleInBall once from the signature's 48-byte c-tilde, ≤256 total bytes | `poly_kl.c:563 mld_poly_challenge`; first eight little-endian sign bytes; loop i=207..255, repeatedly consume index bytes until j≤i, then perform specified assignment/sign shift | **Cap absent.** Count the eight signs plus every index, including rejected indices; fail before consuming byte 257; propagate failure |
| NTT, products, sums, subtraction, inverse NTT, modular representatives | `sign.c:1149–1179`; `polyvec_lazy.c:147` matrix row product, `poly.c:mld_poly_ntt`, `mld_poly_pointwise_montgomery`, `mld_poly_sub/reduce/invntt_tomont/caddq`, `reduce.h:mld_montgomery_reduce` | Native arithmetic is present; differential testing and audited reference intermediates still needed. Native 32-/64-bit Montgomery execution is not the BC-1 checked-width circuit schedule |
| Canonical hints: nondecreasing cumulative counts ≤55, strictly increasing indices per row, zero unused slots | `packing.c:170 mld_sig_unpack_hints`, called for all six rows in `sign.c:1182`; source rejects malformed counts/order/padding | Preserve all rejection paths and test every row, including final padding. Current structural Python records intentionally do not perform this FIPS decoding |
| UseHint/decomposition and encode w1 | `poly_kl.c:107/:135 mld_poly_use_hint`, `rounding.h:206 mld_use_hint` / `:79 mld_decompose`, `poly_kl.c:898 mld_polyw1_pack` | Test wraparound and range 0..15 for this profile, applying DEP-001's algorithmic range disposition |
| Hash reconstructed challenge and compare all 48 bytes | `sign.c:1194 mld_H`, `mld_ct_memcmp`; result maps non-zero comparison to failure | Retain exact `mu \|\| w1` order; test challenge mutations; do not replace by a shorter or outer-protocol hash |
| All FIPS 202 blocks/rounds/suffix/padding in the above | `sign.c:mld_H`, `M/symmetric.h`, `I/fips202_glue.h`, `I/fips202x4_glue.h` → `OQS/src/common/pqclean_shims/fips202.h` → `OQS/src/common/sha3/sha3.c` / `xkcp_sha3.c` | Ordinary SHAKE implementation present; instrument reference block/round traces and byte order. No black-box hash/signature call can stand in for a private-input circuit |

For SHAKE, `xkcp_sha3.c:119–196` processes absorb/squeeze blocks, applies the final
0x80 padding bit, and dispatches to 24-round Keccak permutations (`:42–84`). SHAKE128
and SHAKE256 finalisers use suffix 0x1F (`:334`, `:377`), rates 168/136 bytes. The
four-way SHAKE path has separate glue/dispatch and must also be covered if enabled.
The bounded reference uses scalar Python FIPS operations to keep byte counters
and source order reviewable. Later BC-1 must inline these computations with its
64-/65-/128-bit arithmetic rules; the optimised backend's operation order is not a
circuit specification. Hash callbacks are replaceable in ordinary liboqs, so the
reference records its separate `hashlib` SHAKE implementation and cross-checks it
against CPython's independent `_sha3` implementation. It exposes no hash callbacks.

The native verifier schedules the z norm check before hashing and decodes hints per
row after matrix/challenge expansion. The implemented reference follows the numbered
FIPS algorithm order: decode the complete signature, ExpandA, hash pk/message,
SampleInBall, reconstruct/hash the challenge, then the final norm/challenge conjunction.
Its Python arithmetic is not yet a BC-1 operation trace.

## Completed separate implementation

The original plan's suggested native directory was an engineering choice. The completed
implementation is separately identified Python source in `src/pqdid/bounded_mldsa.py`,
with provenance and digests in [stage2_bounded_mldsa.md](stage2_bounded_mldsa.md).
The installed backend and dependency pins remain unchanged.

1. Both samplers enforce budgets before each read and propagate an internal exhaustion
   exception through matrix/challenge expansion. No partial polynomial escapes. Matrix
   entries run in increasing row/column order; no lazy/SIMD dispatch or cache is used.
2. RejNTTPoly sees at most 1026 bytes per invocation. Candidate 342 may complete the
   polynomial; candidate 343 cannot be read. All 30 invocations have separate budgets.
3. SampleInBall sees at most 256 bytes including the first eight sign bytes. Rejected
   indices consume budget; byte 256 may complete sampling, and byte 257 is inaccessible.
4. Each reader buffers exactly the allowed SHAKE prefix once and advances an offset.
   Hashlib may compute a whole rate block internally, but no extra output is exposed.
   Repeated `digest(n)` calls are not mistaken for consecutive stream reads. There is
   no restart, reseed, increased budget or ordinary-verifier fallback.
5. Complete numbered-algorithm decoding, integer arithmetic, context/hash/challenge
   processing and diagnostics passed independent arithmetic/native differential tests
   before integration. Invalid input, exhaustion and resource errors never accept.
6. `credentials.cred_valid` now composes structural/expected-instance checks, the local
   holder opening for the same B/full m, the existing exact `build_mcred` and bounded
   verification under expected pkI and the fixed credential context. Complete relations
   are the next Stage 2 task; proofs and BC-1 remain Stage 3 work.

## Verification test disposition

[The implementation report](stage2_bounded_mldsa.md) maps the executed tests and commands.
Artificial streams are injected only at internal test boundaries; the public verifier
has no injection, override or skip argument. Real fixtures were generated by the ordinary
native signer, independently of the bounded verifier; they do not validate bounded signing.

| Test group | Completed evidence and remaining boundary |
|---|---|
| RejNTTPoly limits | Completion at 768/771/1023/1026 bytes; needing candidate 343 and all-rejected input exhaust at 1026 with no extra read; q threshold, high-bit masking, little-endian order and every matrix position tested |
| SampleInBall limits | Completion at 57/58/255/256 total bytes; needing byte 257 and all-rejected input exhaust at 256; signs, rejected indices, collisions and continuous SHAKE prefix tested |
| Error propagation | Both diagnostics and public False tested; all 30 matrix positions and challenge exhaustion abort; resource/runtime errors propagate; both exhaustion paths reach CredValid without retry |
| Representations | Exact types and key/signature/context length boundaries, packing/offset extremes and no padding; no new FFI or pointer boundary exists |
| Hints and norms | All six rows' count/order/padding failures, legal maximum weight, z decode extremes and strict positive/negative norm boundary |
| Context/message | Correct credential role; wrong/empty/binary/255/256-byte contexts; prehash/duplicate framing, message/key/signature mutations and certified-field splices |
| Hashes/arithmetic | Four existing fixed hash cases, 40 SHAKE128/256 differential comparisons across rate boundaries; independent polynomial evaluation/convolution, inverse NTT, Decompose/UseHint and w1 encoding. Per-round/gate traces and BC-1 checked widths remain pending |
| Native differential | Twelve frozen native-generated signatures, 96 valid/mutated comparisons, plus four fresh signatures. All fixed cases complete within bounds. No claim of official ML-DSA validation vectors or independently forced native dispatch coverage |
| CredValid | Three real signed credentials; expected-instance, signature, opening and certified-field checks; cross-credential/issuer splices and sampler failures reject |

## Key generation, signing and release are separate work

RejBoundedPoly is **not** on ordinary verification's path. Key generation samples
s1/s2 with `M/sign.c:mld_expand_s`, `poly_kl.c:411 mld_poly_uniform_eta` and
`:326 mld_poly_uniform_eta_4x`, using `mld_rej_eta_c` / native eta4 sampling. Their
refill loops have no manuscript 512-byte cap. Apply independent per-polynomial limits
to all 11 ML-DSA-65 secret polynomials, preserve nibble order and rejected consumption,
and abort setup on failure. Planned tests force success on byte 512 versus needing
513, including both nibbles. Bounded matrix expansion also applies to generated keys.

For signing, `sign.c:823 mld_sign_signature_internal` already has an attempt limit:
`:583–614` defaults `MLD_CONFIG_MAX_SIGNING_ATTEMPTS` to
`MLD_NONCE_UB = (UINT16_MAX−MLDSA_L)/MLDSA_L`, which is **13106** for ML-DSA-65.
The inspected build supplies no override. This is not the manuscript's 1024.
The separate signer must set exactly 1024, propagate sampler failures and preserve
fresh hedging randomness. Test acceptance on attempt 1024 and exhaustion before 1025;
verify that sampler exhaustion is an abort, not an ordinary candidate rejection that
continues signing. A function-level retry wrapper does not count internal attempts.

`sign.c:1551 mld_sign_pk_from_sk` can check s1/s2 coefficient ranges and recomputed
t0/tr while deriving pk. It is not exposed by the current high-level Python signature
API and still uses uncapped expansion. The optional native keygen pairwise test is
commented out in the inspected configs. These observations neither add a new protocol
key test nor justify calling length-checked public parameters cryptographically valid.
The future setup/import layer must document its FIPS key checks, matching public/secret
keys, bounded expansions, randomness and instance authorisation.

Every signature role must bounded-verify before release, with no internal retry after
that failure. Credential release additionally requires the original-B authorisation log
and atomic nonce/log/release semantics. State/update/key setup failure must not activate
partial public state. Planned release tests force bounded rejection after ordinary
signing and assert no release/retry, preserving manuscript durable-state rules.

**DEP-001 remains independent:** the corrected signing mean/minimum in the recorded
FIPS potential-updates review does not validate the conditional `(41/51)^1024` tail or
justify setting Δtail to zero. Keep 1024 fixed; derive the actual conditional loss or
seek a reviewed correction before making numerical security-loss claims.
