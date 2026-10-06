# S3-AURORA-QUERY-MASKING-CONTRACT-1

**Decision: specific construction corrections are required before a private
prototype.** The completed native pilot establishes public EXP2 correspondence,
not the privacy of the existing Aurora prover. This review resolves the distinction
between common-domain query positions and scalar disclosures. It does not establish
the missing source-variant simulator, commitment transformation or quantum knowledge
argument. No profile is adopted and no implementation is changed.

## Authority, snapshot and evidence boundary

Only manuscript Sections II–VIII and SPEC-001–004 govern the PQ-DID relation. The
manuscript SHA-256 remains
`d17ca0a20b319b88e959467cae92d91d619973f84384710ecbf960a3b850aeca`.
The proposed non-holographic binary-field Aurora construction is an alternative
experimental proof layer, not the manuscript's active BC-1/MITH construction.
The certified message, holder binding, revocation relation, disclosure policy and
public statement in the existing specification are unchanged.

The inspected libiop commit is `a2ed2ec2f3e85f29b6035951553b02cb737c817a`, tree
`2e2588ccb085242dd2237875c3b9adf1a0fc958c`. Source references below are relative to
`experiments/aurora_native_transcript_pilot_1/dependency-prefix-v1/guarded-build-v2/work/libiop/libiop/`.
They identify the acquired, patched native copy, not today's upstream branch.
Its retained inventory and patch chain are inherited by the preservation audit.
The EXP2 overlay, ten-reference variable correction, `<cstddef>`/`std::size_t`
correction and libff workaround are preserved. The last two patch identities are
`8a28d44432c4dfd2ff41a07bb4affd1a154b52ae781289210410586b43e4c357` and
`919c57370aa9005f9bcabe683e7e528954903a802e65e4a160a5ed24e8d3e0a5` respectively.
Dependency revisions remain those in the completed lock and acquisition evidence.

The [native report](stage3_aurora_native_transcript_pilot.md) and its completed
[closure](data/s3_aurora_native_transcript_pilot_1/output-guard-repair-1/validation-closure.json)
are reused: eight SEM and sixteen TR cases passed once; five tooling cases passed.
The latest manifest is
`c79748b69639633dd68a237e5a512e7c15229b84648968a8f0039bf078a3cacd`.
Those cases reached native EXP2 initialisation, framed absorption, counters and
challenge extraction through the BCS common driver. They did not execute a private
Aurora proof, mask generation, FRI verification or Merkle opening verification.
The old omission was a negative control, not a forgery. Algebraic primary-input
checks existed independently of the old missing hash-chain initialisation.

In particular, `bcs/bcs_common.tcc:551` dispatches the explicit EXP2 branch before
the legacy scheduler; its comment at line 578 excludes that scheduler. The tested
descriptor literally says `PUBLIC-HARNESS;F=2^192;rho=1/8;eta=1;pow=0;not-an-IOP`.
It supplies no approved private-query schedule. The source's legacy hash path and
private protocol remain outside demonstrated correspondence.

The [construction contract](stage3_aurora_auth_construction_contract.md),
[bridge](stage3_aurora_transcript_bridge.md),
[EXP2 correction contract](stage3_aurora_transcript_correction_contract.md) and
[outer-oracle decision](stage3_outer_oracle_composition.md) remain historical.
The clarification below supersedes an overly conservative reading of the bridge's
masking budget; its original text and measurements are preserved.

## Symbols and complete source-view inventory

Use padded constraint size M, variable-domain size N, public-input-domain size K,
and t=max(M,N). Here N includes the constant slot, unlike the paper's n. Put
`L0=L`, `|L|=2^d`, and `Lj` equal to the successive additive quotient domains.
The proposed field is GF(2^192), rate at most 1/8, binary localisation `eta_j=1`,
and no proof of work. These remain proposals, not inherited defaults. The exact
field certificate and finite authentication dimensions remain open.

Let a be lincheck/sumcheck repetitions, P the reducer's output instances, I the
FRI interactive repetitions, q the number of random initial positions, r the
number of FRI folds, and D the rounded initial FRI degree bound. Degree bounds
below are strict: degree < bound. `Df=D/2^r` requires exact divisibility. Let
`Dlin=2t+b-1`. No numerical values are manufactured for these unresolved quantities.

| Oracle/message | Role, domain and degree bound | Mask, dependence and disclosure |
| --- | --- | --- |
| `fw` | Witness quotient on L0; bound N-K+b; `r1cs_rs_iop/r1cs_rs_iop.tcc:308,498–570` under `protocols/encoded/` | Fresh degree-<b polynomial times the variable vanishing polynomial before division by the public-input vanishing polynomial |
| `fAz,fBz,fCz` | Three matrix-product extensions on L0; M+b; same file:312,450–503 | Three independently sampled degree-<b masks times the constraint vanishing polynomial; related to the same witness on the systematic domain |
| `fz`, rowcheck | Virtual L0 values; N+b and M+2b-1; same file:322,372 | `fz` uses `fw` and public interpolation. Rowcheck uses all three matrix columns and a public denominator nonzero on L0. No separate commitment or independent mask |
| `r_i`, i<a | Real sumcheck masks on L0, Dlin; `protocols/encoded/sumcheck/sumcheck.tcc:198,287–323` | Uniform zero-sum subspace, not unrestricted polynomial space: coefficient of degree t-1 in the remainder is forced to zero |
| `h_i`, i<a | Real quotient on L0, Dlin-t; `sumcheck.tcc:237,344–393` | Determined by masked lincheck divided by Z_H. Flag `make_zk=false`; must be included jointly with its mask and base columns |
| `g_i`, combined lincheck | Virtual L0 values, t-1 and Dlin; `sumcheck.tcc:249–275`; `lincheck/basic_lincheck.tcc:200–225` | Depend recursively on mask, quotient and base columns at the same point, plus public matrix evaluations/challenges. Count real dependencies, not an extra independent opening |
| `z_p`, p<P | Real reducer masks on L0, D; `protocols/ldt/ldt_reducer.tcc:145–155,242–254` | Independent uniform random polynomials. Each reduced combination has its own pad; they share base/quotient oracles |
| `F[0,p]` | Virtual degree-equalised reduced word, L0, D; `ldt_reducer.tcc:165–225`, `ldt_reducer_aux.tcc:1–173` | 3a+5 tested handles: r,h,g for each i, four base columns, rowcheck. Pad appended last. General random coefficient map and bump terms; not the paper's explicit unit pad |
| `F[j,u,p]`, 1≤j<r | Real folded words on Lj, mathematically D/2^j | IP columns per layer; deterministic folds, no fresh masks, flags false. `protocols/ldt/fri/fri_ldt.tcc:350–389`. Registered bounds advance the localisation counter before registration; this remains a metadata obligation, not an adopted mathematical bound |
| Terminal polynomials | IP direct vectors of Df coefficients, not committed tables; `fri_ldt.tcc:391–399,520–543` | Full coefficient vectors, including specified padding, are exposed and hashed. Their dependence on all earlier folds must be simulated |
| Verifier messages | Source round zero: 6a fields (alphas, matrix triples, sumcheck pairs). Reducer: P(6a+12) fields; FRI: Ir fold challenges | Public coins, not witness disclosures. Source registration counts include coefficients unused by the reducer's map; preserve the exact map and transcript consumption rather than silently shortening vectors |

All paths in the table are under the pinned prefix stated above. Source identity
and additional inspected auxiliary files are recorded in `reviewed-inputs.json`.
No hypothetical indexed/holographic oracles are included: they are not this variant.

### Openings, positions and direct messages

`fri_ldt.tcc:401–476` chooses q positions once on L0 and reuses their quotient
trajectories across all I and P. Each layer opens an entire coset. Write Sj for
the actual union of coset points at layer j. For binary localisation:

```text
uj = |Sj| ≤ min(2q, |Lj|)
C0 = 4+a+P, C1 = a, Cfold = IP
E_open = (4+2a+P)u0 + IP * sum(j=1..r-1, uj)
M_direct = IP*Df
V_explicit = E_open + M_direct
```

These are counts of disclosed scalar entries indexed by (oracle, position), not
their entropy and not a masking theorem. Equal numeric values in different oracles
still count separately. The zero-sum source sends no mask sums; a paper-aligned
revision would also expose a sums `mu_i`, and must update this inventory. Salts,
roots, authentication hashes, indices, lengths, statement and challenges remain
part of the view but are not additional field-oracle queries. There are two L0
trees (base/masks, quotients) and r-1 folded trees in this source schedule; terminal
vectors are a separate message. Fields per binary coset leaf are 2C0, 2a and 2IP.

The source deduplicates identical requested positions/paths. Such deduplication
only removes repeated disclosure of an identical entry. It does not erase
correlations or make unsalted hashes private. Virtual evaluations at the same
point require no new points, but all real dependencies remain exposed. An opening
parser or serializer that reveals extra cosets would invalidate this accounting.
The proposed scalar-tree format must reveal exactly the same scheduled entries;
changing packing does not authorise extra openings.

**Refinement of TB-05:** Aurora §4.7 explicitly counts distinct points in the
common RS domain across columns. Thus the theorem-specific base-view projection
is `B_RS=|S0|`, not E_open. In the literal unit-pad simulation, later LDT messages
are generated from a simulated masked word; they are not automatically additional
queries to the original witness. The source position count `2q` is consequently
meaningful. Its `b=2q+1` is neither disproved by E_open nor validated for the
modified source by that inequality alone. Standard full-IOP query complexity,
scalar/wire accounting and this specialised simulation budget remain distinct.

For a corrected protocol, prove the simulation projection's closure, then require
`b >= B_RS`, domain disjointness, and `2t+2b <= |L|/8`. If extra direct messages
consume independent constraints on masks, derive their rank and include them;
do not count coefficients as positions by analogy. Alternatively, the conservative
full-IOP-query route remains available after the protocol itself matches its
theorem. No finite private profile currently supplies m,n,a,P,I,q,r,Df or the
required closure certificate.

The source degree checks additionally require
`Dtest=max(2t+b-1,M+2b-1)`,
`Dconstraint=max(2t+b-1,2M+2b-1)`, rounding D to a multiple of 2^r,
and positive strict proximity slack. For the general reducer, the relevant
condition is `delta < min((1-2*sigma*)/2,(1-sigma*)/3,1-rho*)`, with tested and
constraint rates mapped separately. A descriptor must reconcile these bounds,
the folded registrations and FRI's proven-mode conditions; it must reject an
unsatisfied fixed point rather than accept optimistic defaults.

`Q_H` denotes adversarial classical/quantum random-oracle calls, not q, uj,
E_open, tree hash work or b. Increasing an adversary's Q_H changes transformation
bounds; it does not authorise more committed-oracle openings in one proof.

## Masking correspondence and the complete view

The full cached [Aurora paper](https://eprint.iacr.org/2018/828.pdf), 8 May 2019,
§4.6–4.7, Protocols 5.8, 7.5, 8.6, Theorems 7.4, 8.5, 9.2 and Figure 5 were
inspected. Its RS query convention permits common-position accounting. Its
simulators require specified mask distributions and include derived LDT messages;
Theorem 9.2 requires `2*max(m,n+1)+2b <= rho*|L|`. Screenshot retrieval returned
403; no screenshot verification is claimed. Readable full-paper text, not an
abstract or search snippet, supports the theorem mapping.

An independent local algebra argument explains the four base masks: at v≤b
distinct points outside the systematic domains, the v-by-b Vandermonde evaluation
matrix has full row rank. Multiplication by nonzero vanishing factors preserves
rank. Independent masks can therefore simulate those base columns jointly even
though their unmasked parts derive from one witness. This argument stops before
revealing their dependent quotients, masks and terminal coefficients.

The source sumcheck instead samples `r=Z_H*h+g` with one coefficient of g zero,
then multiplies both r and the lincheck word by fresh challenge coefficients
(`common/random_linear_combination.tcc:11–74`). The paper route uses an
unrestricted pad, its disclosed sum and a unit pad coefficient. Conditioning on a
zero sum is a different distribution. It might admit a separate simulator; none
is supplied by the completed native tests or this review.

The reducer appends z_p after its tested inputs. Although
`ldt_reducer_aux.tcc:26–36` prepends one to its coefficient vector, that one belongs
to input zero, **not** the last pad. Maximal-degree inputs use their single indexed
coefficient; submaximal inputs have additional bump terms. Hence the pad coefficient
can be zero. A unit-pad simulation cannot be invoked on that branch. Honest
random challenges and maliciously selected challenges require different treatment;
no exceptional-event loss is added to a privacy claim without its simulator.
This is a failed correspondence argument, not an executed privacy attack.

The missing joint-view obligation is a simulator for
`(statement, challenges, opened base/r/h/z columns, folded openings, terminal
coefficients, any mu, commitment/opening data)`. One must either restore the
paper's distributions/messages and show the complete mapping, or prove this exact
variant, including zero coefficients, dependent repetitions and the degree map.
Statistical independence of each column alone does not suffice.

Every new presentation must sample fresh independent base, sumcheck and reducer
randomness and commitment salts. Reuse of the same witness is permitted privately;
reuse of masked polynomials across sessions is not in the proposal. Repeated
queries accumulate against reused masks. A byte-identical retransmission of one
proof adds no different openings, but is not a fresh presentation or authority to
bypass freshness. Adaptive session composition, statement leakage and simulator
access still require the protocol's separate security argument.

## Commitment and challenge correspondence

`bcs_common.tcc:440–477,647–720`, `merkle_tree.tcc:12–151` and
`hashing/blake2b.tcc:120–163` show one tree per round/domain, packed columns and
cosets, raw `sizeof(FieldT)` memory encoding, and salting when any registered
column requests it. R0 is salted; quotient/fold trees have false flags. A salted
leaf is `H_D(H_D(raw_fields) || salt)`, an unsalted leaf is `H_D(raw_fields)`.
Salt length is ceil(2s/8) bytes; digest length has the same source formula.
It is not automatically twice the digest bit length. With a 64-byte digest this
source coupling gives 64-byte salts, unlike the draft's 128-byte salts.

`hashing/blake2b.cpp:28–50` hashes concatenated left/right digests without an
explicit node/leaf tag. The legacy integer extractor uses the machine-sized
counter as a BLAKE2b key, whereas EXP2 has separately framed public ports. EXP2
does not retroactively canonicalise Merkle raw-field encoding or separate all
commitment domains. Roots, ordered leaf values, applicable salts and pruned
authentication siblings appear in `bcs_prover.tcc`'s transcript; duplicate leaves
are merged. A bridge must prove this multipath verification implements the same
per-position relation and privacy view as the selected commitment construction.

The proposed draft instead requires canonical 24-byte field encodings, separate
scalar trees, 64-byte digests and fresh 128-byte salts for every leaf. Its wire
format remains unimplemented. Neither that draft nor the packed implementation
is silently identified with the paper's binary encoding. The alphabet/encoding,
position binding, padding, root identifiers, opening grammar and domain tags all
need a single committed descriptor. Hash collision resistance gives no automatic
statistical hiding or knowledge extractor.

The full [BCS paper](https://eprint.iacr.org/2016/116.pdf), 10 February 2016,
§3.3, §6 and Theorem 7.1 uses salted leaves with 2ell random bits and an ell-bit
ideal oracle. Its classical transformation requires restricted state-restoration
soundness/knowledge; the respective loss is `3*(Q_H^2+1)*2^-ell`. HV statistical
ZK gives `z+p*2^(-ell/4+2)`. Here p is the theorem's encoded IOP length, not our
wire bytes. Those premises and its programmable-oracle simulation are not
established for this patch stack. There is no numerical transferred bound here.

The ideal-oracle construction separates challenge and commitment functions. An
injective, typed EXP2 frame repairs the demonstrated absorption/statement defects
at the tested layer, but still needs a compiler correspondence for the full IOP
round schedule and challenge distributions. The selected draft excludes PoW:
remove solve/check/challenge/answer handling and credit no grinding advantage.
The legacy path's zero-work setting is not an established no-PoW switch. Challenge
counters and PoW absence in a public harness do not validate the private scheduler.

The concrete native hash is BLAKE2b via pinned libsodium. No concrete
indifferentiability, binding, hiding or extraction advantage at the required
budgets is established. The prior SHAKE/sponge review does not instantiate this
different hash. Standard hash security intuition is an additional assumption,
not permission to add an unexplained error term to knowledge or privacy.

## Evidence and obligation matrix

| Requirement | Exact component / condition | Theorem and assumptions | Established evidence | Remaining obligation |
| --- | --- | --- | --- | --- |
| TB-01/02 transcript binding | EXP2 native common-driver methods; exact public descriptor and frames | Compiler must commit statement/roots/messages before challenges | Retained SEM/TR outcomes, pinned overlay; no reruns | Private round manifest/caller integration and proof-game correspondence |
| TB-03 no grinding | Legacy PoW caller path versus EXP2 explicit ports | No work credit unless a selected reduction accounts for it | Source inspection, public no-PoW branch only | Literal removal/absence in future private path |
| TB-04 base masks | Four degree-<b pads; disjoint L0 and systematic domains | Aurora 7.4/7.5, fresh randomness | Rank argument and pinned construction sites | Exact field/domain descriptor and full related-oracle view |
| TB-04 sumcheck/reducer | Zero-sum r_i, random pad coefficients, direct terminal vectors | Aurora 5.8/8.6 distributions, unit-pad joint simulation | Deviations located in `sumcheck.tcc` and `ldt_reducer_aux.tcc` | Restore distribution/message contract or supply exact variant proof |
| TB-05 query closure | Sj, E_open, IP*Df, virtual dependencies; B_RS=|S0| under mapped simulator | Aurora §4.7 and 8.5 distinguish shared positions from scalar entries | Complete symbolic source inventory; previous interpretation refined | Finite descriptor, simulator projection and admission inequalities; no silent terminal-message discount |
| TB-06 commitment binding | Packed leaf encoding/root/path relation | BCS §3/§6 ideal hash construction and restricted restoration game | Concrete source located, not executed by native TR cases | Encoding/packing/multipath bridge; collision bound alone insufficient for extraction |
| TB-06 commitment privacy | Selective salts and nested prehash versus all-leaf 2ell-bit salt construction | BCS Lemma 3.4 / 7.1 statistical hiding with opened values simulated | Concrete mismatches documented | Prove selective salting safe for joint view or restore literal commitment contract |
| TB-07 canonical ports | EXP2 byte frames versus raw Merkle fields/legacy extractors | Injective typed encoding and correct challenge distribution | Public EXP2 native correspondence | One private protocol-wide descriptor and hash-domain mapping |
| TB-08 degrees/FRI | Dtest,Dconstraint,D,Df, folded registrations, proven proximity mode | Aurora 8.5/9.2 plus actual FRI domain/degree hypotheses | Source-derived inequalities; no circuit generation | Reconcile per-layer degree metadata, field certificate and finite repetitions |
| TB-09 classical soundness | Exact full public-coin IOP and compiler | BCS 7.1 restricted state-restoration soundness | Full theorem read; application conditional | Establish source-variant restoration bound; preserve construction changes in reduction |
| TB-09 classical knowledge | Extractor for relation, not just decision soundness | BCS 7.1 restricted restoration knowledge | Requirement isolated | No extractor for this complete private profile established |
| TB-09 quantum soundness/knowledge/privacy | Full IOP, not a PCP substitute | CMS BCS result requires round-by-round properties and appropriate ZK | Proceedings Theorem 3 and §2.9 checked; full formal IOP theorem unavailable | Formal hypotheses/constants, round-by-round extraction, commitment and hash correspondence; no numeric quantum claim |
| TB-10 parsing and joint leakage | All openings, lengths, messages, salts, roots, failures | Selected simulator must reproduce admitted full view | Proposed bounded wire only | Implement after algebraic and commitment descriptors settle; no private prototype admission |

The [CMS TCC 2019 proceedings](https://www.iacr.org/archive/tcc2019/11891143/11891143.pdf)
contain an explicitly informal Theorem 3 for BCS: the quantum soundness form is
`O(Q_H^2*epsilon + Q_H^3/2^ell)`, with round-by-round IOP premises and additional
knowledge/privacy conditions. §2.9 is a sketch. The full-version PDF lookup
failed; no unavailable formal theorem, constant or IOP extractor is asserted.
Its PCP/Micali result does not by itself prove this IOP construction. Statistical
privacy there permits programmed ideal-oracle simulation; finite native challenges
provide no substitute. Classical results and quantum obligations remain separate.

## Decision and one next package

**Specific construction corrections required** is the decision. Shared-position
accounting is supported by the theorem's exact convention; a claim that scalar
bundling alone defeats `b=2q+1` is not supported. Conversely, counting positions
does not repair zero-sum/random-pad distribution differences, selective hiding or
the missing compiler/quantum arguments. No attack or overall bit-security claim
follows from this inconclusive correspondence.

Recommend **S3-AURORA-MASKING-CORRECTION-CONTRACT-1**, a source-only, patch-ready
contract for TB-04 and the associated TB-05 closure. It should deliver:

1. An exact proposed diff for unrestricted sumcheck pads with explicit mu messages
   and unit mask coefficients, and a reducer coefficient map fixing the pad to one.
   Preserve the relation; identify all changed registrations, messages and degrees.
2. A matching EXP2 private message/oracle descriptor with order, field encoding,
   absorbed sums, retained terminal coefficients and no legacy fallback. Do not
   modify the completed public harness or its expected results.
3. A joint-view simulation mapping to the cited protocols, including all a/P/I
   repetitions, exceptional challenges, same-domain projection and the inequality
   for b. If this cannot be completed, stop with the exact failed lemma.
4. An explicit per-layer degree reconciliation and inactive, bounded differential
   validation proposal. No numerical profile without finite relation dimensions.

Completion means a reviewable algebraic correction and its symbolic simulation
contract, not implementation, proof security or admission of a private prototype.
Commitment transformation TB-06 and formal quantum/composition TB-09 remain gates
after that package. This is a specific correction task, not another general review.

## Resource and preservation record

The opening analysis balance is **171.26000670727808 seconds**, against its
unchanged cumulative 300-second ceiling. This package permits 60 charged seconds
including a ten-second finalisation reserve. Existing convention charges guarded
wall time and five conservative source-review/bookkeeping seconds; web lookups
add 17.198 seconds (14.198 directly timed, plus a conservative three-second
charge for the first find call). The web failures above are retained as lookup
outcomes, not resource failures. No functional invocation is consumed.

Native remains **107.26425821718294 seconds**, implementation
**111.82163787621539 seconds**, provisioning **41.843650440103374 seconds**.
The completed native continuation is prospectively closed and its **2,320,000-byte
unused evidence reservation is released**. Historical usage, including earlier
failures and the conservative failure charge, is not refunded. Build ledger 5/5,
invocations 448/450 (two unused tooling reruns only), and proof ledger two used/one
unused remain unchanged.

Cumulative evidence opens at **16,194,455 / 18,874,368 bytes**. The new package
reserves at most 1,048,576 bytes, with 262,144 bytes inside it for completion;
the enclosing headroom is 2,679,913 bytes. Native evidence 5,578,088 bytes and
artifacts 27,839,915 bytes remain charged and unchanged. No source/archive is
downloaded. The retained guards enforce one worker, two CPUs, zero swap, 256 MiB
cgroup memory, 1 MiB per file, 8 MiB temporary space and existing disk/diagnostic
stops. Analysis commands are static checks, preparation and one complete audit.

The [package evidence](data/s3_aurora_query_masking_contract_1/opening-ledger.json)
records sources, source hashes, literature availability, explicit allowed report
appendices and closure accounting. Baselines are inherited unchanged, including
all transcript-repair files and the corrected experiment root. Final audit and
readback outcomes are appended below after execution. Production code, active
parameters, dependencies and historical evidence remain protected.

Stages 2–3, AURORA-BRIDGE-001, adaptive Delta_tail, component advantages at
reduction budgets, production custody/entropy/erasure/side-channel obligations and
complete authentication knowledge/privacy remain open. Isolation remains safely
stopped and unactivated; CPU proving and raw-view integration remain paused.


### Completed preservation and finalisation

Static lint/import ordering/format checks passed; preparation passed; the single
full preservation audit exited 0 and completed reporting/readback. It compared
10,901 original/supplemental entries without overlap, with
10,936 identity-inclusive paths. Audit name inventory:
8,217 entries, no additions/removals outside the explicit scope.
Audit wall time 3.589761s; cgroup-v2 memory.peak
48,013,312 bytes (45.789 MiB),
including worker descendants and charged cache/kernel memory; ceiling 268,435,456
bytes, zero swap. Sampled aggregate tree RSS 59,494,400
bytes is a separate metric. No resource breach; temporary storage zero.

Guarded checks consumed 4.392041s. Together with 17.198s lookup accounting and
5s conservative local review/bookkeeping, the package charge is 26.590041s.
Package allowance remaining 33.409959s; analysis remaining 144.669966s.
Native/implementation/provisioning balances and 448/450 invocations are unchanged.
The final additive seal and inventory, including late result/closure files, are
in [validation-closure.json](data/s3_aurora_query_masking_contract_1/validation-closure.json)
and [manifest.json](data/s3_aurora_query_masking_contract_1/manifest.json). Their
output accounting includes report appendices, metadata, lookup-failure records,
guards, inventory and readback. Finalisation is charged within the existing local
bookkeeping allowance; no second baseline scan or experimental execution occurred.

This source-contract package is complete. The decision remains construction
corrections required; private-prototype admission and AURORA-BRIDGE-001 remain open.
