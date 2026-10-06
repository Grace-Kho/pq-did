# ruff: noqa: E501
"""Render retained case metadata and long Markdown tables; no test execution."""

import json
from pathlib import Path

D = Path("docs/data/oct31_auth_relation_integration_run_1")
plan = json.loads(Path("docs/data/oct31_auth_relation_integration_1/cases.json").read_text())
ledger = json.loads((D / "ledger.json").read_text())
records = {}
for p in sorted((D / "cases").glob("*.json")):
    r = json.loads(p.read_text())
    records[r["case_id"]] = r
rows = []
for item in plan["cases"]:
    r = records.get(item["id"])
    detail = {} if r is None else r.get("details", {})
    reason = None
    if r is None:
        reason = "Full constrained comparison not admitted after capacity no-go; unchanged host reference evidence reused."
        if item["id"].startswith("M-"):
            reason = "Full fixed private sampler is not validated within this component route; source inspection only."
        if item["id"].startswith("Q-"):
            reason = (
                "No completed joint descriptor/frontier exists; bounded prefix cannot substitute."
            )
    rows.append(
        {
            "id": item["id"],
            "planned_scope": item["scope"],
            "status": "not-run" if r is None else r["status"],
            "actual_scope": detail.get("coverage", detail.get("outcome", detail.get("decision"))),
            "reason_not_run": reason,
            "evidence": None if r is None else "cases/" + r["invocation_id"] + ".json",
            "full_authentication_validated": False,
        }
    )
summary = {
    "package": "OCT31-AUTH-RELATION-INTEGRATION-1",
    "case_outcomes": rows,
    "invocations": len(records),
    "cumulative_invocations": 867 + len(records),
    "new_builds": len(ledger["builds"]),
    "cumulative_builds": 8 + len(ledger["builds"]),
    "work_events": ledger["work_events"],
    "complete_relation": False,
    "private_route_admitted": False,
    "profile_adopted": False,
    "proof_attempts": 0,
    "baseline_reused": True,
    "benchmark_trials_reused": 276,
}
(D / "case-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
components = []
for cid, r in records.items():
    det = r.get("details", {})
    desc = det.get("descriptor")
    if desc:
        components.append(
            {"case": cid, "coverage": det["coverage"], **desc, "seconds": r["seconds"]}
        )
(D / "component-counts.json").write_text(
    json.dumps(
        {
            "complete_components_only": components,
            "overlapping_counts_not_summed_as_authentication": True,
            "joint_count": None,
        },
        indent=2,
    )
    + "\n"
)
report = """# OCT31-AUTH-RELATION-INTEGRATION-1 — bounded implementation result

**The direct resident Aurora route is not admitted. This is not complete private authentication.**
The approved isolated joint-relation source, streamed Boolean-to-R1CS interface,
small actual native loader and inactive proof boundary are implemented. Bounded
component validation passed. Full joint constraint generation, witness evaluation,
native private relation allocation and proving did not complete and are not claimed.

The implementation follows only manuscript Sections II–VIII and agreed SPEC-001–004.
The active BC-1 profile, production sources, dependencies, parameters and manuscript
are unchanged. OCT31-KYC-NATIVE-MILESTONE-1/v1, its final native binaries and all
276 benchmark measurements are reused unchanged. The immutable [approved proposal](oct31_auth_relation_integration.md)
and [plan](data/oct31_auth_relation_integration_1/execution-plan.json) remain intact;
[current approval and limits](data/oct31_auth_relation_integration_run_1/approval.json)
record this implementation allocation separately.

## Admission and stopping decision

Q-04 reused the complete 27,044,356-gate forward-NTT component measurement. Under
the proposed direct one-gate/one-row mapping it implies padded row domain 2^25;
even mask budget b=1 and the retained expansion rule require 2^30 gf192 elements.
At 24 bytes/element, **one codeword alone needs 25,769,803,776 bytes (24 GiB)**.
This is a conditional representation lower bound, not a measured full Rauth cost,
full circuit count or universal lower bound on compact arithmetic constructions.
It exceeds both the native 1 GiB worker ceiling and aggregate 2 GiB ceiling before
simultaneous matrices/copies, witness/assignment, Az/Bz/Cz, interpolation/FFT,
masking polynomials, other codewords, Merkle trees, salts and openings.

No codeword or large native instance was allocated. The known oversized route
stopped immediately after this admission check; no repeated oversized attempts,
profile adoption or proof attempt occurred. Streaming the Boolean rows reduces
counting storage, but does not implement a streamed Aurora prover or establish
that complete proving fits. No justified alternative compact representation was
available within the approved kernels. The remaining work below is independent
of that allocation and supports a concrete later representation decision.

## Same-witness relation and interfaces

New code is confined to `experiments/auth_relation_integration_1/`:

| Files / check | Actual contract and coverage |
| --- | --- |
| `statement.py` | Reuses canonical encode/decode of X, trusted expected parameter instance, PubOK and Ppub; validates signed public state, context/issuer/schema/suite and disclosure/policy. Derives public A, scaled t1 transform, tr and zero leaf from those inputs. Prepared fields are rederived to reject overrides. |
| `private_relation.py`, `assignment.py` | Exactly 5,329 private bytes / 42,632 bits; parse once into holder secret, attributes, certified rid, issuer signature and 20 siblings. Same parsed attributes feed disclosure and certified message; same rid feeds signature message and Merkle direction. No separate Y/B/mu/rid override enters the composed API. |
| `mldsa_verify.py` | Private decoding, z norm, hint validity, derived mu, bounded SHAKE SampleInBall, forward NTT, public A/private z accumulation, challenge/t1 subtraction, inverse NTT, UseHint, w1 encoding and final challenge comparison remain inside the source relation. |
| `merkle.py` | Fixed 20 private levels, level framing and LSB-first rid direction, derived public zero leaf, required identifier range and final authenticated root equality. No hidden-path or credential check is delegated to public preprocessing. |
| `r1cs.py`, `stream.py` | GF(2^192) with x^192+x^7+x^2+x+1; free-bit Booleanity, XOR/AND/NOT rows and terminal acceptance constraints. Exact producer indices and completion footer. No matrix/trace retained during counting. |
| `native/relation_adapter.cpp` | Bounded public loader to actual pinned native add_term/add_constraint, A/B/C_matrix, create_Az_Bz_Cz_from_variable_assignment and is_satisfied. No prover, IOP, transcript, commitment or FFT calls. |
| `proof_boundary.py` | Inactive bounded envelope with exact PID/RID/Xtag, versions, lengths, field widths, round/opening cardinalities and full consumption. Trusted synthetic schedule used only in parser fixtures. Adapter always returns UNSUPPORTED; ordinary acceptance remains fail-closed. |

The certified message retains CREDENTIAL_SIGNING_CONTEXT, canonical record framing,
metadata, holder binding, attributes and certified identifier. Hidden SHA3/SHAKE
preimages are built from private wires, not caller-supplied digests. Public A/tr/t1
preprocessing is deterministic from already-bound public keys and is rechecked;
this moves no hidden validity obligation outside the relation. Full E(X) is bound
to the engineering stream hash. That SHA-256 engineering identity is not an
Aurora commitment, protocol RID, signature or security claim. A final full-circuit
RID and finite proof profile cannot be issued without a complete admitted descriptor.

One rejection scope conjoins all private checks. Invalid/inactive gadget outputs
are unusable; absent footer, truncated assignment, resource limits or incomplete
compilation cannot produce a completed descriptor or successful verification.
The verifier-facing body/round/opening limits are experimental parser fixtures,
not an admitted private proof encoding. The native loader accepts at most 1 MiB,
4,096 variables, 256 rows and 65,536 terms, with sorted unique nonzero coefficients;
all columns and assignment lengths are checked before native calls. It does not
invoke the known defective native `is_valid` routine.

## Arithmetic and compiler correspondence

The source keeps the original bounded verifier's accepted-set requirements:
SampleInBall consumes exactly 256 bytes (8 sign bytes plus 248 candidate bytes),
counts rejected indices as consumed and rejects incomplete sampling. Its fixed
private reads/writes retain old c[j] before c[i]/c[j] updates, including i=j.
No signing or sampler cap is increased. Strict z norm is abs(z)<524092; malformed
hint ordering/count/padding rejects. A source-only review found no accepted-set
difference, but this is not universal equivalence evidence.

Forward NTT uses the already reviewed canonical-residue butterfly and SPEC-004
signed64 entry normalisation. Inverse NTT retains checked signed arithmetic,
descending negative ordinary twiddles and final factor 8347681; canonical products
remain below q²<2^46. All eight-stage forward/inverse routines are present in source,
but only bounded arithmetic components were exercised here. Existing full-forward
component evidence is reused; it does not validate this complete verifier.

Boolean values embed in gf192: x(x+1)=0 enforces a free bit, XOR is field addition,
AND is multiplication, NOT adds one. Derived bitness follows inductively from
constrained producers. Native column0 is constant1, column1 is public acceptance1,
BC wire0 maps to zero and wire1 to constant1. Other wires retain producer indices.
Terminal rows require output=acceptance and acceptance=1. Matrix identity includes
all canonical nonzero terms. Small actual-native tests use an independent exact
polynomial-reduction oracle and explicit expected rows, not solely the compiler's
own output. Stream assignment checking uses only Boolean rows; arbitrary-field
behaviour is checked separately by native fixtures. Optional assignment storage is
one byte per wire with a hard cap, **not an implemented last-use frontier**.

These are experimental compiler/profile changes. Source equivalence, tested native
operator behaviour and proof-system knowledge/privacy are separate obligations.

## Validation, failures and measured counts

[Individual outcomes](data/oct31_auth_relation_integration_run_1/case-summary.json)
and [complete component descriptors](data/oct31_auth_relation_integration_run_1/component-counts.json)
record all planned IDs, actual scopes, omitted coverage, row digests and invocation evidence.

| IDs | Outcome and coverage |
| --- | --- |
| P-01–P-12 | 12 passed: public reference comparisons and bounded transport/typed rejection. |
| W-01–W-12 | 12 passed: canonical private layout, malformed fields, binding and exact credential-message/context bytes; derived-input override rejected. |
| M-04–M-16 | 13 passed: hint rejection, norm, arithmetic/decomposition/UseHint, encoding and challenge hash components. M-09 is one actual forward butterfly; M-10 one inverse butterfly plus factor; M-11/12 are one coefficient each, not full transforms/polynomial rows. |
| N-01–N-16 | 16 passed through actual native operators: nonzero field equations, unsatisfied/tampered/non-Boolean assignments, lengths, indices, canonical sparse representation and identity errors. |
| B-01–B-12 | 12 passed: inactive proof parsing and lifecycle rejection; synthetic placeholder cannot consume challenge, strict expiry retained. Existing replay evidence reused. |
| G-01–G-08 | 8 passed: tiny partition/stream/resource-role fixtures. These are no proof of full partition composition or measured full frontier. |
| Q-04 | Admission calculation passed; full resident route rejected without allocation. |
| Q-01 | Expected 2M-gate prefix stop recorded; case handling passed but complete relation did not finish. |
| M-01–M-03, J-01–J-16, Q-02–Q-03 | 21 not run: complete sampler, joint constrained comparisons, final descriptor and full-frontier accounting remain unvalidated/unavailable. Unchanged host-reference helpers were not run and relabelled as circuit validation. |

All 75 admitted invocations completed their stated bounded check; no native or
component case failed or was retried. There were two builds: the first failed at
the pinned `linear_combination(vector)` constructor's latent index/coeff member
references. The scoped loader correction uses the native default constructor and
`add_term` API after the unchanged strict sorted/unique input checks. Consequently
no sorting/merging is required, and the empty sum still denotes zero. This changes
only the new loader; frozen dependency files and previous native binaries stay
unchanged. The exact [correction](data/oct31_auth_relation_integration_run_1/native-constructor-correction.diff)
and failed compiler log are retained. The second build linked successfully.
A source-format pass initially failed unused-import/E402/E501 lint; its record
and formatting-only correction are retained. Later checks passed; neither build
nor static failures are erased or relabelled as successful.

Native build settings: C++14, Release `-O0 -g0`, NO_PROCPS/CURVE_ALT_BN128,
/usr/bin/c++, Ninja one worker; links the retained libiop/libff/GMP/libsodium
archives. [Build inputs and commands](data/oct31_auth_relation_integration_run_1/build-inputs-2.json)
and [binary identity](data/oct31_auth_relation_integration_run_1/build-result.json)
pin the exercised target. The original commit remains
`a2ed2ec2f3e85f29b6035951553b02cb737c817a` with the preserved milestone overlay.

Q-01 emitted exactly **2,000,000 gates** (1,377,516 XOR, **580,684 AND**, 41,800 NOT)
and **2,042,632 partial rows** including input Booleanity, with no final output
rows/footer. Counting took **8.396079 s**, guard job **10.014594 s**, cgroup peak
**44,150,784 B**, separately sampled summed tree RSS **59,326,464 B**. Stored trace,
matrix and codeword bytes: zero; 34,000,056 logical trace bytes were streamed and
hashed, not materialised. Parsing/disclosure finished at gate88,212; holder binding
and certified message finished at gate281,749. The limit stopped the ML-DSA body;
non-revocation/final conjunction were not reached by this joint prefix. This is not
an estimate of the completed count. Individual component counts overlap and are
never added into a claimed complete-authentication measurement.

Selected complete component measurements (not full-verifier costs):

| Case | Gates | AND | Rows | Generation + streaming check s |
| --- | ---: | ---: | ---: | ---: |
"""
for cid in ["W-01", "W-10", "W-11", "M-04", "M-09", "M-10", "M-13", "M-14", "M-15", "M-16"]:
    r = records[cid]
    det = r["details"]
    c = det.get("descriptor")
    if c:
        report += f"| {cid} | {c['gates']:,} | {c['gate_counts'][1]:,} | {c['rows']:,} | {det['generation_and_stream_check_seconds']:.6f} |\n"
report += """
Generation and assignment checking run together in these component measurements;
they are not independent timing samples or proving-time estimates. Work accounting
charges emitted/evaluated gates and rows, including failures; native small-fixture
evaluation charges an explicitly conservative two-row-pass bound where early
rejection may skip work. Recorded total is 27,379,838 events, below 2^32. No
whole-proof size, throughput, RISC Zero performance or complete-authentication
speedup is inferred from these component counts.

## Security and October decision

AUTH-REL-001 is only partially satisfied: complete source wiring exists, and the
bounded components/native boundary passed; full compiler equivalence, complete
counts, joint rejection comparisons and full witness checking remain open.
AUTH-CAPACITY-001 remains a no-go for this resident representation. Full native
lowering cannot bypass that decision simply because a streamed prefix fits.

The following remain explicit: TB-06 commitment/BCS committed-view simulation;
private query/masking and corrected transcript correspondence for the complete
schedule; state-restoration and quantum round-by-round knowledge; adaptive
application extraction and privacy; concrete-hash composition; finite parameter
and component-advantage budgets; adaptive Delta_tail; production key custody,
entropy assurance, erasure and side channels. They require the already registered
implementation checks or missing theorem/composition arguments, not more passing
small fixtures. AURORA-BRIDGE-001 and Stages 2–3 remain open.

**No-go for a private Aurora authentication/proof pilot using this direct resident
mapping.** The implementation milestone's bounded endpoint is established, but
complete private authentication for 31 October is not supported by this route or
evidence. The validated reference KYC testbed and v1 benchmarks remain a usable
comparison point. A classical/ideal-model qualification would not remove the
physical memory obstruction and would not replace the intended post-quantum goal.

One next action: authorise a bounded compact-ML-DSA/R1CS representation contract
using the existing backend and completed component evidence. Require exact
signed/mod-q/rejection correspondence and a conservative simultaneous-buffer,
mask/codeword and witness bound below current limits before any generation.
If no such representation is justified, explicitly stop this backend route for
the October private-proof target. This is a specific representation decision,
not another general proof-system survey; no follow-on work is started here.

## Preservation and accounting

The new guard uses a separate serial user cgroup slice, zero swap, two CPUs,
1 GiB native /256 MiB Python/tool/audit limits and aggregate2 GiB. There is one
heavy worker; two source owners performed only independent source work. The
300-second completion reserve is internal to the 2,550-second package allocation.
Opening implementation balance3297.852425 s; invocations867/1050; builds8/13;
opening evidence25,241,433 B and artifacts58,112,659 B. Analysis and isolation
allowances are untouched. The full preservation result and exact final balances
will be appended below after audit, inventory and report readback complete.

No proof/zkVM execution, installation or host-service activation occurred. Isolation
remains stopped/unactivated; CPU proving remains paused. The proof ledger remains
two used/one unused. Ordinary private-proof acceptance remains fail-closed.
"""
Path("docs/oct31_auth_relation_integration_result.md").write_text(report)
