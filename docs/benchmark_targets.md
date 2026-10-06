# Draft benchmarking targets for profile review

19 September 2026. **Project proposals for a research testbed, not established KYC
standards, approved requirements or permission to run experiments.** No earlier
agreed performance target supersedes these proposals in the specification or suite
manifest. Existing execution limits remain in force. Read alongside the
[profile proposal](stage3_profile_change_proposal.md) and
[separate draft amendments](stage3_profile_spec_draft.md).

## Proposed acceptance targets

MiB means 2^20 bytes; GiB means 2^30 bytes. These targets apply to a **complete,
correct, privacy-preserving authentication implementation** at its reviewed security
parameters. A fragment, non-ZK integrity proof, weaker parameter set or native
verification timing cannot demonstrate acceptance. Evaluate enrolment separately;
its measurements do not stand in for authentication.

| Measure | Initial research-testbed proposal | Boundary |
|---|---|---|
| Raw authentication proof | ≤10 MiB = 10,485,760 bytes | All bytes needed to verify the proof: seal, claims, control inclusion path, profile/version identifiers and framing; no counting only the smallest inner seal |
| Complete encoded presentation | ≤12 MiB = 12,582,912 bytes | Entire application presentation, including proof, D, mD, wrapper and embedded metadata/certificates; any required attachment is counted even if fetched separately |
| Local generation | p95 ≤30 s | Validated in-memory request/witness to final serialised raw proof, including parsing, guest execution/trace, proving, recursion, finalisation and required self-checks |
| Local verification | p95 ≤2 s | Complete received bytes to cryptographic/public-check result, including decoding, admission, proof verification, PubOK/StateAuth and Ppub; service waits measured in end-to-end time |
| End-to-end presentation | p95 ≤45 s | Request initiation through final verifier decision/atomic challenge consumption under the network model below |
| Prover peak RSS | ≤4 GiB = 4,294,967,296 bytes | Peak simultaneous RSS of the proving process tree, including recursion/helpers; also report memory charged to its cgroup |
| Verifier peak RSS | ≤1 GiB = 1,073,741,824 bytes | Peak simultaneous RSS of the verifier process tree; also report cgroup memory |

Memory and byte ceilings apply to every measured admitted case, not just p95.
Cryptographic rejection of malformed input must be correct regardless of timing.
Report service failures and resource aborts separately from predicate rejection.
These thresholds do not establish a numerical security level.

**Exploratory scenario:** raw authentication proof ≤1 MiB and end-to-end p95 ≤10 s,
under the same network, correctness and security assumptions. Retain the 12 MiB
presentation and memory ceilings unless a later decision tightens them; measure
the actual encoded payload because the smaller raw target alone does not bound it.
This scenario is more demanding, with no claim that any surveyed candidate can meet
either size/latency combination. More recursion can reduce bytes while increasing
prover work; smaller segments can reduce memory while adding recursion; changing
hashes, signature parameters or privacy/security assumptions is a profile change,
not a performance optimisation within an accepted profile.

## What the frozen raw-view formula permits

For authentication, the manuscript's d=42,632 witness bits and 480 repetitions give

```text
P(g) = 64 + 480 * (515 + 2 * ceil((42632 + 2*g)/8))
     = 5,363,104 + 960 * ceil(g/4) bytes, g an integer ≥0.
```

The second equality holds because 42,632/8=5,329 exactly. Therefore

```text
P(0) = 5,363,104 bytes = 5.114654541015625 MiB
floor((10*2^20 - 5,363,104)/960) = 5,336
ceil(g/4) ≤ 5,336  <=>  g ≤ 21,344
P(21,344) = 10,485,664 bytes  (96 bytes below 10 MiB)
P(21,345) = 10,486,624 bytes  (864 bytes above 10 MiB)
```

The 1 MiB target is impossible with this encoding even at zero AND gates. These are
**algebraic encoding constraints**, not measured complete-circuit counts. The floor
does not claim an actual authentication circuit can have zero AND gates.
The recorded 13,532,448-AND hint prefix gives P=3,253,150,624 bytes
(3,102.446 MiB, about 3.030 GiB) **if those gates occur in complete CGen(auth)**.
That inclusion is not established. The complete message-preparation fragment has
413,709 ANDs; inserting that number gives 104,653,984 bytes, also only conditional
as an authentication projection. Neither calculation represents a generated proof.
See [existing feasibility evidence](stage3_feasibility_review.md) and the new
[checked integer calculations](data/stage3_benchmark_target_calculations.json).

Streaming may reduce resident trace/view storage. It does not change P(g), raw
transmission bytes or the number of cryptographic repetitions. General compression
needs measured worst cases; raw random tapes are not replaced by PRG seeds under
the frozen profile. A new protocol/encoding requires its own length and security
accounting.

## Encoding and network model

Measure both the binary proof and the actual presentation serializer output.
Count length prefixes, field names, base64/base64url, JSON escaping, proof metadata,
duplicated statement fields, certificates and envelope padding. Report cached and
uncached public inputs separately; caching does not make required bytes disappear
from an uncached presentation. If E(X) is reconstructed from a previously received
request, count that request in end-to-end network traffic, without falsely counting
it twice as presentation bytes. Report transport/TLS framing separately from the
application 12 MiB ceiling and include its time on the wire.

Padded base64 requires 4*ceil(n/3) bytes. A 10 MiB binary proof becomes **13,981,016
bytes**, about 13.333 MiB, before any wrapper, exceeding the 12 MiB ceiling. With
zero other overhead, 12 MiB can carry at most 9 MiB of padded-base64 binary data;
real overhead reduces this. Binary transport, a smaller proof or both may be
necessary. Do not silently enlarge either ceiling or report base64 as raw proof.

The initial model proposes a single holder/verifier connection with **10,000,000
bits/s application-payload capacity in each direction**, 50 ms RTT (25 ms each way),
no loss, no competing traffic and an already established authenticated transport.
Shape the link, record achieved goodput and place any TLS/packet overhead outside
the ideal payload calculation. Do not call this a measured mobile/WAN distribution.
Cold connection establishment, packet loss and contention are separate scenarios.
Existing channel security assumptions remain separate from proof security.

Define t0 immediately before the holder requests an authenticated challenge, after
human consent and ordinary credential loading; define t1 when the verifier has
finished its final ordered current-state read and atomic context/expiry recheck and
challenge consumption, and the holder has received the result. Include challenge
request/response, request authentication, witness synchronisation if needed, proof
creation, serialisation, upload, public/proof checks, service waits and final reply.
Human interaction and initial credential issuance are outside this interval and
must be reported separately if studied. Log monotonic clocks and correlated IDs
that cannot identify an operational hidden credential.

For an illustrative serial schedule, allow two RTTs (challenge exchange and
presentation/decision), generation 30 s and verification 2 s:

```text
12 MiB upload = 12*2^20*8 / 10,000,000 = 10.0663296 s
30 + 2 + 10.0663296 + 2*0.050 = 42.1663296 s
45 - 42.1663296 = 2.8336704 s remaining
```

The remaining time must cover control-message serialization/transmission, witness
and current-state services, scheduling and other overhead. It is not an assumed
service SLA. Extra remote service RTTs and a cold TLS handshake consume it. At
1 MiB, binary upload alone is 0.8388608 s: after two RTTs, only 9.0611392 s of a
10 s budget remains for **all** computation/services/overhead. A 1 MiB proof in
base64 is 1,398,104 bytes before wrappers, consuming 1.1184832 s instead.
Measure actual complete presentations; a 12 MiB presentation alone already exceeds
10 s on this link. These arithmetic budgets are not predicted runtimes.

**Summing component p95 values does not prove an end-to-end p95 bound.** Use measured
per-request end-to-end samples. Also report component distributions and correlations
to explain contention or service waits.

## Measurement procedure for later approval

Record source/guest image/verifier-parameter hashes, lockfiles, compiler flags,
proof mode/hash suite/security parameters, statement and synthetic fixture digests,
CPU/ISA/threads, GPU availability, kernel/WSL limits, power mode and memory headroom.
Pin these before a comparison; hardware or parameter changes start a separate row.
Instrument stages without writing private inputs, signature bytes, secret-dependent
debug output or witness-derived stable identifiers to operational logs. Research
fixture artefacts must be labelled synthetic.

| Dimension | Proposed procedure |
|---|---|
| Cold process | Fresh process, guest/verifier context not loaded; include loading/JIT or runtime initialisation where applicable. Build/download/install time is separately reported, outside per-presentation latency. State explicitly whether the OS page cache is warm. Do not drop system caches without separate approval. |
| Warm process | Loaded programme and public verification parameters only. Fresh request, challenge, proof randomness and valid witness each run. No proof reuse, secret-result cache, hidden-index service cache or stale root. Record allowed public caches and misses. |
| Sampling | After feasibility passes and a separate run budget is approved, propose 100 valid sequential samples per fixture/scenario/temperature, and at least 3 independent sessions. Report count, p50, nearest-rank p95 (ceil(.95*n)), max and uncertainty. Small pilot samples remain descriptive, not p95 certification. |
| Concurrency | Acceptance baseline: one request at a time, one proving worker, pinned CPU-thread count. Throughput experiments separately vary 1/2/4 requests with explicit aggregate memory admission; this is a workload plan, not permission to run them now. |
| Timeouts | Predeclare deadlines/cycle/memory limits; no adaptive increase or hidden retry. Proposed later measurement cutoffs: 60 s generation, 10 s verification, 90 s end-to-end, subject to approved lower resource controls. Record timeout as failure and right-censored latency; never delete it from the denominator or replace it with a fast successful retry. Report success-only percentiles separately; an all-attempt p95 obscured by censored samples is unresolved/failing, not passing. |
| Memory | Sample process-tree RSS and collect per-process high-water marks; summed per-process maxima are only an upper bound on simultaneous peak. Prefer kernel cgroup peak and memory ceiling with swap disabled for the worker; distinguish charged memory, RSS, virtual address space and GPU memory. A sampler can miss peaks. |
| Freshness | Fix and report request lifetime, trusted time and state-service topology before running. Apply SPEC-002 now<texp at final atomic check. Classify expired, changed-root, consumed/replayed and unavailable-service runs separately. Longer proving that expires the context is an end-to-end failure, not a cryptographic success. |
| Validation | Before timing, positive/negative reference agreement, proof/public binding mutations, size/parser limits, service-order and concurrent replay tests. Include rejected samples in workload results; do not average them with valid-run latency. |

Request lifetime is an unset deployment input, not derived automatically from 45 s.
Propose a labelled 120 s synthetic lifetime for ordinary performance runs only after
review, plus explicit boundary/expiry scenarios. Record both first-attempt success
rate and all-attempt distributions. Any observed incorrect acceptance fails the
correctness gate; practical reliability thresholds need a separate decision.

## Throughput, revocation and witness-update workloads

These are **measurements to collect**, not additional acceptance SLAs. Later approval
must choose a subset, sample count and total resource budget.

| Workload | Vary/hold fixed | Report |
|---|---|---|
| Authentication throughput | Same schema/security/mode; valid and separately malformed traffic; closed-loop concurrency 1/2/4, then explicitly bounded offered load; CPU threads fixed | Successful fresh acceptances/s, offered load, queue delay, latency tails, rejects/timeouts, memory and bottleneck; saturation is not success |
| Disclosure/instance diversity | 2–16 schema fields within 1024 bytes; minimal/maximal supported disclosure and policies; distinct public instances | Proof/presentation sizes and latency; public-cache reuse/cost; matched-leakage groups for privacy tests |
| Revocation scale | Depth fixed at 20; allocated populations 1, 2^10, 2^16, 2^20 using bounded/sparse fixture generation; 0/1/100/1000 authenticated sequential updates | Manager state/update generation, signature checks, storage, bytes/epoch, fetch costs, holder update cost and proof changes. Depth and private identifier semantics stay fixed. |
| Local witness maintenance | Holder unrevoked/revoked, neighbouring/distant index, 1/10/100/1000 missed updates | Per-update and catch-up time/bytes/RSS, old/new root agreement, authenticated update verification, gaps/reordering/duplicates and failure recovery |
| Service behaviour | Stable epoch, root changes during proving, expired challenge, concurrent duplicate presentations, unavailable/current-state inconsistency | End-to-end aborts and correct final ordering/at-most-once acceptance; no acceptance-rate target invented |

Do not query a service using a hidden rid, DID, witness or credential-specific status
URL. Public update distribution and local path maintenance preserve the intended
privacy boundary; publishing real updates after presentation is part of the later
historical-unlinkability evaluation.

## WSL headroom and present limits

The read-only host snapshot in [source-review data](data/stage3_profile_sources.json)
records an i7-14650HX, 24 logical CPUs, 8,126,111,744 bytes total WSL memory
(about 7.57 GiB), and 5,170,896,896 bytes available (about 4.82 GiB) at inspection.
AVX2/AES are exposed; AVX-512F/BW/VL are absent. No usable GPU was established.
Swap and virtual disk capacity are not extra admissible proving RAM or proof of
physical Windows free space. Existing [environment evidence](environment.md) remains
the toolchain record.

For future experiments, reserve at least **2 GiB of MemAvailable for OS/services**
after the worker's full enforced memory allowance, including its helpers. Recheck
immediately before each run; account separately for tmpfs/page-cache/artifact memory.
At this snapshot, a 4 GiB prover plus that reserve **does not fit available memory**.
Defer or review a smaller envelope; do not enlarge WSL RAM, use swap to conceal the
peak, run prover/verifier simultaneously, or consume the reserve. A 4 GiB evaluation
target is a ceiling, not a demand to allocate it. Concurrency is admitted by aggregate
budget, never by multiplying per-worker ceilings without a host check.

The ordinary 2M-gate controls, existing 32M counting-only profile and separately
authorised 2.1M message pilot remain unchanged. The earlier 64M-gate/2 GiB proposal
is inactive. The next experiment's **proposed** lower envelope and stop criteria are
in the [profile proposal](stage3_profile_change_proposal.md#next-bounded-work-package).
No benchmark or candidate proof was run for this document.
