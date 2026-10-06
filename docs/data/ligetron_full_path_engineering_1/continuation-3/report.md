# Continuation 3: after user-reported cache release

The user reports one manual `sudo sh -c 'sync && echo 1 > /proc/sys/vm/drop_caches'`.
Codex neither performed nor independently verified that operation. It was not
repeated, and no settings, processes, drivers or thresholds were changed.

| Metric (bytes) | Previous, 16:44:21 Singapore | Fresh, 16:58:58 Singapore |
|---|---:|---:|
| Windows free physical memory | 870,797,312 | 2,297,962,496 |
| WSL MemAvailable | 5,394,214,912 | 5,077,135,360 |
| WSL Cached | 3,517,960,192 | 1,141,350,400 |
| WSL SReclaimable | 261,505,024 | 192,614,400 |

Both timestamps are 3 October 2026. Windows increased by1,427,165,184 bytes;
guest cache decreased by2,376,609,792 bytes. They are different quantities and
this is not a controlled causal measurement. Do not add cache to MemAvailable.
The unchanged threshold is4,294,967,296 bytes in each environment. WSL passes;
Windows is still short by1,997,004,800 bytes (1.860 GiB). Exactly one fresh
admission reading was taken before source scans, archive generation or further
implementation. The failed host gate stopped the affected route.

Read-only configuration inspection found WSL2.7.14.0, kernel6.18.33.2-2, Ubuntu
running on WSL2, and no C:\Users\Grace\.wslconfig. The42-byte /etc/wsl.conf
has [boot] systemd=true and a [user] section; these are distribution settings,
not an explicit global memory-reclamation override.

Microsoft's current official configuration reference documents dropCache as the
autoMemoryReclaim default and50% of Windows memory as the VM memory default:
https://learn.microsoft.com/en-us/windows/wsl/wsl-config
No explicit setting means no observed user override, not that automatic reclaim
is disabled. Effective runtime reclamation was not verified. The current table
does not list pageReporting; version-specific source lookups were unavailable
and no default for that setting is asserted. Their diagnostics are retained in
references.json. Adding the already-documented dropCache default is therefore
not a supported remedy for this remaining shortfall.

The next specific action is user-side reduction of approximately1.86 GiB of
Windows memory demand: close unneeded Chrome tabs/windows and unused Windows
VS Code windows identified in the retained consumer snapshot, keeping the active
project session intact. Their current recoverable totals are not guaranteed by
the older working-set snapshot. Confirm host headroom in Task Manager before
the next requested resumption. No automatic cache clear, process restart,
memory-compression change or gate reduction is proposed. Reducing WSL's memory
cap is also unsupported as a guaranteed remedy: its current available margin
above the guest gate is only782,168,064 bytes. If normal application closure is
insufficient, host memory demand/reclamation needs a separate user decision;
do not repeatedly poll or repeat privileged operations to seek a pass.

No acquisition, implementation, native build, device workload, functional case,
benchmark or proof ran. No Dawn adapter was selected. E01–E40 remain unrun;
the retained overlay remains incomplete, uncompiled and unvalidated. All four
package builds,48 invocation slots and the separate synthetic proof attempt are
unspent. KYC funds, older reservations and the300-second completion reserve are
preserved. The intervention is recorded as environment provenance for subsequent
engineering timings, never merged into historical benchmark datasets.

The previous complete historical preservation audit is reused. Only the prior
ZIP/manifest/payload identities, new output inventory and new archive are checked
at this stop checkpoint. Previous files, archives, baselines and failures are
unchanged. Diagnostics exited; no background worker was started. Private
verification remains fail-closed, private proving and isolation remain paused.
Degree/masking, joint committed-view simulation, challenge expansion, compiler
binding, same-assignment extraction and quantum/Fiat–Shamir obligations remain
open. No security result follows from memory admission or this intervention.
