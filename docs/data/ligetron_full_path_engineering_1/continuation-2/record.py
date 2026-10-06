"""Record one failed host-memory admission and verify its review archive only."""

import hashlib
import io
import json
import os
import resource
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath

P = Path(__file__).resolve().parents[4]
D = Path(__file__).resolve().parent
OLD = D.parent / "continuation-1"
PREVIOUS = P / "handover/ligetron_full_path_engineering_review_v2.zip"
DEST = P / "handover/ligetron_full_path_engineering_review_v3.zip"
EXPECTED = "bdbad035dc2bbbe33e971a6bfa34a433721647b3034aac1fcd2a9f5a225608c3"


def h(b):
    return hashlib.sha256(b).hexdigest()


def js(x):
    return (json.dumps(x, indent=2) + "\n").encode()


def put(name, x):
    with (D / name).open("xb") as f:
        f.write(js(x))


def fixed(x):
    b = js(x)
    assert len(b) <= 8192
    return b + b" " * (8192 - len(b))


def main():
    started = time.monotonic()
    assert P == Path('/home/grace/projects/pq-did') and not DEST.exists()
    prior = PREVIOUS.read_bytes()
    assert len(prior) == 1007019 and h(prior) == EXPECTED
    old = json.loads((OLD / 'resource-closure.json').read_bytes())
    assert old['package_remaining_seconds'] == 6882.8980036848225
    assert old['package_invocations_used'] == old['package_builds_used'] == 0
    payload, origins = {}, {}
    with zipfile.ZipFile(io.BytesIO(prior)) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and z.testzip() is None
        man = json.loads(z.read('MANIFEST.json'))['files']
        assert set(names) == {x['archive_path'] for x in man} | {'MANIFEST.json'}
        for row in man:
            n = row['archive_path']; q = PurePosixPath(n)
            assert not q.is_absolute() and '..' not in q.parts and '\\' not in n
            assert not stat.S_ISLNK(z.getinfo(n).external_attr >> 16)
            b = z.read(n)
            assert len(b) == row['bytes'] and h(b) == row['sha256'], n
            if n != 'README.txt':
                f = Path(row['original_path'])
                assert f.is_relative_to(P) and not f.is_symlink() and f.read_bytes() == b, n
                payload[n], origins[n] = b, str(f)
    # Admission applies to this small diagnostic/packaging checkpoint only.
    fs = os.statvfs(P); disk_free = fs.f_bavail * fs.f_frsize
    assert disk_free >= 9663676416 + 2097152 + 65536
    assert old['new_evidence_bytes'] + 65536 < 3145728 - 524288
    assert old['cumulative_evidence_bytes'] + 65536 < 46137344
    assert old['shared_headroom_bytes'] - 65536 >= 2097152
    assert old['cumulative_artifact_bytes'] + 2097152 < 4294967296
    measured = 0.8900809929999696 + 0.5368488789999901
    charged = measured + 20
    assert old['package_remaining_seconds'] - charged >= 300
    put('opening.json', {
        'package': 'LIGETRON-FULL-PATH-ENGINEERING-1', 'continuation': 2,
        'prior_resource_closure': str(OLD / 'resource-closure.json'),
        'prior_resource_sha256': h((OLD / 'resource-closure.json').read_bytes()),
        'prior_validation_sha256': h((OLD / 'validation-closure.json').read_bytes()),
        'prior_archive_sha256': EXPECTED, 'no_budget_reset_or_increase': True,
        'evidence_reservation_bytes': 65536, 'artifact_reservation_bytes': 2097152,
        'registered_artifact': str(DEST), 'artifact_file_ceiling_bytes': 268435456,
        'classification': 'ZIP artifact; diagnostic/report/ledger/script outputs evidence',
        'disk_free_bytes': disk_free, 'KYC_and_older_reservations_unchanged': True,
    })
    ps = '/mnt/c/windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    put('memory-admission.json', {
        'utc': '2026-10-03T08:44:21.979711+00:00',
        'command': [ps, '-NoProfile', '-NonInteractive', '-Command',
            'Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress'],
        'exit_code': 0, 'stdout': '{"TotalVisibleMemorySize":16389632,"FreePhysicalMemory":850388}\n',
        'stderr': '', 'WSL_available_bytes': 5394214912, 'Windows_free_bytes': 870797312,
        'required_each_bytes': 4294967296, 'passed': False,
        'shortfalls_bytes': {'Windows': 3424169984, 'WSL': 0},
        'WSL_memory_bytes': {'MemTotal':8126136320,'MemFree':1642336256,'MemAvailable':5394214912,
            'Buffers':176680960,'Cached':3517960192,'SReclaimable':261505024,'Shmem':3686400,
            'SwapTotal':2147483648,'SwapFree':2147483648},
        'elapsed_seconds':0.8900809929999696,'self_peak_RSS_bytes':13164544,
        'read_count':1,'memory_repolls':0,
        'scope':'One fresh post-manual-restart admission, before implementation/reporting. Failed host gate stopped execution.',
    })
    win = [
        ['vmmemWSL',5500,5579513856,6858383360,20112,None],
        ['chrome',11656,648663040,813842432,26992,'chrome'],
        ['Code',34028,451051520,383873024,2236,'Code'],
        ['chrome',29944,426946560,586481664,26992,'chrome'],
        ['chrome',15996,383041536,496762880,26992,'chrome'],
        ['Code',3560,342933504,288043008,2236,'Code'],
        ['mc-fw-host',6744,292511744,786542592,1776,None],
        ['explorer',15820,244674560,560619520,15704,'explorer'],
        ['Code',2236,218669056,157388800,15820,'Code'],
        ['Code',17244,208297984,205668352,2236,'Code'],
        ['chrome',26992,184868864,179978240,15820,'chrome'],
        ['msedgewebview2',22888,184643584,780996608,25224,'msedgewebview2'],
    ]
    paths = {'chrome':r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'Code':r'C:\Users\Grace\AppData\Local\Programs\Microsoft VS Code\Code.exe',
        'explorer':r'C:\windows\Explorer.EXE',
        'msedgewebview2':r'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\153.0.4234.32\msedgewebview2.exe'}
    for row in win:
        row[5] = paths.get(row[5])
    root = '/home/grace/.vscode-server/bin/07f806f999227108933c2e30515b26eecc1fda74'
    node = root + '/node'
    linux = [[612,'MainThread',542,685195264,node],[1193,'MainThread',612,667725824,node],
        [542,'MainThread',538,388898816,node],
        [712,'codex',612,271593472,'/home/grace/.vscode-server/extensions/openai.chatgpt-26.930.21537-linux-x64/bin/linux-x86_64/codex'],
        [613,'MainThread',542,144814080,node],[594,'MainThread',542,99332096,node],
        [577,'MainThread',571,82812928,node],[701,'MainThread',542,69738496,node],
        [557,'MainThread',555,66883584,node],
        [636,'copilot-runtime',613,50438144,root+'/node_modules/@github/copilot-sdk-linux-x64/prebuilds/linux-x64/copilot-runtime'],
        [227,'unattended-upgr',1,33488896,None],[110,'networkd-dispat',1,30457856,None]]
    put('memory-consumers.json', {
        'utc':'2026-10-03T08:44:58.769806+00:00',
        'Windows_command':[ps,'-NoProfile','-NonInteractive','-Command',
            "& { $top = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 12 ProcessName,Id,WorkingSet64,PrivateMemorySize64; $filter = ($top | ForEach-Object { 'ProcessId = ' + $_.Id }) -join ' OR '; $detail = Get-CimInstance Win32_Process -Filter $filter | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath; @{Largest=$top;Identity=$detail} | ConvertTo-Json -Depth 4 -Compress }"],
        'Windows_exit_code':0,'Windows_stderr':'',
        'Windows_columns':['name','pid','working_set_bytes','private_memory_bytes','parent_pid','executable_path'],
        'Windows_largest':win,
        'Windows_encoding_note':'Paths decoded to their conventional backslash form; no command-line data read.',
        'WSL_method':'Read /proc/PID/status; order VmRSS; read /proc/PID/exe links and up to three parent identities for twelve largest processes. No /proc/PID/cmdline reads.',
        'WSL_columns':['pid','name','parent_pid','rss_bytes','executable_path'],
        'WSL_largest':linux,
        'additional_parent_columns':['pid','name','parent_pid','executable_path'],
        'additional_parents':[[538,'sh',431,'/usr/bin/dash'],[431,'sh',323,'/usr/bin/dash'],
            [323,'sh',319,'/usr/bin/dash'],[571,'Relay(577)',569,None],
            [569,'SessionLeader',2,None],[555,'Relay(557)',554,None],
            [554,'SessionLeader',2,None],[2,'init-systemd(Ub',1,None],[1,'systemd',0,None]],
        'inaccessible_executables':'Linux null paths were PermissionError errno13; Windows null paths unavailable. No privilege escalation to obtain them.',
        'MainThread_finding':'The listed MainThread executables are VS Code Server-distributed Node, established from /proc/exe. Specific extension/task roles not established without command lines.',
        'elapsed_seconds':0.5368488789999901,'self_peak_RSS_bytes':13279232,
        'command_lines_read':False,'processes_or_configuration_changed':False,
        'limitations':['Working sets/RSS include shared pages and are not exclusive totals.',
            'Host vmmemWSL working set and guest MemAvailable are not equivalent.',
            'One snapshot does not establish automatic host reclaim policy or exact reclaimable host bytes.',
            'Diagnostic Python RSS excludes Windows-side process-tree accounting.'],
    })
    put('ledger.json', {
        'parent_ledger':str(OLD/'ledger.json'),'parent_resource_sha256':h((OLD/'resource-closure.json').read_bytes()),
        'measured_diagnostic_seconds':measured,'conservative_completion_bookkeeping_seconds':20,
        'basis':'Selected-file preservation, diagnostic interpretation, archive/accounting preparation, packaging and reporting. Conservative charge is not measured runtime.',
        'charge_seconds':charged,'charged_to':'same package and overall outside-KYC capacity, once',
        'invocations':[],'builds':[],'proofs':[],'memory_repolls':0,
    })
    (D/'report.md').write_text('''# Continuation 2: Windows memory gate remains blocked

At 16:44:21 Singapore time on 3 October 2026, Windows free memory was
870,797,312 bytes (0.811 GiB); WSL available memory was 5,394,214,912 bytes
(5.024 GiB). The unchanged threshold is 4,294,967,296 bytes in each environment.
Windows is short by exactly 3,424,169,984 bytes (3.189 GiB). WSL passes, with
1,099,247,616 bytes above its threshold. Only one gate reading was taken.

The largest Windows working set is vmmemWSL PID5500, 5,579,513,856 bytes
(5.196 GiB). Large Chrome and VS Code processes are corroborated by executable
paths and parent IDs in memory-consumers.json. The largest Linux MainThread
processes are VS Code Server-distributed Node executables: PID612 at
685,195,264 bytes RSS (653.5 MiB) and PID1193 at 667,725,824 bytes (636.8 MiB),
with parent chain 1193 -> 612 -> 542. Codex PID712 is also a child of612,
at 271,593,472 bytes RSS. Their exact extension/task responsibilities were not
inferred from names, and no sensitive command lines were read.

WSL reports 3,517,960,192 bytes Cached (3.276 GiB), 261,505,024 SReclaimable
(249.4 MiB), 176,680,960 Buffers (168.5 MiB), and all2 GiB swap free. Its
MemAvailable already estimates reclaimable pages: adding cache again would
double-count it. The host-resident VM plus substantial guest cache is consistent
with guest-reclaimable memory still occupying host pages, but the snapshot does
not prove a reclaim policy, an exact host-reclaimable amount, or a leak. Host
headroom, rather than the guest's available-memory gate, is the immediate blocker.
RSS/working sets can share pages; they must not be summed as exclusive use.

Next action is host-side headroom remediation by the user, followed by a later
single admission reading. Review unneeded Windows Chrome/VS Code sessions and
WSL host-resident/reclaimable pages; merely repeating the restart or reducing
guest process RSS does not guarantee the required additional3.189 GiB Windows
free memory. No processes were killed, caches flushed, settings/thresholds
changed, memory compression disabled, or admission polling repeated here.

No further implementation, acquisition, builds, device work, functional cases
or proofs ran. No Dawn adapter was selected. E01–E40 remain unrun, and the
retained overlay remains incomplete, uncompiled and unvalidated. Four builds,
48 package invocations and the new synthetic-only proof attempt are unspent;
older reservations, KYC allocation and the300-second reserve are untouched.

Reuse the previous complete historical preservation audit. This checkpoint
verifies the previous ZIP, its manifest and every included payload against the
existing source, then verifies the new archive and exact output inventory.
It performs no new historical audit or functional revalidation. All original
closures, archives, failed outcomes and baseline datasets remain unchanged.
Both diagnostic children exited, and no background worker was started.

Degree/masking correspondence, committed-view simulation, challenge expansion,
compiler binding, same-assignment extraction and quantum/Fiat–Shamir conditions
remain open. Production private verification is fail-closed; private proving
and isolation remain paused. The new synthetic exception remains gated/unspent.
The original full PQ-DID scope and31 October target remain unchanged.
''')
    put('preservation.json', {
        'method':'completed audit reused; selected-file and archive-only checkpoint',
        'previous_archive_identity_verified':True,'previous_payloads_match_existing_sources':True,
        'full_audit_reused':str(D.parent/'result.json'),
        'full_audit_sha256':h((D.parent/'result.json').read_bytes()),
        'historical_comparisons_reused':10901,'full_audit_rerun':False,
        'historical_files_modified':[],'functional_cases_rerun':0,
        'new_background_workers':0,'diagnostic_children_exited':True,
    })
    extra = sum(f.stat().st_size for f in D.iterdir()) + 3*8192
    assert extra <= 65536
    resources = dict(old)
    resources.update(continuation=2, continuation_charge_seconds=charged,
        package_charge_seconds=old['package_charge_seconds']+charged,
        package_remaining_seconds=old['package_remaining_seconds']-charged,
        implementation_aggregate_charged_seconds=old['implementation_aggregate_charged_seconds']+charged,
        implementation_remaining_seconds=old['implementation_remaining_seconds']-charged,
        outside_KYC_remaining_seconds=old['outside_KYC_remaining_seconds']-charged,
        continuation_evidence_bytes=extra,new_evidence_bytes=old['new_evidence_bytes']+extra,
        cumulative_evidence_bytes=old['cumulative_evidence_bytes']+extra,
        shared_headroom_bytes=old['shared_headroom_bytes']-extra,
        continuation_archive_bytes=0,memory_admission='Windows failed, WSL passed; continuation-2/memory-admission.json')
    closure = json.loads((OLD/'validation-closure.json').read_bytes())
    closure.update(continuation=2,outcome='Windows memory gate failed; WSL gate passed',
        prior_validation_sha256=h((OLD/'validation-closure.json').read_bytes()),
        no_native_or_implementation_execution=True)
    for f in D.iterdir():
        n=f.relative_to(P).as_posix();payload[n],origins[n]=f.read_bytes(),str(f)
    f=OLD/'archive-result.json';n=f.relative_to(P).as_posix()
    payload[n],origins[n]=f.read_bytes(),str(f)
    rn=(D/'resource-closure.json').relative_to(P).as_posix()
    cn=(D/'validation-closure.json').relative_to(P).as_posix()
    origins[rn],origins[cn]=str(P/rn),str(P/cn)
    payload['README.txt']=('''LIGETRON-FULL-PATH-ENGINEERING-1 — continuation2 memory stop

Read docs/data/ligetron_full_path_engineering_1/continuation-2/report.md,
memory-admission.json, memory-consumers.json and resource/validation closures.
All previous review payloads remain unchanged: prior reports, patch chain,
source/dependency identities, commands, unrun outcomes and preservation evidence.
The included original preflight ZIP contains the earlier retained source,
native component harnesses/expectations and completed component evidence.

Windows free memory fails4 GiB; WSL now passes. No new build, native validation,
adapter selection or proof exists. The partial overlay is uncompiled/unvalidated.
No private-authentication/security conclusion is supported by these diagnostics.
Patch order and scope limitations remain as recorded in the original report
and prepared-overlay-seal.json. Do not execute archived code for this review.

MANIFEST.json lists every payload and this guide, excluding itself. The final
ZIP identity and verification receipt are reported outside the archive to avoid
self-hashing. Previous archives are preserved unchanged on disk.
''').encode()
    origins['README.txt']='generated reader guide'

    def pack():
        payload[rn],payload[cn]=fixed(resources),fixed(closure)
        manifest={'files':[{'archive_path':n,'original_path':origins[n],'bytes':len(b),'sha256':h(b)}
            for n,b in sorted(payload.items())]}
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            for n,b in sorted({**payload,'MANIFEST.json':js(manifest)}.items()):
                i=zipfile.ZipInfo(n,(2026,10,3,0,0,0));i.external_attr=(stat.S_IFREG|0o644)<<16
                i.compress_type=zipfile.ZIP_STORED if n in {rn,cn,'MANIFEST.json'} else zipfile.ZIP_DEFLATED
                z.writestr(i,b,compresslevel=6)
        return buf.getvalue()

    first=pack();resources['continuation_archive_bytes']=len(first)
    resources['new_artifact_bytes']+=len(first);resources['cumulative_artifact_bytes']+=len(first)
    final=pack();assert len(final)==len(first)<=2097152
    (P/rn).write_bytes(payload[rn]);(P/cn).write_bytes(payload[cn])
    with DEST.open('xb') as f:f.write(final)
    with zipfile.ZipFile(DEST) as z:
        names=z.namelist();assert len(names)==len(set(names)) and set(names)==set(payload)|{'MANIFEST.json'}
        assert z.testzip() is None
        for n in names:
            q=PurePosixPath(n);assert not q.is_absolute() and '..' not in q.parts and '\\' not in n
            assert not stat.S_ISLNK(z.getinfo(n).external_attr>>16)
        for r in json.loads(z.read('MANIFEST.json'))['files']:
            b=z.read(r['archive_path']);assert len(b)==r['bytes'] and h(b)==r['sha256']
            if r['original_path'].startswith(str(P)):assert Path(r['original_path']).read_bytes()==b
    assert PREVIOUS.read_bytes()==prior
    elapsed=time.monotonic()-started;assert elapsed<10
    receipt={'archive':str(DEST),'bytes':len(final),'sha256':h(final),'members':len(payload)+1,
        'verified':True,'checks':'CRC, safe paths, unique members, exact file set, source and manifest hashes',
        'previous_archive_unchanged':True,'measured_packaging_seconds':elapsed,
        'peak_RSS_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        'resource_closure_sha256':h((P/rn).read_bytes()),'validation_closure_sha256':h((P/cn).read_bytes())}
    (D/'archive-result.json').write_bytes(fixed(receipt))
    assert {f.name for f in D.iterdir()}=={'record.py','opening.json','memory-admission.json',
        'memory-consumers.json','ledger.json','report.md','preservation.json','resource-closure.json',
        'validation-closure.json','archive-result.json'}
    assert sum(f.stat().st_size for f in D.iterdir())==extra
    print(json.dumps(receipt,indent=2))
    print(json.dumps({k:resources[k] for k in ['continuation_charge_seconds','package_remaining_seconds',
        'implementation_remaining_seconds','outside_KYC_remaining_seconds','KYC_remaining_seconds_unchanged',
        'continuation_evidence_bytes','cumulative_evidence_bytes','cumulative_artifact_bytes']},indent=2))


if __name__=='__main__':
    main()
