"""Archive-only completion of a failed admission after a user-reported intervention."""

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
OLD = D.parent / 'continuation-2'
PRIOR = P / 'handover/ligetron_full_path_engineering_review_v3.zip'
DEST = P / 'handover/ligetron_full_path_engineering_review_v4.zip'
SHA = '8d5f66f0151435152c95ed7accc32839364413fa112eb3d0c6a00f5c21382301'


def h(b):
    return hashlib.sha256(b).hexdigest()


def js(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def put(name, value):
    with (D / name).open('xb') as f:
        f.write(js(value))


def fixed(value):
    b = js(value)
    assert len(b) <= 8192
    return b + b' ' * (8192 - len(b))


def main():
    started = time.monotonic()
    assert P == Path('/home/grace/projects/pq-did') and not DEST.exists()
    previous = PRIOR.read_bytes()
    assert len(previous) == 1027907 and h(previous) == SHA
    old = json.loads((OLD / 'resource-closure.json').read_bytes())
    assert old['package_remaining_seconds'] == 6861.471073812822
    before = json.loads((OLD / 'memory-admission.json').read_bytes())
    payload, origins = {}, {}
    with zipfile.ZipFile(io.BytesIO(previous)) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and z.testzip() is None
        manifest = json.loads(z.read('MANIFEST.json'))['files']
        assert set(names) == {r['archive_path'] for r in manifest} | {'MANIFEST.json'}
        for row in manifest:
            n = row['archive_path']; q = PurePosixPath(n)
            assert not q.is_absolute() and '..' not in q.parts and '\\' not in n
            assert not stat.S_ISLNK(z.getinfo(n).external_attr >> 16)
            b = z.read(n)
            assert len(b) == row['bytes'] and h(b) == row['sha256'], n
            if n != 'README.txt':
                source = Path(row['original_path'])
                assert source.is_relative_to(P) and not source.is_symlink()
                assert source.read_bytes() == b, n
                payload[n], origins[n] = b, str(source)
    fs = os.statvfs(P); available_disk = fs.f_bavail * fs.f_frsize
    assert available_disk > 9663676416 + 2097152 + 65536
    assert old['new_evidence_bytes'] + 65536 < 3145728 - 524288
    assert old['cumulative_evidence_bytes'] + 65536 < 46137344
    assert old['shared_headroom_bytes'] - 65536 >= 2097152
    assert old['cumulative_artifact_bytes'] + 2097152 < 4294967296
    measured = 0.7047136130001945 + 0.3469498989998101
    charge = measured + 30
    assert old['package_remaining_seconds'] - charge >= 300
    put('opening.json', {
        'package': 'LIGETRON-FULL-PATH-ENGINEERING-1', 'continuation': 3,
        'previous_closure': str(OLD / 'resource-closure.json'),
        'previous_resource_sha256': h((OLD / 'resource-closure.json').read_bytes()),
        'previous_validation_sha256': h((OLD / 'validation-closure.json').read_bytes()),
        'previous_archive_sha256': SHA,
        'new_evidence_reservation_bytes': 65536, 'new_artifact_reservation_bytes': 2097152,
        'registered_artifact': str(DEST), 'registered_artifact_per_file_limit_bytes': 268435456,
        'classification': 'ZIP artifact; diagnostics, script, documentation and ledgers evidence',
        'available_disk_bytes': available_disk, 'no_limits_reset_or_increased': True,
        'KYC_and_older_reservations_preserved': True,
    })
    put('user-reported-intervention.json', {
        'intervention': 'one-off WSL page-cache release',
        'command_reported_by_user': "sudo sh -c 'sync && echo 1 > /proc/sys/vm/drop_caches'",
        'provenance': 'user message preceding this continuation',
        'performed_by_Codex': False, 'execution_independently_verified': False,
        'execution_timestamp': None, 'automatically_repeated': False,
        'causal_effect_quantified': False,
        'timing_annotation': 'Any subsequent engineering timings must retain this reported environment intervention and its uncertainty; no results merged into historical benchmark datasets.',
    })
    ps = '/mnt/c/windows/System32/WindowsPowerShell/v1.0/powershell.exe'
    after = {
        'utc': '2026-10-03T08:58:58.927246+00:00',
        'command': [ps, '-NoProfile', '-NonInteractive', '-Command',
            'Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | ConvertTo-Json -Compress'],
        'exit_code': 0, 'stdout': '{"TotalVisibleMemorySize":16389632,"FreePhysicalMemory":2244104}\n',
        'stderr': '', 'WSL_available_bytes': 5077135360, 'Windows_free_bytes': 2297962496,
        'required_each_bytes': 4294967296, 'passed': False,
        'shortfalls_bytes': {'Windows': 1997004800, 'WSL': 0},
        'WSL_memory_bytes': {'MemTotal':8126136320,'MemFree':3876057088,'MemAvailable':5077135360,
            'Buffers':71389184,'Cached':1141350400,'SReclaimable':192614400,'Shmem':3686400,
            'SwapTotal':2147483648,'SwapFree':2147483648},
        'elapsed_seconds':0.7047136130001945, 'self_peak_RSS_bytes':13123584,
        'read_count':1, 'repeated_admission_polls':0,
    }
    put('memory-admission.json', after)
    compare = {}
    for label in ['Windows_free_bytes','WSL_available_bytes']:
        compare[label] = {'before': before[label], 'after': after[label], 'delta': after[label]-before[label]}
    for label in ['Cached','SReclaimable']:
        a, b = before['WSL_memory_bytes'][label], after['WSL_memory_bytes'][label]
        compare['WSL_'+label+'_bytes'] = {'before':a, 'after':b, 'delta':b-a}
    put('comparison.json', {
        'before_utc':before['utc'],'after_utc':after['utc'],'readings':compare,
        'interpretation':'Observational difference across time and a user-reported intervention, not a controlled causal measurement. Cached memory is never added to MemAvailable. Guest cache reduction is not equated with host recovery.',
    })
    command = "& { $p = Join-Path $env:USERPROFILE '.wslconfig'; $c = if (Test-Path -LiteralPath $p) { $f = Get-Item -LiteralPath $p; if ($f.Length -gt 16384) { throw 'Config exceeds bounded read limit' }; $section=''; $rows=@(); foreach ($line in Get-Content -LiteralPath $p) { if ($line -match '^\\s*\\[([^]]+)\\]') { $section=$Matches[1] }; if ($line -match '^\\s*(memory|swap|pageReporting|autoMemoryReclaim|vmIdleTimeout|processors)\\s*=\\s*([^#;]*)') { $rows += @{Section=$section;Key=$Matches[1];Value=$Matches[2].Trim()} } }; @{Exists=$true;Path=$p;Bytes=$f.Length;SelectedSettings=$rows} } else { @{Exists=$false;Path=$p;SelectedSettings=@()} }; $v = & \"$env:WINDIR\\System32\\wsl.exe\" --version 2>&1 | Out-String; $ve=$LASTEXITCODE; $l = & \"$env:WINDIR\\System32\\wsl.exe\" --list --verbose 2>&1 | Out-String; $le=$LASTEXITCODE; @{Version=$v;VersionExit=$ve;Distributions=$l;ListExit=$le;Config=$c} | ConvertTo-Json -Depth 6 -Compress }"
    put('wsl-configuration.json', {
        'utc':'2026-10-03T09:00:00.807362+00:00',
        'command':[ps,'-NoProfile','-NonInteractive','-Command',command], 'exit_code':0,'stderr':'',
        'version_exit_code':0,'list_exit_code':0,
        'decoded_versions':{'WSL':'2.7.14.0','kernel':'6.18.33.2-2','WSLg':'1.0.73.2',
            'MSRDC':'1.2.7214','Direct3D':'1.611.1-81528511',
            'DXCore':'10.0.26100.1-240331-1435.ge-release','Windows':'10.0.26200.9457'},
        'text_normalisation':'WSL output forwarded through PowerShell contained interleaved NUL characters; decoded fields above remove those NULs and empty CRLF lines only.',
        'distributions':[{'name':'Ubuntu','default':True,'state':'Running','version':2}],
        'global_configuration':{'path':r'C:\Users\Grace\.wslconfig','exists':False,'explicit_settings':[]},
        'distribution_configuration':{'path':'/etc/wsl.conf','exists':True,'bytes':42,
            'selected_lines':['[boot]','systemd=true','[user]']},
        'elapsed_seconds':0.3469498989998101,'self_peak_RSS_bytes':13422592,
        'settings_modified':False, 'runtime_reclaim_activity_verified':False,
    })
    put('references.json', {
        'inspection_date':'2026-10-03', 'no_dependency_acquisition':True,
        'sources':[
            {'url':'https://learn.microsoft.com/en-us/windows/wsl/wsl-config',
             'kind':'official Microsoft configuration documentation, read through web tool',
             'document_last_updated':'2026-09-16',
             'findings':{'experimental.autoMemoryReclaim_documented_default':'dropCache',
                'wsl2.memory_documented_default':'50% of total Windows memory',
                'configuration_path':'%UserProfile%\\.wslconfig',
                'settings_timing':'Configuration applied when VM launches; changed settings may require VM shutdown/restart.',
                'pageReporting':'Not present in the inspected current configuration table; no version-specific default asserted.'}},
            {'url':'https://github.com/microsoft/WSL/releases',
             'kind':'official release index', 'finding':'Release 2.7.14 listed; this does not establish runtime reclamation.'}],
        'unavailable_version_specific_source':[
            {'url':'https://raw.githubusercontent.com/microsoft/WSL/2.7.14/src/windows/service/Config.cpp','result':'404'},
            {'url':'https://raw.githubusercontent.com/microsoft/WSL/2.7.14/src/windows/service/Config.h','result':'404'},
            {'url':'https://github.com/microsoft/WSL/tree/2.7.14/src/windows/service','result':'web-tool cache miss'}],
        'limits':'Documentation defaults are not an observation of effective runtime reclamation. No claim that an installed feature is functioning follows from absence of an override.',
    })
    put('ledger.json', {
        'parent_ledger':str(OLD/'ledger.json'),'parent_resource_sha256':h((OLD/'resource-closure.json').read_bytes()),
        'measured_diagnostic_seconds':measured,'conservative_preparation_and_completion_seconds':30,
        'basis':'Read-only configuration/documentation inspection (including unsuccessful source lookups), comparison, selected-file preservation, ZIP, accounting and final reporting; separate from measured diagnostic runtime.',
        'charge_seconds':charge,'charged_to':'same package and overall outside-KYC capacity, once',
        'invocations':[],'builds':[],'proofs':[],'memory_repolls':0,
    })
    (D/'report.md').write_text('''# Continuation 3: after user-reported cache release

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
running on WSL2, and no C:\\Users\\Grace\\.wslconfig. The42-byte /etc/wsl.conf
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
    resources.update(continuation=3,continuation_charge_seconds=charge,
        package_charge_seconds=old['package_charge_seconds']+charge,
        package_remaining_seconds=old['package_remaining_seconds']-charge,
        implementation_aggregate_charged_seconds=old['implementation_aggregate_charged_seconds']+charge,
        implementation_remaining_seconds=old['implementation_remaining_seconds']-charge,
        outside_KYC_remaining_seconds=old['outside_KYC_remaining_seconds']-charge,
        continuation_evidence_bytes=extra,new_evidence_bytes=old['new_evidence_bytes']+extra,
        cumulative_evidence_bytes=old['cumulative_evidence_bytes']+extra,
        shared_headroom_bytes=old['shared_headroom_bytes']-extra,
        continuation_archive_bytes=0,memory_admission='Windows failed, WSL passed after user-reported intervention; continuation-3/memory-admission.json')
    closure = json.loads((OLD/'validation-closure.json').read_bytes())
    closure.update(continuation=3,outcome='Windows gate failed after user-reported page-cache release; WSL passed',
        prior_validation_sha256=h((OLD/'validation-closure.json').read_bytes()),
        environment_intervention='user-reported, not performed or independently verified by Codex')
    for f in D.iterdir():
        n=f.relative_to(P).as_posix();payload[n],origins[n]=f.read_bytes(),str(f)
    f=OLD/'archive-result.json';n=f.relative_to(P).as_posix()
    payload[n],origins[n]=f.read_bytes(),str(f)
    rn=(D/'resource-closure.json').relative_to(P).as_posix()
    cn=(D/'validation-closure.json').relative_to(P).as_posix()
    origins[rn],origins[cn]=str(P/rn),str(P/cn)
    payload['README.txt']=('''LIGETRON-FULL-PATH-ENGINEERING-1 — continuation3 memory stop

Read docs/data/ligetron_full_path_engineering_1/continuation-3/report.md,
user-reported-intervention.json, comparison.json, wsl-configuration.json,
references.json and resource/validation closures. The cache release is a user
report, not a Codex operation or independently verified intervention.

All earlier review payloads remain unchanged, including source/provenance,
patch chain, exact commands, unrun outcomes, old failures and preservation.
The original preflight ZIP contains retained source, native component harnesses
and expectations. Patch order and scope remain recorded in the original report
and prepared-overlay-seal.json. No executable, shader, adapter result or proof
was generated here; the partial overlay is uncompiled/unvalidated.

Only archive/selected-file checks were performed at this checkpoint. Do not
execute archived scripts for review. No benchmark datasets were changed.
MANIFEST.json covers every payload and this guide, excluding itself. Final
archive identity and verification receipt are external to avoid self-hashing.
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
    assert PRIOR.read_bytes()==previous
    elapsed=time.monotonic()-started;assert elapsed<10
    receipt={'archive':str(DEST),'bytes':len(final),'sha256':h(final),'members':len(payload)+1,
        'verified':True,'checks':'CRC, safe paths, unique members, exact file set, source and manifest hashes',
        'previous_archive_unchanged':True,'measured_packaging_seconds':elapsed,
        'peak_RSS_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        'resource_closure_sha256':h((P/rn).read_bytes()),'validation_closure_sha256':h((P/cn).read_bytes())}
    (D/'archive-result.json').write_bytes(fixed(receipt))
    assert {f.name for f in D.iterdir()}=={'record.py','opening.json','user-reported-intervention.json',
        'memory-admission.json','comparison.json','wsl-configuration.json','references.json',
        'ledger.json','report.md','preservation.json','resource-closure.json','validation-closure.json','archive-result.json'}
    assert sum(f.stat().st_size for f in D.iterdir())==extra
    print(json.dumps(receipt,indent=2))
    print(json.dumps({k:resources[k] for k in ['continuation_charge_seconds','package_remaining_seconds',
        'implementation_remaining_seconds','outside_KYC_remaining_seconds','KYC_remaining_seconds_unchanged',
        'continuation_evidence_bytes','cumulative_evidence_bytes','cumulative_artifact_bytes']},indent=2))


if __name__=='__main__':
    main()
