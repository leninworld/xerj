"""Unrun one-shot hosted ARM adaptation; disabled pending exact execution review."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time

from bounded import LimitAbort, command, limit, save
from artifacts import export, export_ftx, fallback_export
import identity as identity_guards
from fixed_docker_controls_PROPOSED import Controls as FixedEarlyControls
from fixed_host_seam_PROPOSED import FixedSession

limit(sys.flags.optimize == 0, 'OPTIMIZATION_NOT_ALLOWED')

P = Path(__file__).resolve().parent
PLAN = json.loads((P / 'plan.json').read_text())
RUN = os.environ.get('GITHUB_RUN_ID', '')
ROOT = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / ('xerj3016-candidate-' + RUN)
OUT = ROOT / 'evidence'
PRIVATE = ROOT / 'private'
SOURCE = ROOT / 'source'
IMAGE = PLAN['image']
OWNED = {}
START = END = SOFT = None
STEP = 'not-started'
DOCKER_ROOT = None
RX = None
RX_START = None
DRIVER_STATUS = None
FIXED_SESSION = None
FIXED_EARLY_RESULT = None
FIXED_FINAL_RESULT = None
GIT_DIFF = ['git','-c','core.abbrev=9','-c','color.ui=never',
            '-c','diff.noprefix=false','diff','--binary','--no-ext-diff','--no-textconv']
# Forecasts, not measured unpacked sizes. Covers both Docker store branches,
# both images, a full clone and margin above the 5 GiB post-acquisition floor.
DISK_POST = 5*1024**3
DISK_ACQUISITION = 5*1024**3
DISK_INITIAL = DISK_POST+DISK_ACQUISITION


def guard():
    limit(END is not None and time.time() < END-180, 'ORIGINAL_HARD_BOUND_WITH_CLEANUP')
    limit(shutil.disk_usage(ROOT).free >= 1024**3, 'CLEANUP_DISK_RESERVE')
    if DOCKER_ROOT is not None:
        limit(shutil.disk_usage(DOCKER_ROOT).free >= 1024**3, 'DOCKER_DISK_RESERVE')
    if RX is not None:
        delta = int(RX.read_text())-RX_START
        limit(0 <= delta <= 2*1024**3, 'ACQUISITION_NETWORK_CAP')
    limit(sum(p.stat().st_size for p in OUT.rglob('*') if p.is_file()) < 28*1024**2,
          'EVIDENCE_CAP')


def run(label, args, seconds=30, expected=0, cleanup=False, cap=2*1024**2):
    global STEP
    STEP = label
    if not cleanup:
        limit(time.time() < SOFT, 'NO_NEW_STEP_AFTER_TARGET')
    remaining = END-time.time()-(0 if cleanup else 180)
    if not cleanup:
        remaining = min(remaining, SOFT-time.time())
    budget=min(seconds,remaining)
    limit(budget > 6, 'ORIGINAL_HARD_DEADLINE_WITH_REAP_RESERVE')
    return command(args, budget-6, cap,
                   (lambda: None) if cleanup else guard,
                   expected=expected, log=PRIVATE/(label+'.log'))


def identity(name, expected_label=RUN):
    value = json.loads(run(name+'-identity', ['docker', 'inspect', '--format',
        '{{json .Id}}', name], cleanup=True))
    labels = json.loads(run(name+'-label', ['docker', 'inspect', '--format',
        '{{json .Config.Labels}}', name], cleanup=True))
    intent = OWNED[name]
    limit(labels.get('xerj3016-candidate.run') == expected_label and
          labels.get('xerj3016-candidate.owner') == intent['nonce'], 'OWNERSHIP_MISMATCH')
    limit(intent['id'] in (None, value), 'OWNERSHIP_MISMATCH')
    intent['id'] = value


def stop(name):
    identity(name)
    run(name+'-stop', ['docker', 'stop', '-t', '5', name], seconds=15, cleanup=True)
    state = json.loads(run(name+'-state', ['docker', 'inspect', '--format',
        '{{json .State}}', name], cleanup=True))
    selected = {k: state[k] for k in ('Status', 'Running', 'Restarting', 'OOMKilled', 'ExitCode', 'Pid')}
    limit(not selected['Running'] and not selected['Restarting'] and selected['Pid']==0, 'STOP_NOT_VERIFIED')
    save(OUT/(name+'-stopped.json'), selected)
    return selected


def create(label, memory, mounts=(), image=None, evidence=OUT, network='none', setup=False):
    image = image or IMAGE
    name = 'xerj3016-candidate-'+RUN+'-'+label
    matches = run(label+'-absence', ['docker', 'ps', '-a', '--filter',
                  'name=^/'+name+'$', '--format', '{{.ID}}']).strip()
    limit(not matches, 'CONTAINER_NAME_ALREADY_EXISTS')
    intent = {'id': None, 'nonce': os.urandom(16).hex()}
    cpus = ','.join(map(str, sorted(os.sched_getaffinity(0))[:2]))
    args = ['docker', 'create', '--name', name, '--label', 'xerj3016-candidate.run='+RUN,
        '--label', 'xerj3016-candidate.owner='+intent['nonce'],
        '--platform', 'linux/arm64', '--pull=never', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--log-driver=none', '--pids-limit=4096',
        '--cpus=2', '--cpuset-cpus='+cpus, '--memory='+memory, '--memory-swap='+memory,
        '--user='+('0:0' if setup else str(os.getuid())+':'+str(os.getgid())), '--network='+network,
        '--tmpfs=/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777',
        '--tmpfs=/work:rw,exec,nosuid,nodev,size=8g,mode=1777',
        '--mount=type=bind,src='+str(P)+',dst=/packet,readonly',
        '--mount=type=bind,src='+str(evidence)+',dst=/out',
        '--mount=type=bind,src='+str(PRIVATE)+',dst=/private-evidence',
        '--env=HOME=/tmp/home', '--env=PYTHONDONTWRITEBYTECODE=1', '--env=TZ=UTC',
        '--env=XERJ_DISABLE_FEEDBACK=true', '--env=GIT_NO_LAZY_FETCH=1',
        '--env=GIT_OPTIONAL_LOCKS=0', '--env=GIT_CONFIG_COUNT=3',
        '--env=GIT_CONFIG_KEY_0=safe.directory', '--env=GIT_CONFIG_VALUE_0=/repo',
        '--env=GIT_CONFIG_KEY_1=safe.directory', '--env=GIT_CONFIG_VALUE_1=/repo',
        '--env=GIT_CONFIG_KEY_2=core.hooksPath', '--env=GIT_CONFIG_VALUE_2=/dev/null',
        '--env=HTTP_PROXY=', '--env=HTTPS_PROXY=', '--env=ALL_PROXY=',
        '--env=NO_PROXY=localhost,127.0.0.1']
    if setup:
        args += ['--cap-add=CHOWN','--cap-add=DAC_OVERRIDE','--cap-add=FOWNER','--cap-add=SETUID','--cap-add=SETGID']
    else:
        args += ['--read-only']
    for value in mounts:
        args += ['--mount='+value]
    args += ['--entrypoint=sleep', image, '3600']
    # Record intent before create: a CLI disconnect can follow successful creation.
    OWNED[name] = intent
    cid = run(label+'-create', args).decode().strip()
    limit(re.fullmatch('[0-9a-f]{64}', cid) is not None, 'CREATE_ID')
    intent['id'] = cid
    identity(name)
    run(label+'-start', ['docker', 'start', name])
    return name


def phase(name, label, record_label=None, extra_env=(), target_deadline=None):
    identity(name)
    run(record_label or label, ['docker', 'exec', '-e', 'VALIDATION_HARD_DEADLINE='+str(END),
        '-e', 'VALIDATION_TARGET_DEADLINE='+str(SOFT if target_deadline is None else min(SOFT,target_deadline))]+list(extra_env)+[name,
        'python3', '/packet/validate.py', label], seconds=3600, cap=4*1024**2)


def preserve_exact(source, destination, cap=1048576):
    for candidate in (source,destination):
        limit(candidate.is_absolute()and candidate.is_relative_to(ROOT),'OWNED_EVIDENCE_PATH')
        for part in [candidate,*candidate.parents]:
            if part==ROOT.parent:break
            limit(not part.is_symlink(),'EVIDENCE_SYMLINK_CHAIN')
    limit(source.is_file() and not source.is_symlink() and source.stat().st_size<=cap,'BOUNDED_PRESERVATION_SOURCE')
    with source.open('rb')as stream:raw=stream.read(cap+1)
    limit(len(raw)<=cap and not destination.exists(),'EXCLUSIVE_PRESERVATION')
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    destination.write_bytes(raw)
    limit(hashlib.sha256(destination.read_bytes()).digest()==hashlib.sha256(raw).digest(),'PRESERVED_BYTE_IDENTITY')


def resume_offline(name,label):
    # The same exact container/nonce/ID; no assumption about Docker restart
    # network restoration. PID1 sleeps until these real offline gates finish.
    identity(name)
    run(label+'-start',['docker','start',name])
    nets=json.loads(run(label+'-networks',['docker','inspect','--format','{{json .NetworkSettings.Networks}}',name]))
    limit(set(nets)<= {'bridge'},'UNEXPECTED_RESUMED_NETWORK_HOLD')
    if nets:run(label+'-disconnect-bridge',['docker','network','disconnect','bridge',name])
    after=json.loads(run(label+'-networks-after',['docker','inspect','--format','{{json .NetworkSettings.Networks}}',name]))
    limit(after=={},'RESUMED_OFFLINE_NETWORK_NOT_PROVED')
    phase(name,'network-check',record_label=label+'-actual-network-check')
    preserve_exact(OUT/'network-fixture.json',OUT/(label+'-offline-proof.json'))


def fixed_config(binary,nonce):
    cfg=dict(PLAN['fixed_topology'])
    limit(cfg['executionApproved']is True and cfg['rootAgreement']is True and
          cfg['c2AmendmentApproved']is True and cfg['additionalAttemptApproved']is True,
          'FIXED_FTX_EXECUTION_NOT_APPROVED')
    cfg.update(image=IMAGE,imageID=IMAGE,binaryHostPath=str(binary),
       binarySHA256=hashlib.sha256(binary.read_bytes()).hexdigest(),
       originalHardEpoch=END,originalTargetEpoch=SOFT,actualRunID=RUN,runNonce=nonce,
       namespace='xerj3016-'+RUN+'-'+nonce,cpuSet=','.join(map(str,sorted(os.sched_getaffinity(0))[:2])))
    for key in ('c2ApprovalReceiptPath','sourceParityReceiptPath','capApprovalReceiptPath'):
        value=Path(cfg[key]);limit(value.is_absolute()and len(value.parts)>=3 and value.parts[1]=='packet','EXACT_PACKET_APPROVAL_PATH')
        cfg[key]=str(P/value.relative_to('/packet'))
    limit(hashlib.sha256(Path(cfg['c2ApprovalReceiptPath']).read_bytes()).hexdigest()==cfg['c2ApprovalReceiptSHA256'],'C2_APPROVAL_IDENTITY')
    limit(hashlib.sha256(Path(cfg['sourceParityReceiptPath']).read_bytes()).hexdigest()==cfg['sourceParityReceiptSHA256'],'SCOPED_SOURCE_PARITY_IDENTITY')
    limit(hashlib.sha256(Path(cfg['capApprovalReceiptPath']).read_bytes()).hexdigest()==cfg['capApprovalReceiptSHA256']==PLAN['ftx']['capApprovalReceiptSHA256'],'FTX_CAP_APPROVAL_IDENTITY')
    return cfg


def native_controls_before_offline(name):
    global FIXED_EARLY_RESULT
    phase(name,'prepare-runtime-controls')
    proof=json.loads((OUT/'runtime-control-binary-proof.json').read_text())
    limit(proof['bytes']==135764000 and proof['archiveSHA256']==PLAN['ftx']['releaseArchiveSHA256'],'ACTUAL_RELEASE_BINARY_PROOF')
    limit(proof['path']=='/work/unpacked/'+PLAN['archive_name'][:-7]+'/xerj','EXACT_EXTRACTED_BINARY_PATH')
    # Read-only .public inputs only; binary lives outside public export caps.
    binary=ROOT/'runtime-control-xerj'
    run('copy-runtime-control-binary',['docker','cp',name+':'+proof['path'],str(binary)],seconds=30)
    limit(binary.is_file()and not binary.is_symlink()and binary.stat().st_size==proof['bytes'],'COPIED_BINARY_SIZE')
    limit(hashlib.sha256(binary.read_bytes()).hexdigest()==proof['sha256'],'COPIED_BINARY_SHA')
    binary.chmod(0o755)
    for filename in ['runtime-control-binary-proof.json','runtime-control-offline-network.json',
                     'actual-elf.json','actual-checksum-controls.json',
                     'preflight-binary-version.json','preflight-binary-version.stdout','preflight-binary-version.stdout.stderr',
                     'prepare-runtime-controls-resources.json']:
        preserve_exact(OUT/filename,OUT/'initial-runtime-controls'/filename)
    stop(name)
    preserve_exact(OUT/(name+'-stopped.json'),OUT/'offline-stop-before-native-controls.json')
    cfg=fixed_config(binary,os.urandom(4).hex())
    controls=FixedEarlyControls(cfg,ROOT/'fixed-early-controls')
    try:
        FIXED_EARLY_RESULT=controls.run()
    finally:
        terminal=ROOT/'fixed-early-controls/terminal.json'
        if terminal.is_file():
            limit(terminal.stat().st_size<=131072,'EARLY_TERMINAL_CAP')
            FIXED_EARLY_RESULT=json.loads(terminal.read_text())
            save(OUT/'fixed-early-controls.json',FIXED_EARLY_RESULT)
    limit(FIXED_EARLY_RESULT['state']=='PASS_EARLY_LOCAL_AND_KERNEL_CONTROLS'and
          FIXED_EARLY_RESULT['stopVerified']is True,'EARLY_REAL_C2_CONTROLS_INCOMPLETE')
    save(OUT/'fixed-early-controls.json',FIXED_EARLY_RESULT)
    resume_offline(name,'resume-after-native-controls')
    # /work was tmpfs and is gone. This is data-only re-extraction/identity,
    # with prior actual receipts preserved, not a test retry or clock reset.
    phase(name,'prepare-runtime-controls',record_label='restore-runtime-controls-after-stop')
    restored=json.loads((OUT/'runtime-control-binary-proof.json').read_text())
    limit(restored['sha256']==proof['sha256']and restored['bytes']==proof['bytes'],'RESTORED_EXACT_SAME_BINARY')
    return binary,cfg


def fixed_ftx_route(name,binary,cfg):
    global FIXED_SESSION,FIXED_FINAL_RESULT
    handoff=ROOT/'ftx-inputs'
    limit(not handoff.exists(),'HANDOFF_PATH_ALREADY_EXISTS')
    run('copy-exact-ftx-handoff',['docker','cp',name+':/work/ftx-handoff',str(handoff)],seconds=60)
    identity_receipt=json.loads((OUT/'ftx-handoff-identity.json').read_text())
    raw=(handoff/'input-manifest.json').read_bytes()
    limit(hashlib.sha256(raw).hexdigest()==identity_receipt['sha256'],'HANDOFF_MANIFEST_IDENTITY')
    # Small exact manifest for public packet bytes; no host checkout/.git copied.
    packet_rows=[]
    for path in sorted(P.rglob('*')):
        limit(not path.is_symlink(),'PACKET_SYMLINK')
        if path.is_file():
            packet_rows.append({'path':path.relative_to(P).as_posix(),'bytes':path.stat().st_size,
                                'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        else:limit(path.is_dir(),'PACKET_SPECIAL_FILE')
    packet_manifest=ROOT/'ftx-public-packet-manifest.json'
    save(packet_manifest,{'files':packet_rows})
    stop(name)
    preserve_exact(OUT/(name+'-stopped.json'),OUT/'offline-stop-before-ftx.json')
    cfg=dict(cfg)
    cfg.update(ftxStartedAt=time.time(),earlyControlsReceiptPath=str(ROOT/'fixed-early-controls/terminal.json'),
       earlyControlsReceiptSHA256=hashlib.sha256((ROOT/'fixed-early-controls/terminal.json').read_bytes()).hexdigest(),
       earlyControlsImplementationSHA256=FIXED_EARLY_RESULT['implementationSHA256'],
       publicSnapshotPath=str(handoff),publicSnapshotManifest=str(handoff/'input-manifest.json'),
       publicSnapshotSHA256=identity_receipt['sha256'],publicPacketPath=str(P),
       publicPacketManifest=str(packet_manifest),publicPacketSHA256=hashlib.sha256(packet_manifest.read_bytes()).hexdigest(),
       offlineHandoffReceiptPath=str(handoff/'offline-handoff-receipt.json'),
       offlineHandoffReceiptSHA256=hashlib.sha256((handoff/'offline-handoff-receipt.json').read_bytes()).hexdigest(),
       expectedNineUpstreamPaths=PLAN['final_changed_paths'],sourcePin=PLAN['pin'])
    # Reuse the same actual namespace base but different role suffixes; all early
    # containers are stopped and this session has separate owned names.
    FIXED_SESSION=FixedSession(cfg,ROOT/'fixed-ftx')
    prepared=None
    try:
        prepared=FIXED_SESSION.prepare()
        target=prepared['target']
        extra=['-e','VALIDATION_HARD_DEADLINE='+str(END),
               '-e','VALIDATION_TARGET_DEADLINE='+str(min(SOFT,prepared['ftxOperationalEnd'])),
               '-e','XERJ_FTX_HANDOFF_SHA256='+identity_receipt['sha256'],
               '-e','XERJ_C2_HOST_PROOF_SHA256='+prepared['guestProofSHA256'],
               '-e','XERJ_C2_APPROVAL_SHA256='+prepared['guestApprovalSHA256'],
               '-e','XERJ_FTX_CAP_APPROVAL_SHA256='+PLAN['ftx']['capApprovalReceiptSHA256']]
        run('full-fixed-topology-ftx',['docker','exec']+extra+[target,'python3','/packet/validate.py','ftx-only'],
            seconds=min(1200,prepared['ftxOperationalEnd']-time.time()),cap=4*1024**2)
    finally:
        # Forward existing partial evidence even when the FTX command failed;
        # absence stays absence, never a fabricated success receipt.
        if prepared is not None:
            present=[];missing=[];optional_missing=[]
            for filename in ['ftx-controls.json','ftx-surface-corpus-bindings.json','ftx-before-summary.json',
                             'ftx-after-summary.json','ftx-comparison.json','ftx-evidence-accounting.json',
                             'ftx-route-completion.json','ftx-only-resources.json','ftx-only-failure.json']:
                source=Path(prepared['targetOutHostPath'])/filename
                if source.is_file():
                    preserve_exact(source,OUT/filename);present.append(filename)
                elif filename.endswith('-failure.json'):optional_missing.append(filename)
                else:missing.append(filename)
            save(OUT/'fixed-ftx-forwarded-evidence.json',{'present':present,'missingRequired':missing,
                 'optionalMissing':optional_missing,
                 'missingNotTreatedAsPass':True,'rawPrivateTranscriptNotSelected':True})
        FIXED_FINAL_RESULT=FIXED_SESSION.close()
        save(OUT/'fixed-ftx-host-final.json',FIXED_FINAL_RESULT)
    limit(FIXED_FINAL_RESULT['stopVerified']and FIXED_FINAL_RESULT['sourceHandoffUnchanged']and
          not FIXED_FINAL_RESULT['infrastructureHOLD'],'FIXED_FTX_HOST_FINAL_INCOMPLETE')
    resume_offline(name,'resume-after-ftx')
    phase(name,'finalize-ftx')


def collect_fixed_evidence():
    """Explicit synthetic/public VM evidence only; never scan an output tree."""
    destination=OUT/'fixed-topology';destination.mkdir(mode=0o700,exist_ok=False)
    rows=[];missing=[]
    def add(source,relative,role,cap=1048576):
        base=ROOT if source.is_relative_to(ROOT)else P
        limit(source.is_relative_to(base),'FIXED_EVIDENCE_SOURCE_ROOT')
        for part in [source,*source.parents]:
            if part==base.parent:break
            limit(not part.is_symlink(),'FIXED_EVIDENCE_SOURCE_SYMLINK_CHAIN')
        if not source.is_file():
            missing.append(relative);return
        limit(not source.is_symlink()and source.stat().st_size<=cap,'FIXED_PUBLIC_EVIDENCE_CAP')
        with source.open('rb')as stream:raw=stream.read(cap+1)
        limit(len(raw)<=cap,'FIXED_PUBLIC_EVIDENCE_BOUND')
        target=destination/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        limit(not target.exists(),'FIXED_PUBLIC_EVIDENCE_DUPLICATE')
        target.write_bytes(raw)
        rows.append({'path':relative,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'role':role})
    early=ROOT/'fixed-early-controls';fixed=ROOT/'fixed-ftx'
    add(early/'terminal.json','early/terminal.json','EARLY_TERMINAL')
    for role,source,relative,labels in [
      ('EARLY_NATIVE',early/'native/proof','early/native',
       ['version','actual-feedback-help','real-local-positive','real-optout-negative']),
      ('EARLY_NATIVE_PROXY',early/'target/native-proxy-proof','early/native-proxy',
       ['version','actual-feedback-help','real-native-https-proxy'])]:
        for label in labels:
            for suffix in ('.json','.stdout','.stdout.stderr'):
                add(source/(label+suffix),relative+'/'+label+suffix,role,262144)
        for filename in ('result.json','sink-requests.json'):
            add(source/filename,relative+'/'+filename,role)
    for filename in ['transport.json','paired.json','direct.json','connection-bytes.json',
                     'total-bytes.json','header-time.json','connection-time.json']:
        add(early/'target'/filename,'early/transport/'+filename,'EARLY_TRANSPORT')
    for kind in ('archive','checksum'):
        add(early/'target'/('release-route-'+kind+'.json'),
            'release-routes/'+kind+'.json','RELEASE_ROUTE')
    for label in ['fixture-proxy','connection-bytes','total-bytes','header-time','connection-time','real-proxy']:
        for filename in ['config.json','proxy/connections.jsonl','proxy/summary.json',
                         'actual-graceful-finalization.json']:
            add(early/label/filename,'early/proxy/'+label+'/'+filename,'EARLY_PROXY')
    # Exactly nine roles are authored in the early controller. Raw command
    # receipts/stdout are preserved, not reconstructed from a stopped boolean.
    for index in range(9):
        for suffix in ('.json','.stdout','.stdout.stderr'):
            add(early/(f'cleanup-inspect-{index}'+suffix),
                f'early/stops/{index}'+suffix,'EARLY_STOP',262144)
    for filename,role in [('host-proof.json','HOST_PROOF'),('kernel-proof.json','KERNEL_PROOF'),
                          ('actual-target-routing.json','TARGET_ROUTING'),('c2-approval.json','C2_APPROVAL'),
                          ('proxy-config.json','PROXY_CONFIG')]:
        add(fixed/'operator-proof'/filename,
            'host/approval.json'if filename=='c2-approval.json'else'host/'+filename,role)
    # Paired control in the ACTUAL FTX namespace, distinct from the isolated
    # early reflector controls. Preserve the two referenced raw byte witnesses.
    add(fixed/'target-state/operator-direct-denial.json',
        'host/actual-target-direct-denial.json','EARLY_TRANSPORT')
    add(fixed/'fixed-target-proxy-positive.stdout',
        'host/actual-target-proxy-positive.stdout','EARLY_TRANSPORT',32768)
    add(fixed/'fixed-target-proxy-positive.json',
        'host/actual-target-proxy-positive.json','EARLY_TRANSPORT',262144)
    add(fixed/'fixed-final.json','host/final.json','HOST_FINAL')
    add(fixed/'proxy-output/proxy/connections.jsonl','proxy/connections.jsonl','PROXY_LOG')
    add(fixed/'proxy-output/proxy/summary.json','proxy/summary.json','PROXY_FINAL')
    for index in range(2):
        for suffix in ('.json','.stdout','.stdout.stderr'):
            add(fixed/(f'fixed-stop-inspect-{index}'+suffix),
                f'host/stops/{index}'+suffix,'HOST_STOP',262144)
    guest=fixed/'target-state/private-evidence/fixed-containment'
    add(guest/'sink.jsonl','guest/sink.jsonl','GUEST_SINK')
    add(guest/'containment-final.json','guest/final.json','GUEST_FINAL')
    frames=[]
    for index in range(1,257):
        path=guest/'containment-checkpoints'/f'{index:03d}.json'
        if path.is_file():
            limit(not path.is_symlink()and path.stat().st_size<=1048576,'CHECKPOINT_RECORD_BOUND')
            with path.open('rb')as stream:raw=stream.read(1048577)
            limit(len(raw)<=1048576,'CHECKPOINT_BYTES')
            frames.append({'path':path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                           'rawUTF8':raw.decode('utf-8','strict')})
    if frames:
        bundle=fixed/'checkpoint-bundle.json';save(bundle,{'schemaVersion':1,'frames':frames})
        add(bundle,'guest/checkpoints.json','GUEST_CHECKPOINT_BUNDLE')
    else:missing.append('guest/checkpoints.json')
    value=Path(PLAN['fixed_topology']['sourceParityReceiptPath'])
    if value.is_absolute()and value.is_relative_to('/packet'):
        add(P/value.relative_to('/packet'),'receipts/scoped-release-parity.json','SOURCE_PARITY')
    else:missing.append('receipts/scoped-release-parity.json')
    required=['EARLY_NATIVE','EARLY_NATIVE_PROXY','EARLY_TRANSPORT','EARLY_PROXY','EARLY_STOP',
       'EARLY_TERMINAL','HOST_PROOF','KERNEL_PROOF','TARGET_ROUTING','C2_APPROVAL','PROXY_CONFIG',
       'PROXY_FINAL','PROXY_LOG','HOST_FINAL','HOST_STOP','GUEST_CHECKPOINT_BUNDLE','GUEST_FINAL','GUEST_SINK','SOURCE_PARITY','RELEASE_ROUTE']
    save(destination/'manifest.json',{'schemaVersion':1,'files':rows,'requiredRoles':required,
       'missingExpectedPaths':missing,'collectionComplete':not missing})
    limit(sum(row['bytes']for row in rows)<=8*1024**2,'FIXED_PUBLIC_BUNDLE_FORECAST_CAP')


def fixtures(image, label):
    evidence = OUT/label
    evidence.mkdir(exist_ok=False)
    name = create(label, '512m', image=image, evidence=evidence)
    result = {}
    try:
        value = run(label+'-success', ['docker', 'exec', name, 'python3', '-c',
                    'import json;print(json.dumps({"success":True}))'])
        result['actual_json_success'] = json.loads(value) == {'success': True}
        try:
            run(label+'-nonzero', ['docker', 'exec', name, 'python3', '-c', 'raise SystemExit(3)'])
        except RuntimeError as exc:
            assert str(exc).startswith('command exit 3, expected 0:')
            result['nonzero_blocks_dependent_step'] = True
        else:
            raise AssertionError('NONZERO_NOT_PROPAGATED')
        try:
            run(label+'-timeout', ['docker', 'exec', name, 'python3', '-c',
                'import time;print("TIMEOUT_CASE_ENTERED",flush=True);time.sleep(60)'], seconds=10)
        except TimeoutError as exc:
            assert str(exc) == 'command elapsed limit'
            assert b'TIMEOUT_CASE_ENTERED' in (PRIVATE/(label+'-timeout.log')).read_bytes()
            result['host_cli_timeout_only'] = True
        else:
            raise AssertionError('TIMEOUT_NOT_PROPAGATED')
        try:
            identity(name, expected_label='intentional-fixture-mismatch')
        except LimitAbort as exc:
            if str(exc) != 'OWNERSHIP_MISMATCH':
                raise
            result['label_mismatch_refused'] = True
        else:
            raise AssertionError('OWNERSHIP_NOT_ENFORCED')
        malformed = run(label+'-malformed', ['docker', 'exec', name, 'python3', '-c',
                        'print("not-json")'])
        assert malformed == b'not-json\n'
        try:
            json.loads(malformed)
        except json.JSONDecodeError:
            result['malformed_evidence_refused'] = True
        else:
            raise AssertionError('MALFORMED_JSON_ACCEPTED')
        phase(name, 'helper-fixtures')
        helper_result = json.loads((evidence/'helper-fixtures.json').read_text())
        assert helper_result['privacy_cases'] == 4
        assert helper_result['listenerParser']['positive']==1 and len(helper_result['listenerParser']['negative'])==8 and helper_result['listenerParser']['allExpectedOutcomesObserved']is True
        assert helper_result['ftx']['expectedCount']==24 and len(helper_result['ftx']['controls'])==24
        assert (evidence/'ftx-pure-controls.json').is_file()
        route_parser=helper_result['releaseRouteParser']
        assert route_parser['caseCount']==10 and all(route_parser['cases'].values())
        assert route_parser['parserSourceSHA256']==hashlib.sha256((P/'release_head_PROPOSED.py').read_bytes()).hexdigest()
        assert (evidence/'release-route-parser-fixtures.json').is_file()
        assert helper_result['registry']['real_HTTP_cases'] == 5
        assert helper_result['artifacts']['actual_filesystem_cases'] == 10
        assert helper_result['bounded']['actual_cases'] == 3
        assert helper_result['oracle']['state']=='PASS'and len(helper_result['oracle']['negativeControls'])==9
        assert helper_result['aptClosure']['state']=='PASS'and helper_result['aptClosure']['capturedRows']==3 and len(helper_result['aptClosure']['negativeControls'])==14
        assert helper_result['identity']['globalRunNumberPositives']==['1','2','101']and len(helper_result['identity']['negativeControls'])==11
        assert helper_result['artifact_decode']['actual_zip_cases']==10 and helper_result['artifact_decode']['actual_export_manifest_cases']==5 and helper_result['artifact_decode']['all_passed']is True
        full_reader=helper_result['artifact_decode']['ftx_semantic_cases']['fullPipelineCases']
        assert len(full_reader)==5 and all(r['accepted']==r['expectedAccepted']for r in full_reader)
        result['input_identity'] = helper_result['input_identity']
        result['image'] = image
        expected = 'BOOTSTRAP_HARNESS_ONLY_NOT_PRODUCT' if label=='fixture-bootstrap' else 'EXACT_TARGET_REPEAT'
        assert result['input_identity']['role'] == expected
    finally:
        result['confirmed_stopped'] = not stop(name)['Running']
        save(OUT/(label+'-host-helper-fixtures.json'), result)
    limit(all(result.values()), 'HOST_HELPER_FIXTURE_FAILED')




def pull_image(image, proof, label):
    assert proof['closed'] and proof['image'] == image
    remote = json.loads(run(label+'-head',
        ['python3',str(P/'registry.py'),image.split('@')[1],proof['media_type']],seconds=50))
    if remote['remaining'] is not None:
        assert int(remote['remaining'].split(';')[0]) >= 4, 'ANONYMOUS_PULL_MARGIN'
    else:
        assert proof['verified_policy_allows_missing_rate_headers'] is True
    save(OUT/(label+'-registry-HEAD.json'), remote)
    # One invocation. There is no mid-pull byte cancellation claim.
    run(label+'-image-pull', ['docker','pull','--platform=linux/arm64',image],seconds=180)
    selected = json.loads(run(label+'-image-inspect',['docker','image','inspect',image]))[0]
    assert image in selected['RepoDigests'] and selected['Architecture']=='arm64' and selected['Os']=='linux'
    containerd = any('containerd' in str(row).lower() for row in DRIVER_STATUS)
    expected_id = image.split('@')[1] if containerd else proof['config_digest']
    assert selected['Id'] == expected_id, 'DAEMON_IMAGE_ID_FOR_STORE'
    env = dict(v.split('=',1) for v in selected['Config']['Env'] if '=' in v)
    assert env['PYTHON_VERSION'] == proof['python_version']
    save(OUT/(label+'-image-identity.json'),
         dict({k:selected[k] for k in ('Id','RepoDigests','Architecture','Os','Size')},
              store_branch='containerd' if containerd else 'classic',
              daemon_verified_PYTHON_VERSION=env['PYTHON_VERSION'],
              Size_is_store_dependent_not_unpacked_bound=True))


def finite_host_limits():
    root = Path('/sys/fs/cgroup')
    assert (root/'cgroup.controllers').exists(), 'CGROUP_V2_REQUIRED'
    memberships = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                   if line.startswith('0::')]
    assert len(memberships) == 1
    cursor = root/memberships[0].lstrip('/')
    assert cursor.exists() and cursor.resolve().is_relative_to(root.resolve())
    limits = []
    while True:
        path = cursor/'memory.max'
        if path.exists():
            value = path.read_text().strip()
            if value != 'max':
                current = int((cursor/'memory.current').read_text())
                limit_bytes = int(value)
                assert limit_bytes >= 12*1024**3 and limit_bytes-current >= 10*1024**3
                limits.append({'limit_bytes':limit_bytes,'current_bytes':current})
        if cursor == root:
            return limits
        cursor = cursor.parent





def public_artifacts():
    # Strict candidate proof set is additive to every original I2 requirement.
    # No raw private path map, node/proxy transcript or transport log is selected.
    limit(PLAN.get('strict_candidate_ftx_export_implemented') is True, 'STRICT_CANDIDATE_FTX_EXPORT_NOT_BOUND')
    result=json.loads((OUT/'hosted-result.json').read_text())
    full_claim = result.get('full_validation') is True
    # Exists even on early failure, before any ftx-* member is examined.
    save(OUT/'candidate-ftx-export-status.json', {'schemaVersion':1,'fullCandidateClaim':full_claim,
        'state':'COMPLETE_CANDIDATE_EVIDENCE' if full_claim else 'INCOMPLETE_NOT_CANDIDATE_PASS',
        'presentFTXProofs':[n for n in ['ftx-controls.json','ftx-surface-corpus-bindings.json','ftx-before-summary.json','ftx-after-summary.json','ftx-comparison.json','ftx-evidence-accounting.json'] if (OUT/n).is_file()],
        'expectedFTXProofs':['ftx-controls.json','ftx-surface-corpus-bindings.json','ftx-before-summary.json','ftx-after-summary.json','ftx-comparison.json','ftx-evidence-accounting.json']})
    from artifacts import fixed_host_export_contract
    fixed_names,fixed_required=fixed_host_export_contract(OUT,PLAN)
    # OUT contains reviewed public-source/check output only. Raw node and Git transport logs live PRIVATE.
    names={'hosted-result.json','host-admission.json','early-or-runtime-failure.json','workflow-clock.json','packet-input-identity.json','source-identity.json','canonical-tag-set-proof.json','derived-image-identity.json','apt-closure.json','apt-official-sources-before.json','apt-resolved-before-download.json','apt-parser-setup-fixtures.json','apt-download-inventory.json','apt-install-delta.json','result.json','seo-suite.json','light-suite.json','mechanics.json','oracle-fixtures.json','actual-elf.json','actual-release-input.json','actual-checksum-controls.json','node-exit.json','node-log-summary.json','node-stderr-summary.json','early-operator-compatibility.json','offline-network.json','network-fixture.json','g0-fixture.json','initial-source-manifest.json','final-source-manifest.json','actual-site-output-hashes.json','required-failures.json'}
    candidate_records={'candidate-source-manifest.json','post-ftx-source-manifest.json','candidate-source-proof.json','final-tested-patch-identity.json','mechanics-node-stop-before-ftx.json','ftx-path-map-identity.json'}
    ftx_records={'ftx-controls.json','ftx-surface-corpus-bindings.json','ftx-before-summary.json','ftx-after-summary.json','ftx-comparison.json','ftx-evidence-accounting.json'}
    generated_records={'generated/'+name for name in PLAN['generator_owned_paths']}
    names |= candidate_records | ftx_records | generated_records | {'candidate-ftx-export-status.json'}
    candidate_labels=['candidate-full-article-generation','candidate-nine-paths','candidate-untracked','candidate-generator-idempotence','candidate-generator-equality','final-nine-tested-patch']+[state+'-'+kind for state in ['candidate','post-ftx'] for kind in ['head','tracked-status','tracked']]
    names |= {label+suffix for label in candidate_labels for suffix in ['.json','.stdout','.stdout.stderr']}
    labels=['version-python']+['version-'+x for x in ['git','curl','bash','awk','sort','jq']]+['actual-tags','actual-cargo-version','initial-head','initial-tracked-status','initial-tracked','final-head','final-tracked-status','final-tracked','final-whitespace','binary-version','original-five-doc-example','deployment-sitemap']+['seo-'+f'{i:02d}'for i in range(19)]+['light-'+f'{i:02d}'for i in range(9)]+['apt-'+x for x in ['signed-update','resolve-uris','download-only','offline-install','jq-version','inventory-before','inventory-after']]+['apt-'+kind+'-'+pkg for kind in ['metadata','deb-control','installed']for pkg in ['jq','libjq1','libonig5']]
    names|={label+suffix for label in labels for suffix in ['.json','.stdout','.stdout.stderr']}
    names|={'apt-license-'+pkg+'.txt'for pkg in ['jq','libjq1','libonig5']}
    for label in ['fixture-bootstrap','fixture-target']:
        names.add(label+'-host-helper-fixtures.json')
        names|={label+'/'+n for n in ['helper-fixtures.json','helper-fixtures-resources.json','helper-fixtures-failure.json','ftx-pure-controls.json','release-route-parser-fixtures.json']}
    names|={label+'-'+kind+'.json'for label in ['fixture-bootstrap','target']for kind in ['image-identity','registry-HEAD']}
    for label in ['g0','fetch','offline','network-check','helper-fixtures']:
        names|={label+'-'+kind+'.json'for kind in ['resources','failure']}
    names|={n+'-stopped.json'for n in OWNED}
    names|={archive_guard_name+'.receipt.json'for archive_guard_name in [PLAN['archive_name'],PLAN['archive_name']+'.sha256']}
    names|={prefix+suffix for prefix in ['corpus','leg-0','leg-1','hybrid-default','hybrid-unequal','hybrid-custom-k','hybrid-zero-keyword']for suffix in ['-request.json','-raw.json','-failure.json']}
    names|=fixed_names
    actual={p.relative_to(OUT).as_posix()for p in OUT.rglob('*')if p.is_file()}
    limit(actual<=names,'UNEXPECTED_EVIDENCE_FILE_REFUSED_BEFORE_EXPORT')
    required={'hosted-result.json','host-admission.json','candidate-ftx-export-status.json'}
    if full_claim:
        required|=fixed_required
        required|={'result.json','seo-suite.json','light-suite.json','mechanics.json','oracle-fixtures.json','actual-elf.json','actual-release-input.json','actual-checksum-controls.json','node-exit.json','node-log-summary.json','node-stderr-summary.json','early-operator-compatibility.json','offline-network.json','g0-fixture.json','initial-source-manifest.json','final-source-manifest.json','actual-site-output-hashes.json','required-failures.json','apt-closure.json','apt-resolved-before-download.json','apt-download-inventory.json','apt-install-delta.json','apt-parser-setup-fixtures.json','derived-image-identity.json','source-identity.json','canonical-tag-set-proof.json','packet-input-identity.json','workflow-clock.json','target-image-identity.json','fixture-bootstrap-image-identity.json','target-registry-HEAD.json','fixture-bootstrap-registry-HEAD.json','fixture-bootstrap-host-helper-fixtures.json','fixture-target-host-helper-fixtures.json'}
        for label in ['seo-'+f'{i:02d}'for i in range(19)]+['light-'+f'{i:02d}'for i in range(9)]:
            required|={label+'.json',label+'.stdout',label+'.stdout.stderr'}
        required|={prefix+suffix for prefix in ['corpus','leg-0','leg-1','hybrid-default','hybrid-unequal','hybrid-custom-k','hybrid-zero-keyword']for suffix in ['-request.json','-raw.json']}
        required|={label+suffix for label in ['original-five-doc-example','binary-version','version-python']for suffix in ['.json','.stdout','.stdout.stderr']}
        required|={label+suffix for label in ['apt-resolve-uris','apt-inventory-before','apt-inventory-after']+['apt-'+kind+'-'+pkg for kind in ['metadata','deb-control','installed']for pkg in ['jq','libjq1','libonig5']]for suffix in ['.stdout','.stdout.stderr']}
        required|={'apt-license-'+pkg+'.txt'for pkg in ['jq','libjq1','libonig5']}
        required|={PLAN['archive_name']+'.receipt.json',PLAN['archive_name']+'.sha256.receipt.json'}
        required|={n+'-stopped.json'for n in OWNED}
        required|={label+'/helper-fixtures.json'for label in ['fixture-bootstrap','fixture-target']}
        required |= candidate_records | ftx_records | generated_records
        required |= {label+suffix for label in candidate_labels for suffix in ['.json','.stdout','.stdout.stderr']}
        required |= {label+'/ftx-pure-controls.json' for label in ['fixture-bootstrap','fixture-target']}
        required |= {label+'/release-route-parser-fixtures.json' for label in ['fixture-bootstrap','fixture-target']}
    if full_claim:
        # Strict all-six semantic verification is reserved for complete candidate claims.
        export_ftx(OUT,ROOT/'public-evidence',names,required=required)
    else:
        # Sanitized partial proofs remain available through generic decode only.
        # verify_partial_ftx checks the explicit INCOMPLETE marker, privacy and caps.
        export(OUT,ROOT/'public-evidence',names,required=required)


def workflow_clock():
    import datetime,urllib.request
    token=os.environ.get('GITHUB_TOKEN','')
    limit(token!='','EXACT_READ_ONLY_WORKFLOW_TOKEN_REQUIRED')
    url='https://api.github.com/repos/leninworld/xerj/actions/runs/'+RUN
    request=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','Authorization':'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28'})
    start=time.monotonic()
    with urllib.request.urlopen(request,timeout=15)as response:
        raw=response.read(262145)
    limit(len(raw)<=262144 and time.monotonic()-start<15,'WORKFLOW_CLOCK_READ_BOUND')
    d=json.loads(raw);identity_guards.metadata(d,os.environ,PLAN);limit(d['id']==int(RUN)and d['run_attempt']==1 and d['event']=='push'and d['head_branch']==PLAN['branch']and d['head_sha']==os.environ['GITHUB_SHA']and d['path']==PLAN['workflow_published_path'],'WORKFLOW_CLOCK_IDENTITY')
    limit(d['actor']['login']=='leninworld'and int(d['run_number'])>=1,'WORKFLOW_CLOCK_ACTOR')
    created=datetime.datetime.fromisoformat(d['created_at'].replace('Z','+00:00')).timestamp()
    limit(created<=time.time()and time.time()-created<3000,'QUEUE_AND_SETUP_ALREADY_OUTSIDE_TARGET')
    save(OUT/'workflow-clock.json',{'id':d['id'],'created_at':d['created_at'],'head_sha':d['head_sha'],'run_attempt':d['run_attempt'],'run_number':d['run_number'],'target':created+3000,'hard':created+PLAN['hard_seconds'],'queueIncluded':True,'oneReadOnlyAPI':True,'responseSHA256':hashlib.sha256(raw).hexdigest()})
    return created


def apt_image():
    global IMAGE
    base=IMAGE
    name=create('signed-apt-setup','1g',image=base,network='bridge',setup=True)
    try:
        identity(name)
        run('official-apt-setup',['docker','exec','-u','0:0','-e','DEBIAN_FRONTEND=noninteractive','-e','VALIDATION_HARD_DEADLINE='+str(END),'-e','VALIDATION_TARGET_DEADLINE='+str(SOFT),name,'python3','/packet/apt_setup.py'],seconds=180,cap=2*1024**2)
        receipt=json.loads((OUT/'apt-closure.json').read_text());limit(receipt['state']=='SIGNED_OFFICIAL_BOOKWORM_JQ_PRETEST_SETUP'and receipt['completeDeclaredPlanVerified']and receipt['allThreeSignedArchiveControlLicenseInstalledVerified']and len(receipt['packages'])==3 and {p['name']for p in receipt['packages']}=={'jq','libjq1','libonig5'},'APT_CLOSURE_REQUIRED')
        tag='xerj3016-candidate-apt:'+RUN
        image_id=run('apt-image-commit',['docker','commit','--pause=true',name,tag],seconds=60).decode().strip()
        limit(re.fullmatch('sha256:[0-9a-f]{64}',image_id)is not None,'DERIVED_IMAGE_ID')
        selected=json.loads(run('apt-derived-inspect',['docker','image','inspect',image_id]))[0]
        limit(selected['Id']==image_id and selected['Architecture']=='arm64'and selected['Os']=='linux','DERIVED_IMAGE_IDENTITY')
        ancestry=run('apt-image-history',['docker','history','--no-trunc','--format','{{.ID}}',image_id]).decode().splitlines()
        # Content-addressed diffIDs, not compressed registry layer digests, prove base prefix.
        original=json.loads(run('apt-base-inspect',['docker','image','inspect',base]))[0]
        bl=original['RootFS']['Layers'];dl=selected['RootFS']['Layers'];limit(len(dl)>len(bl)and dl[:len(bl)]==bl,'DERIVED_BASE_DIFFID_PREFIX')
        save(OUT/'derived-image-identity.json',{'Id':image_id,'base':base,'baseId':original['Id'],'baseDiffIDs':bl,'derivedDiffIDs':dl,'actualAPTReceiptSHA256':hashlib.sha256((OUT/'apt-closure.json').read_bytes()).hexdigest(),'localDerivedNotRegistryDigest':True,'noDeleteOrPrune':True})
        IMAGE=image_id
    finally:stop(name)


def main():
    global START,END,SOFT,DOCKER_ROOT,RX,RX_START,DRIVER_STATUS
    global FIXED_SESSION,FIXED_EARLY_RESULT,FIXED_FINAL_RESULT
    # Human read is enforced BEFORE public push by the private exact-manifest seal;
    # public planning fields stay false to avoid self-referential attestations/mutations.
    limit(PLAN['runtime_attempt']==3 and PLAN['ordinary_consumed_before']==2 and PLAN['runtime_consumed_before']==2 and PLAN['prior_explicit_exceptions_consumed']==0 and PLAN['explicit_additional_candidate_attempt_approved'] is True and PLAN['ordinary_limit']==2,'EXPLICIT_ADDITIONAL_CANDIDATE_ATTEMPT_AND_H1_REQUIRED_NO_RESET')
    limit(RUN.isdigit()and int(RUN)>0,'RUN_NAMESPACE_REQUIRED')
    ROOT.mkdir(exist_ok=False);OUT.mkdir();PRIVATE.mkdir(mode=0o700)
    result={'status':'INCOMPLETE','full_validation':False};START=time.time()
    save(OUT/'host-admission.json',{'state':'IDENTITY_NOT_YET_ADMITTED','runtimeAttempt':3,'priorRuntimeAttempts':2})
    try:
        limit(PLAN['execution_enabled']is True and PLAN['provenance_closed']is True and PLAN['capacity_probe_authorized']is True,'DISABLED_PENDING_EXACT_WHOLE_EXECUTION_APPROVAL')
        for n,digest in PLAN['files'].items():limit(hashlib.sha256((P/n).read_bytes()).hexdigest()==digest,'PAYLOAD_HASH')
        workflow=Path(os.environ['GITHUB_WORKSPACE'])/PLAN['workflow_published_path']
        limit(workflow.is_file()and not workflow.is_symlink()and hashlib.sha256(workflow.read_bytes()).hexdigest()==PLAN['workflow_sha256'],'WORKFLOW_BYTES')
        identity_guards.environment(os.environ,PLAN)
        limit(platform.system()=='Linux'and platform.machine()=='aarch64','HOSTED_ARM_ONLY')
        limit(os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'and os.environ.get('GITHUB_REPOSITORY')=='leninworld/xerj','PERSONAL_HOSTED_REPOSITORY')
        limit(os.environ.get('GITHUB_REF')=='refs/heads/'+PLAN['branch']and os.environ.get('GITHUB_EVENT_NAME')=='push'and os.environ.get('GITHUB_ACTOR')=='leninworld','EXACT_PUSH_ONLY')
        limit(os.environ.get('GITHUB_RUN_ATTEMPT')=='1'and os.environ.get('GITHUB_RUN_NUMBER','').isdigit()and int(os.environ['GITHUB_RUN_NUMBER'])>=1,'ONE_RUNTIME_ATTEMPT_GLOBAL_RUN_NUMBER')
        os.environ.update({'GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0','GIT_ASKPASS':'/bin/false','GIT_LFS_SKIP_SMUDGE':'1'})
        START=workflow_clock();END=START+3480;SOFT=START+3000
        githead=run('packet-head',['git','-C',str(P),'rev-parse','HEAD'],seconds=10,cap=65536).decode().strip();limit(githead==os.environ['GITHUB_SHA'],'EXACT_PACKET_HEAD')
        save(OUT/'packet-input-identity.json',{'packetCommit':githead,'workflowSHA256':PLAN['workflow_sha256'],'planSHA256':hashlib.sha256((P/'plan.json').read_bytes()).hexdigest(),'files':PLAN['files'],'sourceProvenanceSHA256':hashlib.sha256((P/'source-provenance.json').read_bytes()).hexdigest()})
        save(ROOT/'attempt-ledger.json',{'workflowOrigin':START,'target':SOFT,'hard':END,'runtimeAttempt':3,'ordinaryLimit':2,'priorConsumed':2,'proposedAdditionalException':1,'noRetry':True,'earlierClosedAPIStagesUnchanged':True})
        memory={k:int(v)*1024 for k,v in re.findall(r'^(MemTotal|MemAvailable):\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)}
        limit(memory['MemTotal']>=12*1024**3 and memory['MemAvailable']>=10*1024**3,'ACTUAL_HOST_MEMORY_ADMISSION')
        cgroups=finite_host_limits();limit(len(os.sched_getaffinity(0))>=2,'ACTUAL_TWO_CPU_ADMISSION')
        limit(shutil.disk_usage(ROOT).free>=DISK_INITIAL,'ACTUAL_HOST_DISK_ADMISSION')
        docker=json.loads(run('actual-docker-info',['docker','info','--format','{{json .}}']))
        limit(bool(docker.get('ServerVersion'))and docker.get('NCPU',0)>=2 and docker.get('MemTotal',0)>=12*1024**3,'REAL_DOCKER_SERVER_CAPACITY_NOT_EXIT0_ONLY')
        # Exclusive project runtime preflight: do not interfere with unrelated or scheduled workloads.
        active=run('actual-running-containers',['docker','ps','--format','{{.ID}}']).strip();limit(not active,'UNPRICED_ACTIVE_DOCKER_WORKLOAD_HOLD')
        DOCKER_ROOT=Path(docker['DockerRootDir']);limit(DOCKER_ROOT.is_absolute()and DOCKER_ROOT.is_dir()and shutil.disk_usage(DOCKER_ROOT).free>=DISK_INITIAL,'ACTUAL_DOCKER_DATA_DISK')
        DRIVER_STATUS=docker['DriverStatus'];save(OUT/'host-admission.json',{'state':'ACTUAL_REMOTE_CANDIDATE_RESOURCE_ADMITTED','memory':memory,'cgroupAncestors':cgroups,'cpuAffinity':sorted(os.sched_getaffinity(0)),'dockerServer':docker['ServerVersion'],'dockerNCPU':docker['NCPU'],'dockerRAM':docker['MemTotal'],'hostFreeDisk':shutil.disk_usage(ROOT).free,'dockerFreeDisk':shutil.disk_usage(DOCKER_ROOT).free,'diskForecastNotMeasuredUnpacked':True,'minimumDisk':DISK_INITIAL,'exclusiveRunningContainers':0,'remoteNotMac':True})
        routes=[line.split()[0]for line in Path('/proc/net/route').read_text().splitlines()[1:]if line.split()[1]=='00000000'];limit(len(set(routes))==1,'NETWORK_ACCOUNTING_INTERFACE');RX=Path('/sys/class/net')/routes[0]/'statistics/rx_bytes';RX_START=int(RX.read_text())
        proofs=json.loads((P/'registry-proof.json').read_text());limit(proofs['closed']and proofs['bootstrap']['closed']and proofs['target']['closed'],'REGISTRY_PROOF_CLOSED_REQUIRED')
        pull_image(PLAN['bootstrap_image'],proofs['bootstrap'],'fixture-bootstrap');fixtures(PLAN['bootstrap_image'],'fixture-bootstrap')
        pull_image(IMAGE,proofs['target'],'target');fixtures(IMAGE,'fixture-target')
        apt_image()
        run('source-clone',['git','-c','credential.helper=','-c','core.hooksPath=/dev/null','-c','init.defaultRefFormat=files','clone','--no-checkout','https://github.com/xerj-org/xerj.git',str(SOURCE)],seconds=300,cap=8*1024**2)
        run('source-checkout',['git','-C',str(SOURCE),'-c','core.hooksPath=/dev/null','-c','submodule.recurse=false','checkout','--detach',PLAN['pin']])
        limit(run('source-full-history',['git','-C',str(SOURCE),'rev-parse','--is-shallow-repository']).strip()==b'false','FULL_HISTORY_REQUIRED')
        limit(run('source-no-promisor',['git','-C',str(SOURCE),'config','--get','extensions.partialClone'],expected=1)==b'','NO_PARTIAL_CLONE')
        canonical=run('canonical-full-tags',['git','ls-remote','--tags','https://github.com/xerj-org/xerj.git'],seconds=20,cap=1048576).decode().splitlines()
        local=run('local-full-tags',['git','-C',str(SOURCE),'show-ref','--tags','--dereference'],seconds=20,cap=1048576).decode().splitlines()
        def parse_tags(lines):
            pairs=[]
            for line in lines:
                fields=line.split();limit(len(fields)==2 and re.fullmatch('[0-9a-f]{40}',fields[0])is not None and fields[1].startswith('refs/tags/'),'EXACT_TAG_ROW')
                pairs.append((fields[1],fields[0]))
            limit(len({x[0]for x in pairs})==len(pairs),'DUPLICATE_TAG_REFERENCE');return dict(pairs)
        ct,lt=parse_tags(canonical),parse_tags(local);limit(ct and ct==lt,'FULL_CANONICAL_TAG_SET_MISMATCH')
        limit(ct.get('refs/tags/v1.0.0-rc.102^{}',ct.get('refs/tags/v1.0.0-rc.102'))==PLAN['release_commit'],'EXACT_RC102_PEELED_TAG_COMMIT')
        save(OUT/'canonical-tag-set-proof.json',{'canonicalURL':'https://github.com/xerj-org/xerj.git','canonical':ct,'local':lt,'allCanonicalTagsMatch':True,'rc102Commit':PLAN['release_commit'],'noTagSubsetOrSilentSkip':True})
        tree=run('source-tree',['git','-C',str(SOURCE),'rev-parse','HEAD^{tree}']).decode().strip()
        limit(tree==PLAN['source_tree'],'EXACT_CURRENT_SOURCE_TREE')
        save(OUT/'source-identity.json',{'pin':PLAN['pin'],'tree':tree,'fullHistory':True,'noPartialClone':True,'candidateNotAppliedYet':True,'expectedTrackedPaths':3697,'expectedTrackedBytes':235549390})
        downloads=ROOT/'downloads';downloads.mkdir();os.chmod(downloads,0o700)
        name=create('validation','8g',['type=bind,src='+str(SOURCE)+',dst=/repo','type=bind,src='+str(downloads)+',dst=/downloads'],network='bridge')
        phase(name,'g0');run('fixture-disconnect',['docker','network','disconnect','bridge',name]);phase(name,'network-check');run('fixture-reconnect',['docker','network','connect','bridge',name]);phase(name,'fetch');run('final-disconnect',['docker','network','disconnect','bridge',name])
        actual_image=json.loads(run('offline-container-actual-image',['docker','inspect','--format','{{json .Image}}',name]))
        limit(actual_image==IMAGE,'SAME_ACTUAL_DERIVED_IMAGE')
        save(OUT/'offline-container-image-identity.json',{'actualImageID':actual_image,'identityVerifiedByHost':True})
        binary,fixed_cfg=native_controls_before_offline(name)
        phase(name,'offline')
        fixed_ftx_route(name,binary,fixed_cfg)
        result=json.loads((OUT/'result.json').read_text());limit(result['state']=='CANDIDATE_REQUIRED_CHECKS_COMPLETED_FULL_FTX' and result['ftxComplete'] is True and result['postFTXAllSourceUnchanged'] is True,'CANDIDATE_FTX_INCOMPLETE');result['full_validation']=True
    except BaseException as exc:
        result={'status':'FAILED_NO_RETRY','kind':type(exc).__name__,'step':STEP,'full_validation':False}
        save(OUT/'early-or-runtime-failure.json',{'kind':type(exc).__name__,'message':str(exc)[:512],'identity':{k:os.environ.get(k)for k in ['GITHUB_RUN_ID','GITHUB_RUN_NUMBER','GITHUB_RUN_ATTEMPT','GITHUB_REF','GITHUB_SHA','GITHUB_EVENT_NAME','GITHUB_ACTOR']},'projectValidationComplete':False})
        print('XERJ G0 stopped: '+type(exc).__name__,flush=True)
    finally:
        stops={}
        if FIXED_SESSION is not None and FIXED_FINAL_RESULT is None:
            try:
                FIXED_FINAL_RESULT=FIXED_SESSION.close()
                save(OUT/'fixed-ftx-host-final.json',FIXED_FINAL_RESULT)
            except BaseException:
                result['full_validation']=False
        for name in OWNED:
            try:stops[name]=not stop(name)['Running']
            except BaseException:stops[name]=False
        fixed_stops=(FIXED_EARLY_RESULT is not None and FIXED_EARLY_RESULT.get('stopVerified')is True and
                     FIXED_FINAL_RESULT is not None and FIXED_FINAL_RESULT.get('stopVerified')is True and
                     not FIXED_FINAL_RESULT.get('infrastructureHOLD'))
        result.update(ownedStops=stops,stopVerified=all(stops.values())and fixed_stops,
           fixedEarlyStopProof=(FIXED_EARLY_RESULT or {}).get('ownedStops',{}),
           fixedFTXStopProof=(FIXED_FINAL_RESULT or {}).get('ownedStops',{}),
           workflowSeconds=time.time()-START,runtimeAttempt=3,priorRuntimeConsumed=2,rawNodeLogUploaded=False,containersDeleted=False)
        save(OUT/'hosted-result.json',result)
        try:collect_fixed_evidence()
        except BaseException as exc:
            result['full_validation']=False;result['fixedEvidenceCollectionHOLD']=type(exc).__name__
            save(OUT/'hosted-result.json',result)
        try:public_artifacts()
        except BaseException:
            result['full_validation']=False;result['exportFailure']=True;save(OUT/'hosted-result.json',result);fallback_export(OUT,ROOT/'public-evidence-minimal');raise
    limit(result['full_validation']and result['stopVerified'],'G0_NOT_COMPLETE')

if __name__=='__main__':main()
