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
from artifacts import export, fallback_export
import identity as identity_guards

limit(sys.flags.optimize == 0, 'OPTIMIZATION_NOT_ALLOWED')

P = Path(__file__).resolve().parent
PLAN = json.loads((P / 'plan.json').read_text())
RUN = os.environ.get('GITHUB_RUN_ID', '')
ROOT = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / ('xerj3016-g0-' + RUN)
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
    limit(labels.get('xerj3016-g0.run') == expected_label and
          labels.get('xerj3016-g0.owner') == intent['nonce'], 'OWNERSHIP_MISMATCH')
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
    name = 'xerj3016-g0-'+RUN+'-'+label
    matches = run(label+'-absence', ['docker', 'ps', '-a', '--filter',
                  'name=^/'+name+'$', '--format', '{{.ID}}']).strip()
    limit(not matches, 'CONTAINER_NAME_ALREADY_EXISTS')
    intent = {'id': None, 'nonce': os.urandom(16).hex()}
    cpus = ','.join(map(str, sorted(os.sched_getaffinity(0))[:2]))
    args = ['docker', 'create', '--name', name, '--label', 'xerj3016-g0.run='+RUN,
        '--label', 'xerj3016-g0.owner='+intent['nonce'],
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


def phase(name, label):
    identity(name)
    run(label, ['docker', 'exec', '-e', 'VALIDATION_HARD_DEADLINE='+str(END),
        '-e', 'VALIDATION_TARGET_DEADLINE='+str(SOFT), name,
        'python3', '/packet/validate.py', label], seconds=3600, cap=4*1024**2)


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
        assert helper_result['registry']['real_HTTP_cases'] == 5
        assert helper_result['artifacts']['actual_filesystem_cases'] == 10
        assert helper_result['bounded']['actual_cases'] == 3
        assert helper_result['oracle']['state']=='PASS'and len(helper_result['oracle']['negativeControls'])==9
        assert helper_result['aptClosure']['state']=='PASS'and helper_result['aptClosure']['capturedRows']==3 and len(helper_result['aptClosure']['negativeControls'])==14
        assert helper_result['identity']['globalRunNumberPositives']==['1','2','101']and len(helper_result['identity']['negativeControls'])==11
        assert helper_result['artifact_decode']['actual_zip_cases']==10 and helper_result['artifact_decode']['actual_export_manifest_cases']==5 and helper_result['artifact_decode']['all_passed']is True
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
    # OUT contains reviewed public-source/check output only. Raw node and Git transport logs live PRIVATE.
    names={'hosted-result.json','host-admission.json','early-or-runtime-failure.json','workflow-clock.json','packet-input-identity.json','source-identity.json','canonical-tag-set-proof.json','derived-image-identity.json','apt-closure.json','apt-official-sources-before.json','apt-resolved-before-download.json','apt-parser-setup-fixtures.json','apt-download-inventory.json','apt-install-delta.json','result.json','seo-suite.json','light-suite.json','mechanics.json','oracle-fixtures.json','actual-elf.json','actual-release-input.json','actual-checksum-controls.json','node-exit.json','node-log-summary.json','offline-network.json','network-fixture.json','g0-fixture.json','initial-source-manifest.json','final-source-manifest.json','actual-site-output-hashes.json','required-failures.json'}
    labels=['version-python']+['version-'+x for x in ['git','curl','bash','awk','sort','jq']]+['actual-tags','actual-cargo-version','initial-head','initial-tracked-status','initial-tracked','final-head','final-tracked-status','final-tracked','final-whitespace','binary-version','original-five-doc-example','deployment-sitemap']+['seo-'+f'{i:02d}'for i in range(19)]+['light-'+f'{i:02d}'for i in range(9)]+['apt-'+x for x in ['signed-update','resolve-uris','download-only','offline-install','jq-version','inventory-before','inventory-after']]+['apt-'+kind+'-'+pkg for kind in ['metadata','deb-control','installed']for pkg in ['jq','libjq1','libonig5']]
    names|={label+suffix for label in labels for suffix in ['.json','.stdout','.stdout.stderr']}
    names|={'apt-license-'+pkg+'.txt'for pkg in ['jq','libjq1','libonig5']}
    for label in ['fixture-bootstrap','fixture-target']:
        names.add(label+'-host-helper-fixtures.json')
        names|={label+'/'+n for n in ['helper-fixtures.json','helper-fixtures-resources.json','helper-fixtures-failure.json']}
    names|={label+'-'+kind+'.json'for label in ['fixture-bootstrap','target']for kind in ['image-identity','registry-HEAD']}
    for label in ['g0','fetch','offline','network-check','helper-fixtures']:
        names|={label+'-'+kind+'.json'for kind in ['resources','failure']}
    names|={n+'-stopped.json'for n in OWNED}
    names|={archive_guard_name+'.receipt.json'for archive_guard_name in [PLAN['archive_name'],PLAN['archive_name']+'.sha256']}
    names|={prefix+suffix for prefix in ['corpus','leg-0','leg-1','hybrid-default','hybrid-unequal','hybrid-custom-k','hybrid-zero-keyword']for suffix in ['-request.json','-raw.json','-failure.json']}
    actual={p.relative_to(OUT).as_posix()for p in OUT.rglob('*')if p.is_file()}
    limit(actual<=names,'UNEXPECTED_EVIDENCE_FILE_REFUSED_BEFORE_EXPORT')
    required={'hosted-result.json','host-admission.json'}
    result=json.loads((OUT/'hosted-result.json').read_text())
    if result.get('full_validation'):
        required|={'result.json','seo-suite.json','light-suite.json','mechanics.json','oracle-fixtures.json','actual-elf.json','actual-release-input.json','actual-checksum-controls.json','node-exit.json','node-log-summary.json','offline-network.json','g0-fixture.json','initial-source-manifest.json','final-source-manifest.json','actual-site-output-hashes.json','required-failures.json','apt-closure.json','apt-resolved-before-download.json','apt-download-inventory.json','apt-install-delta.json','apt-parser-setup-fixtures.json','derived-image-identity.json','source-identity.json','canonical-tag-set-proof.json','packet-input-identity.json','workflow-clock.json','target-image-identity.json','fixture-bootstrap-image-identity.json','target-registry-HEAD.json','fixture-bootstrap-registry-HEAD.json','fixture-bootstrap-host-helper-fixtures.json','fixture-target-host-helper-fixtures.json'}
        for label in ['seo-'+f'{i:02d}'for i in range(19)]+['light-'+f'{i:02d}'for i in range(9)]:
            required|={label+'.json',label+'.stdout',label+'.stdout.stderr'}
        required|={prefix+suffix for prefix in ['corpus','leg-0','leg-1','hybrid-default','hybrid-unequal','hybrid-custom-k','hybrid-zero-keyword']for suffix in ['-request.json','-raw.json']}
        required|={label+suffix for label in ['original-five-doc-example','binary-version','version-python']for suffix in ['.json','.stdout','.stdout.stderr']}
        required|={label+suffix for label in ['apt-resolve-uris','apt-inventory-before','apt-inventory-after']+['apt-'+kind+'-'+pkg for kind in ['metadata','deb-control','installed']for pkg in ['jq','libjq1','libonig5']]for suffix in ['.stdout','.stdout.stderr']}
        required|={'apt-license-'+pkg+'.txt'for pkg in ['jq','libjq1','libonig5']}
        required|={PLAN['archive_name']+'.receipt.json',PLAN['archive_name']+'.sha256.receipt.json'}
        required|={n+'-stopped.json'for n in OWNED}
        required|={label+'/helper-fixtures.json'for label in ['fixture-bootstrap','fixture-target']}
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
        tag='xerj3016-g0-apt:'+RUN
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
    limit(PLAN['runtime_attempt']==2 and PLAN['ordinary_consumed_before']==1 and PLAN['runtime_consumed_before']==1 and PLAN['ordinary_limit']==2,'EXACT_SECOND_ORDINARY_ATTEMPT_NO_RESET')
    limit(RUN.isdigit()and int(RUN)>0,'RUN_NAMESPACE_REQUIRED')
    ROOT.mkdir(exist_ok=False);OUT.mkdir();PRIVATE.mkdir(mode=0o700)
    result={'status':'INCOMPLETE','full_validation':False};START=time.time()
    save(OUT/'host-admission.json',{'state':'IDENTITY_NOT_YET_ADMITTED','runtimeAttempt':2,'priorRuntimeAttempts':1})
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
        save(ROOT/'attempt-ledger.json',{'workflowOrigin':START,'target':SOFT,'hard':END,'runtimeAttempt':2,'ordinaryLimit':2,'priorConsumed':1,'noRetry':True,'earlierClosedAPIStagesUnchanged':True})
        memory={k:int(v)*1024 for k,v in re.findall(r'^(MemTotal|MemAvailable):\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)}
        limit(memory['MemTotal']>=12*1024**3 and memory['MemAvailable']>=10*1024**3,'ACTUAL_HOST_MEMORY_ADMISSION')
        cgroups=finite_host_limits();limit(len(os.sched_getaffinity(0))>=2,'ACTUAL_TWO_CPU_ADMISSION')
        limit(shutil.disk_usage(ROOT).free>=DISK_INITIAL,'ACTUAL_HOST_DISK_ADMISSION')
        docker=json.loads(run('actual-docker-info',['docker','info','--format','{{json .}}']))
        limit(bool(docker.get('ServerVersion'))and docker.get('NCPU',0)>=2 and docker.get('MemTotal',0)>=12*1024**3,'REAL_DOCKER_SERVER_CAPACITY_NOT_EXIT0_ONLY')
        # Exclusive project runtime preflight: do not interfere with unrelated or scheduled workloads.
        active=run('actual-running-containers',['docker','ps','--format','{{.ID}}']).strip();limit(not active,'UNPRICED_ACTIVE_DOCKER_WORKLOAD_HOLD')
        DOCKER_ROOT=Path(docker['DockerRootDir']);limit(DOCKER_ROOT.is_absolute()and DOCKER_ROOT.is_dir()and shutil.disk_usage(DOCKER_ROOT).free>=DISK_INITIAL,'ACTUAL_DOCKER_DATA_DISK')
        DRIVER_STATUS=docker['DriverStatus'];save(OUT/'host-admission.json',{'state':'ACTUAL_REMOTE_G0_ADMITTED','memory':memory,'cgroupAncestors':cgroups,'cpuAffinity':sorted(os.sched_getaffinity(0)),'dockerServer':docker['ServerVersion'],'dockerNCPU':docker['NCPU'],'dockerRAM':docker['MemTotal'],'hostFreeDisk':shutil.disk_usage(ROOT).free,'dockerFreeDisk':shutil.disk_usage(DOCKER_ROOT).free,'diskForecastNotMeasuredUnpacked':True,'minimumDisk':DISK_INITIAL,'exclusiveRunningContainers':0,'remoteNotMac':True})
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
        save(OUT/'source-identity.json',{'pin':PLAN['pin'],'tree':tree,'fullHistory':True,'noPartialClone':True,'noCandidatePatchApplied':True,'expectedTrackedPaths':3697,'expectedTrackedBytes':235549390})
        downloads=ROOT/'downloads';downloads.mkdir();os.chmod(downloads,0o700)
        name=create('validation','8g',['type=bind,src='+str(SOURCE)+',dst=/repo','type=bind,src='+str(downloads)+',dst=/downloads'],network='bridge')
        phase(name,'g0');run('fixture-disconnect',['docker','network','disconnect','bridge',name]);phase(name,'network-check');run('fixture-reconnect',['docker','network','connect','bridge',name]);phase(name,'fetch');run('final-disconnect',['docker','network','disconnect','bridge',name]);phase(name,'offline')
        result=json.loads((OUT/'result.json').read_text());limit(result['state']=='PASS_UNMODIFIED_G0_FULL_SCOPE','FULL_G0_RESULT');result['full_validation']=True
    except BaseException as exc:
        result={'status':'FAILED_NO_RETRY','kind':type(exc).__name__,'step':STEP,'full_validation':False}
        save(OUT/'early-or-runtime-failure.json',{'kind':type(exc).__name__,'message':str(exc)[:512],'identity':{k:os.environ.get(k)for k in ['GITHUB_RUN_ID','GITHUB_RUN_NUMBER','GITHUB_RUN_ATTEMPT','GITHUB_REF','GITHUB_SHA','GITHUB_EVENT_NAME','GITHUB_ACTOR']},'projectValidationComplete':False})
        print('XERJ G0 stopped: '+type(exc).__name__,flush=True)
    finally:
        stops={}
        for name in OWNED:
            try:stops[name]=not stop(name)['Running']
            except BaseException:stops[name]=False
        result.update(ownedStops=stops,stopVerified=all(stops.values()),workflowSeconds=time.time()-START,runtimeAttempt=2,priorRuntimeConsumed=1,rawNodeLogUploaded=False,containersDeleted=False)
        save(OUT/'hosted-result.json',result)
        try:public_artifacts()
        except BaseException:
            result['full_validation']=False;result['exportFailure']=True;save(OUT/'hosted-result.json',result);fallback_export(OUT,ROOT/'public-evidence-minimal');raise
    limit(result['full_validation']and result['stopVerified'],'G0_NOT_COMPLETE')

if __name__=='__main__':main()
