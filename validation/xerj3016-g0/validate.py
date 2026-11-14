"""PRIVATE DISABLED G0; executes only inside the separately reviewed owned Linux container."""
from __future__ import annotations
import hashlib,json,math,os,pathlib,platform,re,shutil,struct,subprocess,sys,tempfile,threading,time,urllib.request,urllib.error
import archive_guard
from bounded import command
if sys.flags.optimize: raise RuntimeError('OPTIMIZATION_NOT_ALLOWED')
OUT=pathlib.Path('/out');REPO=pathlib.Path('/repo');BASE='http://127.0.0.1:9200'
PIN='50e4ffded5518b1822cfac5450fa34d3829ab8ab'
DEADLINE=float(os.environ['VALIDATION_HARD_DEADLINE']);TARGET=float(os.environ['VALIDATION_TARGET_DEADLINE'])
def save(name,value):
 (OUT/name).write_text(json.dumps(value,indent=2)+'\n')
def run(name,argv,cwd=REPO,seconds=180,check=True):
 if time.time()>=TARGET:raise TimeoutError('NO_NEW_STEP_AFTER_ORIGINAL_TARGET')
 left=min(seconds,TARGET-time.time(),DEADLINE-time.time()-180)
 if left<=6:raise TimeoutError('CLEANUP_AND_REAP_RESERVE')
 start=time.monotonic();record={'argv':argv,'complete':False}
 try:
  command(argv,left-6,2*1024**2,cwd=cwd,log=OUT/(name+'.stdout'))
  record.update(exit=0,complete=True)
 except RuntimeError as e:
  m=re.match(r'command exit (-?\d+), expected 0:',str(e))
  if m is None:raise
  record.update(exit=int(m[1]),complete=True)
  if check:raise
 finally:
  record['seconds']=time.monotonic()-start;save(name+'.json',record)
 return record


def elf_check(path):
    size=path.stat().st_size
    with path.open('rb') as f:
        h=f.read(64)
        if len(h)!=64 or h[:6]!=b'\x7fELF\x02\x01': raise ValueError('Not ELF64 little-endian')
        typ,machine=struct.unpack_from('<HH',h,16)
        if typ not in (2,3) or machine!=183: raise ValueError('Wrong ELF architecture/type')
        off=struct.unpack_from('<Q',h,32)[0]
        ent,num=struct.unpack_from('<HH',h,54)
        if ent!=56 or not 0<num<=128 or off+ent*num>size: raise ValueError('ELF program table')
        load=False
        for n in range(num):
            f.seek(off+n*ent);p=struct.unpack('<IIQQQQQQ',f.read(ent))
            if p[2]+p[5]>size: raise ValueError('ELF segment bounds')
            if p[0]==1:load=True
            if p[0]==3:raise ValueError('Dynamic interpreter not admitted')
            if p[0]==2:
                if p[5]%16 or p[5]>16384:raise ValueError('Dynamic table bounds')
                f.seek(p[2])
                for unused in range(p[5]//16):
                    tag,val=struct.unpack('<QQ',f.read(16))
                    if tag==1:raise ValueError('DT_NEEDED not admitted')
                    if tag==0:break
        if not load:raise ValueError('No PT_LOAD')
    return {'ELF64':True,'machine':'AArch64','PT_INTERP':False,'DT_NEEDED':False,'bytes':size}

def elf_fixture():
    root=pathlib.Path(tempfile.mkdtemp(prefix='xerj3016-elf-'))
    for name,machine,kinds,ok in [('static',183,[1],True),('wrong-arch',62,[1],False),
                                 ('interpreter',183,[1,3],False),('needed',183,[1,2],False)]:
        length=64+56*len(kinds)+32
        b=bytearray(length);b[:6]=b'\x7fELF\x02\x01'
        struct.pack_into('<HH',b,16,2,machine);struct.pack_into('<Q',b,32,64)
        struct.pack_into('<HH',b,54,56,len(kinds))
        for n,kind in enumerate(kinds):
            pos=64+56*len(kinds)
            struct.pack_into('<IIQQQQQQ',b,64+56*n,kind,5,0 if kind==1 else pos,0,0,
                             length if kind==1 else 32,length,4096)
            if kind==2:struct.pack_into('<QQQQ',b,pos,1,1,0,0)
        p=root/name;p.write_bytes(b)
        try:elf_check(p)
        except ValueError:
            if ok:raise
        else:
            if not ok:raise AssertionError(name)
    return {'synthetic_ELF_cases':4,'binary_executed':False}

def offline():
    interfaces={p.name:(p/'operstate').read_text().strip() for p in pathlib.Path('/sys/class/net').iterdir()}
    assert 'lo' in interfaces
    fallback={'tunl0','gre0','gretap0','erspan0','sit0','ip6tnl0','ip6gre0','ip_vti0','ip6_vti0'}
    non_loopback={name:state for name,state in interfaces.items() if name!='lo'}
    assert all(name in fallback and state=='down' for name,state in non_loopback.items()),interfaces
    routes=pathlib.Path('/proc/net/route').read_text().splitlines()
    assert all(line.split()[1]!='00000000' for line in routes[1:]),routes
    v6=pathlib.Path('/proc/net/ipv6_route')
    if v6.exists():
        for line in v6.read_text().splitlines():
            fields=line.split();assert len(fields)>=10
            assert not(fields[0]=='0'*32 and fields[1]=='00' and fields[-1]!='lo'),line
    return {'interfaces':interfaces,'non_loopback':non_loopback,'IPv4_default_routes':0,
            'IPv6_non_loopback_default_routes':0,'IPv6_route_file_present':v6.exists()}

def node_log_summary(source):
    hasher=hashlib.sha256();byte_count=0;newlines=0;last=b'';carry=b''
    patterns=(b'panic',b'ERROR',b'bind',b'OOM')
    counts={p.decode():0 for p in patterns}
    with source.open('rb') as stream:
        for block in iter(lambda:stream.read(65536),b''):
            hasher.update(block);byte_count+=len(block);newlines+=block.count(b'\n')
            for pattern in patterns:
                counts[pattern.decode()]+=(carry+block).count(pattern)-carry.count(pattern)
            carry=(carry+block)[-4:];last=block[-1:]
    return ({'bytes':byte_count,
        'lines':newlines+int(bool(last) and last!=b'\n'),
        'sha256':hasher.hexdigest(),'literal_case_sensitive_occurrences':counts,
        'raw_lines_exported':False,'raw_log_destroyed_with_hosted_VM':True})

def helper_fixtures():
    root=pathlib.Path(tempfile.mkdtemp(prefix='xerj3016-privacy-fixture-'))
    cases=[b'',b'last line',b'line\n',b'X'*65534+b'ERROR\n'+b'panic bind OOM\nSYNTHETIC_CREDENTIAL_DO_NOT_EXPORT']
    for n,data in enumerate(cases):
        path=root/str(n);path.write_bytes(data);summary=node_log_summary(path)
        assert summary['bytes']==len(data)
        assert summary['sha256']==hashlib.sha256(data).hexdigest()
        assert summary['lines']==data.count(b'\n')+int(bool(data) and not data.endswith(b'\n'))
        for token in (b'panic',b'ERROR',b'bind',b'OOM'):
            assert summary['literal_case_sensitive_occurrences'][token.decode()]==data.count(token)
        assert 'SYNTHETIC_CREDENTIAL_DO_NOT_EXPORT' not in json.dumps(summary)
    import registry,artifacts,artifact_decode,identity,mechanics,apt_closure
    apt_parser_fixture=apt_closure.fixture()
    assert apt_parser_fixture['state']=='PASS'and apt_parser_fixture['capturedRows']==3 and len(apt_parser_fixture['negativeControls'])==14
    early_oracle=mechanics.fixture()
    assert early_oracle['state']=='PASS'and len(early_oracle['negativeControls'])==9
    decoded_fixture=artifact_decode.fixture()
    assert decoded_fixture['actual_zip_cases']==10 and decoded_fixture['actual_export_manifest_cases']==5 and decoded_fixture['all_passed']is True
    from bounded import command,save as bounded_save
    if sys.version_info[:3] not in ((3,12,15),(3,12,16)) or platform.machine()!='aarch64':
        raise RuntimeError('FIXTURE_INPUT_VERSION_ARCHITECTURE')
    tool_versions={}
    if sys.version_info[:3]==(3,12,16):
        for tool in ('git','curl','bash'):
            tool_versions[tool]=command([tool,'--version'],10,65536).decode().splitlines()[0]
    log=root/'bounded.log'
    value=command([sys.executable,'-c','import sys,json;print(json.dumps({"ok":True}));print("warning",file=sys.stderr)'],10,65536,log=log)
    assert json.loads(value)=={'ok':True} and (root/'bounded.log.stderr').read_bytes()==b'warning\n'
    try:
        command([sys.executable,'-c','import sys;sys.stderr.write("x"*4096)'],10,1024)
    except OverflowError as exc:
        assert str(exc)=='command output limit'
    else:
        raise AssertionError('STDERR_CAP_NOT_ENFORCED')
    destination=root/'save-link';destination.symlink_to(root/'0')
    original=(root/'0').read_bytes()
    try:
        bounded_save(destination,{'unsafe':True})
    except OSError:
        assert (root/'0').read_bytes()==original
    else:
        raise AssertionError('SAVE_SYMLINK_NOT_REFUSED')
    return {'privacy_cases':len(cases),'archive':archive_guard.fixture(),'elf':elf_fixture(),
            'registry':registry.fixture(),'artifacts':artifacts.fixture(),'artifact_decode':decoded_fixture,'identity':identity.fixture(),'oracle':early_oracle,'aptClosure':apt_parser_fixture,'bounded':{'actual_cases':3},
            'input_identity':{'role':'BOOTSTRAP_HARNESS_ONLY_NOT_PRODUCT' if sys.version_info[:3]==(3,12,15) else 'EXACT_TARGET_REPEAT',
                              'Python':sys.version,'architecture':platform.machine(),'tool_versions':tool_versions},
            'Python':sys.version,'architecture':platform.machine(),'raw_log_lines_exported':False}

SEO=[['python3','scripts/seo/'+n]for n in ['test_article_schema.py','test_urlmap.py','test_verify_live.py','test_verify_agent_discovery.py','test_audit_dates.py','test_llms_field_report.py','test_llms_facts_wait_loop.py','test_build_skills.py']]+[
 ['python3','scripts/seo/'+n,'--check']for n in ['build_skills.py','build_articles.py','gen_sitemap.py','fix_heads.py','fix_links.py','mk_og_card.py']]+[
 ['python3','scripts/seo/seo_lint.py'],['python3','scripts/seo/factcheck.py','--self-test'],['python3','scripts/seo/factcheck.py','--fixture-check'],['python3','scripts/seo/factcheck.py','--fail-on','error'],['python3','scripts/seo/audit.py','--root','landing','--fail-on','critical','--max-findings','99']]
LIGHT=[['bash','scripts/ci/change_scope.sh'],['bash','scripts/ci/test_change_scope.sh'],['bash','.github/scripts/landing-constants-guard.sh'],['python3','tools/agents/gen_cohere_tools.py','--check'],['python3','.github/scripts/workflow-timeout-guard.py','--self-test'],['python3','.github/scripts/workflow-timeout-guard.py'],['python3','scripts/test_cla_coauthors.py'],['jq','-e','type == "array" and all(.[]; type == "string")','.contributors'],['jq','-e','index("dependabot[bot]") != null','.contributors']]

def source_snapshot(label):
 run(label+'-head',['git','rev-parse','HEAD']);assert (OUT/(label+'-head.stdout')).read_text().strip()==PIN
 run(label+'-tracked-status',['git','status','--porcelain','--untracked-files=no']);assert not (OUT/(label+'-tracked-status.stdout')).read_bytes()
 run(label+'-tracked',['git','ls-files','--stage','-z'],seconds=60)
 rows=[]
 for entry in (OUT/(label+'-tracked.stdout')).read_bytes().split(b'\0'):
  if not entry:continue
  meta,rel=entry.split(b'\t',1);mode,oid,stage=meta.split();assert stage==b'0'
  p=REPO/os.fsdecode(rel)
  if mode==b'120000':b=os.readlink(p).encode()
  else:
   assert mode in (b'100644',b'100755') and p.is_file()and not p.is_symlink();b=p.read_bytes()
  actual=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest();assert actual==oid.decode()
  rows.append({'path':os.fsdecode(rel),'mode':mode.decode(),'oid':actual,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
 assert len(rows)==3697 and sum(r['bytes']for r in rows)==235549390
 save(label+'-source-manifest.json',rows);return rows

def g0():
 assert sys.version_info[:3]==(3,12,16)and platform.machine()=='aarch64'
 assert pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip()==str(8*1024**3)
 assert pathlib.Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()=='0'
 assert pathlib.Path('/sys/fs/cgroup/pids.max').read_text().strip()=='4096'
 assert len(os.sched_getaffinity(0))==2
 assert shutil.disk_usage('/work').free>=5*1024**3
 versions={}
 run('version-python',[sys.executable,'-VV']);versions['python']=(OUT/'version-python.stdout').read_text().strip();assert versions['python']
 for tool in ['git','curl','bash','awk','sort','jq']:
  run('version-'+tool,[tool,'-W','version']if tool=='awk'else[tool,'--version']);text=(OUT/('version-'+tool+'.stdout')).read_text()+(OUT/('version-'+tool+'.stdout.stderr')).read_text();assert text.strip();versions[tool]=text.splitlines()[0]
 tagproof=json.loads((OUT/'canonical-tag-set-proof.json').read_text());assert tagproof['allCanonicalTagsMatch']and tagproof['rc102Commit']=='cfdea42205816052cf4b5aaf4b395739f32c948b'
 run('actual-tags',['git','tag','--list','v1.0.0-rc.*']);tags=(OUT/'actual-tags.stdout').read_text().splitlines();assert 'v1.0.0-rc.102'in tags
 run('actual-cargo-version',['git','show','HEAD:engine/Cargo.toml']);assert (OUT/'actual-cargo-version.stdout').read_bytes()
 save('g0-fixture.json',{'xmllintAvailable':shutil.which('xmllint')is not None,'optionalXmllintNotClaimedIfAbsent':True,'archive':archive_guard.fixture(),'elf':elf_fixture(),'Python':sys.version,'versions':versions,'tagBranchNotSilentlySkipped':True})
 source_snapshot('initial')

class Redirects(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  from urllib.parse import urlsplit
  u=urlsplit(newurl)
  if u.scheme!='https'or u.hostname not in {'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}:raise ValueError('UNAPPROVED_ASSET_REDIRECT')
  return super().redirect_request(req,fp,code,msg,headers,newurl)

def fetch():
 opener=urllib.request.build_opener(Redirects());downloads=pathlib.Path('/downloads');downloads.mkdir(exist_ok=True)
 for name,size in [(archive_guard.ARCHIVE_NAME+'.sha256',118),(archive_guard.ARCHIVE_NAME,33666646)]:
  url='https://github.com/xerj-org/xerj/releases/download/v1.0.0-rc.102/'+name
  p=downloads/name;assert not p.exists();n=0;h=hashlib.sha256();stop=min(TARGET,time.time()+180)
  with opener.open(urllib.request.Request(url,headers={'User-Agent':'XERJ-private-G0-validation'}),timeout=20)as r,p.open('xb')as f:
   while True:
    if time.time()>=stop:raise TimeoutError('ORIGINAL_ASSET_DEADLINE')
    b=r.read(min(65536,size-n+1))
    if not b:break
    n+=len(b);assert n<=size;f.write(b);h.update(b)
  assert n==size;save(name+'.receipt.json',{'officialURL':url,'bytes':n,'actualSHA256':h.hexdigest(),'sourceTag':'v1.0.0-rc.102','checksumAuthenticity':'publisher HTTPS sidecar; no preinvented checksum'})
 # Archive verification here is data-only and repeats before execution offline.
 checksum=(downloads/(archive_guard.ARCHIVE_NAME+'.sha256')).read_text().strip().split()
 assert len(checksum)==2 and re.fullmatch('[0-9a-f]{64}',checksum[0])and checksum[1].lstrip('*')==archive_guard.ARCHIVE_NAME
 assert hashlib.sha256((downloads/archive_guard.ARCHIVE_NAME).read_bytes()).hexdigest()==checksum[0]
 save('actual-release-input.json',{'archive':archive_guard.ARCHIVE_NAME,'archiveSHA256':checksum[0],'checksumSHA256':hashlib.sha256((downloads/(archive_guard.ARCHIVE_NAME+'.sha256')).read_bytes()).hexdigest(),'publisherChecksumMatched':True})

def request(method,path,body=None,status=200):
 if time.time()>=min(TARGET,DEADLINE-180):raise TimeoutError('HTTP_ORIGINAL_CLOCK')
 data=None if body is None else json.dumps(body).encode()
 req=urllib.request.Request(BASE+path,data=data,method=method,headers={'Content-Type':'application/json'})
 try:
  with urllib.request.urlopen(req,timeout=min(20,max(1,TARGET-time.time())))as r:code=r.status;raw=r.read(1048577)
 except urllib.error.HTTPError as e:code=e.code;raw=e.read(1048577)
 assert len(raw)<=1048576 and code==status,(method,path,code)
 return json.loads(raw)

DOCS=[('d1','Reset your password',[1.,.15,0.,.1]),('d2','Regain entry to a locked-out account',[.95,.1,0.,.15]),('d3','Password complexity and rotation policy',[.15,1.,0.,.1]),('d4','How to bake sourdough bread',[0.,0.,1.,.1]),('d5','Change your account password',[.85,.25,0.,.2])]
QUERY_VEC=[1.,.2,0.,.1]
LEG0={'match':{'title':'reset password'}}
LEG1={'knn':{'field':'vec','query_vector':QUERY_VEC,'k':3}}




def validate():
 import mechanics
 save('offline-network.json',offline());oracle_fixture=mechanics.fixture();assert oracle_fixture['state']=='PASS'and len(oracle_fixture['negativeControls'])==9;save('oracle-fixtures.json',oracle_fixture)
 binary,expanded=archive_guard.verify_and_extract(pathlib.Path('/downloads')/archive_guard.ARCHIVE_NAME,pathlib.Path('/downloads')/(archive_guard.ARCHIVE_NAME+'.sha256'),pathlib.Path('/work/unpacked'))
 save('actual-checksum-controls.json',archive_guard.actual_checksum_controls(pathlib.Path('/downloads')/archive_guard.ARCHIVE_NAME,pathlib.Path('/downloads')/(archive_guard.ARCHIVE_NAME+'.sha256'),pathlib.Path('/work/checksum-controls')))
 save('actual-elf.json',elf_check(binary));run('binary-version',[str(binary),'--version'],cwd=pathlib.Path('/work'),seconds=20)
 version=(OUT/'binary-version.stdout').read_text().splitlines()[0].strip();assert re.fullmatch(r'xerj(?:\s+v?)?1\.0\.0-rc\.102(?:[ -][^\r\n]+)?',version),version
 node=None;log=None;failures=[]
 try:
  log=pathlib.Path('/private-evidence/node.log').open('xb');os.chmod(log.name,0o600)
  node=subprocess.Popen([str(binary),'--insecure','--data-dir','/work/data'],cwd='/work',stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  stop=min(TARGET,time.time()+60)
  while True:
   if node.poll()is not None:raise RuntimeError('OWNED_NODE_EARLY_EXIT_RAW_LOG_PRIVATE')
   try:request('GET','/_cluster/health');break
   except(urllib.error.URLError,ConnectionError,AssertionError):
    if time.time()>=stop:raise TimeoutError('OWNED_NODE_READINESS')
    time.sleep(.25)
  mechanics.run(REPO,OUT,run,request)
  results=[]
  assert len(SEO)==19
  for i,argv in enumerate(SEO):
   rec=run(f'seo-{i:02d}',argv,seconds=300,check=False);results.append(rec)
   if rec['exit']!=0:failures.append({'section':'SEO','index':i,'exit':rec['exit']})
  save('seo-suite.json',results)
  results=[]
  for i,argv in enumerate(LIGHT):
   rec=run(f'light-{i:02d}',argv,seconds=180,check=False);results.append(rec)
   if rec['exit']!=0:failures.append({'section':'light','index':i,'exit':rec['exit']})
  save('light-suite.json',results)
  run('deployment-sitemap',['python3','scripts/seo/gen_sitemap.py','--write'],seconds=120)
  rows=[]
  for f in sorted((REPO/'landing').rglob('*')):
   if f.is_file()and not f.is_symlink():
    b=f.read_bytes();rows.append({'path':f.relative_to(REPO).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
  save('actual-site-output-hashes.json',rows)
  initial=json.loads((OUT/'initial-source-manifest.json').read_text());assert source_snapshot('final')==initial
  run('final-whitespace',['git','diff','--check']);save('required-failures.json',failures)
  assert not failures,'ACTUAL_FULL_SCOPE_CHECK_FAILURES_RETAINED'
  save('result.json',{'state':'PASS_UNMODIFIED_G0_FULL_SCOPE','seoCommands':19,'lightCommands':len(LIGHT),'mechanicsCases':4,'originalFiveDocExample':True,'baselineOnly':True,'candidatePass':False,'sourcePin':PIN,'releaseVersion':version,'fullSiteHashCount':len(rows),'noEngineTestsOrQualityBenchmarkClaim':True})
 finally:
  if node is not None:
   if node.poll()is None:
    os.killpg(node.pid,__import__('signal').SIGTERM)
    try:node.wait(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(node.pid,__import__('signal').SIGKILL);node.wait(timeout=3)
   save('node-exit.json',{'exit':node.returncode,'confirmedReaped':node.poll()is not None,'rawLogsNotUploaded':True})
  if log is not None:log.close();save('node-log-summary.json',node_log_summary(pathlib.Path('/private-evidence/node.log')))

if __name__=='__main__':
 phase=sys.argv[1];done=threading.Event();samples={'maxMemorySampled':0,'maxPidsSampled':0}
 def monitor():
  while not done.is_set():
   for n,k in [('memory.current','maxMemorySampled'),('pids.current','maxPidsSampled')]:
    try:samples[k]=max(samples[k],int(pathlib.Path('/sys/fs/cgroup',n).read_text()))
    except(OSError,ValueError):samples['incomplete']=True
   done.wait(.25)
 watch=threading.Thread(target=monitor,daemon=True);watch.start()
 try:
  {'g0':g0,'fetch':fetch,'offline':validate,'network-check':lambda:save('network-fixture.json',offline()),'helper-fixtures':lambda:save('helper-fixtures.json',helper_fixtures())}[phase]()
 except BaseException as e:save(phase+'-failure.json',{'kind':type(e).__name__,'message':str(e)[:512],'validationComplete':False});raise
 finally:
  done.set();watch.join(timeout=1)
  for n in ['memory.peak','memory.events','pids.events']:
   try:samples[n]=pathlib.Path('/sys/fs/cgroup',n).read_text()
   except OSError:samples[n]='UNAVAILABLE'
  save(phase+'-resources.json',samples)
