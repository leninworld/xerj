"""Owned writable root setup ONLY, before offline product tests; never a host install."""
from pathlib import Path
import hashlib,json,os,re,subprocess,time
from bounded import command
O=Path('/out');HARD=float(os.environ['VALIDATION_HARD_DEADLINE']);TARGET=float(os.environ['VALIDATION_TARGET_DEADLINE']);START=time.time();ORIGINAL_APT_END=min(TARGET,HARD-180,START+180);END=ORIGINAL_APT_END-6
def guard():
 if time.time()>=min(END,HARD-180):raise TimeoutError('SIGNED_APT_SETUP_ORIGINAL_CLOCK')
def run(name,args,seconds=45):
 budget=min(seconds,ORIGINAL_APT_END-time.time())
 if budget<=6:raise TimeoutError('APT_PER_STEP_REAP_RESERVE')
 return command(args,budget-6,2*1024**2,guard=guard,log=O/('apt-'+name+'.stdout'))
def save(n,d):(O/n).write_text(json.dumps(d,indent=2)+'\n')
assert os.getuid()==0 and Path('/etc/os-release').read_text().find('bookworm')>=0
sources=[]
for p in [Path('/etc/apt/sources.list'),*Path('/etc/apt/sources.list.d').glob('*')]:
 if p.is_file():
  text=p.read_text();assert not any(x in text.lower()for x in ['trusted=yes','allow-insecure','allow-weak']);sources.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'content':text})
assert sources
keyring=Path('/usr/share/keyrings/debian-archive-keyring.gpg');assert keyring.is_file()
save('apt-official-sources-before.json',{'files':sources,'keyringSHA256':hashlib.sha256(keyring.read_bytes()).hexdigest(),'noNewRepositoryOrKey':True})
opts=['-o','APT::Update::Error-Mode=any','-o','Acquire::Retries=0','-o','Acquire::http::Timeout=15','-o','Acquire::https::Timeout=15','-o','Acquire::AllowInsecureRepositories=false','-o','APT::Get::AllowUnauthenticated=false']
run('signed-update',['apt-get',*opts,'update'],60)
uris=run('resolve-uris',['apt-get',*opts,'--print-uris','--yes','--no-install-recommends','install','jq']).decode()
packages=[]
for line in uris.splitlines():
 m=re.fullmatch(r"'([^']+)' (\S+) (\d+) (\S+)",line)
 if not m:continue
 uri,name,size,digest=m.groups();assert uri.startswith(('http://deb.debian.org/debian/','https://deb.debian.org/debian/','http://deb.debian.org/debian-security/','https://deb.debian.org/debian-security/'))
 assert '/'not in name and name.endswith('.deb');parts=name.split('_');assert len(parts)==3
 pkg,version,arch=parts;arch=arch[:-4];assert pkg in {'jq','libjq1','libonig5'}and arch=='arm64'
 meta=run('metadata-'+pkg,['apt-cache','show',pkg+'='+version]).decode();blocks=[dict(line.split(': ',1)for line in block.splitlines()if ': 'in line and not line.startswith(' '))for block in meta.strip().split('\n\n')];matches=[b for b in blocks if b.get('Package')==pkg and b.get('Architecture')==arch and b.get('Version')==version];assert len(matches)==1
 b=matches[0];assert int(b['Size'])==int(size)and re.fullmatch('[0-9a-f]{64}',b['SHA256']);packages.append({'uri':uri,'filename':name,'bytes':int(size),'name':pkg,'version':version,'architecture':arch,'sha256':b['SHA256']})
assert 0<len(packages)<=8 and sum(p['bytes']for p in packages)<=64*1024**2
save('apt-resolved-before-download.json',{'packages':packages,'totalBytes':sum(p['bytes']for p in packages),'signedIndexValidatedByAPT':True,'noRetry':True})
run('download-only',['apt-get',*opts,'--download-only','--yes','--no-install-recommends','install','jq'],60)
for row in packages:
 p=Path('/var/cache/apt/archives')/row['filename'];assert p.is_file()and not p.is_symlink()and p.stat().st_size==row['bytes']and hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256']
 control=run('deb-control-'+row['name'],['dpkg-deb','-W','--showformat=${Package}\n${Version}\n${Architecture}\n',str(p)]).decode().splitlines();assert control==[row['name'],row['version'],row['architecture']]
run('offline-install',['apt-get',*opts,'--no-download','--yes','--no-install-recommends','install','jq'],60)
installed=[]
for row in packages:
 actual=run('installed-'+row['name'],['dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\n',row['name']]).decode().strip().split('\t');assert actual==[row['name'],row['version'],row['architecture']];installed.append(dict(name=actual[0],version=actual[1],architecture=actual[2]))
licenses=[]
for row in packages:
 p=Path('/usr/share/doc')/row['name']/'copyright';assert p.is_file();b=p.read_bytes();assert len(b)<=1048576;(O/('apt-license-'+row['name']+'.txt')).write_bytes(b);licenses.append({'name':row['name'],'copyrightSHA256':hashlib.sha256(b).hexdigest()})
version=run('jq-version',['jq','--version']).decode().strip();assert version.startswith('jq-')
assert time.time()<=ORIGINAL_APT_END,'APT_WHOLE_SETUP_180_SECOND_BOUND'
save('apt-closure.json',{'state':'SIGNED_OFFICIAL_BOOKWORM_JQ_PRETEST_SETUP','packages':packages,'actualInstalled':installed,'actualElapsedSeconds':time.time()-START,'cleanupReapReserveSeconds':6,'licenses':licenses,'jqVersion':version,'secondsCap':180,'downloadCap':64*1024**2,'noHostInstall':True,'noProjectTestsDuringSetup':True})
