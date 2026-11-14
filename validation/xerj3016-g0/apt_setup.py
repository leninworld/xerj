"""Owned bounded signed APT setup; complete captured-plan closure, never host install."""
from pathlib import Path
import hashlib,json,os,time
from bounded import command
import apt_closure
O=Path('/out');HARD=float(os.environ['VALIDATION_HARD_DEADLINE']);TARGET=float(os.environ['VALIDATION_TARGET_DEADLINE']);START=time.time();ORIGINAL_APT_END=min(TARGET,HARD-180,START+180);END=ORIGINAL_APT_END-6

def guard():
 if time.time()>=min(END,HARD-180):raise TimeoutError('SIGNED_APT_SETUP_ORIGINAL_CLOCK')
def run(name,args,seconds=45):
 budget=min(seconds,ORIGINAL_APT_END-time.time())
 if budget<=6:raise TimeoutError('APT_PER_STEP_REAP_RESERVE')
 return command(args,budget-6,2*1024**2,guard=guard,log=O/('apt-'+name+'.stdout'))
def save(name,value):(O/name).write_text(json.dumps(value,indent=2)+'\n')
def package_inventory(label):
 return run(label,['dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n']).decode()

assert os.getuid()==0 and'bookworm'in Path('/etc/os-release').read_text()
os.environ['LC_ALL']='C.UTF-8'
fixtures=apt_closure.fixture();assert fixtures['state']=='PASS'and fixtures['capturedRows']==3
save('apt-parser-setup-fixtures.json',fixtures)
sources=[]
for p in [Path('/etc/apt/sources.list'),*Path('/etc/apt/sources.list.d').glob('*')]:
 if p.is_file():
  text=p.read_text();assert not any(x in text.lower()for x in ['trusted=yes','allow-insecure','allow-weak']);sources.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'content':text})
assert sources
keyring=Path('/usr/share/keyrings/debian-archive-keyring.gpg');assert keyring.is_file()
save('apt-official-sources-before.json',{'files':sources,'keyringSHA256':hashlib.sha256(keyring.read_bytes()).hexdigest(),'noNewRepositoryOrKey':True})
before=package_inventory('inventory-before');apt_closure.inventory(before)
opts=['-o','APT::Update::Error-Mode=any','-o','Acquire::Retries=0','-o','Acquire::http::Timeout=15','-o','Acquire::https::Timeout=15','-o','Acquire::AllowInsecureRepositories=false','-o','APT::Get::AllowUnauthenticated=false']
run('signed-update',['apt-get',*opts,'update'],60)
uris=run('resolve-uris',['apt-get',*opts,'--print-uris','--yes','--no-install-recommends','install','jq']).decode()
rows=apt_closure.parse_plan(uris);packages=[]
for row in rows:
 metadata=run('metadata-'+row['name'],['apt-cache','show',row['name']+'='+row['version']]).decode()
 packages.append(apt_closure.signed_metadata(metadata,row))
assert len(packages)==3 and{r['name']for r in packages}==apt_closure.NAMES
save('apt-resolved-before-download.json',{'packages':packages,'declaredNewNames':sorted(apt_closure.NAMES),'parsedRows':len(packages),'totalBytes':sum(r['bytes']for r in packages),'signedIndexValidatedByAPT':True,'optionalPrintedDigestNotAuthentication':True,'noRetry':True})
cache=Path('/var/cache/apt/archives');assert not list(cache.glob('*.deb')),'UNPRICED_PREEXISTING_DEB_CACHE'
run('download-only',['apt-get',*opts,'--download-only','--yes','--no-install-recommends','install','jq'],60)
assert{p.name for p in cache.glob('*.deb')}=={r['filename']for r in packages},'DOWNLOADED_DEB_INVENTORY_MISMATCH'
archive_inventory=[]
for row in packages:
 p=cache/row['filename'];assert p.is_file()and not p.is_symlink()and p.stat().st_size==row['bytes']
 with p.open('rb')as f:data=f.read(row['bytes']+1)
 apt_closure.verify_archive(row,data)
 control=run('deb-control-'+row['name'],['dpkg-deb','-W','--showformat=${Package}\n${Version}\n${Architecture}\n',str(p)]).decode()
 apt_closure.verify_control(row,control);archive_inventory.append(dict(row,actualSHA256=hashlib.sha256(data).hexdigest(),controlIdentityVerified=True))
save('apt-download-inventory.json',{'allDeclaredArchivesVerified':True,'archives':archive_inventory,'count':len(archive_inventory)})
run('offline-install',['apt-get',*opts,'--no-download','--yes','--no-install-recommends','install','jq'],60)
after=package_inventory('inventory-after');delta=apt_closure.verify_install(before,after,packages);save('apt-install-delta.json',delta)
installed=[];licenses=[]
for row in packages:
 actual=run('installed-'+row['name'],['dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\n',row['name']]).decode().strip().split('\t');assert actual==[row['name'],row['version'],row['architecture']]
 installed.append(dict(name=actual[0],version=actual[1],architecture=actual[2]))
 p=Path('/usr/share/doc')/row['name']/'copyright';assert p.is_file();b=p.read_bytes();assert len(b)<=1048576;(O/('apt-license-'+row['name']+'.txt')).write_bytes(b);licenses.append({'name':row['name'],'copyrightSHA256':hashlib.sha256(b).hexdigest()})
assert{r['name']for r in installed}=={r['name']for r in licenses}==apt_closure.NAMES
version=run('jq-version',['jq','--version']).decode().strip();assert version.startswith('jq-')
assert time.time()<=ORIGINAL_APT_END,'APT_WHOLE_SETUP_180_SECOND_BOUND'
save('apt-closure.json',{'state':'SIGNED_OFFICIAL_BOOKWORM_JQ_PRETEST_SETUP','completeDeclaredPlanVerified':True,'allThreeSignedArchiveControlLicenseInstalledVerified':True,'packages':packages,'actualInstalled':installed,'completeInstallDelta':delta,'actualElapsedSeconds':time.time()-START,'cleanupReapReserveSeconds':6,'licenses':licenses,'jqVersion':version,'secondsCap':180,'downloadCap':64*1024**2,'noHostInstall':True,'noProjectTestsDuringSetup':True})
