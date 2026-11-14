"""Pure complete APT plan/identity checks. Fixtures run only in reviewed Docker phases."""
from pathlib import Path
from urllib.parse import urlsplit,unquote
import copy,hashlib,re
NAMES={'jq','libjq1','libonig5'}

def require(ok,message):
    if not ok:raise ValueError(message)

def parse_plan(text):
    lines=text.splitlines();marker='The following NEW packages will be installed:'
    require(lines.count(marker)==1,'EXACT_NEW_PACKAGE_DECLARATION_REQUIRED')
    start=lines.index(marker)+1;declared=[];summary=None
    for line in lines[start:]:
        m=re.fullmatch(r'(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.',line.strip())
        if m:
            summary=tuple(map(int,m.groups()));break
        require(not line.strip()or line.startswith(' '),'MALFORMED_NEW_PACKAGE_DECLARATION')
        declared.extend(line.split())
    require(summary is not None and summary[:3]==(0,3,0),'UNPRICED_UPGRADE_REMOVAL_OR_NEW_COUNT')
    require(len(declared)==3 and set(declared)==NAMES,'DECLARED_CLOSURE_NOT_EXACT_THREE')
    rows=[]
    for line in lines:
        if not(line.lstrip().startswith("'")or'.deb'in line):continue
        # The final digest is OPTIONAL in real APT output. Its absence is not
        # absence of a package. Authentication uses signed-index SHA256 below.
        m=re.fullmatch(r"'([^']+)'[ \t]+(\S+)[ \t]+(\d+)(?:[ \t]+(\S+))?[ \t]*",line)
        require(m is not None,'MALFORMED_URI_ROW_NOT_SILENTLY_IGNORED')
        uri,filename,size,optional=m.groups();u=urlsplit(uri)
        require(u.scheme in {'http','https'}and u.netloc=='deb.debian.org'and not u.query and not u.fragment and(u.path.startswith('/debian/')or u.path.startswith('/debian-security/')),'NONCANONICAL_OFFICIAL_DEBIAN_URI')
        require('/'not in filename and'\\'not in filename and unquote(u.path.rsplit('/',1)[-1])==filename,'URI_FILENAME_MISMATCH')
        parts=filename.split('_');require(len(parts)==3 and parts[0]in NAMES and parts[2]=='arm64.deb','UNPRICED_PACKAGE_OR_ARCH')
        require(int(size)>0,'NONPOSITIVE_ARCHIVE_SIZE')
        if optional is not None:require(re.fullmatch(r'(?:MD5Sum:[0-9a-f]{32}|SHA256:[0-9a-f]{64})',optional)is not None,'MALFORMED_OPTIONAL_DIGEST')
        rows.append({'uri':uri,'filename':filename,'bytes':int(size),'name':parts[0],'version':parts[1],'architecture':'arm64','optionalAPTPrintDigest':optional})
    require(len(rows)==3 and{r['name']for r in rows}==NAMES,'URI_DECLARATION_CLOSURE_MISMATCH')
    require(len({r['filename']for r in rows})==len(rows)and len({r['uri']for r in rows})==len(rows),'DUPLICATE_URI_OR_ARCHIVE')
    require(sum(r['bytes']for r in rows)<=64*1024**2,'PACKAGE_DOWNLOAD_BOUND')
    return rows

def signed_metadata(text,row):
    blocks=[]
    for block in text.strip().split('\n\n'):
        fields={}
        for line in block.splitlines():
            if not line or line.startswith((' ','\t')):continue
            require(': 'in line,'MALFORMED_SIGNED_METADATA_FIELD');k,v=line.split(': ',1)
            require(k not in fields,'DUPLICATE_SIGNED_METADATA_FIELD');fields[k]=v
        blocks.append(fields)
    matches=[b for b in blocks if all(b.get(k)==row[v]for k,v in [('Package','name'),('Version','version'),('Architecture','architecture')])]
    require(len(matches)==1,'EXACT_SIGNED_PACKAGE_IDENTITY_REQUIRED');b=matches[0]
    require(b.get('Size')==str(row['bytes'])and re.fullmatch('[0-9a-f]{64}',b.get('SHA256',''))is not None,'SIGNED_SIZE_SHA256_REQUIRED')
    relative=urlsplit(row['uri']).path.split('/',2)[2]
    require(unquote(relative)==b.get('Filename'),'SIGNED_FILENAME_URI_MISMATCH')
    return dict(row,sha256=b['SHA256'],signedFilename=b['Filename'])

def verify_archive(row,data):
    require(len(data)==row['bytes']and hashlib.sha256(data).hexdigest()==row['sha256'],'SIGNED_ARCHIVE_SIZE_OR_SHA256_MISMATCH')

def verify_control(row,text):
    require(text.splitlines()==[row['name'],row['version'],row['architecture']],'DEB_CONTROL_IDENTITY_MISMATCH')

def inventory(text):
    result={}
    for line in text.splitlines():
        fields=line.split('\t');require(len(fields)==4,'DPKG_INVENTORY_FIELD_COUNT')
        name,version,arch,status=fields
        require(name and version and arch and status in {'not-installed','config-files','half-installed','unpacked','half-configured','triggers-awaited','triggers-pending','installed'},'UNKNOWN_DPKG_STATUS')
        require(name not in result,'DUPLICATE_INSTALLED_PACKAGE');result[name]=(version,arch,status)
    require(result,'EMPTY_DPKG_INVENTORY');return result

def verify_install(before,after,rows):
    old,new=inventory(before),inventory(after)
    expected={r['name']:(r['version'],r['architecture'],'installed')for r in rows}
    require(set(expected)==NAMES,'INSTALL_EXPECTED_COMPLETE_THREE')
    require(not(set(old)&NAMES),'BASE_HAS_UNPRICED_ALREADY_INSTALLED_CLOSURE')
    require(set(new)-set(old)==NAMES and not(set(old)-set(new)),'UNPRICED_INSTALL_OR_REMOVAL')
    require(all(new[k]==v for k,v in old.items()),'UNPRICED_PREEXISTING_PACKAGE_CHANGE')
    require(all(new[k]==v for k,v in expected.items()),'ACTUAL_INSTALLED_IDENTITY_MISMATCH')
    return {'beforePackageCount':len(old),'afterPackageCount':len(new),'added':expected,'removed':[],'changedExisting':[],'completeDeltaVerified':True}

def fixture():
    source=Path(__file__).with_name('apt-plan-captured-I1.txt');b=source.read_bytes()
    require(len(b)<65536 and hashlib.sha256(b).hexdigest()=='69a2df0a607b02726573fe78b53e9590b6f80d22f801beee9a77ed5dce87895f','EXACT_CAPTURED_FIXTURE_IDENTITY')
    text=b.decode();rows=parse_plan(text)
    require({r['name']for r in rows}==NAMES and sum(r['bytes']for r in rows)==365244,'ACTUAL_CAPTURED_THREE_ROW_POSITIVE')
    blank=re.sub(r'MD5Sum:[0-9a-f]{32}','',text);require(len(parse_plan(blank))==3,'BLANK_OPTIONAL_DIGEST_POSITIVE')
    bad={
      'malformed-uri':text.replace('http://deb.debian.org/debian/pool','http://not-debian.invalid/debian/pool',1),
      'unquoted-uri-row':text.replace("'http://deb.debian.org/debian/pool",'http://deb.debian.org/debian/pool',1),
      'missing-row':'\n'.join(x for x in text.splitlines()if not x.startswith("'http")or' jq_'not in x),
      'duplicate-row':text+'\n'+next(x for x in text.splitlines()if x.startswith("'http")),
      'extra-package':text.replace('  jq libjq1 libonig5','  jq libjq1 libonig5 libc6').replace('0 upgraded, 3 newly','0 upgraded, 4 newly'),
      'malformed-trailing-token':text+'\n'+next(x for x in text.splitlines()if x.startswith("'http"))+' bad-token',
      'upgraded-package':text.replace('0 upgraded, 3 newly','1 upgraded, 3 newly'),
    }
    rejected=[]
    for name,value in bad.items():
        try:parse_plan(value)
        except ValueError:rejected.append(name)
        else:raise ValueError('MUTATION_ACCEPTED:'+name)
    row={'uri':'http://deb.debian.org/debian/pool/main/j/jq/jq_1_arm64.deb','filename':'jq_1_arm64.deb','bytes':3,'name':'jq','version':'1','architecture':'arm64'}
    data=b'abc';digest=hashlib.sha256(data).hexdigest()
    meta='Package: jq\nVersion: 1\nArchitecture: arm64\nSize: 3\nFilename: pool/main/j/jq/jq_1_arm64.deb\nSHA256: '+digest+'\n'
    sealed=signed_metadata(meta,row);verify_archive(sealed,data);verify_control(sealed,'jq\n1\narm64\n')
    for name,operation in [('signed-sha-missing',lambda:signed_metadata(meta.replace('SHA256: '+digest,'SHA256: broken'),row)),('control-wrong-name',lambda:verify_control(sealed,'other\n1\narm64\n')),('control-wrong-version',lambda:verify_control(sealed,'jq\n2\narm64\n')),('archive-same-size-wrong-hash',lambda:verify_archive(sealed,b'abd'))]:
        try:operation()
        except ValueError:rejected.append(name)
        else:raise ValueError('MUTATION_ACCEPTED:'+name)
    before='base\t1\tarm64\tinstalled\n';after=before+''.join(f"{r['name']}\t{r['version']}\tarm64\tinstalled\n"for r in rows);verify_install(before,after,rows)
    for name,value in [('installed-extra',after+'other\t1\tarm64\tinstalled\n'),('installed-missing',before),('installed-existing-upgraded',after.replace('base\t1','base\t2'))]:
        try:verify_install(before,value,rows)
        except ValueError:rejected.append(name)
        else:raise ValueError('MUTATION_ACCEPTED:'+name)
    return {'state':'PASS','actualCapturedPlanSHA256':hashlib.sha256(b).hexdigest(),'capturedRows':3,'capturedBytes':365244,'blankOptionalDigestPositive':True,'signedMetadataArchiveControlPositive':True,'completeInstallDeltaPositive':True,'negativeControls':rejected,'optionalPrintedDigestNotAuthentication':True,'noDownloadOrInstall':True}
