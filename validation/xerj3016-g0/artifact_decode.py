"""Unrun XERJ export decoder: reused Bambi ZIP algorithm, narrowed caps, real manifest/hash controls."""
"""Local-only adaptation of Bambi558 harvest ZIP loop; root exact seal required."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import stat
import struct
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ET
import zipfile

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_members(z, clock):
    members = z.infolist()
    assert len(members) <= 514 and sum(i.file_size for i in members) <= 33 * 1024**2
    names = {}
    folded = set()
    for i in members:
        clock()
        name = PurePosixPath(i.filename)
        assert i.orig_filename == i.filename and '\x00' not in i.filename
        assert name.parts and not name.is_absolute() and '..' not in name.parts
        assert '\\' not in i.filename and ':' not in name.parts[0]
        normalized = str(name)
        assert normalized not in ('.', '') and normalized == i.filename.rstrip('/')
        key = unicodedata.normalize('NFC', normalized).casefold()
        assert key not in folded, 'CASE_OR_UNICODE_PATH_COLLISION'
        folded.add(key)
        assert normalized not in names and not (i.flag_bits & 1)
        kind = stat.S_IFMT(i.external_attr >> 16)
        assert kind in (0, stat.S_IFREG, stat.S_IFDIR)
        assert i.file_size <= 8 * 1024**2
        assert i.is_dir() or kind != stat.S_IFDIR
        assert not i.is_dir() or kind != stat.S_IFREG
        assert not i.is_dir() or i.file_size == 0
        names[normalized] = i
    for name, i in names.items():
        for parent in PurePosixPath(name).parents:
            assert str(parent) not in names or names[str(parent)].is_dir(), 'FILE_DIRECTORY_COLLISION'
    return names


def extract_members(z, names, root, clock):
    expanded = 0
    for name, i in names.items():
        clock()
        target = root.joinpath(*PurePosixPath(name).parts)
        assert target.resolve().is_relative_to(root.resolve())
        if i.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        h = hashlib.sha256()
        with z.open(i) as source, target.open('xb') as destination:
            while True:
                clock()
                chunk = source.read(min(65536, i.file_size - written + 1))
                if not chunk:
                    break
                written += len(chunk)
                expanded += len(chunk)
                assert written <= i.file_size and expanded <= 33 * 1024**2
                destination.write(chunk)
                h.update(chunk)
        assert written == i.file_size
        yield {'path': name, 'bytes': written, 'sha256': h.hexdigest(),
               'zipCRC': i.CRC, 'mode': i.external_attr >> 16}


def zip_fixtures(out, clock):
    records = []
    first = None
    root = Path(tempfile.mkdtemp(prefix='synthetic-zip-fixtures-', dir=out))

    def archive(rows):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as z:
            for name, data in rows:
                z.writestr(name, data)
        return stream.getvalue()

    def check(label, raw, expected, crc=False):
        clock()
        target = root/label
        target.mkdir(exist_ok=False)
        error = None
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                names = validate_members(z, clock)
                entries = list(extract_members(z, names, target, clock))
            assert entries
            if expected:
                assert len(ET.parse(target/'actual.xml').findall('.//testcase')) == 1
                assert (target/'regular.txt').read_bytes() == b'synthetic regular file'
        except (AssertionError, zipfile.BadZipFile, RuntimeError) as exc:
            error = {'type': type(exc).__name__, 'message': str(exc)}
        records.append({'case': label, 'expectedAccepted': expected,
                        'accepted': error is None, 'error': error})
        assert (error is None) == expected, 'FIXTURE_UNEXPECTED_RESULT:' + label
        if crc:
            assert error['type'] == 'BadZipFile' and 'CRC' in error['message'], 'REAL_CRC_FAILURE_NOT_OBSERVED'

    try:
        valid = archive([('regular.txt', b'synthetic regular file'),
                         ('actual.xml', b'<testsuites><testsuite><testcase name="ok"/></testsuite></testsuites>')])
        check('valid-regular-and-junit', valid, True)
        corrupt = bytearray(valid)
        start = 30 + struct.unpack_from('<H', corrupt, 26)[0] + struct.unpack_from('<H', corrupt, 28)[0]
        corrupt[start] ^= 1
        check('corrupted-crc', bytes(corrupt), False, crc=True)
        check('truncated-archive', valid[:-8], False)
        check('parent-traversal', archive([('../escape.txt', b'bad')]), False)
        check('normalized-duplicate', archive([('a/b.txt', b'one'), ('a//b.txt', b'two')]), False)
        link = zipfile.ZipInfo('link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        check('symlink-mode', archive([(link, b'elsewhere')]), False)
        encrypted = bytearray(archive([('encrypted.txt', b'fixture')]))
        central = encrypted.index(b'PK\x01\x02')
        struct.pack_into('<H', encrypted, 6, struct.unpack_from('<H', encrypted, 6)[0] | 1)
        struct.pack_into('<H', encrypted, central + 8, struct.unpack_from('<H', encrypted, central + 8)[0] | 1)
        check('encrypted-flag', bytes(encrypted), False)
        check('file-directory-collision', archive([('a', b'file'), ('a/b.txt', b'child')]), False)
        oversized = bytearray(archive([('oversized.txt', b'synthetic')]))
        central = oversized.index(b'PK\x01\x02')
        struct.pack_into('<I', oversized, 22, 64 * 1024**2 + 1)
        struct.pack_into('<I', oversized, central + 24, 64 * 1024**2 + 1)
        check('declared-size-over-limit', bytes(oversized), False)
        check('case-only-collision', archive([('Case.txt', b'one'), ('case.txt', b'two')]), False)
        assert len(records) == 10
    except BaseException as exc:
        first = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        (out/'fixtures-terminal.json').write_text(json.dumps({
            'allTenPassed': first is None and len(records) == 10,
            'firstFailure': first, 'cases': records,
            'realArtifactOpened': False, 'fixtureDirectory': str(root)}, indent=2) + '\n')


# The reviewed ZIP stream/path/CRC algorithm is reused above; only caps are narrower.
from artifacts import verify as verify_export, export as export_files

def decode(archive, destination, clock):
    archive, destination = Path(archive), Path(destination)
    assert archive.is_file() and not archive.is_symlink() and 0 < archive.stat().st_size <= 40*1024**2
    assert not destination.exists() and not destination.is_symlink()
    with zipfile.ZipFile(archive) as z:
        names = validate_members(z, clock)
        manifest_names = [n for n,i in names.items() if not i.is_dir() and PurePosixPath(n).name == 'file-manifest.json']
        assert len(manifest_names) == 1, 'ONE_EXPORTED_MANIFEST_REQUIRED'
        manifest_name = manifest_names[0]
        prefix = str(PurePosixPath(manifest_name).parent)
        assert prefix in ('.','public-evidence','public-evidence-minimal'), 'UNEXPECTED_ARTIFACT_LAYOUT'
        mi = names[manifest_name];assert mi.file_size <= 1024**2
        manifest = json.loads(z.read(mi))
        assert isinstance(manifest,list) and len(manifest) <= 512
        expected = {str(PurePosixPath(prefix)/r['path']) for r in manifest}
        assert len(expected) == len(manifest)
        assert {n for n,i in names.items() if not i.is_dir()} == expected | {manifest_name}, 'UNDECLARED_OR_MISSING_ARTIFACT_FILE'
        destination.mkdir(exist_ok=False)
        records = list(extract_members(z,names,destination,clock))
    exported = destination if prefix == '.' else destination/prefix
    rows = verify_export(exported)
    assert rows == manifest
    return {'state':'EXACT_EXPORTED_FILES_HASH_VERIFIED_SEMANTIC_REVIEW_REQUIRED','root':str(exported),'files':len(rows),'bytes':sum(r['bytes']for r in rows),'archiveSHA256':digest(archive),'decodedMembers':records,'productPassClaim':False}

def fixture():
    origin=time.monotonic()
    def clock():assert time.monotonic()-origin<60,'DECODER_FIXTURE_60_SECOND_BOUND'
    out=Path(tempfile.mkdtemp(prefix='xerj3016-decode-fixtures-'))
    zip_fixtures(out,clock)
    cases=[]
    source=out/'manifest-source';source.mkdir();(source/'value.json').write_text('{"synthetic":true}')
    exported=out/'manifest-export';export_files(source,exported,['value.json'])
    def pack(label,mutate):
        rows={str(f.relative_to(exported)):f.read_bytes() for f in exported.rglob('*') if f.is_file()}
        mutate(rows)
        archive=out/(label+'.zip')
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,data in rows.items():z.writestr(name,data)
        return archive
    def check(label,mutate,accepted):
        archive=pack(label,mutate);error=None
        try:result=decode(archive,out/('decoded-'+label),clock)
        except (AssertionError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as exc:error=type(exc).__name__
        assert (error is None)==accepted,label
        cases.append({'case':label,'accepted':error is None,'expectedAccepted':accepted,'error':error})
    check('valid-manifest-export',lambda r:None,True)
    check('corrupt-file-digest',lambda r:r.__setitem__('value.json',b'{"synthetic":null}'),False)
    check('missing-file',lambda r:r.pop('value.json'),False)
    check('unlisted-file',lambda r:r.__setitem__('extra.txt',b'synthetic'),False)
    check('missing-manifest',lambda r:r.pop('file-manifest.json'),False)
    return {'actual_zip_cases':10,'actual_export_manifest_cases':5,'all_passed':True,'cases':cases,'network':False,'productExecuted':False}
