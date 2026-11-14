"""Explicit synthetic-artifact export; no raw logs or source trees."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile


def relative(name):
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and '\\' not in name
    assert path.as_posix() == name, 'NONCANONICAL_ARTIFACT_NAME'
    assert all(part not in ('', '.', '..', '.git', 'private', 'source') for part in path.parts)
    assert path.name not in ('node.log', 'baseline-source.tar', 'file-manifest.json')
    return path


def verify(root):
    root = Path(root)
    assert not root.is_symlink() and not (root/'file-manifest.json').is_symlink()
    rows = json.loads((root/'file-manifest.json').read_text())
    assert isinstance(rows, list) and len(rows) <= 512
    assert len({row['path'] for row in rows}) == len(rows)
    for row in rows:
        path = root/relative(row['path'])
        assert path.is_file() and not path.is_symlink()
        assert path.resolve().is_relative_to(root.resolve())
        assert path.stat().st_size == row['bytes'] <= 8*1024**2
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256']
    assert sum(row['bytes'] for row in rows) <= 32*1024**2
    return rows


def export(source, destination, names, per_file_cap=8*1024**2, total_cap=32*1024**2, required=()):
    source, destination = Path(source), Path(destination)
    assert not destination.exists()
    records, payloads, exclusions = [], [], []
    used = 0
    selected = sorted(set(required)) + sorted(set(names) - set(required))
    assert set(required) <= set(names)
    # Validate the entire selected set before publishing any directory.
    for name in selected:
        path = source/relative(name)
        assert all(not ancestor.is_symlink() for ancestor in [path,*path.parents]
                   if ancestor == source or source in ancestor.parents)
        if not path.exists() and not path.is_symlink():
            assert name not in required, 'REQUIRED_EVIDENCE_MISSING'
            continue
        assert path.is_file() and not path.is_symlink()
        assert path.resolve().is_relative_to(source.resolve())
        size = path.stat().st_size
        if size > per_file_cap or used+size > total_cap:
            assert name not in required, 'REQUIRED_EVIDENCE_EXCEEDS_CAP'
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda:stream.read(65536),b''):
                    digest.update(block)
            exclusions.append({'path':name,'bytes':size,'sha256':digest.hexdigest(),
                'reason':'PER_FILE_CAP' if size > per_file_cap else 'TOTAL_CAP'})
            continue
        data = path.read_bytes(); assert len(data) == size
        used += size
        payloads.append((name, data))
        records.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    assert sum(row['bytes'] for row in records) <= total_cap
    # This exporter-owned record cannot be supplied by an input file.
    assert 'excluded-evidence.json' not in selected
    data = (json.dumps(exclusions,indent=2)+'\n').encode()
    assert len(data) <= 1024**2 and used+len(data) <= 32*1024**2
    payloads.append(('excluded-evidence.json',data))
    records.append({'path':'excluded-evidence.json','bytes':len(data),
                    'sha256':hashlib.sha256(data).hexdigest()})
    staging = destination.with_name(destination.name+'.unpublished')
    staging.mkdir(exist_ok=False)
    for name,data in payloads:
        target = staging/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
    (staging/'file-manifest.json').write_text(json.dumps(records,indent=2)+'\n')
    verify(staging)
    staging.rename(destination)
    return records


def fallback_export(source,destination):
    """Only fixed sanitized records after a failed normal export."""
    names={'hosted-result.json','host-admission.json'}
    return export(source,destination,names,required=names)


def fixture():
    root = Path(tempfile.mkdtemp(prefix='xerj3019-artifact-fixture-'))
    source = root/'input'; source.mkdir()
    (source/'nested').mkdir(); (source/'nested/value.json').write_text('{"fixture":true}')
    exported = export(source,root/'success',['nested/value.json'])
    assert verify(root/'success') == exported
    (root/'success/nested/value.json').write_text('corrupted')
    try:
        verify(root/'success')
    except AssertionError:
        pass
    else:
        raise AssertionError('CORRUPTION_NOT_REJECTED')
    private = root/'private-value'; private.write_text('SYNTHETIC_PRIVATE_NOT_FOR_EXPORT')
    (source/'link.json').symlink_to(private)
    cases = [('symlink',['link.json'],8*1024**2),
             ('traversal',['../private-value'],8*1024**2),
             ('raw-log',['node.log'],8*1024**2)]
    for label,names,cap in cases:
        destination = root/label
        try:
            export(source,destination,names,per_file_cap=cap)
        except AssertionError:
            assert not destination.exists()
        else:
            raise AssertionError('UNSAFE_EXPORT_ACCEPTED')
    export(source,root/'size',['nested/value.json'],per_file_cap=1)
    assert json.loads((root/'size/excluded-evidence.json').read_text())[0]['reason']=='PER_FILE_CAP'
    export(source,root/'total',['nested/value.json'],total_cap=1)
    assert json.loads((root/'total/excluded-evidence.json').read_text())[0]['reason']=='TOTAL_CAP'
    try:
        export(source,root/'missing',['missing.json'],required=['missing.json'])
    except AssertionError as exc:
        assert str(exc)=='REQUIRED_EVIDENCE_MISSING' and not (root/'missing').exists()
    else:
        raise AssertionError('MISSING_REQUIRED_ACCEPTED')
    (source/'linked-parent').symlink_to(source/'nested',target_is_directory=True)
    try:
        export(source,root/'parent-link',['linked-parent/value.json'])
    except AssertionError:
        assert not (root/'parent-link').exists()
    else:
        raise AssertionError('PARENT_SYMLINK_ACCEPTED')
    for name in ('hosted-result.json','host-admission.json'):
        (source/name).write_text('{"synthetic":true}')
    fallback_export(source,root/'minimal')
    assert {r['path'] for r in verify(root/'minimal')}=={'hosted-result.json','host-admission.json','excluded-evidence.json'}
    return {'actual_filesystem_cases':10,'unsafe_publication_directories_created':0}
