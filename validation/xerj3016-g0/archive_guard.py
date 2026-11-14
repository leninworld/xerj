"""3019 PRIVATE UNRUN: verify the official rc.102 input before safe extraction.

Reuses the earlier XERJ archive checks, adding canonical-path collision and
streamed member limits. No code from the release is executed by this module.
"""
import hashlib
import io
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

ARCHIVE_NAME = 'xerj-1.0.0-rc.102-aarch64-unknown-linux-musl.tar.gz'
ARCHIVE_BYTES = 33666646
ARCHIVE_SHA = None  # Actual publisher checksum validated at acquisition; not invented.
CHECKSUM_BYTES = 118
CHECKSUM_SHA = None
MAX_EXPANDED = 256 * 1024 * 1024


def extract(source, destination, *, max_expanded=MAX_EXPANDED):
    destination = Path(destination)
    destination.mkdir(exist_ok=False)
    names = set()
    members = []
    total = 0
    with tarfile.open(source, 'r:gz') as archive:
        for number, member in enumerate(archive):
            if number >= 128 or len(member.name) > 512:
                raise ValueError('Archive member/name cap')
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in member.name.split('/') or len(path.parts) > 32:
                raise ValueError('Archive escapes destination')
            key = path.as_posix()
            if key in names or not (member.isfile() or member.isdir()):
                raise ValueError('Archive collision or unsupported member')
            if key == '.' and not member.isdir():
                raise ValueError('Non-directory root member')
            names.add(key)
            total += member.size
            if total > max_expanded:
                raise ValueError('Archive expansion cap')
            members.append(member)
        # Validate the complete header set before writing any member content.
        for member in members:
            target = destination / PurePosixPath(member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            incoming = archive.extractfile(member)
            if incoming is None:
                raise ValueError('Missing archive member content')
            with incoming, target.open('xb') as output:
                written = 0
                while True:
                    chunk = incoming.read(min(65536, member.size - written + 1))
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > member.size:
                        raise ValueError('Archive content size mismatch')
                    output.write(chunk)
                if written != member.size:
                    raise ValueError('Truncated archive content')
    binaries = [p for p in destination.rglob('xerj') if p.is_file()]
    if len(binaries) != 1:
        raise ValueError('Expected exactly one xerj executable')
    binaries[0].chmod(0o755)
    return binaries[0], total


def verify_and_extract(archive, checksum, destination):
    archive, checksum = Path(archive), Path(checksum)
    if archive.stat().st_size != ARCHIVE_BYTES or checksum.stat().st_size != CHECKSUM_BYTES:
        raise ValueError('Official release input size mismatch')
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if ARCHIVE_SHA is not None and archive_digest != ARCHIVE_SHA:
        raise ValueError('Sealed release artifact digest mismatch')
    if CHECKSUM_SHA is not None and hashlib.sha256(checksum.read_bytes()).hexdigest() != CHECKSUM_SHA:
        raise ValueError('Sealed publisher checksum-file digest mismatch')
    tokens = checksum.read_text().strip().split()
    if len(tokens) != 2 or not __import__('re').fullmatch('[0-9a-f]{64}',tokens[0]) or tokens[0] != archive_digest or tokens[1].lstrip('*') != ARCHIVE_NAME:
        raise ValueError('Publisher checksum content mismatch')
    return extract(archive, destination)


def fixture():
    # No cleanup: owned synthetic fixtures remain until the hosted runner ends.
    root = Path(tempfile.mkdtemp(prefix='xerj3019-archive-fixture-'))
    cases = [
        ('valid', [('release/xerj', tarfile.REGTYPE, b'abc')], True),
        ('traversal', [('../xerj', tarfile.REGTYPE, b'abc')], False),
        ('absolute', [('/xerj', tarfile.REGTYPE, b'abc')], False),
        ('symlink', [('xerj', tarfile.SYMTYPE, b'')], False),
        ('device', [('xerj', tarfile.CHRTYPE, b'')], False),
        ('duplicate', [('release/xerj', tarfile.REGTYPE, b'abc'),
                       ('release//xerj', tarfile.REGTYPE, b'def')], False),
    ]
    for label, entries, expected in cases:
        source = root / (label + '.tar.gz')
        with tarfile.open(source, 'w:gz') as archive:
            for name, kind, content in entries:
                info = tarfile.TarInfo(name)
                info.type, info.size = kind, len(content)
                info.linkname = '/etc/passwd'
                archive.addfile(info, io.BytesIO(content) if content else None)
        try:
            binary, expanded = extract(source, root / label)
        except ValueError:
            if expected:
                raise
        else:
            if not expected or binary.read_bytes() != b'abc' or expanded != 3:
                raise AssertionError(label)
    try:
        extract(root / 'valid.tar.gz', root / 'oversized', max_expanded=2)
    except ValueError:
        pass
    else:
        raise AssertionError('Expansion cap not enforced')
    if not root.joinpath('valid/release/xerj').is_file():
        raise AssertionError('Valid fixture not retained')
    return {'kind': 'SYNTHETIC_HARNESS_SELF_CHECK_ONLY', 'archive_cases': 7,
            'binary_executed': False, 'external_network_requests': 0}

def actual_checksum_controls(archive,checksum,root):
    """Real downloaded-input negatives, before any released executable is launched."""
    root=Path(root);root.mkdir(exist_ok=False);original=Path(checksum).read_bytes()
    assert len(original)==CHECKSUM_BYTES
    results=[]
    for name,data in [('wrong-digest',bytes([ord('0')if original[0]!=ord('0')else ord('1')])+original[1:]),('wrong-name',original.replace(ARCHIVE_NAME.encode(),ARCHIVE_NAME.replace('xerj-','xerx-',1).encode()))]:
        assert len(data)==CHECKSUM_BYTES
        p=root/(name+'.sha256');p.write_bytes(data)
        try:verify_and_extract(archive,p,root/name)
        except ValueError:
            assert not(root/name).exists();results.append(name)
        else:raise AssertionError('ACTUAL_CHECKSUM_MUTATION_NOT_REJECTED')
    return {'actualVerifiedInputNegativeControls':results,'noBinaryExecuted':True}
