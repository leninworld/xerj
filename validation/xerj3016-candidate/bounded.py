"""Bounded command, byte-identity and evidence helpers for an owned Linux VM."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


class LimitAbort(BaseException):
    """A global stop that independent diagnostic lanes must never catch."""


def limit(condition, message):
    if not condition:
        raise LimitAbort(message)


def cgroup_sample(root="/sys/fs/cgroup"):
    root = Path(root)
    current = int((root / "memory.current").read_text())
    stat = dict(line.split() for line in (root / "memory.stat").read_text().splitlines())
    return {"at": time.time(), "current": current, "peak": int((root / "memory.peak").read_text()),
            "working_set": max(0, current-int(stat.get("inactive_file", "0"))),
            "limit": int((root / "memory.max").read_text())}


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def command(args, seconds, cap, guard=lambda: None, expected=0, cwd=None, log=None):
    """Bound output and elapsed time, reap the owned subprocess on every path."""
    guard()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ACTIONS_")
           and not any(s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY"))}
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, env=env, cwd=cwd)
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ, 'stdout')
    sel.register(p.stderr, selectors.EVENT_READ, 'stderr')
    data = {'stdout':bytearray(), 'stderr':bytearray()}
    start = time.monotonic()
    try:
        while sel.get_map():
            guard()
            if time.monotonic() - start >= seconds:
                raise TimeoutError("command elapsed limit")
            for key, _ in sel.select(.2):
                part = os.read(key.fd, 65536)
                if not part:
                    sel.unregister(key.fileobj)
                else:
                    if sum(map(len,data.values())) + len(part) > cap:
                        raise OverflowError("command output limit")
                    data[key.data].extend(part)
        code = p.wait(timeout=2)
        if code != expected:
            tail = bytes(data['stdout'][-2048:])+bytes(data['stderr'][-2048:])
            raise RuntimeError(f"command exit {code}, expected {expected}: " + tail.decode(errors="replace"))
        return bytes(data['stdout'])
    finally:
        sel.close()
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(timeout=2)
        p.stdout.close()
        p.stderr.close()
        if log is not None:
            Path(log).write_bytes(data['stdout'])
            Path(str(log)+'.stderr').write_bytes(data['stderr'])


def emit(root):
    """Export only owned, size-bounded synthetic results as hash-framed records."""
    files = sorted(p for p in Path(root).rglob("*") if p.is_file())
    assert not any(p.is_symlink() for p in files)
    assert sum(p.stat().st_size for p in files) <= 16 * 1024**2
    for p in files:
        name = p.relative_to(root).as_posix()
        assert all(c.isalnum() or c in "-._/" for c in name)
        data = p.read_bytes()
        print("EVIDENCE", name, len(data), hashlib.sha256(data).hexdigest(), flush=True)
        for index, start in enumerate(range(0, len(data), 16384)):
            print("DATA", name, index, base64.b64encode(data[start:start+16384]).decode(), flush=True)


def save(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(data)
