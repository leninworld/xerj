"""Disabled review draft. Encrypted CONNECT metadata is not HTTP path visibility.

No network action occurs on import. The reviewed Docker controller must prove
INTERNAL-only target routing, proxy dual-network topology and direct-egress
denial. Environment variables and this helper alone do not provide isolation.
"""

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import threading
import time


def require(condition, name):
    if not condition:
        raise ValueError(name)


def configuration(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 16384,
            'CONFIG_REGULAR_BOUNDED')
    raw = p.read_bytes()
    cfg = json.loads(raw)
    require(cfg['schemaVersion'] == 1 and cfg['executionApproved'] is True,
            'EXACT_FUTURE_EXECUTION_APPROVAL_REQUIRED')
    require(cfg['c2AmendmentApproved'] is True, 'C2_AMENDMENT_NOT_INHERITED')
    require(cfg['phase'] in ('fixture', 'product'), 'PHASE')
    require(isinstance(cfg['hardEpoch'], (int, float)) and
            math.isfinite(cfg['hardEpoch']) and
            0 < cfg['hardEpoch'] - time.time() <= 1300, 'FINITE_CURRENT_WINDOW')
    require(isinstance(cfg['bindAddress'], str) and
            ipaddress.ip_address(cfg['bindAddress']).version == 4, 'EXPLICIT_BIND_IPV4')
    require(type(cfg['port']) is int and 1024 <= cfg['port'] <= 65535, 'BIND_PORT')
    for name, minimum, maximum in (
        ('maxConnections', 1, 64), ('maxConcurrent', 1, 4),
        ('maxTotalBytes', 1, 268435456), ('maxConnectionBytes', 1, 67108864),
        ('maxHeaderBytes', 128, 8192), ('maxLogBytes', 1024, 1048576),
        ('maxEvents', 1, 512), ('connectionSeconds', 1, 120),
        ('connectSeconds', 1, 20), ('headerSeconds', 1, 10),
    ):
        require(type(cfg[name]) is int and minimum <= cfg[name] <= maximum, name)
    hosts = cfg['allowedHosts']
    require(isinstance(hosts, list) and 0 < len(hosts) <= 8 and len(set(hosts)) == len(hosts),
            'FINITE_UNIQUE_HOST_ALLOWLIST')
    for host in hosts:
        require(isinstance(host, str) and len(host) <= 253 and
                re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', host) is not None,
                'EXACT_CANONICAL_HOST')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError('NO_LITERAL_IP_DESTINATIONS')
    fixture = cfg.get('fixturePrivateAddress')
    if cfg['phase'] == 'product':
        require(fixture is None, 'NO_PRIVATE_DESTINATION_EXCEPTION_IN_PRODUCT')
        require(set(hosts) <= {'xerj.org', 'github.com',
                               'release-assets.githubusercontent.com', 'hub.xerj.org'},
                'PRODUCT_HOSTS_REQUIRE_EXACT_REVIEW')
    else:
        require(hosts == ['fixture-upstream'] and isinstance(fixture, str) and
                ipaddress.ip_address(fixture).is_private, 'ISOLATED_FIXTURE_ONLY')
    return cfg, hashlib.sha256(raw).hexdigest()


class Proxy:
    def __init__(self, cfg, config_hash, out):
        self.cfg, self.config_hash = cfg, config_hash
        self.out = Path(out)
        self.out.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.log = (self.out / 'connections.jsonl').open('xb')
        os.chmod(self.out / 'connections.jsonl', 0o600)
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.sockets = set()
        self.threads = []
        self.bytes = self.accepted = self.events = self.log_bytes = self.active = 0
        self.connection_bytes = {}
        self.exhausted = False
        self.closed = False

    def emit(self, kind, **fields):
        with self.lock:
            record = {'time': time.time(), 'kind': kind, **fields}
            raw = (json.dumps(record, sort_keys=True) + '\n').encode()
            if (self.events + 1 > self.cfg['maxEvents'] or
                    self.log_bytes + len(raw) > self.cfg['maxLogBytes']):
                self.exhausted = True
                self.stop.set()
                raise ValueError('LOG_LIMIT_FAIL_CLOSED')
            self.log.write(raw)
            self.log.flush()
            self.events += 1
            self.log_bytes += len(raw)

    def current(self):
        require(not self.stop.is_set() and time.time() < self.cfg['hardEpoch'],
                'PROXY_ORIGINAL_DEADLINE')

    def charge(self, count, number):
        with self.lock:
            require(self.bytes + count <= self.cfg['maxTotalBytes'], 'TOTAL_BYTE_CAP')
            self.bytes += count
            self.connection_bytes[number] = self.connection_bytes.get(number, 0) + count

    def register(self, sock):
        with self.lock:
            self.current()
            self.sockets.add(sock)

    def close(self, sock):
        with self.lock:
            self.sockets.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def header(self, client, number):
        end = min(self.cfg['hardEpoch'], time.time() + self.cfg['headerSeconds'])
        data = bytearray()
        while b'\r\n\r\n' not in data:
            self.current()
            require(time.time() < end, 'HEADER_TIMEOUT')
            client.settimeout(max(.001, end-time.time()))
            try:
                piece = client.recv(min(1024, self.cfg['maxHeaderBytes']-len(data)+1))
            except socket.timeout as exc:
                raise ValueError('HEADER_TIMEOUT') from exc
            require(piece, 'HEADER_EOF')
            self.charge(len(piece), number)
            data.extend(piece)
            require(len(data) <= self.cfg['maxHeaderBytes'], 'HEADER_CAP')
        head, after = bytes(data).split(b'\r\n\r\n', 1)
        require(not after, 'NO_PIPELINED_BYTES_BEFORE_CONNECT_RESPONSE')
        lines = head.decode('ascii', 'strict').split('\r\n')
        match = re.fullmatch(r'CONNECT ([a-z0-9.-]+):([0-9]{1,5}) HTTP/1\.[01]', lines[0])
        require(match is not None, 'CONNECT_ONLY_CANONICAL_AUTHORITY')
        host, port = match.group(1), int(match.group(2))
        self.emit('requested-destination', connection=number, host=host, port=port)
        require(host in self.cfg['allowedHosts'], 'HOST_DENIED')
        expected = 8443 if self.cfg['phase'] == 'fixture' else 443
        require(port == expected, 'PORT_DENIED')
        seen = set()
        for line in lines[1:]:
            name, sep, value = line.partition(':')
            require(sep and name.lower() in ('host', 'user-agent', 'proxy-connection') and
                    name.lower() not in seen and not any(ord(x) < 32 for x in value),
                    'NO_AUTH_OR_UNEXPECTED_PROXY_HEADER')
            seen.add(name.lower())
            if name.lower() == 'host':
                require(value.strip() == f'{host}:{port}', 'HOST_HEADER_BINDING')
        return host, port

    def resolve(self, host, port):
        self.current()
        if self.cfg['phase'] == 'fixture':
            return [(socket.AF_INET, self.cfg['fixturePrivateAddress'])]
        # DNS can block in libc: daemon workers cannot keep the process alive;
        # controller supervision and the main hard deadline remain mandatory.
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        self.current()
        result = []
        for family, _, _, _, sockaddr in addresses:
            ip = ipaddress.ip_address(sockaddr[0])
            require(ip.is_global and not ip.is_multicast, 'NONPUBLIC_DNS_DESTINATION_DENIED')
            pair = (family, str(ip))
            if pair not in result:
                result.append(pair)
        require(0 < len(result) <= 16, 'FINITE_DNS_RESULT')
        return result

    def relay(self, client, remote, end, number):
        client.setblocking(False)
        remote.setblocking(False)
        transferred = 0
        with selectors.DefaultSelector() as selector:
            selector.register(client, selectors.EVENT_READ, remote)
            selector.register(remote, selectors.EVENT_READ, client)
            while True:
                self.current()
                require(time.time() < end, 'CONNECTION_TIMEOUT')
                for key, _ in selector.select(min(.2, max(.001, end-time.time()))):
                    raw = key.fileobj.recv(32768)
                    if not raw:
                        return transferred
                    require(transferred + len(raw) <= self.cfg['maxConnectionBytes'],
                            'CONNECTION_BYTE_CAP')
                    self.charge(len(raw), number)
                    transferred += len(raw)
                    view = memoryview(raw)
                    while view:
                        self.current()
                        require(time.time() < end, 'WRITE_TIMEOUT')
                        try:
                            n = key.data.send(view)
                            require(n > 0, 'WRITE_EOF')
                            view = view[n:]
                        except BlockingIOError:
                            time.sleep(.01)

    def handle(self, client, number):
        remote = None
        host = None
        connected = False
        sent = 0
        began = time.time()
        try:
            host, port = self.header(client, number)
            self.emit('destination', connection=number, host=host, port=port)
            addresses = self.resolve(host, port)
            connect_end = min(self.cfg['hardEpoch'], began+self.cfg['connectSeconds'])
            for family, ip in addresses:
                self.current()
                require(time.time() < connect_end, 'CONNECT_TIMEOUT')
                remote = socket.socket(family, socket.SOCK_STREAM)
                self.register(remote)
                try:
                    remote.settimeout(max(.001, connect_end-time.time()))
                    remote.connect((ip, port))
                    connected = True
                    break
                except OSError:
                    self.close(remote)
                    remote = None
            require(connected, 'UPSTREAM_UNAVAILABLE')
            response = b'HTTP/1.1 200 Connection Established\r\n\r\n'
            self.charge(len(response), number)
            client.settimeout(max(.001, min(2, self.cfg['hardEpoch']-time.time())))
            client.sendall(response)
            self.emit('allowed', connection=number, host=host, port=port,
                      resolvedAddress=ip, encryptedPathVisibility=False)
            sent = self.relay(client, remote,
                              min(self.cfg['hardEpoch'], began+self.cfg['connectionSeconds']), number)
            self.emit('closed', connection=number, host=host, tunneledBytes=sent,
                      accountedBytes=self.connection_bytes.get(number, 0))
        except Exception as exc:
            # Only known error labels; no raw request, URL, TLS or payload output.
            label = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            try:
                self.emit('refused-or-failed', connection=number, host=host,
                          reason=label[:96], connected=connected,
                          accountedBytes=self.connection_bytes.get(number, 0),
                          accountedBytesMayExceedCompletedRelay=True)
            except Exception:
                self.stop.set()
        finally:
            if remote is not None:
                self.close(remote)
            self.close(client)
            with self.lock:
                self.active -= 1

    def run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        previous_signals = {sig: signal.signal(sig, lambda *_: self.stop.set())
                            for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.register(listener)
            listener.bind((self.cfg['bindAddress'], self.cfg['port']))
            listener.listen(self.cfg['maxConcurrent'])
            listener.settimeout(.2)
            self.emit('ready', configSHA256=self.config_hash, phase=self.cfg['phase'],
                      allowedHosts=self.cfg['allowedHosts'], encryptedPathVisibility=False,
                      proxyPID=os.getpid())
            while time.time() < self.cfg['hardEpoch'] and not self.stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                with self.lock:
                    self.accepted += 1
                    if (self.accepted > self.cfg['maxConnections'] or
                            self.active >= self.cfg['maxConcurrent']):
                        client.close()
                        self.emit('connection-cap-denied', connection=self.accepted)
                        continue
                    self.register(client)
                    self.active += 1
                thread = threading.Thread(target=self.handle,
                                          args=(client, self.accepted), daemon=True)
                self.threads.append(thread)
                thread.start()
        finally:
            self.stop.set()
            with self.lock:
                sockets = list(self.sockets)
            for sock in sockets:
                self.close(sock)
            # All joins share one 2s cleanup allowance; outer controller reserves it.
            join_end = time.monotonic() + 2
            for thread in self.threads:
                thread.join(max(0, join_end-time.monotonic()))
            with self.lock:
                summary = {'schemaVersion': 1, 'configSHA256': self.config_hash,
                           'connections': self.accepted, 'accountedBytes': self.bytes,
                           'logBytes': self.log_bytes, 'logEvents': self.events,
                           'exhausted': self.exhausted,
                           'daemonWorkersStillAlive': sum(t.is_alive() for t in self.threads),
                           'encryptedPathVisibility': False,
                           'pathBlockProved': False, 'networkIsolationProvedByHelper': False,
                           'productPass': False}
                self.log.close()
                (self.out / 'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
            for sig, handler in previous_signals.items():
                signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    cfg, digest = configuration(args.config)
    Proxy(cfg, digest, args.out).run()


if __name__ == '__main__':
    main()
