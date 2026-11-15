"""Synthetic Docker transport controls only. Never a product/catalogue mock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time


def exchange(proxy, request, payload=b'', expect_tunnel=False):
    with socket.create_connection((proxy, 3128), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(request)
        raw = sock.recv(8192)
        if expect_tunnel:
            assert raw.startswith(b'HTTP/1.1 200 ')
            if payload:
                sock.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    part = sock.recv(len(payload)-len(received))
                    assert part
                    received.extend(part)
                assert bytes(received) == payload
            return {'tunnelAccepted': True, 'echoBytes': len(payload)}
        assert not raw.startswith(b'HTTP/1.1 200 ')
        return {'tunnelRefused': True, 'responseBytes': len(raw)}


def target(proxy, out):
    result = {'state': 'INCOMPLETE', 'cases': {}}
    try:
        result['cases']['allowed-reflector'] = exchange(
            proxy, b'CONNECT fixture-upstream:8443 HTTP/1.1\r\nHost: fixture-upstream:8443\r\n\r\n',
            b'XERJ-SYNTHETIC-TRANSPORT-ONLY-123456', True)
        requests = {
            'host-denied': b'CONNECT forbidden.invalid:8443 HTTP/1.1\r\n\r\n',
            'literal-ip': b'CONNECT 127.0.0.1:8443 HTTP/1.1\r\n\r\n',
            'port-denied': b'CONNECT fixture-upstream:80 HTTP/1.1\r\n\r\n',
            'method': b'GET http://fixture-upstream/ HTTP/1.1\r\n\r\n',
            'host-conflict': b'CONNECT fixture-upstream:8443 HTTP/1.1\r\nHost: other:8443\r\n\r\n',
            'duplicate-host': b'CONNECT fixture-upstream:8443 HTTP/1.1\r\nHost: fixture-upstream:8443\r\nHost: fixture-upstream:8443\r\n\r\n',
            'auth': b'CONNECT fixture-upstream:8443 HTTP/1.1\r\nProxy-Authorization: fake\r\n\r\n',
            'overlong': b'CONNECT fixture-upstream:8443 HTTP/1.1\r\nUser-Agent: '+b'x'*9000+b'\r\n\r\n',
        }
        for name, request in requests.items():
            try:
                result['cases'][name] = exchange(proxy, request)
            except (ConnectionResetError, BrokenPipeError):
                result['cases'][name] = {'tunnelRefused': True, 'reset': True}
        result['state'] = 'PASS_SYNTHETIC_CONNECT_CASES'
        return result
    finally:
        Path(out).write_text(json.dumps(result, indent=2)+'\n')


def bypass(out):
    result = {'state': 'INCOMPLETE', 'attempts': []}
    # Explicit known public TCP/UDP destinations; DNS packet contains only the
    # synthetic reserved name. No product, corpus or credential payload.
    tcp = [('1.1.1.1', 443), ('8.8.8.8', 53), ('2606:4700:4700::1111', 443)]
    try:
        for host, port in tcp:
            family = socket.AF_INET6 if ':' in host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((host, port))
            except OSError as exc:
                result['attempts'].append({'host': host, 'port': port, 'denied': True,
                                           'exception': type(exc).__name__})
            else:
                raise AssertionError('DIRECT_TCP_EGRESS_WORKED')
            finally:
                sock.close()
        transaction = os.urandom(2)
        packet = transaction+struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0)+b'\x04xerj\x03org\x00'+struct.pack('!HH', 1, 1)
        # Docker's local stub can return SERVFAIL with a dead loopback-only
        # upstream. That is not public resolution or an external-path proof;
        # pair it with actual HostConfig.Dns==127.0.0.1 and INTERNAL topology.
        for host in ('1.1.1.1', '8.8.8.8', '127.0.0.11', '127.0.0.1'):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            try:
                sock.sendto(packet, (host, 53))
                response, _ = sock.recvfrom(4096)
            except OSError as exc:
                result['attempts'].append({'host': host, 'port': 53, 'udp': True,
                                           'noReply': True, 'exception': type(exc).__name__})
            else:
                assert host == '127.0.0.11', 'DIRECT_EXTERNAL_DNS_RESPONSE'
                assert len(response) >= 12 and response[:2] == transaction
                _, flags, _, answer, authority, additional = struct.unpack('!HHHHHH', response[:12])
                assert flags & 0x8000 and flags & 15 in (2, 5)
                assert answer == 0 and authority == 0
                result['attempts'].append({'host': host, 'port': 53,
                                           'udp': True, 'localStubFailureRCODE': flags & 15,
                                           'answerRecords': answer,
                                           'notSoleProofOfNoDNSEgress': True})
            finally:
                sock.close()
        result['state'] = 'PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'
        return result
    finally:
        Path(out).write_text(json.dumps(result, indent=2)+'\n')


def boundary(proxy, kind, out):
    result = {'state': 'INCOMPLETE', 'kind': kind}
    sock = socket.create_connection((proxy, 3128), timeout=2)
    sock.settimeout(4)
    try:
        if kind == 'header-time':
            sock.sendall(b'CONNECT')
        else:
            sock.sendall(b'CONNECT fixture-upstream:8443 HTTP/1.1\r\n\r\n')
            assert sock.recv(4096).startswith(b'HTTP/1.1 200 ')
            if kind in ('connection-bytes', 'total-bytes'):
                sock.sendall(b'synthetic-byte-cap-control'*128)
        began = time.monotonic()
        received = bytearray()
        while True:
            try:
                raw = sock.recv(4096)
            except ConnectionResetError:
                break
            if not raw:
                break
            received.extend(raw)
            assert len(received) <= 8192
        result.update(state='CLOSED_BY_PROXY_OBSERVED', elapsed=time.monotonic()-began,
                      bytesReceived=len(received))
        return result
    finally:
        sock.close()
        Path(out).write_text(json.dumps(result, indent=2)+'\n')


def paired(proxy, upstream, out):
    result = {'state': 'INCOMPLETE', 'ownedUpstream': upstream}
    try:
        result['proxyPositive'] = exchange(
            proxy, b'CONNECT fixture-upstream:8443 HTTP/1.1\r\n\r\n',
            b'PAIRED-REACHABILITY-ORACLE', True)
        with socket.socket() as direct:
            direct.settimeout(1)
            try:
                direct.connect((upstream, 8443))
            except OSError as exc:
                result['directDenied'] = type(exc).__name__
            else:
                raise AssertionError('CROSS_INTERNAL_BRIDGE_DIRECT_BYPASS')
        result['state'] = 'PASS_SAME_OWNED_UPSTREAM_PROXY_REACHABLE_DIRECT_DENIED'
    finally:
        Path(out).write_text(json.dumps(result, indent=2)+'\n')


def reflect(hard, out):
    server = socket.socket()
    server.bind(('0.0.0.0', 8443))
    server.listen(4)
    server.settimeout(.2)
    Path(out).write_text(json.dumps({'state': 'BOUND_OWNED_SYNTHETIC_REFLECTOR',
                                   'port': 8443, 'pid': os.getpid()})+'\n')
    threads = []

    def echo(conn):
        with conn:
            conn.settimeout(1)
            total = 0
            while time.time() < hard:
                try:
                    raw = conn.recv(4096)
                except socket.timeout:
                    continue
                if not raw:
                    return
                total += len(raw)
                assert total <= 1048576
                conn.sendall(raw)

    try:
        while time.time() < hard:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            assert len(threads) < 32
            thread = threading.Thread(target=echo, args=(conn,), daemon=True)
            threads.append(thread)
            thread.start()
    finally:
        server.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('target', 'bypass', 'reflect', 'boundary', 'paired'))
    parser.add_argument('--proxy')
    parser.add_argument('--out')
    parser.add_argument('--hard', type=float)
    parser.add_argument('--kind')
    parser.add_argument('--upstream')
    args = parser.parse_args()
    if args.mode == 'target':
        target(args.proxy, args.out)
    elif args.mode == 'bypass':
        bypass(args.out)
    elif args.mode == 'boundary':
        boundary(args.proxy, args.kind, args.out)
    elif args.mode == 'paired':
        paired(args.proxy, args.upstream, args.out)
    else:
        reflect(args.hard, args.out)
