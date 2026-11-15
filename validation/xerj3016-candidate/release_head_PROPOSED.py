"""R3 bounded HEAD transcript parser; no HTTP, subprocess or work on import.

Raw header/write-out captures can contain signed redirect queries and MUST stay
private. Only the explicitly constructed sanitized receipt is public evidence.
"""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlsplit

HOSTS = ['xerj.org', 'github.com', 'release-assets.githubusercontent.com', 'hub.xerj.org']
TAG = 'v1.0.0-rc.102'
ARCHIVE = 'xerj-1.0.0-rc.102-aarch64-unknown-linux-musl.tar.gz'
BASE = 'https://github.com/xerj-org/xerj/releases/download/'+TAG+'/'
INSTALLER_SHA256 = '158b53201b9c5ddaffd0afa5860307a6dd5c684902303aa9dff64978618cf14f'
REDIRECTS = {301, 302, 303, 307, 308}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class RouteError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise RouteError(code)


def initial_url(kind):
    need(kind in ('archive', 'checksum'), 'ASSET_KIND')
    return BASE+ARCHIVE+('.sha256' if kind == 'checksum' else '')


def sanitized_url(url):
    need(isinstance(url, str) and len(url) <= 16384 and
         not any(ord(c) <= 32 or ord(c) == 127 for c in url), 'URL_BOUNDED_NO_CONTROL')
    parsed = urlsplit(url)
    need(parsed.scheme == 'https' and parsed.hostname in HOSTS and
         parsed.port in (None, 443), 'HTTPS_ALLOWLISTED_HOST_PORT')
    need(not parsed.username and not parsed.password and not parsed.fragment,
         'NO_USERINFO_OR_FRAGMENT')
    need(parsed.netloc == parsed.hostname or parsed.netloc == parsed.hostname+':443',
         'CANONICAL_AUTHORITY')
    return {'scheme': parsed.scheme, 'host': parsed.hostname,
            'pathSHA256': sha(parsed.path.encode('utf-8')), 'queryPresent': bool(parsed.query)}


def parse(kind, headers, writeout, curl_exit):
    """Always return a sanitized receipt, including a safe failure code.

    No exception text, header values, effective URL, Location or query is copied
    into this receipt. Evidence hashes bind private raw captures without leaking
    signed URLs. A failed receipt must HOLD; it is never a product loss.
    """
    source = initial_url(kind)
    result = {'schemaVersion': 1, 'assetKind': kind, 'sourceTag': TAG,
              'archiveName': ARCHIVE, 'expectedBytes': 118 if kind == 'checksum' else 33666646,
              'installerSourceSHA256': INSTALLER_SHA256,
              'initialURLSHA256': sha(source.encode()),
              'parserSourceSHA256': sha(Path(__file__).read_bytes()),
              'rawHeadersSHA256': sha(headers), 'rawWriteoutSHA256': sha(writeout),
              'rawHeaderBytes': len(headers), 'rawWriteoutBytes': len(writeout),
              'maxRedirects': 3, 'headOnly': True, 'bodyDownloaded': False,
              'bodyIntegrityProved': False, 'runtimeInstallerMustVerifySHA': True,
              'curlExit': curl_exit, 'chain': [], 'complete': False,
              'classification': 'INFRASTRUCTURE_UNVERIFIED'}
    try:
        need(type(curl_exit) is int and curl_exit == 0, 'CURL_HEAD_FAILED')
        need(0 < len(headers) <= 65536 and 0 < len(writeout) <= 32768,
             'RAW_TRANSCRIPT_CAP')
        text = headers.decode('iso-8859-1')
        need('\r\n' in text and text.endswith('\r\n\r\n'), 'HEADER_FRAMING')
        blocks = text.split('\r\n\r\n')[:-1]
        need(1 <= len(blocks) <= 12, 'HEADER_BLOCK_CAP')
        responses = []
        informational = 0
        for block in blocks:
            lines = block.split('\r\n')
            match = re.fullmatch(r'HTTP/(?:1\.[01]|2|3) ([0-9]{3})(?: [^\r\n]*)?', lines[0])
            need(match is not None, 'STATUS_LINE')
            status = int(match.group(1))
            fields = {}
            for line in lines[1:]:
                need(len(line) <= 8192 and line and line[0] not in ' \t', 'HEADER_LINE')
                key, sep, value = line.partition(':')
                need(bool(sep) and re.fullmatch(r'[!#$%&\'*+.^_`|~0-9A-Za-z-]+', key) is not None,
                     'HEADER_NAME')
                key = key.lower()
                if key in ('location', 'content-length'):
                    need(key not in fields, 'DUPLICATE_ROUTING_HEADER')
                    fields[key] = value.strip()
            if 100 <= status < 200:
                need(status in (100, 102, 103), 'UNSUPPORTED_INFORMATIONAL_STATUS')
                informational += 1
            else:
                responses.append((status, fields))
        need(1 <= len(responses) <= 4, 'RESPONSE_COUNT')
        line = writeout.decode('ascii', 'strict').strip()
        final_url, sep, count = line.rpartition(' ')
        need(bool(sep) and re.fullmatch(r'[0-3]', count) is not None, 'WRITEOUT_FORMAT')
        redirect_count = int(count)
        need(redirect_count == len(responses)-1, 'REDIRECT_COUNT_MISMATCH')
        current = source
        for index, (status, fields) in enumerate(responses):
            # Append only whitelisted fields; never raw Location/query.
            row = {**sanitized_url(current), 'status': status}
            result['chain'].append(row)
            if index < len(responses)-1:
                need(status in REDIRECTS and 'location' in fields, 'REDIRECT_RESPONSE')
                current = urljoin(current, fields['location'])
                sanitized_url(current)  # validate BEFORE accepting next hop
            else:
                need(status == 200 and 'location' not in fields, 'FINAL_STATUS_NOT_200')
                if 'content-length' in fields:
                    need(fields['content-length'].isdigit(), 'CONTENT_LENGTH_FORMAT')
                    need(int(fields['content-length']) == result['expectedBytes'], 'ASSET_SIZE_DRIFT')
        need(current == final_url, 'EFFECTIVE_URL_MISMATCH')
        sanitized_url(final_url)
        result.update(complete=True, classification='PINNED_INSTALLER_RELEASE_ROUTE_VERIFIED_HEAD_ONLY',
                      finalStatus=200, redirectCount=redirect_count,
                      responseCount=len(responses), informationalCount=informational,
                      allRedirectHostsAllowed=True)
    except RouteError as exc:
        result['failureCode'] = str(exc)
    except (UnicodeError, ValueError, TypeError, OverflowError):
        result['failureCode'] = 'MALFORMED_HEAD_TRANSCRIPT'
    return result


def fixture_controls():
    """Future Docker-only pure parser controls, no network/helper invocation."""
    url = initial_url('archive')
    redirected = 'https://release-assets.githubusercontent.com/releaseasset/synthetic?sig=PRIVATE_SYNTHETIC_TOKEN'
    good = ('HTTP/1.1 302 Found\r\nLocation: '+redirected+'\r\n\r\n'
            'HTTP/2 200\r\nContent-Length: 33666646\r\n\r\n').encode()
    output = (redirected+' 1').encode()
    row = parse('archive', good, output, 0)
    assert row['complete'] and len(row['chain']) == 2
    public = json.dumps(row)
    assert 'PRIVATE_SYNTHETIC_TOKEN' not in public and 'Location' not in public and redirected not in public
    cases = {'allowed-redirect-and-no-signed-URL-leak': True}
    tests = {
        'curl-failure': (good, output, 22),
        'non200-final': (good.replace(b'HTTP/2 200', b'HTTP/2 404'), output, 0),
        'foreign-redirect': (good.replace(b'release-assets.githubusercontent.com', b'foreign.invalid'), output, 0),
        'redirect-count-mismatch': (good, (redirected+' 0').encode(), 0),
        'insecure-hop': (good.replace(b'https://release-assets', b'http://release-assets'), output, 0),
        'duplicate-location': (good.replace(b'Location: ', b'Location: '+redirected.encode()+b'\r\nLocation: ', 1), output, 0),
        'wrong-size': (good.replace(b'33666646', b'33666645'), output, 0),
        'malformed-writeout': (good, b'not a valid final-url count', 0),
    }
    for name, (head, final, code) in tests.items():
        failed = parse('archive', head, final, code)
        assert failed['complete'] is False and failed['classification'] == 'INFRASTRUCTURE_UNVERIFIED'
        assert 'failureCode' in failed
        cases[name] = True
    checksum = parse('checksum', b'HTTP/2 200\r\nContent-Length: 118\r\n\r\n',
                     (initial_url('checksum')+' 0').encode(), 0)
    assert checksum['complete']
    cases['checksum-direct-200'] = True
    assert len(cases) == 10
    return {'schemaVersion': 1, 'parserSourceSHA256': sha(Path(__file__).read_bytes()),
            'caseCount': 10, 'cases': cases, 'actualNetworkCalls': 0,
            'rawSignedURLExported': False}


def capture(kind, proxy, private, hard):
    """One future Docker curl HEAD. Kernel-bounded private regular files."""
    import ipaddress
    import os
    import resource
    import signal
    import subprocess
    import time
    parsed = urlsplit(proxy)
    need(parsed.scheme == 'http' and parsed.port == 3128 and
         ipaddress.ip_address(parsed.hostname).is_private and
         not parsed.username and not parsed.password and not parsed.query and
         not parsed.fragment and parsed.path in ('', '/'), 'OWNED_PROXY_URL')
    root = Path(private)
    root.mkdir(mode=0o700, exist_ok=False)
    headers = root/'headers.private'
    writeout = root/'writeout.private'
    stderr = root/'stderr.private'
    # RLIMIT_FSIZE applies to curl's dump-header and both redirected streams.
    # Thus unexpected headers cannot fill the VM before post-read checks.
    def file_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    argv = ['curl', '--fail', '--silent', '--show-error', '--head', '--location',
            '--max-redirs', '3', '--connect-timeout', '5', '--max-time', '15',
            '--suppress-connect-headers', '--dump-header', str(headers),
            '--output', '/dev/null', '--proxy', proxy, '--noproxy', '',
            '--write-out', '%{url_effective} %{num_redirects}', initial_url(kind)]
    code = None
    timed_out = False
    with writeout.open('xb') as stdout_file, stderr.open('xb') as stderr_file:
        need(time.time() < hard-6, 'ORIGINAL_HEAD_CLOCK')
        process = subprocess.Popen(argv, stdout=stdout_file, stderr=stderr_file,
                                   start_new_session=True, preexec_fn=file_limit)
        try:
            process.wait(timeout=min(15, max(.001, hard-time.time()-6)))
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
            code = process.returncode
    def raw(path):
        if not path.exists():
            return b''
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
             'PRIVATE_CAPTURE_FILE_BOUND')
        with path.open('rb') as stream:
            return stream.read(65537)
    receipt = parse(kind, raw(headers), raw(writeout), code)
    if timed_out:
        receipt.update(complete=False, classification='INFRASTRUCTURE_UNVERIFIED',
                       failureCode='HEAD_CHILD_TIMEOUT')
    receipt['kernelRawFileCapBytes'] = 65536
    receipt['privateStderrSHA256'] = sha(raw(stderr))
    receipt['childReaped'] = process.poll() is not None
    receipt['headArgvSHA256'] = sha(json.dumps(argv, separators=(',', ':')).encode())
    # No raw URL appears in stdout or exceptions of this wrapper.
    print(json.dumps(receipt, sort_keys=True))
    return receipt


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--capture', choices=('archive', 'checksum'), required=True)
    parser.add_argument('--proxy', required=True)
    parser.add_argument('--private', required=True)
    parser.add_argument('--hard', type=float, required=True)
    args = parser.parse_args()
    try:
        result = capture(args.capture, args.proxy, args.private, args.hard)
    except BaseException:
        # Raw captures remain private for diagnosis. Never print exception text.
        print('{"complete":false,"failureCode":"HEAD_CAPTURE_INFRASTRUCTURE_HOLD"}')
        raise SystemExit(1) from None
    raise SystemExit(0 if result['complete'] else 1)
