"""Future Docker-only rc102 controls. No work happens on import."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import threading
import time

import bounded


def run(binary, expected_sha, out, hard, proxy=None):
    out = Path(out)
    out.mkdir(mode=0o700, exist_ok=False)
    binary = Path(binary)
    assert binary.is_file() and not binary.is_symlink()
    assert binary.stat().st_size == 135764000
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected_sha
    requests = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            assert self.client_address[0] == '127.0.0.1'
            size = int(self.headers.get('Content-Length', '-1'))
            if not 0 < size <= 16384 or self.path != '/api/corpus-feedback':
                self.send_error(400)
                return
            self.connection.settimeout(2)
            raw = self.rfile.read(size)
            with lock:
                assert len(requests) < 4
                requests.append({'path': self.path, 'bytes': size,
                                 'sha256': hashlib.sha256(raw).hexdigest(),
                                 'at': time.time()})
            body = json.loads(raw)
            with lock:
                requests[-1]['body'] = body
            assert body['corpus'] == 'synthetic-corpus'
            assert body['usefulness'] == 3 and body['found'] == 'no'
            response = b'{"accepted":true,"syntheticLocalControl":true}\n'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.timeout = .2
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # All actual product children inherit only synthetic owned state. The caller
    # must additionally prove the container is --network none, not just no proxy.
    os.environ.clear()
    os.environ.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME=str(out/'home'),
                      TMPDIR=str(out/'tmp'), XERJ_HUB_HOME=str(out/'hub'),
                      XERJ_CORPUS_FEEDBACK_URL=
                      f'http://127.0.0.1:{server.server_port}/api/corpus-feedback')
    for name in ('home', 'tmp', 'hub'):
        (out/name).mkdir(mode=0o700)

    def command(label, args, seconds=20, expected=0):
        left = min(seconds, hard-time.time())
        assert left > 6
        began = time.monotonic()
        record = {'argv': args, 'complete': False,
                  'feedbackDisabled': os.environ.get('XERJ_DISABLE_FEEDBACK'),
                  'endpoint': os.environ['XERJ_CORPUS_FEEDBACK_URL']}
        try:
            raw = bounded.command(args, left-6, 262144,
                                  guard=lambda: bounded.limit(time.time() < hard-2,
                                                              'LOCAL_CONTROL_DEADLINE'),
                                  expected=expected,
                                  log=out/(label+'.stdout'))
            record.update(complete=True, exit=expected)
            return raw
        finally:
            record['seconds'] = time.monotonic()-began
            bounded.save(out/(label+'.json'), record)

    result = {'state': 'INCOMPLETE', 'publicFeedback': False}
    try:
        os.environ['XERJ_DISABLE_FEEDBACK'] = 'true'
        version = command('version', [str(binary), '--version'])
        assert version.strip() == b'xerj v1.0.0-rc.102'
        help_text = command('actual-feedback-help', [str(binary), 'hub', 'feedback', '--help'])
        for token in (b'--usefulness', b'--found', b'XERJ_CORPUS_FEEDBACK_URL',
                      b'XERJ_DISABLE_FEEDBACK'):
            assert token in help_text
        argv = [str(binary), 'hub', 'feedback', 'synthetic-corpus',
                '--usefulness', '3', '--found', 'no']
        if proxy is not None:
            # A strictly synthetic isolated reflector, not a public endpoint.
            # TLS must fail because reflector is not a TLS/product service;
            # the host verifies a NEW actual CONNECT event, proving this real
            # native sender used HTTPS proxy transport. No fake TLS success.
            import ipaddress
            assert ipaddress.ip_address(proxy).is_private
            os.environ['XERJ_CORPUS_FEEDBACK_URL'] = 'https://fixture-upstream:8443/api/corpus-feedback'
            os.environ['XERJ_DISABLE_FEEDBACK'] = 'false'
            for name in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'):
                os.environ[name] = f'http://{proxy}:3128'
            os.environ['NO_PROXY'] = os.environ['no_proxy'] = 'localhost,127.0.0.1,::1'
            raw = command('real-native-https-proxy', argv, expected=1)
            stderr = (out/'real-native-https-proxy.stdout.stderr').read_bytes()
            assert b'xerj hub feedback:' in stderr and b'Nothing was sent' not in raw
            with lock:
                assert requests == []
            result.update(state='EXPECTED_SYNTHETIC_TLS_REFLECTOR_FAILURE',
                          onlyKnownManualSenderProved=True,
                          nativeTLSVerificationSuccessProved=False,
                          hostMustVerifyNewCONNECTEvent=True,
                          publicFeedback=False)
            return result
        os.environ['XERJ_DISABLE_FEEDBACK'] = 'false'
        command('real-local-positive', argv)
        with lock:
            assert len(requests) == 1
            positive = list(requests)
        os.environ['XERJ_DISABLE_FEEDBACK'] = 'true'
        raw = command('real-optout-negative', argv)
        assert b'Nothing was sent' in raw
        # Manual CLI sender is synchronous in admitted source. Pair completion
        # with a bounded post-completion observation; do not infer a global no-
        # telemetry property from this one sender's silence.
        end = min(hard-3, time.time()+2)
        assert end > time.time()+1
        while time.time() < end:
            time.sleep(.05)
        with lock:
            assert requests == positive
        result.update(state='PASS_REAL_LOCAL_SENDER_CONTROLS',
                      positivePosts=1, optoutAdditionalPosts=0,
                      binarySHA256=expected_sha, actualHelpGate=True,
                      onlyKnownManualSenderProved=True,
                      sourceParityOrAllSendersProved=False)
        return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        with lock:
            bounded.save(out/'sink-requests.json', requests)
        bounded.save(out/'result.json', result)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--hard', type=float, required=True)
    parser.add_argument('--proxy')
    args = parser.parse_args()
    run(args.binary, args.sha256, args.out, args.hard, args.proxy)
