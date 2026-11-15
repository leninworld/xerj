"""Read-only fixed-topology guard. No Docker, RPC or phase switching."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

MODE = 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'
HOSTS = ['xerj.org', 'github.com', 'release-assets.githubusercontent.com', 'hub.xerj.org']


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, expected, cap=131072):
    p = Path(path)
    assert p.is_file() and not p.is_symlink() and p.stat().st_size <= cap
    with p.open('rb') as stream:
        raw = stream.read(cap+1)
    assert len(raw) <= cap and digest(raw) == expected
    return json.loads(raw)


class LoopbackSink:
    """Diagnostic only, never a catalogue/product mock or a public sender."""
    def __init__(self, port, log):
        self.log = Path(log)
        assert not self.log.exists()
        self.stream = self.log.open('xb')
        self.lock = threading.Lock()
        self.count = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                assert self.client_address[0] == '127.0.0.1'
                with owner.lock:
                    owner.count += 1
                    ordinal = owner.count
                    if ordinal <= 8:
                        owner.stream.write((json.dumps({'at': time.time(), 'ordinal': ordinal,
                            'containmentHOLD': True, 'requestObservedBeforeBodyValidation': True,
                            'pathSHA256': digest(self.path.encode()),
                            'lengthHeaderSHA256': digest(self.headers.get('Content-Length', '').encode())})+'\n').encode())
                    elif ordinal == 9:
                        owner.stream.write(b'{"containmentHOLD":true,"sinkCapExhausted":true}\n')
                    owner.stream.flush()
                try:
                    size = int(self.headers.get('Content-Length', '-1'))
                except ValueError:
                    self.send_error(400)
                    return
                self.connection.settimeout(2)
                # Any POST is a containment finding. Hash first, before JSON,
                # shape or path validation; malformed input cannot erase it.
                raw = self.rfile.read(size) if 0 < size <= 16384 else b''
                with owner.lock:
                    record = {'at': time.time(), 'bytes': len(raw),
                              'sha256': digest(raw), 'declaredBytes': size,
                              'pathSHA256': digest(self.path.encode()),
                              'containmentHOLD': True, 'ordinal': ordinal}
                    if ordinal <= 8:
                        owner.stream.write((json.dumps(record)+'\n').encode())
                    owner.stream.flush()
                if not 0 < size <= 16384 or self.path != '/api/corpus-feedback':
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()

        self.server = HTTPServer(('127.0.0.1', port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.stream.close()


class Guard:
    def __init__(self, host_proof, host_sha, approval, approval_sha, sink_log):
        self.proof = load(host_proof, host_sha)
        self.approval = load(approval, approval_sha)
        self.host_sha, self.approval_sha = host_sha, approval_sha
        self.checkpoint_root = Path(sink_log).parent/'containment-checkpoints'
        self.checkpoint_root.mkdir(mode=0o700, exist_ok=False)
        self.checkpoint_count = 0
        self._active_record = None
        self.final_close_receipt = None
        p, a = self.proof, self.approval
        assert p['mode'] == a['mode'] == MODE
        assert a['claudeApproved'] is True and a['rootAgreement'] is True
        assert a['implementationSHA256'] == p['implementationSHA256']
        assert digest(json.dumps(p['implementationFiles'], sort_keys=True,
                                 separators=(',', ':')).encode()) == p['implementationSHA256']
        assert p['c2ApprovalReceiptSHA256'] == approval_sha
        assert p['allowedHosts'] == HOSTS
        assert p['limits'] == {'totalBytes': 268435456, 'connectionBytes': 67108864}
        assert p['nativeControls']['state'] == 'PASS_EARLY_LOCAL_AND_KERNEL_CONTROLS'
        assert p['nativeControls']['actualNativeFeedbackControlsPassed'] is True
        assert p['targetInternalNetworkCount'] == 1 and p['targetCapEff'] == '0000000000000000'
        assert p['resourcePartition']['targetMemoryBytes'] == 7936*1048576
        assert p['resourcePartition']['proxyMemoryBytes'] == 256*1048576
        assert p['resourcePartition']['aggregateMemoryBytes'] == 8589934592
        # Read-only proof mount is supplied by the host, not an expected PASS
        # produced by the guest. Actual kernel state must still match it.
        mounts = Path('/proc/self/mountinfo').read_text().splitlines()
        assert any(line.split()[4] == '/operator-proof' and
                   'ro' in line.split()[5].split(',') for line in mounts)
        for relative, row in p['guestCode'].items():
            path = Path('/packet')/relative
            assert path.is_file() and not path.is_symlink()
            assert path.stat().st_size == row['bytes']
            assert digest(path.read_bytes()) == row['sha256']
        for name, value in p['implementationFiles'].items():
            assert p['guestCode'][name]['sha256'] == value
        self.sink = LoopbackSink(p['feedbackSinkPort'], sink_log)
        try:
            self.guard('INSTALLER')
        except BaseException:
            self.sink.close()
            raise

    def child_environment_receipt(self):
        expected_endpoint = f"http://127.0.0.1:{self.proof['feedbackSinkPort']}/api/corpus-feedback".encode()
        result = []
        receipt = {'checkpointAt': time.time(), 'scanPerformed': True,
                   'processes': result, 'allLiveXerjMatched': False,
                   'shortLivedProcessesBetweenCheckpointsNotAttested': True}
        self._active_record['childEnvironmentCheckpoint'] = receipt
        # Bounded actual PID namespace, no host PID mount. Read every live xerj
        # executable (CLI/node/MCP/launcher descendant) at this checkpoint.
        candidates = sorted(p for p in Path('/proc').iterdir() if p.name.isdigit())
        assert len(candidates) <= 512
        for directory in candidates:
            try:
                exe = os.readlink(directory/'exe')
                comm = (directory/'comm').read_text().strip()
            except FileNotFoundError:
                continue
            if Path(exe.removesuffix(' (deleted)')).name not in ('xerj', 'xerj.exe') and not comm.startswith('xerj'):
                continue
            try:
                before = (directory/'stat').read_bytes()
                with (directory/'environ').open('rb') as stream:
                    raw = stream.read(131073)
                after = (directory/'stat').read_bytes()
            except FileNotFoundError:
                continue
            assert len(raw) <= 131072
            start_before = before.rsplit(b')', 1)[1].split()[19]
            start_after = after.rsplit(b')', 1)[1].split()[19]
            if start_before != start_after:
                continue  # PID replaced during sample, not proof about new PID.
            env = {}
            for part in raw.split(b'\0'):
                if part:
                    name, sep, value = part.partition(b'=')
                    assert sep and name not in env
                    env[name] = value
            result.append({'pid': int(directory.name), 'startTimeTicks': int(start_after),
                           'executablePathSHA256': digest(exe.encode()),
                           'environmentSHA256': digest(raw),
                           'optoutValueSHA256': digest(env.get(b'XERJ_DISABLE_FEEDBACK', b'')),
                           'sinkValueSHA256': digest(env.get(b'XERJ_CORPUS_FEEDBACK_URL', b'')),
                           'optoutCorrect': env.get(b'XERJ_DISABLE_FEEDBACK') == b'true',
                           'sinkCorrect': env.get(b'XERJ_CORPUS_FEEDBACK_URL') == expected_endpoint})
            assert result[-1]['optoutCorrect'], 'XERJ_CHILD_OPTOUT_MISSING_INFRA_HOLD'
            assert result[-1]['sinkCorrect'], 'XERJ_CHILD_SINK_MISSING_INFRA_HOLD'
        receipt.update(allLiveXerjMatched=True, matchedCount=len(result))
        return receipt

    def guard(self, phase):
        self.checkpoint_count += 1
        assert self.checkpoint_count <= 256
        record = {'phase': phase, 'at': time.time(), 'mode': MODE,
                  'ordinaryPhaseLabelsDoNotSwitchNetworks': True,
                  'parentOptoutValueSHA256': digest(os.environ.get('XERJ_DISABLE_FEEDBACK', '').encode()),
                  'parentSinkValueSHA256': digest(os.environ.get('XERJ_CORPUS_FEEDBACK_URL', '').encode())}
        self._active_record = record
        try:
            result = self._guard(phase)
            record['observedProof'] = result
            return result
        except BaseException as exc:
            record['infrastructureHOLD'] = type(exc).__name__
            raise
        finally:
            (self.checkpoint_root/f'{self.checkpoint_count:03d}.json').write_text(json.dumps(record, indent=2)+'\n')

    def _guard(self, phase):
        assert phase in ('INSTALLER', 'HUB', 'OFFLINE', 'CHECKPOINT')
        p = self.proof
        assert time.time() < p['hardEpoch']-6
        assert os.stat('/proc/self/ns/net').st_ino == p['networkNamespaceInode']
        route = Path('/proc/net/route').read_bytes()
        assert digest(route) == p['routeSHA256']
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                      if ':' in line)
        assert status['CapEff'].strip() == '0000000000000000'
        assert status['NoNewPrivs'].strip() == '1'
        memory = int(Path('/sys/fs/cgroup/memory.max').read_text())
        quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
        assert memory == p['resourcePartition']['targetMemoryBytes']
        assert quota != 'max' and int(quota)*4 == int(period)*7
        assert len(os.sched_getaffinity(0)) == 2
        proxy = p['proxyURL']
        for key in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'):
            assert os.environ.get(key) == proxy
        assert not os.environ.get('ALL_PROXY') and not os.environ.get('all_proxy')
        assert os.environ.get('NO_PROXY') == os.environ.get('no_proxy') == 'localhost,127.0.0.1,::1'
        assert os.environ.get('XERJ_DISABLE_FEEDBACK') == 'true'
        assert 'XERJ_HUB_PUBKEY' not in os.environ and 'XERJ_HUB_URL' not in os.environ
        assert 'XERJ_INSECURE_SKIP_CHECKSUM' not in os.environ
        endpoint = os.environ.get('XERJ_CORPUS_FEEDBACK_URL', '')
        assert endpoint == f"http://127.0.0.1:{p['feedbackSinkPort']}/api/corpus-feedback"
        url = urlsplit(endpoint)
        assert url.hostname == '127.0.0.1' and not url.username and not url.password
        with self.sink.lock:
            assert self.sink.count == 0, 'UNEXPECTED_FEEDBACK_DESPITE_OPTOUT_HOLD'
        child_receipt = self.child_environment_receipt()
        for key in os.environ:
            assert not any(t in key.upper() for t in ('TOKEN', 'PASSWORD', 'CREDENTIAL', 'API_KEY'))
        # Live, read-only proxy log. Actual host final inspection/stops remain
        # mandatory; log presence alone is not a process-liveness attestation.
        log = Path('/proxy-evidence/proxy/connections.jsonl')
        assert log.is_file() and not log.is_symlink() and log.stat().st_size <= 1048576
        with log.open('rb') as stream:
            raw = stream.read(1048577)
        assert len(raw) <= 1048576
        complete = raw[:raw.rfind(b'\n')+1]
        events = [json.loads(line) for line in complete.splitlines()]
        assert events and events[0]['kind'] == 'ready'
        assert events[0]['configSHA256'] == p['proxyConfigSHA256']
        assert events[0]['allowedHosts'] == HOSTS
        return {'mode': MODE, 'phase': phase, 'actualKernelEnforced': True,
                'connectionLoggingActive': True, 'allOtherEgressDenied': True,
                'helperExecutionNamespaceMatches': True,
                'sourceProvenOptOutApplied': True, 'feedbackEndpointLoopbackOnly': True,
                'actualNativeFeedbackControlsPassed': True,
                'fixedTopologyAcrossEntireFTX': True, 'projectTestsSeparateOffline': True,
                'projectTestsExecutionProvedByThisGuard': False,
                'allFourReviewedHostsPermittedFromStart': True,
                'hostAllowlistPhaseSpecific': False,
                'externalNetworkPhysicallyDisconnected': False,
                'encryptedPathBlocked': False, 'corpusFeedbackEndpointBlocked': False,
                'allowedHosts': HOSTS, 'limits': p['limits'],
                'c2ApprovalReceiptSHA256': self.approval_sha,
                'implementationSHA256': p['implementationSHA256'],
                'hostProofSHA256': self.host_sha, 'evidenceSHA256': self.host_sha,
                'targetContainerID': p['targetContainerID'],
                'networkNamespaceInode': p['networkNamespaceInode'],
                'currentRouteSHA256': digest(route),
                'publicSnapshotSHA256': p['publicSnapshotSHA256'],
                'publicPacketSHA256': p['publicPacketSHA256'],
                'resourcePartition': p['resourcePartition'],
                'offlineHandoffReceiptSHA256': p['offlineHandoffReceiptSHA256'],
                'nativeControlsSHA256': p['nativeControls']['receiptSHA256'],
                'kernelProofSHA256': p['kernelProofSHA256'],
                'actualTargetRoutingSHA256': p['actualTargetRoutingSHA256'],
                'sourceParityReceiptSHA256': p['sourceParityReceiptSHA256'],
                'feedbackEndpointURLSHA256': digest(endpoint.encode()),
                'currentProxyLogSHA256': digest(complete),
                'currentProxyLogBytes': len(complete),
                'childEnvironmentCheckpoint': child_receipt,
                'sinkLiveEntireFTX': self.thread_liveness(),
                'unexpectedSinkRequests': self.sink.count}

    def thread_liveness(self):
        assert self.sink.thread.is_alive()
        return True

    def close(self):
        if self.final_close_receipt is not None:
            assert not self.final_close_receipt['infrastructureHOLD'], 'FTX_CONTAINMENT_HOLD'
            return dict(self.final_close_receipt)
        alive_at_close = self.sink.thread.is_alive()
        # Finish any in-flight bounded request before reading final count; no
        # gap where a final request could escape the final containment verdict.
        self.sink.close()
        with self.sink.lock:
            count = self.sink.count
        receipt = {'mode': MODE, 'sinkLiveUntilFTXClose': alive_at_close,
                       'unexpectedSinkRequests': count, 'infrastructureHOLD': count != 0,
                       'checkpointCount': self.checkpoint_count}
        receipt['sinkLogSHA256'] = digest(self.sink.log.read_bytes())
        (self.sink.log.parent/'containment-final.json').write_text(json.dumps(receipt, indent=2)+'\n')
        self.final_close_receipt = dict(receipt)
        assert receipt['sinkLiveUntilFTXClose'] and count == 0, 'FTX_CONTAINMENT_HOLD'
        return receipt


def create(host_proof, host_sha, approval, approval_sha, sink_log):
    """Caller retains Guard, supplies guard.guard as FTX callable, closes finally."""
    return Guard(host_proof, host_sha, approval, approval_sha, sink_log)
