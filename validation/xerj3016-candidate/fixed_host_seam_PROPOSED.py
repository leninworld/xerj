"""Fixed FTX-only topology. Host setup/finally; guest never controls Docker.

Private authoring, UNRUN. No work on import. Uses the composed bounded Docker
control layer; no pull/install, account API, guest RPC or encrypted path filter.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time

import bounded
from fixed_docker_controls_PROPOSED import Controls

MODE = 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'
HOSTS = ['xerj.org', 'github.com', 'release-assets.githubusercontent.com', 'hub.xerj.org']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FixedSession(Controls):
    def __init__(self, config, root):
        super().__init__(config, root)
        assert config['allowedHosts'] == HOSTS
        assert config['ftxStartedAt'] <= time.time() < config['ftxStartedAt']+60
        self.ftx_hard = min(config['ftxStartedAt']+1200, config['originalTargetEpoch'],
                            config['originalHardEpoch']-180)
        self.end = self.ftx_hard-60
        assert self.end > time.time()+60
        self.proxy_name = self.target_name = None
        self.final_close_result = None

    def snapshot(self, kind):
        assert kind in ('inputs', 'packet')
        prefix = 'publicSnapshot' if kind == 'inputs' else 'publicPacket'
        root = Path(self.cfg[prefix+'Path'])
        assert root.is_dir() and not root.is_symlink()
        manifest = Path(self.cfg[prefix+'Manifest'])
        assert manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 262144
        raw = manifest.read_bytes()
        assert sha(raw) == self.cfg[prefix+'SHA256']
        rows = json.loads(raw)['files']
        assert 0 < len(rows) <= 512
        expected, total = {}, 0
        for row in rows:
            rel = row['path']
            assert isinstance(rel, str) and re.fullmatch(r'[A-Za-z0-9_./-]+', rel)
            assert not rel.startswith('/') and all(x not in ('', '.', '..', '.git', '.ssh',
                   '.netrc', '.env', '.git-credentials') for x in rel.split('/'))
            assert rel not in expected and type(row['bytes']) is int and 0 <= row['bytes'] <= 150000000
            path = root/rel
            assert all(not p.is_symlink() for p in [path, *path.parents] if p != root.parent)
            assert path.is_file() and path.stat().st_size == row['bytes']
            with path.open('rb') as stream:
                content = stream.read(row['bytes']+1)
            assert len(content) == row['bytes'] and sha(content) == row['sha256']
            expected[rel] = row
            total += row['bytes']
        assert total <= 268435456
        actual = set()
        for path in root.rglob('*'):
            assert not path.is_symlink() and path.name != '.git'
            if path.is_file():
                actual.add(path.relative_to(root).as_posix())
            else:
                assert path.is_dir(), 'NO_SPECIAL_FILE_OR_SOCKET_IN_PUBLIC_SNAPSHOT'
        self_manifest = set()
        if manifest.resolve().is_relative_to(root.resolve()):
            self_manifest = {manifest.resolve().relative_to(root.resolve()).as_posix()}
        assert actual == set(expected) | self_manifest
        if kind == 'packet':
            for name, digest in self.cfg['helperHashes'].items():
                assert expected[name]['sha256'] == digest
        return root.resolve(), expected

    def create(self, suffix, network, mounts, env, cpus, memory):
        name = self.cfg['namespace']+'-'+suffix
        self.containers.append(name)
        self.container_intents[name] = {'id': None, 'observed': False}
        args = ['docker', 'create', '--name', name, '--network', network,
                '--pull=never', '--platform', 'linux/arm64',
                '--entrypoint', 'python3',
                '--label', 'contribution.case=3016', '--label', 'contribution.run='+self.cfg['actualRunID'],
                '--label', 'contribution.nonce='+self.cfg['runNonce'],
                '--cpus', cpus, '--cpuset-cpus', self.cfg['cpuSet'],
                '--memory', memory, '--memory-swap', memory,
                '--pids-limit', '4096' if suffix == 'ftx-target' else '64',
                '--log-driver', 'none',
                '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--user', f'{os.getuid()}:{os.getgid()}']
        if suffix == 'ftx-target':
            args += ['--dns', '127.0.0.1']
        for source, target, readonly in mounts:
            assert ',' not in str(source)
            args += ['--mount', f'type=bind,src={source},dst={target}'+(',readonly' if readonly else '')]
        for key, value in env.items():
            assert re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key)
            assert not any(x in key.upper() for x in ('TOKEN', 'PASSWORD', 'CREDENTIAL', 'API_KEY'))
            args += ['--env', key+'='+value]
        args += [self.cfg['image'], '-c',
                 'import time,sys;time.sleep(max(0,float(sys.argv[1])-time.time()))', str(self.ftx_hard)]
        raw = self.call('create-'+suffix, args).decode().strip()
        assert re.fullmatch(r'[0-9a-f]{64}', raw)
        self.container_intents[name]['id'] = raw
        self.owned_item('created-'+suffix, name)
        self.call('start-'+suffix, ['docker', 'start', name])
        return name

    def prepare(self):
        """Return exact target and operator paths to the existing host runner."""
        image, = json.loads(self.call('fixed-image-inspect', ['docker', 'image', 'inspect', self.cfg['image']]))
        assert image['Id'] == self.cfg['imageID'] and image['Architecture'] == 'arm64'
        snapshot, rows = self.snapshot('inputs')
        packet, packet_rows = self.snapshot('packet')
        early_path = Path(self.cfg['earlyControlsReceiptPath'])
        assert early_path.is_file() and early_path.stat().st_size <= 131072
        early_raw = early_path.read_bytes()
        assert sha(early_raw) == self.cfg['earlyControlsReceiptSHA256']
        early = json.loads(early_raw)
        assert early['state'] == 'PASS_EARLY_LOCAL_AND_KERNEL_CONTROLS'
        assert early['nativeFeedbackControlsPassed'] is True and early['stopVerified'] is True
        assert early['C2Mode'] == MODE and early['encryptedPathBlocked'] is False
        # This receipt must belong to this implementation and same actual image;
        # the whole controller seals the raw early receipts, not caller booleans.
        assert self.cfg['earlyControlsImplementationSHA256'] == sha(json.dumps(
            self.cfg['helperHashes'], sort_keys=True, separators=(',', ':')).encode())
        assert early['implementationSHA256'] == self.cfg['earlyControlsImplementationSHA256']
        assert early['imageID'] == self.cfg['imageID']
        handoff_path = Path(self.cfg['offlineHandoffReceiptPath'])
        assert handoff_path.is_file() and handoff_path.stat().st_size <= 262144
        handoff_raw = handoff_path.read_bytes()
        assert sha(handoff_raw) == self.cfg['offlineHandoffReceiptSHA256']
        handoff = json.loads(handoff_raw)
        assert len(handoff['exactTestedNine']) == 9
        assert {r['upstreamPath'] for r in handoff['exactTestedNine']} == set(self.cfg['expectedNineUpstreamPaths'])
        assert len(set(self.cfg['expectedNineUpstreamPaths'])) == 9
        assert handoff['offlineStageImageID'] == self.cfg['imageID']
        assert handoff['offlineSourcePin'] == self.cfg['sourcePin']
        assert handoff['sourceBeforeManifestSHA256'] == handoff['sourceAfterOfflineManifestSHA256']
        for row in handoff['exactTestedNine']+handoff['baselineSurfaces']:
            actual = rows[row['path']]
            assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
        inside, outside = self.network('fixed-internal', True), self.network('fixed-egress', False)
        proxy_out = self.root/'proxy-output'
        proof_dir = self.root/'operator-proof'
        state = self.root/'target-state'
        for path in (proxy_out, proof_dir, state):
            path.mkdir(mode=0o700)
        for folder in ('home', 'tmp'):
            (proxy_out/folder).mkdir(mode=0o700)
        proxy_cfg_path = proof_dir/'proxy-config.json'
        # Proxy starts idle on internal network, then host records actual IP and
        # writes config before launching the helper. No guest-to-host seam.
        self.proxy_name = self.create('ftx-proxy', inside,
            [(packet, '/packet', True), (proxy_out, '/out', False),
             (proof_dir, '/operator-proof', True)],
             {'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/out/home', 'TMPDIR': '/out/tmp'}, '.25', '256m')
        self.proxy_out = proxy_out
        self.call('connect-fixed-proxy', ['docker', 'network', 'connect', outside, self.proxy_name])
        proxy_item, = json.loads(self.call('fixed-proxy-inspect', ['docker', 'inspect', self.proxy_name]))
        proxy_nets = proxy_item['NetworkSettings']['Networks']
        assert set(proxy_nets) == {inside, outside}
        proxy_ip = proxy_nets[inside]['IPAddress']
        assert proxy_ip
        proxy_cfg = {'schemaVersion': 1, 'executionApproved': True, 'c2AmendmentApproved': True,
                     'phase': 'product', 'hardEpoch': self.end, 'bindAddress': proxy_ip, 'port': 3128,
                     'allowedHosts': HOSTS, 'fixturePrivateAddress': None, 'maxConnections': 64,
                     'maxConcurrent': 4, 'maxTotalBytes': 268435456,
                     'maxConnectionBytes': 67108864, 'maxHeaderBytes': 8192,
                     'maxLogBytes': 1048576, 'maxEvents': 512, 'connectionSeconds': 120,
                     'connectSeconds': 20, 'headerSeconds': 10}
        bounded.save(proxy_cfg_path, proxy_cfg)
        proxy_config_sha = sha(proxy_cfg_path.read_bytes())
        self.call('launch-fixed-proxy', ['docker', 'exec', '-d', self.proxy_name, 'python3',
                  '/packet/fixed_connect_proxy_PROPOSED.py', '--config',
                  '/operator-proof/proxy-config.json', '--out', '/out/proxy'])
        self.wait_file(proxy_out/'proxy/connections.jsonl', lambda raw: b'"kind": "ready"' in raw)
        proxy_url = f'http://{proxy_ip}:3128'
        sink_port = 18765
        env = {'HOME': '/state/operator-home', 'TMPDIR': '/state/tmp',
               'PYTHONDONTWRITEBYTECODE': '1', 'XERJ_DISABLE_FEEDBACK': 'true',
               'XERJ_CORPUS_FEEDBACK_URL': f'http://127.0.0.1:{sink_port}/api/corpus-feedback',
               'NO_PROXY': 'localhost,127.0.0.1,::1', 'no_proxy': 'localhost,127.0.0.1,::1'}
        env.update({key: proxy_url for key in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy')})
        for name in ('operator-home', 'tmp'):
            (state/name).mkdir(mode=0o700)
        target_outputs = {}
        for name in ('work', 'out', 'private-evidence'):
            target_outputs[name] = state/name
            target_outputs[name].mkdir(mode=0o700)
        self.target_name = self.create('ftx-target', inside,
            [(snapshot, '/ftx-inputs', True), (packet, '/packet', True), (state, '/state', False),
             (proof_dir, '/operator-proof', True), (proxy_out, '/proxy-evidence', True)] +
             [(path, '/'+name, False) for name, path in target_outputs.items()],
            env, '1.75', '7936m')
        item, = json.loads(self.call('fixed-target-inspect', ['docker', 'inspect', self.target_name]))
        assert item['Image'] == proxy_item['Image'] == self.cfg['imageID']
        for value, nano, memory in ((item, 1750000000, 7936*1048576),
                                     (proxy_item, 250000000, 256*1048576)):
            host = value['HostConfig']
            assert host['NanoCpus'] == nano and host['Memory'] == host['MemorySwap'] == memory
            assert host['CpusetCpus'] == self.cfg['cpuSet']
        assert set(item['NetworkSettings']['Networks']) == {inside}
        hc = item['HostConfig']
        assert hc['Dns'] == ['127.0.0.1'] and hc['CapDrop'] == ['ALL'] and hc['Privileged'] is False
        assert not hc['PortBindings'] and not hc.get('Devices') and not hc.get('CapAdd')
        assert any(x in ('no-new-privileges', 'no-new-privileges:true') for x in hc['SecurityOpt'])
        assert len(item['Mounts']) == 8 and {m['Destination'] for m in item['Mounts']} == {
            '/ftx-inputs', '/packet', '/state', '/operator-proof', '/proxy-evidence',
            '/work', '/out', '/private-evidence'}
        assert all(m['RW'] is (m['Destination'] in ('/state', '/work', '/out', '/private-evidence'))
                   for m in item['Mounts'])
        assert hc['ReadonlyRootfs'] is True and proxy_item['HostConfig']['ReadonlyRootfs'] is True
        assert item['State']['Running'] is True
        self.exec('fixed-target-direct-denial', self.target_name,
                  ['python3', '/packet/transport_probe_PROPOSED.py', 'bypass',
                   '--out', '/state/operator-direct-denial.json'], seconds=25)
        route_bytes = self.exec('fixed-target-proxy-positive', self.target_name,
                  ['curl', '--fail', '--silent', '--show-error', '--location',
                   '--max-time', '15', '--max-filesize', '32768',
                   '--proxy', proxy_url, '--noproxy', '', 'https://xerj.org/get'], seconds=22)
        assert len(route_bytes) == self.cfg['installerBytes'] == 17290
        assert sha(route_bytes) == self.cfg['installerSHA256']
        direct_raw = (state/'operator-direct-denial.json').read_bytes()
        assert json.loads(direct_raw)['state'] == 'PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'
        paired_route = {'targetContainerID': item['Id'],
                        'directNegativeSHA256': sha(direct_raw),
                        'allowedProxyResponseSHA256': sha(route_bytes),
                        'actualPublicTLSPositive': True,
                        'notInferredFromINTERNALLabel': True}
        bounded.save(proof_dir/'actual-target-routing.json', paired_route)
        # Actual namespace inode, route and capability fields from this target.
        code = ('import os,pathlib,hashlib,json;'
                's=dict(x.split(":",1)for x in pathlib.Path("/proc/self/status").read_text().splitlines()if":"in x);'
                'print(json.dumps({"inode":os.stat("/proc/self/ns/net").st_ino,'
                '"routeSHA256":hashlib.sha256(pathlib.Path("/proc/net/route").read_bytes()).hexdigest(),'
                '"CapEff":s["CapEff"].strip(),"NoNewPrivs":s["NoNewPrivs"].strip()}))')
        kernel = json.loads(self.exec('fixed-target-kernel', self.target_name, ['python3', '-c', code]))
        assert kernel['CapEff'] == '0000000000000000' and kernel['NoNewPrivs'] == '1'
        pid = item['State']['Pid']
        assert pid > 0 and os.stat(f'/proc/{pid}/ns/net').st_ino == kernel['inode']
        bounded.save(proof_dir/'kernel-proof.json', {'target': item, 'proxy': proxy_item, 'kernel': kernel})
        parity = Path(self.cfg['sourceParityReceiptPath'])
        assert parity.is_file() and sha(parity.read_bytes()) == self.cfg['sourceParityReceiptSHA256']
        approval = Path(self.cfg['c2ApprovalReceiptPath']).read_bytes()
        (proof_dir/'c2-approval.json').write_bytes(approval)
        cap_path = Path(self.cfg['capApprovalReceiptPath'])
        assert cap_path.is_file() and cap_path.stat().st_size <= 65536
        cap_raw = cap_path.read_bytes()
        assert sha(cap_raw) == self.cfg['capApprovalReceiptSHA256']
        assert cap_raw == approval, 'ONE_EXACT_WHOLE_APPROVAL_BINDS_MODE_AND_CAPS'
        (proof_dir/'caps-approval.json').write_bytes(cap_raw)
        proof = {'schemaVersion': 1, 'mode': MODE,
                 'c2ApprovalReceiptSHA256': self.cfg['c2ApprovalReceiptSHA256'],
                 'implementationSHA256': self.cfg['earlyControlsImplementationSHA256'],
                 'implementationFiles': self.cfg['helperHashes'],
                 'allowedHosts': HOSTS, 'limits': {'totalBytes': 268435456, 'connectionBytes': 67108864},
                 'targetContainerID': item['Id'], 'targetImageID': item['Image'],
                 'networkNamespaceInode': kernel['inode'], 'routeSHA256': kernel['routeSHA256'],
                 'targetCapEff': kernel['CapEff'], 'targetInternalNetworkCount': 1,
                 'proxyURL': proxy_url, 'proxyConfigSHA256': proxy_config_sha,
                 'feedbackSinkPort': sink_port, 'hardEpoch': self.end,
                 'publicSnapshotSHA256': self.cfg['publicSnapshotSHA256'],
                 'publicPacketSHA256': self.cfg['publicPacketSHA256'],
                 'offlineHandoffReceiptSHA256': self.cfg['offlineHandoffReceiptSHA256'],
                 'exactTestedNine': handoff['exactTestedNine'],
                 'baselineSurfaces': handoff['baselineSurfaces'],
                 'guestCode': packet_rows,
                 'kernelProofSHA256': sha((proof_dir/'kernel-proof.json').read_bytes()),
                 'actualTargetRoutingSHA256': sha((proof_dir/'actual-target-routing.json').read_bytes()),
                 'sourceParityReceiptSHA256': self.cfg['sourceParityReceiptSHA256'],
                 'sourceParityNotBinaryAttestation': True,
                 'resourcePartition': {'targetNanoCPUs': 1750000000,
                     'targetMemoryBytes': 7936*1048576, 'proxyNanoCPUs': 250000000,
                     'proxyMemoryBytes': 256*1048576, 'aggregateCPUs': 2,
                     'aggregateMemoryBytes': 8589934592, 'cpuSet': self.cfg['cpuSet']},
                 'nativeControls': {'state': early['state'], 'actualNativeFeedbackControlsPassed': True,
                                    'receiptSHA256': self.cfg['earlyControlsReceiptSHA256']}}
        bounded.save(proof_dir/'host-proof.json', proof)
        return {'target': self.target_name, 'targetStateHostPath': str(state),
                'targetOutHostPath': str(target_outputs['out']),
                'targetPrivateHostPath': str(target_outputs['private-evidence']),
                'targetWorkHostPath': str(target_outputs['work']),
                'guestProofPath': '/operator-proof/host-proof.json',
                'guestProofSHA256': sha((proof_dir/'host-proof.json').read_bytes()),
                'guestApprovalPath': '/operator-proof/c2-approval.json',
                'guestApprovalSHA256': self.cfg['c2ApprovalReceiptSHA256'],
                'guestGuardModule': '/packet/fixed_guest_adapter_PROPOSED.py',
                'ftxOperationalEnd': self.end, 'ftxHardWithCleanup': self.ftx_hard}

    def close(self):
        """Call finally even if prepare/FTX fails; never grants a product pass."""
        if self.final_close_result is not None:
            assert not self.final_close_result['infrastructureHOLD'] and self.final_close_result['stopVerified']
            return dict(self.final_close_result)
        result = {'mode': MODE, 'fullProtocolPass': False, 'ownedStops': {},
                  'sourceHandoffUnchanged': False, 'infrastructureHOLD': False}
        try:
            if self.target_name:
                item, = json.loads(self.call('fixed-final-target-inspect',
                                            ['docker', 'inspect', self.target_name],
                                            seconds=min(12, self.ftx_hard-time.time()), cleanup=True))
                assert set(item['NetworkSettings']['Networks']) == {self.networks[0]}
            self.snapshot('inputs')
            self.snapshot('packet')
            result['sourceHandoffUnchanged'] = True
            if self.proxy_name:
                path = self.proxy_out/'proxy/connections.jsonl'
                assert path.stat().st_size <= 1048576
                events = [json.loads(line) for line in path.read_bytes().splitlines()]
                assert events and events[0]['kind'] == 'ready'
                pid = events[0]['proxyPID']
                assert type(pid) is int and pid > 1
                self.call('fixed-proxy-graceful-stop', ['docker', 'exec', self.proxy_name,
                          'python3', '-c', 'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)',
                          str(pid)], seconds=min(12, self.ftx_hard-time.time()), cleanup=True)
                finish = min(self.ftx_hard-6, time.time()+4)
                summary_path = self.proxy_out/'proxy/summary.json'
                while time.time() < finish and not summary_path.is_file():
                    time.sleep(.05)
                assert summary_path.is_file() and summary_path.stat().st_size <= 16384
                summary = json.loads(summary_path.read_bytes())
                final_events = [json.loads(line) for line in path.read_bytes().splitlines()]
                assert not summary['exhausted'] and summary['daemonWorkersStillAlive'] == 0
                assert summary['logBytes'] == path.stat().st_size
                assert summary['logEvents'] == len(final_events)
                assert summary['accountedBytes'] <= 268435456
                assert not any(e['kind'] in ('refused-or-failed', 'connection-cap-denied') for e in final_events)
                result['proxyFinalProof'] = {'summarySHA256': sha(summary_path.read_bytes()),
                    'logSHA256': sha(path.read_bytes()), 'actualPID': pid,
                    'finalSummaryReconciled': True, 'noProxyLimitOrFailure': True,
                    'currentPIDLivenessNotInferredFromReadyFile': True}
        except BaseException as exc:
            result['infrastructureHOLD'] = type(exc).__name__
        finally:
            for index, name in enumerate(reversed(self.containers)):
                try:
                    left = min(12, self.ftx_hard-time.time())
                    assert left > 6
                    owned = self.owned_item(f'fixed-owned-{index}', name, cleanup=True, seconds=left)
                    if owned is None:
                        result['ownedStops'][name] = {'absenceObserved': True,
                                                      'notInferredFromCreateFailure': True}
                        continue
                    self.call(f'fixed-stop-{index}', ['docker', 'stop', '--time', '2', owned['Id']],
                              seconds=left, cleanup=True)
                    raw = self.call(f'fixed-stop-inspect-{index}', ['docker', 'inspect', name],
                                    seconds=min(12, self.ftx_hard-time.time()), cleanup=True)
                    item, = json.loads(raw)
                    state = item['State']
                    result['ownedStops'][name] = state
                    assert state['Running'] is False and state['Restarting'] is False and state['Pid'] == 0
                except BaseException as exc:
                    result['ownedStops'].setdefault(name, {})['stopUnverified'] = type(exc).__name__
                    result['infrastructureHOLD'] = type(exc).__name__
            result['stopVerified'] = bool(self.containers) and all(
                x.get('Pid') == 0 and not x.get('stopUnverified') for x in result['ownedStops'].values())
            result['networksPreserved'] = self.networks
            result['ownedContainerIntents'] = self.container_intents
            result['ownedNetworkIntents'] = self.network_intents
            bounded.save(self.root/'fixed-final.json', result)
            self.final_close_result = dict(result)
        assert result['sourceHandoffUnchanged'] and result['stopVerified'] and not result['infrastructureHOLD']
        return result
