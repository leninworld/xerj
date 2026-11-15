"""Private disabled composition; run ONLY inside a future approved owned Linux VM.

Uses the unchanged I2 bounded.command primitive, no pull/install/restart/host UI.
The whole review must approve the C2 substitution and exact Docker composition.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time

import bounded
import release_head_PROPOSED as release_head


class Controls:
    def __init__(self, config, root):
        self.cfg = config
        assert os.uname().sysname == 'Linux' and os.uname().machine in ('aarch64', 'arm64')
        assert re.fullmatch(r'[0-9]+,[0-9]+', config['cpuSet'])
        cores = [int(x) for x in config['cpuSet'].split(',')]
        assert len(set(cores)) == 2 and set(cores) <= set(os.sched_getaffinity(0))
        assert config['executionApproved'] is True and config['rootAgreement'] is True
        assert config['c2AmendmentApproved'] is True
        assert config['c2Mode'] == 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'
        assert config['ordinaryConsumed'] == 2 and config['additionalAttemptApproved'] is True
        assert isinstance(config['originalHardEpoch'], (int, float))
        assert 40 < config['originalHardEpoch']-time.time() <= 3600
        self.end = min(config['originalHardEpoch']-180,
                       config['originalTargetEpoch'], time.time()+240)
        assert self.end > time.time()+30
        assert re.fullmatch(r'xerj3016-[a-z0-9-]{1,40}', config['namespace'])
        assert re.fullmatch(r'[0-9]+', config['actualRunID'])
        assert re.fullmatch(r'[0-9a-f]{8}', config['runNonce'])
        assert config['namespace'] == f"xerj3016-{config['actualRunID']}-{config['runNonce']}"
        assert os.environ.get('GITHUB_RUN_ID') == config['actualRunID']
        assert os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
        assert config['runtimeAttempt'] == 3 and config['runtimeBefore'] == 2
        assert re.fullmatch(r'(?:python@)?sha256:[0-9a-f]{64}', config['image'])
        assert re.fullmatch(r'sha256:[0-9a-f]{64}', config['imageID'])
        if config['image'].startswith('sha256:'):
            assert config['image'] == config['imageID']
        self.root = Path(root).resolve()
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.helpers = Path(__file__).resolve().parent
        assert ',' not in str(self.root) and ',' not in str(self.helpers)
        self.binary = Path(config['binaryHostPath']).resolve(strict=True)
        assert self.binary.is_file() and not Path(config['binaryHostPath']).is_symlink()
        assert self.binary.stat().st_size == 135764000
        assert re.fullmatch(r'[0-9a-f]{64}', config['binarySHA256'])
        assert hashlib.sha256(self.binary.read_bytes()).hexdigest() == config['binarySHA256']
        assert ',' not in str(self.binary)
        for name, digest in config['helperHashes'].items():
            assert '/' not in name and (self.helpers/name).is_file()
            assert hashlib.sha256((self.helpers/name).read_bytes()).hexdigest() == digest
        assert set(config['helperHashes']) == {
            'bounded.py', 'fixed_connect_proxy_PROPOSED.py',
            'native_local_controls_PROPOSED.py', 'transport_probe_PROPOSED.py',
            'fixed_docker_controls_PROPOSED.py', 'fixed_host_seam_PROPOSED.py',
            'fixed_guest_adapter_PROPOSED.py', 'release_head_PROPOSED.py'}
        # Actual future private authority must bind this exact composition;
        # booleans in a caller's config are not a substitute for that receipt.
        receipt_path = Path(config['c2ApprovalReceiptPath'])
        assert receipt_path.is_file() and not receipt_path.is_symlink()
        assert receipt_path.stat().st_size <= 65536
        receipt_raw = receipt_path.read_bytes()
        assert hashlib.sha256(receipt_raw).hexdigest() == config['c2ApprovalReceiptSHA256']
        receipt = json.loads(receipt_raw)
        implementation = hashlib.sha256(json.dumps(config['helperHashes'],
                                      sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        assert receipt['claudeApproved'] is True and receipt['rootAgreement'] is True
        assert receipt['mode'] == config['c2Mode']
        assert receipt['implementationSHA256'] == implementation
        assert re.fullmatch(r'[0-9a-f]{64}', receipt['actualVerdictSHA256'])
        self.commands = 0
        self.captured_bytes = 0
        self.containers = []
        self.networks = []
        self.container_intents = {}
        self.network_intents = {}
        self.result = {'state': 'INCOMPLETE', 'runtimeExecutedHere': True,
                       'encryptedPathBlocked': False, 'C2Mode': config['c2Mode'],
                       'implementationSHA256': implementation, 'imageID': config['imageID'],
                       'binarySHA256': config['binarySHA256']}

    def call(self, label, args, seconds=20, expected=0, cleanup=False):
        assert re.fullmatch(r'[a-z0-9-]+', label)
        assert self.commands < 160
        left = min(seconds, (self.cfg['originalHardEpoch'] if cleanup else self.end)-time.time())
        assert left > 6
        output_limit = 8388608 if cleanup else 7340032
        cap = min(262144, output_limit-self.captured_bytes)
        assert cap > 0
        self.commands += 1
        record = {'argv': args, 'expected': expected, 'complete': False}
        began = time.monotonic()
        try:
            raw = bounded.command(args, left-6, cap,
                                  guard=lambda: bounded.limit(
                                      time.time() < (self.cfg['originalHardEpoch'] if cleanup else self.end)-2,
                                      'ORIGINAL_CONTAINMENT_CLOCK'),
                                  expected=expected, log=self.root/(label+'.stdout'))
            record.update(complete=True, exit=expected)
            return raw
        finally:
            self.captured_bytes += sum(p.stat().st_size for p in (
                self.root/(label+'.stdout'), self.root/(label+'.stdout.stderr')) if p.is_file())
            assert self.captured_bytes <= output_limit
            record['seconds'] = time.monotonic()-began
            bounded.save(self.root/(label+'.json'), record)

    def network(self, suffix, internal):
        name = self.cfg['namespace']+'-'+suffix
        self.networks.append(name)
        self.network_intents[name] = {'id': None, 'observed': False}
        args = ['docker', 'network', 'create', '--driver', 'bridge',
                '--label', 'contribution.case=3016', '--label', 'contribution.run='+self.cfg['actualRunID'],
                '--label', 'contribution.nonce='+self.cfg['runNonce']]
        if internal:
            args += ['--internal']
        args += [name]
        raw = self.call('create-net-'+suffix, args).decode().strip()
        assert re.fullmatch(r'[0-9a-f]{64}', raw)
        self.network_intents[name]['id'] = raw
        value = json.loads(self.call('inspect-net-'+suffix,
                                    ['docker', 'network', 'inspect', name]))
        assert len(value) == 1 and value[0]['Name'] == name
        assert value[0]['Id'] == raw
        labels = value[0]['Labels']
        assert labels['contribution.case'] == '3016' and labels['contribution.run'] == self.cfg['actualRunID']
        assert labels['contribution.nonce'] == self.cfg['runNonce']
        self.network_intents[name]['observed'] = True
        assert value[0]['Internal'] is internal and value[0]['EnableIPv6'] is False
        return name

    def container(self, suffix, network, cpus, memory, extra=None, resolver=False):
        name = self.cfg['namespace']+'-'+suffix
        # Intent precedes the daemon mutation. A client timeout can follow
        # successful create; cleanup may inspect only this exact labelled name.
        self.containers.append(name)
        self.container_intents[name] = {'id': None, 'observed': False}
        out = self.root/suffix
        out.mkdir(mode=0o700)
        (out/'tmp').mkdir(mode=0o700)
        args = ['docker', 'create', '--name', name, '--network', network,
                '--pull=never', '--platform', 'linux/arm64', '--log-driver', 'none',
                '--entrypoint', 'python3',
                '--read-only',
                '--label', 'contribution.case=3016', '--label', 'contribution.run='+self.cfg['actualRunID'],
                '--label', 'contribution.nonce='+self.cfg['runNonce'],
                '--cpus', cpus, '--cpuset-cpus', self.cfg['cpuSet'],
                '--memory', memory, '--memory-swap', memory,
                '--pids-limit', '64', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges',
                '--user', f'{os.getuid()}:{os.getgid()}',
                '--env', 'HOME=/out/home', '--env', 'TMPDIR=/out/tmp', '--env', 'PYTHONDONTWRITEBYTECODE=1',
                '--mount', f'type=bind,src={self.helpers},dst=/helpers,readonly',
                '--mount', f'type=bind,src={out},dst=/out',
                '--mount', f'type=bind,src={self.binary},dst=/opt/ftx/xerj,readonly']
        if not resolver:
            args += ['--dns', '127.0.0.1']
        if extra:
            args += extra
        args += [self.cfg['image'], '-c',
                 'import time,sys;time.sleep(max(0,float(sys.argv[1])-time.time()))',
                 str(self.cfg['originalHardEpoch'])]
        raw = self.call('create-'+suffix, args).decode().strip()
        assert re.fullmatch(r'[0-9a-f]{64}', raw)
        self.container_intents[name]['id'] = raw
        self.owned_item('created-'+suffix, name)
        self.call('start-'+suffix, ['docker', 'start', name])
        return name, out

    def inspect(self, label, name, networks, resolver=False):
        item, = json.loads(self.call(label, ['docker', 'inspect', name]))
        self.owned_identity(item, name)
        assert item['Image'] == self.cfg['imageID']
        actual = item['NetworkSettings']['Networks']
        assert set(actual) == set(networks)
        host = item['HostConfig']
        assert host['Privileged'] is False and host['CapDrop'] == ['ALL']
        assert host['ReadonlyRootfs'] is True
        assert any(x in ('no-new-privileges', 'no-new-privileges:true') for x in host['SecurityOpt'])
        assert host['Dns'] == ([] if resolver else ['127.0.0.1']) and not host['PortBindings']
        assert not host.get('Devices') and not host.get('CapAdd')
        assert all(m['Destination'] in ('/helpers', '/out', '/opt/ftx/xerj')
                   for m in item['Mounts'])
        return actual

    def owned_identity(self, item, name):
        assert name in self.container_intents
        labels = item['Config']['Labels']
        assert labels.get('contribution.case') == '3016'
        assert labels.get('contribution.run') == self.cfg['actualRunID']
        assert labels.get('contribution.nonce') == self.cfg['runNonce']
        assert item['Name'] == '/'+name and item['Image'] == self.cfg['imageID']
        wanted = self.container_intents[name]['id']
        assert wanted is None or item['Id'] == wanted
        self.container_intents[name].update(id=item['Id'], observed=True)

    def owned_item(self, label, name, cleanup=False, seconds=20):
        ids = self.call(label+'-presence', ['docker', 'ps', '-a', '--filter',
                        'name=^/'+name+'$', '--format', '{{.ID}}'],
                        cleanup=cleanup, seconds=seconds).splitlines()
        if not ids:
            self.container_intents[name]['absenceObservedAt'] = time.time()
            return None
        assert len(ids) == 1
        item, = json.loads(self.call(label+'-identity', ['docker', 'inspect', name],
                                   cleanup=cleanup, seconds=seconds))
        self.owned_identity(item, name)
        return item

    def exec(self, label, name, argv, seconds=25):
        return self.call(label, ['docker', 'exec', name]+argv, seconds=seconds)

    def wait_file(self, path, predicate, seconds=5):
        end = min(self.end-6, time.time()+seconds)
        while time.time() < end:
            if path.is_file() and path.stat().st_size <= 1048576:
                try:
                    value = path.read_bytes()
                    if predicate(value):
                        return value
                except (OSError, ValueError):
                    pass
            time.sleep(.05)
        raise AssertionError('EXPECTED_ACTUAL_CONTROL_RECEIPT_MISSING')

    def proxy(self, suffix, inside, outside, fixture_ip=None, **changes):
        name, out = self.container(suffix, inside, '.25', '128m', resolver=True)
        if outside:
            self.call('connect-'+suffix, ['docker', 'network', 'connect', outside, name])
        nets = self.inspect('topology-'+suffix, name, [inside]+([outside] if outside else []), resolver=True)
        ip = nets[inside]['IPAddress']
        assert ip
        cfg = {'schemaVersion': 1, 'executionApproved': True,
               'c2AmendmentApproved': True, 'phase': 'fixture' if fixture_ip else 'product',
               'hardEpoch': min(self.end-6, time.time()+90), 'bindAddress': ip, 'port': 3128,
               'allowedHosts': ['fixture-upstream'] if fixture_ip else self.cfg['allowedHosts'],
               'fixturePrivateAddress': fixture_ip,
               'maxConnections': 64, 'maxConcurrent': 4, 'maxTotalBytes': 268435456,
               'maxConnectionBytes': 67108864, 'maxHeaderBytes': 8192,
               'maxLogBytes': 1048576, 'maxEvents': 512,
               'connectionSeconds': 20, 'connectSeconds': 5, 'headerSeconds': 2}
        cfg.update(changes)
        bounded.save(out/'config.json', cfg)
        self.call('launch-'+suffix, ['docker', 'exec', '-d', name, 'python3',
                                    '/helpers/fixed_connect_proxy_PROPOSED.py', '--config',
                                    '/out/config.json', '--out', '/out/proxy'])
        self.wait_file(out/'proxy/connections.jsonl', lambda raw: b'"kind": "ready"' in raw)
        return name, out, ip

    def graceful_proxy(self, label, name, out):
        """Same real SIGTERM/finally path production uses; evidence before stop."""
        path = out/'proxy/connections.jsonl'
        assert path.stat().st_size <= 1048576
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        assert events and events[0]['kind'] == 'ready'
        pid = events[0]['proxyPID']
        assert type(pid) is int and pid > 1
        self.call(label+'-signal', ['docker', 'exec', name, 'python3', '-c',
                  'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGTERM)', str(pid)])
        summary_raw = self.wait_file(out/'proxy/summary.json', lambda raw: bool(json.loads(raw)), seconds=4)
        summary = json.loads(summary_raw)
        final = path.read_bytes()
        assert summary['daemonWorkersStillAlive'] == 0
        assert summary['logBytes'] == len(final)
        assert summary['logEvents'] == len(final.splitlines())
        assert summary['configSHA256'] == hashlib.sha256((out/'config.json').read_bytes()).hexdigest()
        bounded.save(out/'actual-graceful-finalization.json',
                     {'summarySHA256': hashlib.sha256(summary_raw).hexdigest(),
                      'logSHA256': hashlib.sha256(final).hexdigest(),
                      'actualProxyPID': pid, 'realSIGTERMFinallyObserved': True,
                      'intentionalFixtureRefusalsNotProductFailures': True})
        return summary

    def release_head_routes(self, target, target_out, proxy_ip):
        """One real HEAD per pinned asset; only sanitized stdout is public."""
        receipts = []
        for kind in ('archive', 'checksum'):
            label = 'release-head-'+kind
            output = b''
            failure = None
            try:
                output = self.exec(label, target,
                    ['python3', '/helpers/release_head_PROPOSED.py', '--capture', kind,
                     '--proxy', f'http://{proxy_ip}:3128', '--private',
                     '/out/private-release-head-'+kind, '--hard', str(self.end-6)], seconds=28)
            except BaseException as exc:
                failure = exc
                path = self.root/(label+'.stdout')
                if path.is_file() and path.stat().st_size <= 32768:
                    output = path.read_bytes()
            # Capture wrapper never prints raw headers, Locations or effective
            # URLs. A failed/partial wrapper cannot be mistaken for a valid row.
            try:
                receipt = json.loads(output)
            except (ValueError, UnicodeError):
                receipt = {'schemaVersion': 1, 'assetKind': kind, 'complete': False,
                           'classification': 'INFRASTRUCTURE_UNVERIFIED',
                           'failureCode': 'HEAD_CAPTURE_NO_SANITIZED_RECEIPT'}
            command = self.root/(label+'.json')
            if command.is_file() and command.stat().st_size <= 262144:
                receipt['privateCommandReceiptSHA256'] = hashlib.sha256(command.read_bytes()).hexdigest()
            bounded.save(target_out/('release-route-'+kind+'.json'), receipt)
            receipts.append(receipt)
            if failure is not None or receipt.get('complete') is not True:
                if failure is not None and not isinstance(failure, Exception):
                    raise failure
                # Do not chain an exception whose curl output might have URLs.
                raise ValueError('RELEASE_HEAD_ROUTE_INFRASTRUCTURE_HOLD') from None
        self.result['releaseRoutePreflight'] = {
            'archiveAndChecksumHEADVerified': True, 'headRequests': 2,
            'beforeCostlyOfflineWork': True, 'signedURLsPubliclyExported': False,
            'receipts': {row['assetKind']: hashlib.sha256(
                (target_out/('release-route-'+row['assetKind']+'.json')).read_bytes()).hexdigest()
                for row in receipts}}
        return receipts

    def run(self):
        try:
            image, = json.loads(self.call('image-identity', ['docker', 'image', 'inspect', self.cfg['image']]))
            assert image['Id'] == self.cfg['imageID'] and image['Architecture'] == 'arm64'
            # First real controls cannot reach ANY external network.
            native, native_out = self.container('native', 'none', '1', '512m')
            self.inspect('topology-native', native, ['none'])
            self.exec('native-local-controls', native, ['python3',
                      '/helpers/native_local_controls_PROPOSED.py', '--binary', '/opt/ftx/xerj',
                      '--sha256', self.cfg['binarySHA256'], '--out', '/out/proof',
                      '--hard', str(min(self.end-6, time.time()+70))], seconds=75)
            native_proof = json.loads((native_out/'proof/result.json').read_bytes())
            assert native_proof['state'] == 'PASS_REAL_LOCAL_SENDER_CONTROLS'
            self.call('stop-native', ['docker', 'stop', '--time', '2', native])

            inside = self.network('internal', True)
            fixture_net = self.network('fixture-upstream', True)
            # Isolated reflector is not a product or catalogue endpoint. It is
            # never mounted into persona state or used to claim product success.
            reflector, reflector_out = self.container('reflector', fixture_net, '.25', '128m')
            self.call('reflector-launch', ['docker', 'exec', '-d', reflector, 'python3',
                      '/helpers/transport_probe_PROPOSED.py', 'reflect', '--hard', str(self.end-6),
                      '--out', '/out/reflector-ready.json'])
            self.wait_file(reflector_out/'reflector-ready.json',
                           lambda raw: json.loads(raw)['state'] == 'BOUND_OWNED_SYNTHETIC_REFLECTOR')
            reflected = self.inspect('topology-reflector', reflector, [fixture_net])
            fixture_ip = reflected[fixture_net]['IPAddress']
            proxy, proxy_out, proxy_ip = self.proxy('fixture-proxy', inside, fixture_net, fixture_ip)
            target, target_out = self.container('target', inside, '1', '512m')
            self.inspect('topology-target', target, [inside])
            self.exec('synthetic-transport', target, ['python3', '/helpers/transport_probe_PROPOSED.py',
                      'target', '--proxy', proxy_ip, '--out', '/out/transport.json'])
            transport = json.loads((target_out/'transport.json').read_bytes())
            assert transport['state'] == 'PASS_SYNTHETIC_CONNECT_CASES'
            assert len(transport['cases']) == 9

            expected = {'connection-bytes': 'CONNECTION_BYTE_CAP',
                        'total-bytes': 'TOTAL_BYTE_CAP',
                        'header-time': 'HEADER_TIMEOUT',
                        'connection-time': 'CONNECTION_TIMEOUT'}
            for n, reason in expected.items():
                change = {'maxConnectionBytes': 128} if n == 'connection-bytes' else \
                         {'maxTotalBytes': 256} if n == 'total-bytes' else \
                         {'headerSeconds': 1} if n == 'header-time' else {'connectionSeconds': 1}
                boundary_proxy, o, ip = self.proxy(n, inside, fixture_net, fixture_ip, **change)
                self.exec('exercise-'+n, target, ['python3', '/helpers/transport_probe_PROPOSED.py',
                          'boundary', '--proxy', ip, '--kind', n, '--out', '/out/'+n+'.json'])
                raw = self.wait_file(o/'proxy/connections.jsonl', lambda data: reason.encode() in data)
                assert reason.encode() in raw
                self.graceful_proxy('finalize-'+n, boundary_proxy, o)
                self.call('stop-'+n, ['docker', 'stop', '--time', '2', boundary_proxy])

            # Paired routing oracle: this exact owned private service is
            # reachable via proxy from target, but unreachable directly from
            # target's different internal bridge. Not merely public outage.
            self.exec('paired-private-direct-denial', target,
                      ['python3', '/helpers/transport_probe_PROPOSED.py', 'paired',
                       '--proxy', proxy_ip, '--upstream', fixture_ip,
                       '--out', '/out/paired.json'])
            proxy_before = (proxy_out/'proxy/connections.jsonl').stat().st_size
            self.exec('native-https-proxy-transport', target,
                      ['python3', '/helpers/native_local_controls_PROPOSED.py',
                       '--binary', '/opt/ftx/xerj', '--sha256', self.cfg['binarySHA256'],
                       '--out', '/out/native-proxy-proof', '--hard', str(min(self.end-6, time.time()+30)),
                       '--proxy', proxy_ip], seconds=35)
            new_native_log = self.wait_file(proxy_out/'proxy/connections.jsonl',
                           lambda data: b'"kind": "allowed"' in data[proxy_before:] and
                           b'"host": "fixture-upstream"' in data[proxy_before:])
            assert b'"kind": "allowed"' in new_native_log[proxy_before:]
            native_transport = json.loads((target_out/'native-proxy-proof/result.json').read_bytes())
            assert native_transport['state'] == 'EXPECTED_SYNTHETIC_TLS_REFLECTOR_FAILURE'
            self.graceful_proxy('finalize-fixture-proxy', proxy, proxy_out)
            self.call('stop-fixture-proxy', ['docker', 'stop', '--time', '2', proxy])
            self.call('stop-reflector', ['docker', 'stop', '--time', '2', reflector])

            # Proxy outbound route is enabled only after no-network native and
            # isolated transport controls pass. No product Hub call occurs here.
            egress = self.network('egress', False)
            real_proxy, real_out, real_ip = self.proxy('real-proxy', inside, egress)
            self.inspect('topology-target-before-direct', target, [inside])
            self.exec('direct-egress-negative', target, ['python3', '/helpers/transport_probe_PROPOSED.py',
                      'bypass', '--out', '/out/direct.json'], seconds=25)
            direct = json.loads((target_out/'direct.json').read_bytes())
            assert direct['state'] == 'PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'
            url = self.cfg['allowedControlURL']
            assert url == 'https://xerj.org/get'
            raw = self.exec('real-curl-proxy-positive', target,
                            ['curl', '--fail', '--silent', '--show-error', '--location',
                             '--max-time', '15', '--max-filesize', '32768',
                             '--proxy', f'http://{real_ip}:3128', '--noproxy', '', url], seconds=22)
            assert len(raw) == self.cfg['installerBytes'] == 17290
            assert hashlib.sha256(raw).hexdigest() == self.cfg['installerSHA256']
            log = (real_out/'proxy/connections.jsonl').read_bytes()
            assert b'"kind": "allowed"' in log and b'"host": "xerj.org"' in log
            self.release_head_routes(target, target_out, real_ip)
            self.graceful_proxy('finalize-real-proxy', real_proxy, real_out)
            # Remove target networking, preserve loopback, prove state. No
            # service or network is deleted; owner stops remain in final proof.
            self.call('target-disconnect', ['docker', 'network', 'disconnect', inside, target])
            item, = json.loads(self.call('topology-offline', ['docker', 'inspect', target]))
            assert item['NetworkSettings']['Networks'] == {}
            self.result.update(state='PASS_EARLY_LOCAL_AND_KERNEL_CONTROLS',
                               nativeFeedbackControlsPassed=True,
                               proxyCurlTLSControlPassed=True,
                               directEgressNegativePassed=True,
                               actualTargetDisconnected=True,
                               nativeHTTPSProxyCONNECTObserved=True,
                               nativeHTTPSApplicationSuccess='UNPROVED_UNTIL_REAL_HUB_PATH',
                               requiredProductHubCallsExecuted=False,
                               encryptedPathBlocked=False)
            return self.result
        finally:
            stops = {}
            for index, name in enumerate(reversed(self.containers)):
                try:
                    owned = self.owned_item(f'cleanup-owned-{index}', name, cleanup=True, seconds=12)
                    if owned is None:
                        stops[name] = {'absenceObserved': True,
                                       'notInferredFromCreateFailure': True}
                        continue
                    self.call(f'cleanup-stop-{index}', ['docker', 'stop', '--time', '2', owned['Id']],
                              seconds=12, cleanup=True)
                    value, = json.loads(self.call(f'cleanup-inspect-{index}',
                                                ['docker', 'inspect', name],
                                                seconds=12, cleanup=True))
                    state = value['State']
                    stops[name] = {'Running': state['Running'], 'Restarting': state['Restarting'],
                                   'Pid': state['Pid'], 'OOMKilled': state['OOMKilled'],
                                   'ExitCode': state['ExitCode']}
                    assert not state['Running'] and not state['Restarting'] and state['Pid'] == 0
                except BaseException as exc:
                    stops[name] = {'stopUnverified': type(exc).__name__}
            self.result.update(commands=self.commands, ownedStops=stops,
                               capturedCommandBytes=self.captured_bytes,
                               stopVerified=(len(stops) == len(self.containers) and all(
                                   x.get('Pid') == 0 and x.get('Running') is False and
                                   x.get('Restarting') is False for x in stops.values())),
                               ownedNetworksPreserved=self.networks,
                               ownedContainerIntents=self.container_intents,
                               ownedNetworkIntents=self.network_intents,
                               noDeletionOrPrune=True,
                               fullProtocolPass=False)
            if not self.result['stopVerified']:
                self.result['state'] = 'HOLD_OWNED_STOP_PROOF_INCOMPLETE'
            bounded.save(self.root/'terminal.json', self.result)


def run(config, root):
    return Controls(config, root).run()
