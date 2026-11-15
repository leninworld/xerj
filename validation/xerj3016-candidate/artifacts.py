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


FTX_NINE_PATHS = (
    'docs/recipes/hybrid-search.md', 'landing/docs/recipes/hybrid-search.html',
    'content/answers/reciprocal-rank-fusion-when-to-use.md', 'landing/llms.txt', 'landing/llms-full.txt',
    'landing/answers/reciprocal-rank-fusion-when-to-use.html',
    'landing/answers/reciprocal-rank-fusion-when-to-use.md', 'landing/answers/index.html', 'landing/answers/index.json',
)
FTX_SPLIT_CORE_FILES = (
    'offline-required-result.json', 'ftx-handoff-manifest.json', 'ftx-handoff-identity.json',
    'ftx-route-completion.json', 'result.json', 'candidate-source-proof.json',
    'candidate-source-manifest.json', 'final-source-manifest.json', 'post-ftx-source-manifest.json',
    'runtime-control-binary-proof.json', 'runtime-control-offline-network.json',
    'post-ftx-offline-network.json', 'offline-container-image-identity.json',
    'preflight-binary-version.json', 'preflight-binary-version.stdout', 'preflight-binary-version.stdout.stderr',
    'prepare-runtime-controls-resources.json', 'finalize-ftx-resources.json', 'ftx-only-resources.json',
)


def _ftx_split_core(root, indexed, binding):
    assert set(FTX_SPLIT_CORE_FILES) <= set(indexed), 'FTX_REQUIRED_SPLIT_PROOF_MISSING'
    def load(name):
        return json.loads((root/name).read_bytes())
    offline = load('offline-required-result.json')
    assert offline['state'] == 'OFFLINE_REQUIRED_CHECKS_COMPLETE_FTX_PENDING'
    assert offline['seoCommands'] == 19 and offline['lightCommands'] == 9 and offline['mechanicsCases'] == 4
    assert offline['candidatePass'] is False and offline['ftxComplete'] is False and offline['baselineOnly'] is False
    assert offline['sourcePin'] == binding['sourcePin']
    nine = offline['ninePathHashes']
    assert set(nine) == set(FTX_NINE_PATHS)
    for value in nine.values(): _ftx_digest(value)
    handoff = load('ftx-handoff-manifest.json')
    identity = load('ftx-handoff-identity.json')
    assert handoff['schemaVersion'] == 1 and handoff['sourcePin'] == binding['sourcePin']
    assert handoff['finalNineHashes'] == nine
    assert identity['sha256'] == indexed['ftx-handoff-manifest.json']['sha256'] == offline['handoffSHA256']
    assert identity['copiedBeforeOfflineStopRequired'] is True
    rows = handoff['files']
    _ftx_ids(rows, 'path')
    assert len(rows) == identity['files'] == 23
    assert sum(row['bytes'] for row in rows) == identity['bytes']
    by_name = {row['path']: row for row in rows}
    for row in rows:
        relative(row['path']); assert type(row['bytes']) is int and row['bytes'] >= 0
        _ftx_digest(row['sha256'])
    for name, value in nine.items():
        assert by_name['candidate/'+name]['sha256'] == value
    assert handoff['publicInputsOnly'] is True and handoff['noGitOrCredentialsCopied'] is True
    assert handoff['sameDerivedImageRequired'] is True
    assert handoff['binarySHA256'] == binding['binarySHA256'] == by_name['binary/xerj']['sha256']
    baselines = {name: row['sha256'] for name, row in by_name.items() if name.startswith('baseline-surfaces/')}
    assert len(baselines) == 3
    assert set(baselines.values()) == set(handoff['baselineSurfaceHashes'].values())
    completion = load('ftx-route-completion.json')
    assert completion['state'] == 'FULL_FTX_COMPLETED_REQUIRES_FINAL_SOURCE_CHECK'
    assert completion['handoffSHA256'] == identity['sha256'] and completion['finalNineHashes'] == nine
    assert completion['c2Mode'] == binding['c2Mode'] and completion['c2CloseProofRequired'] is True
    assert completion['sourceInvariantNotClaimedYet'] is True
    final = load('result.json')
    assert final['state'] == 'CANDIDATE_REQUIRED_CHECKS_COMPLETED_FULL_FTX'
    assert final['ftxComplete'] is True and final['postFTXAllSourceUnchanged'] is True
    assert final['ftxOutcome'] == 'NO_OBSERVED_REGRESSION_WITH_LOSSES' == load('ftx-comparison.json')['outcome']
    assert final['candidatePass'] is False and final['fullFinalReviewPending'] is True
    assert final['ninePathHashes'] == nine
    assert load('candidate-source-proof.json')['finalNineHashes'] == nine
    assert indexed['candidate-source-manifest.json']['sha256'] == indexed['final-source-manifest.json']['sha256'] == indexed['post-ftx-source-manifest.json']['sha256'], 'FTX_POST_SOURCE_CHANGED'
    binary = load('runtime-control-binary-proof.json')
    assert binary['sha256'] == binding['binarySHA256'] and binary['archiveSHA256'] == binding['releaseArchiveSHA256']
    assert binary['versionSHA256'] == indexed['preflight-binary-version.stdout']['sha256']
    assert binary['beforeCostlyOfflineSteps'] is True and binary['sameOriginalClock'] is True
    initial=load('initial-runtime-controls/runtime-control-binary-proof.json')
    for key in ('sha256','archiveSHA256','versionSHA256'):
        assert initial[key] == binary[key], 'REPEATED_DATA_PREPARATION_BINARY_DRIFT'
    assert indexed['initial-runtime-controls/preflight-binary-version.stdout']['sha256'] == indexed['preflight-binary-version.stdout']['sha256']
    image = load('offline-container-image-identity.json')
    assert image['identityVerifiedByHost'] is True
    assert isinstance(image['actualImageID'], str) and image['actualImageID'].startswith('sha256:')
    _ftx_digest(image['actualImageID'][7:])
    fallback = {'tunl0','gre0','gretap0','erspan0','sit0','ip6tnl0','ip6gre0','ip_vti0','ip6_vti0'}
    for name in ('runtime-control-offline-network.json', 'post-ftx-offline-network.json'):
        network = load(name)
        assert 'lo' in network['interfaces']
        assert network['IPv4_default_routes'] == network['IPv6_non_loopback_default_routes'] == 0
        assert all(key in fallback and state == 'down' for key, state in network['non_loopback'].items())
    return {'exactNine': nine, 'handoffSHA256': identity['sha256'], 'offlineAndPostSourceReceiptsBound': True}


FTX_FIXED_ROLES = (
    'EARLY_NATIVE','EARLY_NATIVE_PROXY','EARLY_TRANSPORT','EARLY_PROXY','EARLY_STOP','EARLY_TERMINAL',
    'HOST_PROOF','KERNEL_PROOF','TARGET_ROUTING','C2_APPROVAL','PROXY_CONFIG','PROXY_FINAL','PROXY_LOG',
    'HOST_FINAL','HOST_STOP','GUEST_CHECKPOINT_BUNDLE','GUEST_FINAL','GUEST_SINK','SOURCE_PARITY','RELEASE_ROUTE',
)
FTX_FIXED_ADJUNCTS = (
    'offline-stop-before-native-controls.json','resume-after-native-controls-offline-proof.json',
    'offline-stop-before-ftx.json','resume-after-ftx-offline-proof.json',
    'fixed-early-controls.json','fixed-ftx-host-final.json','fixed-ftx-forwarded-evidence.json',
) + tuple('initial-runtime-controls/'+name for name in (
    'runtime-control-binary-proof.json','runtime-control-offline-network.json','actual-elf.json',
    'actual-checksum-controls.json','preflight-binary-version.json','preflight-binary-version.stdout',
    'preflight-binary-version.stdout.stderr','prepare-runtime-controls-resources.json'))


def _fixed_curated_manifest(root, complete):
    root = Path(root)
    path = root/'fixed-topology/manifest.json'
    assert path.is_file() and not path.is_symlink(), 'FIXED_TOPOLOGY_MANIFEST_MISSING'
    assert path.stat().st_size <= 1024**2
    manifest = json.loads(path.read_bytes())
    assert manifest['schemaVersion'] == 1 and manifest['requiredRoles'] == list(FTX_FIXED_ROLES)
    assert type(manifest['collectionComplete']) is bool and isinstance(manifest['missingExpectedPaths'], list)
    rows = manifest['files']
    _ftx_ids(rows, 'path')
    assert len(rows) <= 256 and sum(row['bytes'] for row in rows) <= 8*1024**2
    for row in rows:
        assert row['role'] in FTX_FIXED_ROLES
        name = str(relative('fixed-topology/'+row['path']))
        assert name == 'fixed-topology/'+row['path']
        item = root/name
        assert not item.is_symlink() and item.is_file() and item.resolve().is_relative_to(root.resolve())
        assert type(row['bytes']) is int and 0 <= row['bytes'] <= 1024**2
        assert item.stat().st_size == row['bytes'] and hashlib.sha256(item.read_bytes()).hexdigest() == _ftx_digest(row['sha256'])
    if complete:
        assert manifest['collectionComplete'] is True and manifest['missingExpectedPaths'] == [], 'FIXED_TOPOLOGY_COLLECTION_INCOMPLETE'
        assert set(row['role'] for row in rows) == set(FTX_FIXED_ROLES)
    return manifest


def fixed_host_export_contract(root, plan):
    # Explicit OUT names only, never a recursive output or source-tree scan.
    root = Path(root)
    status_path = root/'candidate-ftx-export-status.json'
    complete = status_path.is_file() and json.loads(status_path.read_bytes()).get('fullCandidateClaim') is True
    names = set(FTX_SPLIT_CORE_FILES) | set(FTX_FIXED_ADJUNCTS) | {'fixed-topology/manifest.json','fixture-target/release-route-parser-fixtures.json','fixture-bootstrap/release-route-parser-fixtures.json'}
    if (root/'fixed-topology/manifest.json').is_file():
        manifest = _fixed_curated_manifest(root, complete)
        names.update('fixed-topology/'+row['path'] for row in manifest['files'])
    elif complete:
        raise AssertionError('FIXED_TOPOLOGY_MANIFEST_MISSING')
    optional = {'prepare-runtime-controls-failure.json','ftx-only-failure.json','finalize-ftx-failure.json'}
    names.update(name for name in optional if (root/name).is_file())
    required = names if complete else {name for name in names if (root/name).is_file()}
    return names, required


def _ftx_fixed_raw_proofs(root, indexed, binding):
    assert set(FTX_FIXED_ADJUNCTS) <= set(indexed), 'FIXED_TOPOLOGY_ADJUNCT_MISSING'
    manifest = _fixed_curated_manifest(root, True)
    by_role = {role: [row for row in manifest['files'] if row['role'] == role] for role in FTX_FIXED_ROLES}
    for row in manifest['files']:
        assert indexed['fixed-topology/'+row['path']]['sha256'] == row['sha256']
    # Exactly the declared curated union; no forgotten raw source, private tree or unexpected sibling file.
    assert {name for name in indexed if name.startswith('fixed-topology/')} == {'fixed-topology/manifest.json'} | {'fixed-topology/'+row['path'] for row in manifest['files']}
    def only(role):
        rows = by_role[role]; assert len(rows) == 1, 'FIXED_PROOF_ROLE_NOT_UNIQUE'
        return rows[0]
    def read(role):
        return (root/'fixed-topology'/only(role)['path']).read_bytes()
    before = json.loads((root/'ftx-before-summary.json').read_bytes())
    after = json.loads((root/'ftx-after-summary.json').read_bytes())
    phases = [phase for state in (before, after) for phase in state['networkProof']['phases']]
    if binding['c2Mode'] != 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        return
    forwarded = json.loads((root/'fixed-ftx-forwarded-evidence.json').read_bytes())
    forwarded_required = set(FTX_FILES) | {'ftx-route-completion.json','ftx-only-resources.json'}
    assert forwarded['missingRequired'] == []
    assert forwarded['missingNotTreatedAsPass'] is True and forwarded['rawPrivateTranscriptNotSelected'] is True
    assert forwarded_required <= set(forwarded['present']) <= forwarded_required | {'ftx-only-failure.json'}
    assert set(forwarded['optionalMissing']) <= {'ftx-only-failure.json'}
    assert set(forwarded['present']).isdisjoint(forwarded['optionalMissing'])
    host_final = json.loads((root/'fixed-ftx-host-final.json').read_bytes())
    assert host_final['stopVerified'] is True and host_final['sourceHandoffUnchanged'] is True and host_final['infrastructureHOLD'] is False
    assert host_final['ownedStops'] and all(row.get('Running') is False and row.get('Restarting') is False and row.get('Pid') == 0 for row in host_final['ownedStops'].values())
    assert json.loads(read('HOST_FINAL')) == host_final
    stop_rows = {row['path']:row for row in by_role['HOST_STOP']}
    expected_stops = {f'host/stops/{index}'+suffix for index in range(2) for suffix in ('.json','.stdout','.stdout.stderr')}
    assert set(stop_rows) == expected_stops, 'FIXED_RAW_STOP_RECEIPTS_INCOMPLETE'
    seen_stops = set()
    for index in range(2):
        command = json.loads((root/'fixed-topology'/f'host/stops/{index}.json').read_bytes())
        assert command['complete'] is True and command['exit'] == command['expected'] == 0
        actual, = json.loads((root/'fixed-topology'/f'host/stops/{index}.stdout').read_bytes())
        name = actual['Name'].removeprefix('/')
        assert command['argv'] == ['docker','inspect',name]
        assert name not in seen_stops and actual['State'] == host_final['ownedStops'][name]
        assert actual['State']['Running'] is False and actual['State']['Restarting'] is False and actual['State']['Pid'] == 0
        seen_stops.add(name)
    assert seen_stops == set(host_final['ownedStops']), 'FIXED_STOP_CONTAINER_SET_MISMATCH'
    host = json.loads(read('HOST_PROOF'))
    assert host['mode'] == binding['c2Mode']
    early=json.loads(read('EARLY_TERMINAL'))
    assert early['state']=='PASS_EARLY_LOCAL_AND_KERNEL_CONTROLS' and early['stopVerified'] is True
    assert early['nativeFeedbackControlsPassed'] is True and early['directEgressNegativePassed'] is True and early['proxyCurlTLSControlPassed'] is True
    def role_json(role,suffix):
        rows=[row for row in by_role[role]if row['path'].endswith(suffix)];assert len(rows)==1
        return json.loads((root/'fixed-topology'/rows[0]['path']).read_bytes())
    native=role_json('EARLY_NATIVE','/result.json')
    assert native['state']=='PASS_REAL_LOCAL_SENDER_CONTROLS' and native['positivePosts']==1 and native['optoutAdditionalPosts']==0
    assert native['binarySHA256']==binding['binarySHA256'] and native['actualHelpGate'] is True and native['sourceParityOrAllSendersProved'] is False
    requests=role_json('EARLY_NATIVE','/sink-requests.json');assert len(requests)==1 and requests[0]['path']=='/api/corpus-feedback' and requests[0]['bytes']>0
    _ftx_digest(requests[0]['sha256'])
    native_positive=role_json('EARLY_NATIVE','/real-local-positive.json');native_negative=role_json('EARLY_NATIVE','/real-optout-negative.json')
    assert native_positive['complete']is True and native_negative['complete']is True and native_positive['exit']==native_negative['exit']==0
    assert native_positive['feedbackDisabled']=='false' and native_negative['feedbackDisabled']=='true'
    assert native_positive['endpoint']==native_negative['endpoint'] and native_positive['endpoint'].startswith('http://127.0.0.1:') and native_positive['endpoint'].endswith('/api/corpus-feedback')
    native_proxy=role_json('EARLY_NATIVE_PROXY','/result.json')
    assert native_proxy['state']=='EXPECTED_SYNTHETIC_TLS_REFLECTOR_FAILURE' and native_proxy['hostMustVerifyNewCONNECTEvent'] is True
    assert native_proxy['nativeTLSVerificationSuccessProved'] is False and native_proxy['publicFeedback'] is False
    native_proxy_command=role_json('EARLY_NATIVE_PROXY','/real-native-https-proxy.json');assert native_proxy_command['complete']is True and native_proxy_command['exit']==1
    transport=role_json('EARLY_TRANSPORT','/transport.json')
    assert transport['state']=='PASS_SYNTHETIC_CONNECT_CASES'
    assert set(transport['cases'])=={'allowed-reflector','host-denied','literal-ip','port-denied','method','host-conflict','duplicate-host','auth','overlong'}
    assert transport['cases']['allowed-reflector']['tunnelAccepted'] is True
    assert all(row.get('tunnelRefused')is True for name,row in transport['cases'].items()if name!='allowed-reflector')
    paired=role_json('EARLY_TRANSPORT','/paired.json')
    assert paired['state']=='PASS_SAME_OWNED_UPSTREAM_PROXY_REACHABLE_DIRECT_DENIED' and paired['proxyPositive']['tunnelAccepted'] is True and paired['directDenied']
    assert role_json('EARLY_TRANSPORT','/direct.json')['state']=='PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'
    for name,reason in {'connection-bytes':'CONNECTION_BYTE_CAP','total-bytes':'TOTAL_BYTE_CAP','header-time':'HEADER_TIMEOUT','connection-time':'CONNECTION_TIMEOUT'}.items():
        assert role_json('EARLY_TRANSPORT','/'+name+'.json')['state']=='CLOSED_BY_PROXY_OBSERVED'
        log_rows=[row for row in by_role['EARLY_PROXY']if row['path']=='early/proxy/'+name+'/proxy/connections.jsonl'];assert len(log_rows)==1
        assert reason.encode()in(root/'fixed-topology'/log_rows[0]['path']).read_bytes()
    for label in ('fixture-proxy','connection-bytes','total-bytes','header-time','connection-time','real-proxy'):
        prefix='early/proxy/'+label+'/'
        rows={row['path'][len(prefix):]:row for row in by_role['EARLY_PROXY']if row['path'].startswith(prefix)}
        assert set(rows)=={'config.json','proxy/connections.jsonl','proxy/summary.json','actual-graceful-finalization.json'}
        def raw(name):return(root/'fixed-topology'/rows[name]['path']).read_bytes()
        summary=json.loads(raw('proxy/summary.json'));log=raw('proxy/connections.jsonl')
        assert summary['configSHA256']==hashlib.sha256(raw('config.json')).hexdigest() and summary['logBytes']==len(log)
        assert summary['logEvents']==len(log.splitlines()) and summary['daemonWorkersStillAlive']==0
    stop_rows={row['path']:row for row in by_role['EARLY_STOP']}
    assert set(stop_rows)=={f'early/stops/{index}'+suffix for index in range(9)for suffix in('.json','.stdout','.stdout.stderr')}
    early_seen=set()
    for index in range(9):
        command=json.loads((root/'fixed-topology'/f'early/stops/{index}.json').read_bytes())
        actual,=json.loads((root/'fixed-topology'/f'early/stops/{index}.stdout').read_bytes());name=actual['Name'].removeprefix('/')
        assert command['complete']is True and command['exit']==command['expected']==0 and command['argv']==['docker','inspect',name]
        assert name not in early_seen;early_seen.add(name)
        state=actual['State'];assert state['Running']is False and state['Restarting']is False and state['Pid']==0
        assert all(state[key]==value for key,value in early['ownedStops'][name].items())
    assert early_seen==set(early['ownedStops'])
    assert host['nativeControls']['receiptSHA256'] == only('EARLY_TERMINAL')['sha256']
    release_rows={row['path']:row for row in by_role['RELEASE_ROUTE']}
    assert set(release_rows)=={'release-routes/archive.json','release-routes/checksum.json'}
    parser_fixture=json.loads((root/'fixture-target/release-route-parser-fixtures.json').read_bytes())
    bootstrap_parser_fixture=json.loads((root/'fixture-bootstrap/release-route-parser-fixtures.json').read_bytes())
    assert bootstrap_parser_fixture==parser_fixture, 'RELEASE_PARSER_BOOTSTRAP_TARGET_CONTROL_MISMATCH'
    parser_cases={'allowed-redirect-and-no-signed-URL-leak','curl-failure','non200-final','foreign-redirect','redirect-count-mismatch','insecure-hop','duplicate-location','wrong-size','malformed-writeout','checksum-direct-200'}
    assert parser_fixture['schemaVersion']==1 and parser_fixture['caseCount']==10 and set(parser_fixture['cases'])==parser_cases
    assert all(value is True for value in parser_fixture['cases'].values()) and parser_fixture['actualNetworkCalls']==0 and parser_fixture['rawSignedURLExported']is False
    assert parser_fixture['parserSourceSHA256']==host['guestCode']['release_head_PROPOSED.py']['sha256']
    release_preflight=early['releaseRoutePreflight']
    assert release_preflight['archiveAndChecksumHEADVerified']is True and release_preflight['headRequests']==2
    assert release_preflight['beforeCostlyOfflineWork']is True and release_preflight['signedURLsPubliclyExported']is False
    assert set(release_preflight['receipts'])=={'archive','checksum'}
    archive_name='xerj-1.0.0-rc.102-aarch64-unknown-linux-musl.tar.gz'
    for kind,expected_bytes in (('archive',33666646),('checksum',118)):
        row=release_rows['release-routes/'+kind+'.json'];route=json.loads((root/'fixed-topology'/row['path']).read_bytes())
        assert set(route)=={'schemaVersion','assetKind','sourceTag','archiveName','expectedBytes','installerSourceSHA256','initialURLSHA256','parserSourceSHA256','rawHeadersSHA256','rawWriteoutSHA256','rawHeaderBytes','rawWriteoutBytes','maxRedirects','headOnly','bodyDownloaded','bodyIntegrityProved','runtimeInstallerMustVerifySHA','curlExit','chain','complete','classification','finalStatus','redirectCount','responseCount','informationalCount','allRedirectHostsAllowed','privateCommandReceiptSHA256','kernelRawFileCapBytes','privateStderrSHA256','childReaped','headArgvSHA256'}, 'SIGNED_ROUTE_DETAILS_NOT_PUBLIC'
        assert release_preflight['receipts'][kind]==row['sha256']
        assert route['schemaVersion']==1 and route['assetKind']==kind and route['sourceTag']=='v1.0.0-rc.102'
        assert route['archiveName']==archive_name and route['expectedBytes']==expected_bytes
        assert route['installerSourceSHA256']=='158b53201b9c5ddaffd0afa5860307a6dd5c684902303aa9dff64978618cf14f'
        initial='https://github.com/xerj-org/xerj/releases/download/v1.0.0-rc.102/'+archive_name+('.sha256'if kind=='checksum'else'')
        assert route['initialURLSHA256']==hashlib.sha256(initial.encode()).hexdigest()
        assert route['parserSourceSHA256']==parser_fixture['parserSourceSHA256']
        for key in ('rawHeadersSHA256','rawWriteoutSHA256','privateCommandReceiptSHA256','privateStderrSHA256','headArgvSHA256'):_ftx_digest(route[key])
        assert route['kernelRawFileCapBytes']==65536 and route['childReaped']is True
        assert type(route['rawHeaderBytes'])is int and 0<route['rawHeaderBytes']<=65536
        assert type(route['rawWriteoutBytes'])is int and 0<route['rawWriteoutBytes']<=32768
        assert route['maxRedirects']==3 and route['headOnly']is True and route['bodyDownloaded']is False
        assert route['bodyIntegrityProved']is False and route['runtimeInstallerMustVerifySHA']is True and route['curlExit']==0
        assert route['complete']is True and route['classification']=='PINNED_INSTALLER_RELEASE_ROUTE_VERIFIED_HEAD_ONLY' and route['finalStatus']==200
        assert type(route['redirectCount'])is int and 0<=route['redirectCount']<=3
        assert type(route['informationalCount'])is int and 0<=route['informationalCount']<=12
        assert route['responseCount']==len(route['chain'])==route['redirectCount']+1 and route['allRedirectHostsAllowed']is True
        assert route['chain'][-1]['status']==200
        for index,hop in enumerate(route['chain']):
            assert set(hop)=={'scheme','host','pathSHA256','queryPresent','status'}
            assert hop['scheme']=='https' and hop['host']in host['allowedHosts'] and type(hop['queryPresent'])is bool
            _ftx_digest(hop['pathSHA256'])
            if index<len(route['chain'])-1:assert 300<=hop['status']<400
    approval = json.loads(read('C2_APPROVAL'))
    assert approval['mode'] == binding['c2Mode'] and approval['claudeApproved'] is True and approval['rootAgreement'] is True
    assert approval['implementationSHA256'] == host['implementationSHA256']
    _ftx_digest(approval['actualVerdictSHA256'])
    assert approval['evidenceCaps'] == FTX_EVIDENCE_CAP_PROFILE
    implementation = host['implementationFiles']
    assert hashlib.sha256(json.dumps(implementation,sort_keys=True,separators=(',',':')).encode()).hexdigest() == host['implementationSHA256']
    for name,digest in implementation.items():
        assert host['guestCode'][name]['sha256'] == _ftx_digest(digest)
    kernel = json.loads(read('KERNEL_PROOF'))
    assert kernel['kernel']['inode'] == host['networkNamespaceInode'] and kernel['kernel']['routeSHA256'] == host['routeSHA256']
    assert kernel['kernel']['CapEff'] == host['targetCapEff'] == '0000000000000000' and kernel['kernel']['NoNewPrivs'] == '1'
    target, proxy = kernel['target'], kernel['proxy']
    target_env=dict(entry.split('=',1)for entry in target['Config']['Env']);assert target_env['XERJ_DISABLE_FEEDBACK']=='true' and target_env['XERJ_CORPUS_FEEDBACK_URL']==f"http://127.0.0.1:{host['feedbackSinkPort']}/api/corpus-feedback"
    assert target['Id'] == host['targetContainerID'] and target['Image'] == proxy['Image'] == host['targetImageID']
    assert target['State']['Running'] is True and proxy['State']['Running'] is True
    target_networks=set(target['NetworkSettings']['Networks']);proxy_networks=set(proxy['NetworkSettings']['Networks'])
    assert len(target_networks)==1 and len(proxy_networks)==2 and target_networks < proxy_networks
    for item,nano,memory in ((target,1750000000,8321499136),(proxy,250000000,268435456)):
        hc=item['HostConfig'];assert hc['NanoCpus']==nano and hc['Memory']==hc['MemorySwap']==memory
        assert hc['ReadonlyRootfs'] is True and hc['CpusetCpus']==host['resourcePartition']['cpuSet']
    hc=target['HostConfig'];assert hc['Dns']==['127.0.0.1'] and hc['CapDrop']==['ALL'] and hc['Privileged'] is False
    assert not hc['PortBindings'] and not hc.get('Devices') and not hc.get('CapAdd')
    assert any(flag in ('no-new-privileges','no-new-privileges:true')for flag in hc['SecurityOpt'])
    routing=json.loads(read('TARGET_ROUTING'))
    assert routing['targetContainerID']==target['Id'] and routing['actualPublicTLSPositive'] is True and routing['notInferredFromINTERNALLabel'] is True
    _ftx_digest(routing['directNegativeSHA256']);_ftx_digest(routing['allowedProxyResponseSHA256'])
    actual_direct=next(row for row in by_role['EARLY_TRANSPORT']if row['path']=='host/actual-target-direct-denial.json')
    actual_positive=next(row for row in by_role['EARLY_TRANSPORT']if row['path']=='host/actual-target-proxy-positive.stdout')
    assert actual_direct['sha256']==routing['directNegativeSHA256'] and actual_positive['sha256']==routing['allowedProxyResponseSHA256']
    assert json.loads((root/'fixed-topology'/actual_direct['path']).read_bytes())['state']=='PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'
    actual_command=json.loads((root/'fixed-topology/host/actual-target-proxy-positive.json').read_bytes())
    assert actual_command['complete']is True and actual_command['exit']==actual_command['expected']==0
    assert actual_command['argv'][:3]==['docker','exec',target['Name'].removeprefix('/')]
    assert actual_positive['bytes']==17290 and actual_command['argv'][-1]=='https://xerj.org/get'
    parity=json.loads(read('SOURCE_PARITY'))
    assert parity['state']=='SIX_SCOPED_CACHED_TAG_TREE_IDENTITIES_MATCH_ALREADY_ADMITTED_MAIN_SOURCE'
    assert parity['cachedTagRef']=='refs/tags/v1.0.0-rc.102' and len(parity['rows'])==6
    assert all(row['sameAsAdmittedSource'] is True and row['mode']=='100644' and type(row['bytes'])is int and row['bytes']>0 and len(row['gitOID'])==40 for row in parity['rows'])
    assert len({row['path']for row in parity['rows']})==6 and parity['newSourceBodies']==parity['newAPICalls']==parity['runtimeAttemptsAdded']==0
    proxy_config=json.loads(read('PROXY_CONFIG'));proxy_summary=json.loads(read('PROXY_FINAL'))
    assert hashlib.sha256(read('PROXY_CONFIG')).hexdigest()==host['proxyConfigSHA256']==proxy_summary['configSHA256']
    assert proxy_config['allowedHosts']==host['allowedHosts'] and proxy_config['maxTotalBytes']==268435456 and proxy_config['maxConnectionBytes']==67108864
    assert proxy_summary['exhausted'] is False and proxy_summary['daemonWorkersStillAlive']==0 and proxy_summary['accountedBytes']<=268435456
    assert proxy_summary['encryptedPathVisibility'] is False and proxy_summary['pathBlockProved'] is False and proxy_summary['productPass'] is False
    partition=host['resourcePartition']
    for key,value in {'targetNanoCPUs':1750000000,'targetMemoryBytes':8321499136,'proxyNanoCPUs':250000000,'proxyMemoryBytes':268435456,'aggregateCPUs':2,'aggregateMemoryBytes':8589934592}.items():
        assert partition[key] == value, 'FIXED_HOST_RESOURCE_PARTITION_MISMATCH'
    mapping = {'hostProofSHA256':'HOST_PROOF','kernelProofSHA256':'KERNEL_PROOF',
               'actualTargetRoutingSHA256':'TARGET_ROUTING','c2ApprovalReceiptSHA256':'C2_APPROVAL',
               'sourceParityReceiptSHA256':'SOURCE_PARITY'}
    proxy_raw = read('PROXY_LOG')
    events=[json.loads(line)for line in proxy_raw.splitlines()]
    assert events and events[0]['kind']=='ready' and events[0]['configSHA256']==host['proxyConfigSHA256'] and events[0]['allowedHosts']==host['allowedHosts']
    assert proxy_summary['logBytes']==len(proxy_raw) and proxy_summary['logEvents']==len(events)
    assert host_final['proxyFinalProof']['summarySHA256']==only('PROXY_FINAL')['sha256'] and host_final['proxyFinalProof']['logSHA256']==only('PROXY_LOG')['sha256']
    assert host_final['proxyFinalProof']['finalSummaryReconciled']is True and host_final['proxyFinalProof']['noProxyLimitOrFailure']is True
    assert not any(event['kind']in('refused-or-failed','connection-cap-denied')for event in events)
    expected_optout=hashlib.sha256(b'true').hexdigest()
    expected_sink=hashlib.sha256(f"http://127.0.0.1:{host['feedbackSinkPort']}/api/corpus-feedback".encode()).hexdigest()
    for phase in phases:
        for key, role in mapping.items():
            assert phase[key] == only(role)['sha256'], 'FIXED_PROOF_HASH_NOT_RETAINED'
        assert phase['nativeControlsSHA256'] == only('EARLY_TERMINAL')['sha256']
        assert phase['feedbackEndpointURLSHA256']==expected_sink
        for process in phase['childEnvironmentCheckpoint']['processes']:
            assert process['optoutValueSHA256']==expected_optout and process['sinkValueSHA256']==expected_sink, 'FIXED_CHILD_ENV_EXPECTED_HASH_MISMATCH'
        assert phase['targetContainerID'] == host['targetContainerID']
        assert phase['networkNamespaceInode'] == host['networkNamespaceInode']
        assert phase['currentRouteSHA256'] == host['routeSHA256']
        assert phase['implementationSHA256'] == host['implementationSHA256'] == binding['c2ImplementationSHA256']
        assert phase['resourcePartition'] == host['resourcePartition']
        assert phase['publicSnapshotSHA256'] == host['publicSnapshotSHA256']
        assert phase['publicPacketSHA256'] == host['publicPacketSHA256']
        assert phase['offlineHandoffReceiptSHA256'] == host['offlineHandoffReceiptSHA256']
        count = phase['currentProxyLogBytes']
        assert count <= len(proxy_raw) and hashlib.sha256(proxy_raw[:count]).hexdigest() == phase['currentProxyLogSHA256'], 'FIXED_PROXY_LOG_PREFIX_MISMATCH'
    final = json.loads(read('GUEST_FINAL'))
    comparison = json.loads((root/'ftx-comparison.json').read_bytes())
    assert {key:value for key,value in comparison['c2FinalProof'].items() if key != 'receiptSHA256'} == final
    assert comparison['c2FinalProof']['receiptSHA256'] == only('GUEST_FINAL')['sha256']
    assert final['sinkLogSHA256'] == only('GUEST_SINK')['sha256']
    bundle = json.loads(read('GUEST_CHECKPOINT_BUNDLE'))
    assert bundle['schemaVersion'] == 1 and len(bundle['frames']) == final['checkpointCount'] <= 256
    expected_names = {f'{index:03d}.json' for index in range(1, final['checkpointCount']+1)}
    assert set(_ftx_ids(bundle['frames'],'path')) == expected_names
    observed = []
    for frame in bundle['frames']:
        relative(frame['path'])
        raw = frame['rawUTF8'].encode('utf-8')
        assert len(raw) == frame['bytes'] <= 1024**2 and hashlib.sha256(raw).hexdigest() == _ftx_digest(frame['sha256'])
        record = json.loads(raw)
        assert not record.get('infrastructureHOLD'), 'FIXED_CHECKPOINT_INFRASTRUCTURE_HOLD'
        proof = record['observedProof']
        proof = _ftx_public_containment_proof(proof)
        observed.append(proof)
    latest = json.loads(bundle['frames'][-1]['rawUTF8'])['observedProof']
    latest = _ftx_public_containment_proof(latest)
    assert hashlib.sha256(json.dumps(latest,sort_keys=True).encode()).hexdigest() == after['ownedStopProof']['zeroLiveXerjProofSHA256'], 'FIXED_FINAL_CHECKPOINT_NOT_CANDIDATE_CLEANUP'
    for phase in phases:
        matches = [index for index, proof in enumerate(observed) if all(proof.get(key) == value for key,value in phase.items())]
        assert matches, 'FIXED_PHASE_HAS_NO_ACTUAL_RAW_CHECKPOINT'
        observed.pop(matches[0])


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
    if any(row['path'] == 'candidate-ftx-export-status.json' for row in rows):
        status = json.loads((root/'candidate-ftx-export-status.json').read_text())
        if status.get('fullCandidateClaim') is True:
            verify_ftx(root, rows)
            indexed={r['path']:r for r in rows}
            early=json.loads((root/'early-operator-compatibility.json').read_text())
            binding=json.loads((root/'ftx-surface-corpus-bindings.json').read_text())
            _ftx_split_core(root,indexed,binding)
            _ftx_fixed_raw_proofs(root,indexed,binding)
            assert early['realDependencyGate']is True and early['childrenReaped']is True and early['beforeCandidateAndExpensiveChecks']is True
            assert early['helperSHA256']==binding['helperSHA256'] and early['actualToolCount']>0 and early['noFixedToolCount']is True
            probe=early['realDecoderProbe']
            assert probe['operatorOnly']is True and probe['syntheticOwnedRustCorpus']is True and probe['sameProductionDecoders']is True and probe['complete']is True, 'REAL_DECODER_PROBE_INCOMPLETE'
            for key in ('sourceSHA256','statusSchemaSHA256','gainSchemaSHA256','knowledgeSchemaSHA256','symbolDecoderActualEvidenceSHA256'):_ftx_digest(probe[key])
            _ftx_map_content(probe['mapContentAssertions'])
            _ftx_response_sets(early,({'rawEvidenceCountsAndHashes':{'requestIntentIDs':early['requestIntentIDs']}},))
            assert early['privateBytes']<=24*1024**2 and early['actualCLICommandCount']>0 and early['actualRPCRequestCount']>0
            generated=json.loads((root/'candidate-source-proof.json').read_text())
            for name in generated['generatedPaths']:
                assert indexed['generated/'+name]['sha256']==generated['finalNineHashes'][name]
            assert set(generated['generatedPaths'])=={'landing/answers/reciprocal-rank-fusion-when-to-use.html','landing/answers/reciprocal-rank-fusion-when-to-use.md','landing/answers/index.html','landing/answers/index.json'}
        else:
            verify_partial_ftx(root, rows)
    elif any(row['path'].startswith('ftx-') for row in rows):
        verify_ftx(root, rows)
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


# Additive candidate-only contract. Original I2 caps/fixtures remain unchanged.
FTX_FILES = (
    'ftx-controls.json', 'ftx-surface-corpus-bindings.json',
    'ftx-before-summary.json', 'ftx-after-summary.json',
    'ftx-comparison.json', 'ftx-evidence-accounting.json',
)
FTX_CONTROL_IDS = (
    'forwarder_content_length_request', 'forwarder_content_length_response',
    'forwarder_chunked_request', 'forwarder_chunked_response',
    'forwarder_external_host_refused', 'forwarder_connect_refused',
    'forwarder_no_self_traffic', 'forwarder_actor_headers_preserved',
    'forwarder_log_overflow_abort', 'forwarder_encoded_json_decode',
    'scanner_xerj_first', 'scanner_xerj_middle', 'scanner_xerj_last',
    'scanner_xerj_absent', 'scanner_duplicate_xerj_refused',
    'scanner_duplicate_other_key_refused', 'scanner_nonobject_refused',
    'rpc_matching_id', 'rpc_timeout', 'rpc_error_response',
    'rpc_interleaved_reply_refused', 'audit_exact_match',
    'audit_mismatch_unknown', 'audit_machine_actor_classified',
    'real_node_success', 'real_wrong_port_loss', 'real_missing_flag_loss',
)
FTX_ACTION_IDS = (
    'P2_REGISTERED_SESSION', 'P2_MAP', 'P2_SEARCH', 'P2_PLAN',
    'P2_SEARCH_PLANNED_QUERY', 'P2_HUB_OBSERVATION', 'P2_CLI_BOUNDARY',
    'P3_CONSOLE', 'P3_KNOWLEDGE', 'P3_CATALOG', 'P3_PROJECTED_SEARCH',
    'P3_PROJECTION_SAVINGS', 'P3_ASK', 'P3_INDEX_SCOPED_ASK',
    'READ_OFFERED_RECIPE',
)
FTX_QUALIFICATIONS = (
    'SCRIPTED_CLIENT',
    'ACTUAL_PUBLIC_INSTALLER_OUTCOMES_RECORDED', 'LOCAL_PROSPECTIVE_SURFACES',
    'CONDITIONAL_HUB_ACTUAL_OUTCOMES_RECORDED', 'PARTIAL_BINARY_PARITY',
    'FORWARDER_FRAMING_CHANGES', 'SMALL_CORPUS',
    'SINGLE_RUN_NO_VARIANCE',
)


FTX_FULL_PROTOCOL_IDS = ('P1_INSTALL', 'P1_PATH', 'P1_LLMS_FIRST_RUN', 'P1_NAIVE_NO_NODE_AUTOINDEX', 'P1_FIRST_RUN_NODE', 'P1_AUTOINDEX', 'P1_LITERAL_NEXT', 'P1_ZERO_FLAG_SEARCH', 'P1_ZERO_FLAG_DEF', 'P1_ZERO_HIT_RECOVERY', 'P1_MAP', 'P1_STATUS', 'P1_AUTH_NODE', 'P1_AUTH_ZERO_FLAG_SEARCH', 'P1_AUTH_ZERO_FLAG_DEF', 'P1_NO_NODE_RECOVERY', 'P1_INIT', 'P1_INIT_EXISTING', 'P1_HUB_COUNTERPART', 'P2_FIRST_SESSION', 'P2_SEARCH_MAP_PLAN', 'P2_CLI_BOUNDARY', 'P2_SAME_HINTS', 'P2_HUB_IF_ADVERTISED', 'P3_CURL_CONSOLE', 'P3_CURL_KNOWLEDGE', 'P3_CURL_CATALOG', 'P3_CURL_PROJECTION', 'P3_CURL_ROOT_ASK', 'P3_CURL_INDEX_ASK', 'P3_CLI_BOUNDARY', 'KNOWLEDGE_SEMANTICS', 'GAIN_NAIVE_THEN_DOCUMENTED', 'GAIN_USER_MACHINE_POLLS', 'TOKEN_QUESTIONS')


# Proposed only: actual execution requires the separate immutable cap approval receipt.
FTX_EVIDENCE_CAP_PROFILE = {
    'mode': 'FULL_PROTOCOL_PROPOSED_CAPS_V1',
    'privateRecords': 4096, 'privateBytes': 768*1024**2,
    'publicFileBytes': 1024**2, 'publicTotalBytes': 6*1024**2,
    'cliPerState': 64, 'rpcPerSession': 16, 'httpPerState': 168,
    'forwardedPerState': 160, 'directHTTPPerState': 8, 'containmentCheckpointsPerState': 128,
}


def _ftx_cap_sizes(private_records, private_bytes, public_sizes):
    assert type(private_records) is int and 0 <= private_records <= FTX_EVIDENCE_CAP_PROFILE['privateRecords']
    assert type(private_bytes) is int and 0 <= private_bytes <= FTX_EVIDENCE_CAP_PROFILE['privateBytes']
    assert isinstance(public_sizes, list) and len(public_sizes) <= 6
    assert all(type(size) is int and 0 <= size <= FTX_EVIDENCE_CAP_PROFILE['publicFileBytes'] for size in public_sizes)
    assert sum(public_sizes) <= FTX_EVIDENCE_CAP_PROFILE['publicTotalBytes']


def _ftx_cap_operation_counts(counts):
    limits = {'cli': 64, 'rpc': 16, 'http': 168, 'forwarded': 160, 'directHTTP': 8}
    assert set(counts) == set(limits)
    for key, limit in limits.items():
        assert type(counts[key]) is int and 0 <= counts[key] <= limit, 'FTX_PER_STATE_OPERATION_CAP'


def _ftx_cap_binding(binding, accounting):
    caps = binding['evidenceCaps']
    assert set(caps) == set(FTX_EVIDENCE_CAP_PROFILE) | {'approvalSHA256'}
    for key, expected in FTX_EVIDENCE_CAP_PROFILE.items():
        assert caps[key] == expected, 'FTX_CAP_PROFILE_MISMATCH'
    approval = _ftx_digest(caps['approvalSHA256'])
    assert accounting['evidenceCapsApprovalSHA256'] == approval, 'FTX_CAP_APPROVAL_BINDING_MISMATCH'
    return approval


def _ftx_digest(value):
    assert isinstance(value, str) and len(value) == 64
    assert all(c in '0123456789abcdef' for c in value)
    return value


def _ftx_ids(rows, key, expected=None):
    assert isinstance(rows, list)
    ids = [r[key] for r in rows]
    assert all(isinstance(v, str) and v for v in ids)
    assert len(ids) == len(set(ids)), 'FTX_DUPLICATE_ID'
    if expected is not None:
        assert set(ids) == set(expected), 'FTX_REQUIRED_ID_SET_INCOMPLETE'
    return ids


def _ftx_map_content(assertions):
    for key in ('datasetIdentityObserved', 'perFieldTypesAndExamplesObserved', 'readyQueryTemplatesObserved'):
        assert assertions[key] is True, 'FTX_MAP_CONTENT_NOT_OBSERVED'
    for key in ('observedFieldCount', 'observedQueryCount'):
        assert type(assertions[key]) is int and assertions[key] > 0, 'FTX_MAP_EMPTY_CONTENT'
    _ftx_digest(assertions['actualMapOutputSHA256'])


def _ftx_full_protocol(value, binding, accounting):
    """Full observations require operation receipts or referenced observed output."""
    full = value['fullProtocol']
    assert full['schemaVersion'] == 1
    assert full['requiredIDs'] == list(FTX_FULL_PROTOCOL_IDS)
    assert value['evidenceCaps'] == binding['evidenceCaps'], 'FTX_STATE_CAP_APPROVAL_MISMATCH'
    assert full['sourceCount'] == binding['sourceCount'] == 120
    assert full['sourceBytes'] == binding['sourceBytes'] == 9444700
    records = full['records']
    _ftx_ids(records, 'id', FTX_FULL_PROTOCOL_IDS)
    assert full['allRequiredAccounted'] is True
    kinds = ('cli', 'rpc', 'http', 'forwarded')
    universe = value['rawEvidenceCountsAndHashes']['requestIntentIDs']
    accounted = {kind: {r['id'] for r in accounting['responseSets'][kind]} for kind in kinds}
    exercised = True
    for row in records:
        assert row['outcome'] in ('RECORDED', 'LOSS', 'INCOMPLETE')
        failure_class = row['failureClass']
        assert failure_class in (None, 'REAL_OPERATION_OR_CONTRACT_FAILURE', 'HARNESS_UNVERIFIED')
        if row['outcome'] == 'RECORDED':
            assert failure_class is None, 'FTX_RECORDED_HARNESS_FAILURE'
        elif row['outcome'] == 'LOSS':
            assert failure_class == 'REAL_OPERATION_OR_CONTRACT_FAILURE', 'FTX_HARNESS_ERROR_IS_NOT_PRODUCT_LOSS'
        elif failure_class is not None:
            assert failure_class == 'HARNESS_UNVERIFIED'
        assert type(row['attempted']) is bool
        assert type(row['routedThroughCapture']) is bool, 'FTX_ROUTING_OBSERVATION_MISSING'
        if row['id'] in ('P1_AUTOINDEX','P1_LITERAL_NEXT','P1_ZERO_FLAG_SEARCH','P1_ZERO_FLAG_DEF','GAIN_NAIVE_THEN_DOCUMENTED'):
            assert row['routedThroughCapture'] is False, 'FTX_NAIVE_DEFAULT_ROUTE_REPLACED'
        assert row['operationStatus'] in ('EXECUTED', 'OBSERVED_PRIOR_OUTPUT', 'BLOCKED_NO_OPERATION')
        assert isinstance(row['wallSeconds'], (int, float)) and 0 <= row['wallSeconds'] <= 600
        _ftx_digest(row['rawRecordSHA256'])
        intents = row['operationIntentIDs']
        assert set(intents) == set(kinds)
        actual_count = 0
        for kind in kinds:
            ids = intents[kind]
            assert isinstance(ids, list) and len(ids) == len(set(ids))
            assert set(ids) <= set(universe[kind]) & accounted[kind], 'FTX_PHASE_OPERATION_NOT_ACCOUNTED'
            actual_count += len(ids)
        assert row['attempted'] is (actual_count > 0), 'FTX_FALSE_PHASE_ATTEMPT'
        refs = row['observationRefs']
        assert isinstance(refs, list)
        operator_phases = {'P2_SEARCH_MAP_PLAN','P2_SAME_HINTS','KNOWLEDGE_SEMANTICS','GAIN_USER_MACHINE_POLLS'}
        persona = 'P2' if row['id'].startswith('P2_') else 'P3' if row['id'].startswith('P3_') else 'P1'
        for ref in refs:
            assert isinstance(ref['observedId'], str) and ref['observedId']
            _ftx_digest(ref['sha256'])
            assert ref['role'] in ('SHARED_PUBLIC','P1','P2','P3','OPERATOR_MEASUREMENT')
            assert ref['purpose'] in ('DISCOVERY','ACTUAL_OUTPUT','OPERATOR_COMPARISON_ONLY')
            if ref['purpose'] == 'OPERATOR_COMPARISON_ONLY':
                applicability = row['id'] in ('P1_HUB_COUNTERPART','P2_HUB_IF_ADVERTISED') and row['contentAssertions'].get('notApplicableNotAdvertised') is True
                assert row['id'] in operator_phases or applicability, 'FTX_OPERATOR_TEACHING_PERSONA'
            else:
                assert ref['role'] != 'OPERATOR_MEASUREMENT', 'FTX_MEASUREMENT_IS_NOT_PERSONA_DISCOVERY'
                assert ref['role'] in ('SHARED_PUBLIC',persona), 'FTX_CROSS_PERSONA_TEACHER'
                assert row['id'] not in operator_phases or ref['purpose'] == 'ACTUAL_OUTPUT'

        assertions = row['contentAssertions']
        assert isinstance(assertions, dict)
        if row['operationStatus'] == 'EXECUTED':
            assert actual_count > 0
        elif row['operationStatus'] == 'OBSERVED_PRIOR_OUTPUT':
            assert actual_count == 0 and refs and assertions, 'FTX_LABEL_ONLY_OBSERVATION'
        else:
            assert actual_count == 0 and row['outcome'] != 'RECORDED', 'FTX_BLOCKED_IS_NOT_RECORDED'
            exercised = False
        if row['outcome'] == 'INCOMPLETE':
            exercised = False
        if assertions.get('notApplicableNotAdvertised') is True:
            assert row['id'] in ('P2_HUB_IF_ADVERTISED', 'P1_HUB_COUNTERPART')
            assert row['operationStatus'] == 'OBSERVED_PRIOR_OUTPUT'
            _ftx_digest(assertions['actualInventorySHA256'])
    assert type(full['fullMandatoryScopeExercised']) is bool
    assert full['fullMandatoryScopeExercised'] is exercised, 'FTX_FALSE_FULL_PROTOCOL_SCOPE'
    by_id = {r['id']: r for r in records}
    hubs = [by_id[k] for k in ('P1_HUB_COUNTERPART', 'P2_HUB_IF_ADVERTISED')]
    if all(r['attempted'] for r in hubs):
        questions = [_ftx_digest(r['contentAssertions']['questionSHA256']) for r in hubs]
        assert questions[0] == questions[1] == binding['hubPublicQuestion']['questionSHA256'], 'FTX_HUB_QUESTION_MISMATCH'
    gain=by_id['GAIN_NAIVE_THEN_DOCUMENTED']
    if gain['outcome'] in ('RECORDED','LOSS'):
        for key in ('naiveXerjURLAbsent','structuredXerjURLAbsent','operatorHelpXerjURLAbsent'):
            assert gain['contentAssertions'][key] is True, 'FTX_GAIN_DEFAULT_ROUTE_NOT_OBSERVED'
    if all(r['contentAssertions'].get('notApplicableNotAdvertised') is True for r in hubs):
        assert hubs[0]['contentAssertions']['actualInventorySHA256'] == hubs[1]['contentAssertions']['actualInventorySHA256']
    if by_id['P1_MAP']['outcome'] == 'RECORDED':
        _ftx_map_content(by_id['P1_MAP']['contentAssertions'])
    if by_id['KNOWLEDGE_SEMANTICS']['outcome'] == 'RECORDED':
        assertions = by_id['KNOWLEDGE_SEMANTICS']['contentAssertions']
        for key in ('recordsFilesCompared', 'relationsLabelled', 'lexicalClaimsChecked',
                    'explicitRuntimeModeLexical', 'explicitVectorClaimFalse', 'explicitSemanticClaimFalse'):
            assert assertions[key] is True, 'FTX_KNOWLEDGE_VACUOUS_OR_UNOBSERVED'
        _ftx_digest(assertions['representationSHA256'])
    hints = by_id['P2_SAME_HINTS']
    if hints['outcome'] == 'RECORDED':
        assertions = hints['contentAssertions']
        assert assertions['sameHints'] is True
        assert _ftx_digest(assertions['mcpHintsSHA256']) == _ftx_digest(assertions['cliHintsSHA256']), 'FTX_HINTS_MISMATCH'
    if value['complete']:
        assert exercised, 'FTX_INCOMPLETE_MANDATORY_PHASE'
    return exercised


def _ftx_question_top_one(metric):
    if metric.get('outcome') in ('LOSS_REAL_FAILURE', 'LOSS_ZERO_HIT'):
        return
    assert metric['top1Definition'] == 'SINGLE_FIRST_ACTUAL_CLI_DISPLAYED_FILE_PER_QUESTION'
    top = metric['armATopOneQuestionFileBytes']
    assert type(top) is int and 0 <= top <= metric['armAAllUniqueFilesBytes']
    assert metric['armATopOnePerResponseUniqueBytes'] == top, 'FTX_PER_RESPONSE_TOP1_SUBSTITUTION'
    assert metric['approxTokensAtFourBytes']['ATop1'] == top / 4
    b = metric['armBDecodedWireMinusHintsBytes']
    assert metric['top1Ratio'] == (top / b if b else None)


FTX_PUBLIC_CONTAINMENT_KEYS = ('actualKernelEnforced', 'actualNativeFeedbackControlsPassed', 'actualTargetRoutingSHA256', 'allFourReviewedHostsPermittedFromStart', 'allOtherEgressDenied', 'allowedHosts', 'approvalSHA256', 'c2ApprovalReceiptSHA256', 'c2Mode', 'childEnvironmentCheckpoint', 'connectionLoggingActive', 'corpusFeedbackEndpointBlocked', 'currentProxyLogBytes', 'currentProxyLogSHA256', 'currentRouteSHA256', 'encryptedPathBlocked', 'evidenceSHA256', 'externalNetworkPhysicallyDisconnected', 'feedbackEndpointLoopbackOnly', 'feedbackEndpointURLSHA256', 'fixedTopologyAcrossEntireFTX', 'helperExecutionNamespaceMatches', 'hostAllowlistPhaseSpecific', 'hostProofSHA256', 'hubCatalogueOnlyIfObserved', 'implementationSHA256', 'installerAndReleaseAllowlistOnly', 'kernelProofSHA256', 'limits', 'mode', 'nativeControlsSHA256', 'networkNamespaceInode', 'offlineHandoffReceiptSHA256', 'phase', 'projectTestsExecutionProvedByThisGuard', 'projectTestsSeparateOffline', 'publicPacketSHA256', 'publicSnapshotSHA256', 'resourcePartition', 'sinkLiveEntireFTX', 'sourceParityReceiptSHA256', 'sourceProvenOptOutApplied', 'targetContainerID', 'unexpectedSinkRequests')

def _ftx_public_containment_proof(proof):
    proof = dict(proof)
    if proof.get('mode') == 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        proof['c2Mode'] = proof['mode']
        proof['approvalSHA256'] = proof['c2ApprovalReceiptSHA256']
    return {key:value for key,value in proof.items() if key in FTX_PUBLIC_CONTAINMENT_KEYS}


def _ftx_fixed_proxy_phase(phase):
    assert phase.get('mode', phase.get('c2Mode')) == 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'
    if phase.get('mode') and phase.get('c2Mode'):
        assert phase['mode'] == phase['c2Mode']
    for key in ('actualKernelEnforced', 'connectionLoggingActive', 'allOtherEgressDenied',
                'helperExecutionNamespaceMatches', 'sourceProvenOptOutApplied',
                'feedbackEndpointLoopbackOnly', 'actualNativeFeedbackControlsPassed',
                'fixedTopologyAcrossEntireFTX', 'projectTestsSeparateOffline',
                'allFourReviewedHostsPermittedFromStart', 'sinkLiveEntireFTX'):
        assert phase[key] is True, 'FTX_FIXED_PROXY_REQUIRED_PROOF_MISSING'
    for key in ('externalNetworkPhysicallyDisconnected', 'encryptedPathBlocked',
                'corpusFeedbackEndpointBlocked', 'hostAllowlistPhaseSpecific',
                'projectTestsExecutionProvedByThisGuard'):
        assert phase[key] is False, 'FTX_FIXED_PROXY_FALSE_OFFLINE_OR_PATH_BLOCK_CLAIM'
    assert phase.get('installerAndReleaseAllowlistOnly') is not True and phase.get('hubCatalogueOnlyIfObserved') is not True, 'FTX_FIXED_PROXY_FALSE_PHASE_RESTRICTION'
    assert phase['allowedHosts'] == ['xerj.org', 'github.com', 'release-assets.githubusercontent.com', 'hub.xerj.org']
    assert phase['limits'] == {'totalBytes': 268435456, 'connectionBytes': 67108864}
    for key,value in {'targetNanoCPUs':1750000000,'targetMemoryBytes':8321499136,'proxyNanoCPUs':250000000,'proxyMemoryBytes':268435456,'aggregateCPUs':2,'aggregateMemoryBytes':8589934592}.items():
        assert phase['resourcePartition'][key] == value, 'FTX_FIXED_PROXY_RESOURCE_PARTITION_MISMATCH'
    for key in ('c2ApprovalReceiptSHA256', 'implementationSHA256', 'hostProofSHA256',
                'evidenceSHA256', 'targetContainerID', 'currentRouteSHA256', 'publicSnapshotSHA256',
                'nativeControlsSHA256', 'kernelProofSHA256', 'sourceParityReceiptSHA256', 'currentProxyLogSHA256',
                'actualTargetRoutingSHA256', 'publicPacketSHA256', 'offlineHandoffReceiptSHA256'):
        _ftx_digest(phase[key])
    assert phase['hostProofSHA256'] == phase['evidenceSHA256']
    assert type(phase['networkNamespaceInode']) is int and phase['networkNamespaceInode'] > 0
    assert type(phase['currentProxyLogBytes']) is int and 0 <= phase['currentProxyLogBytes'] <= FTX_EVIDENCE_CAP_PROFILE['privateBytes']
    assert type(phase['unexpectedSinkRequests']) is int and phase['unexpectedSinkRequests'] == 0, 'FTX_UNEXPECTED_FEEDBACK_INFRA_HOLD'
    checkpoint = phase['childEnvironmentCheckpoint']
    assert checkpoint['scanPerformed'] is True and checkpoint['allLiveXerjMatched'] is True
    assert checkpoint['shortLivedProcessesBetweenCheckpointsNotAttested'] is True
    assert type(checkpoint['matchedCount']) is int and checkpoint['matchedCount'] == len(checkpoint['processes']) <= 512
    ids = []
    for process in checkpoint['processes']:
        assert type(process['pid']) is int and process['pid'] > 0
        assert type(process['startTimeTicks']) is int and process['startTimeTicks'] >= 0
        ids.append((process['pid'], process['startTimeTicks']))
        assert process['optoutCorrect'] is True and process['sinkCorrect'] is True
        for key in ('executablePathSHA256', 'environmentSHA256', 'optoutValueSHA256', 'sinkValueSHA256'):
            _ftx_digest(process[key])
    assert len(ids) == len(set(ids))
    return ('FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT', phase['c2ApprovalReceiptSHA256'], phase['implementationSHA256'])


def _ftx_full_network(value):
    network = value['networkProof']
    phases = network['phases']
    assert isinstance(phases, list) and 2 <= len(phases) <= FTX_EVIDENCE_CAP_PROFILE['containmentCheckpointsPerState']
    names = {p['phase'] for p in phases}
    assert {'INSTALLER', 'OFFLINE'} <= names <= {'INSTALLER', 'HUB', 'OFFLINE', 'CHECKPOINT'}
    records = {r['id']: r for r in value['fullProtocol']['records']}
    hub_called = any(records[k]['attempted'] for k in ('P1_HUB_COUNTERPART', 'P2_HUB_IF_ADVERTISED'))
    if hub_called:
        assert 'HUB' in names, 'FTX_HUB_WITHOUT_CONTAINMENT'
    identities = set()
    fixed_identities = set()
    fixed_processes = 0
    for phase in phases:
        mode = phase.get('mode') or phase.get('c2Mode')
        if mode == 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
            identities.add(_ftx_fixed_proxy_phase(phase))
            fixed_identities.add(tuple(phase[k] for k in ('hostProofSHA256', 'targetContainerID', 'networkNamespaceInode', 'currentRouteSHA256', 'publicSnapshotSHA256')))
            fixed_processes += phase['childEnvironmentCheckpoint']['matchedCount']
            continue
        assert network['externalNetworkPhysicallyDisconnected'] is True and network['nonLoopbackInterfaces'] == 0

        assert phase['phase'] != 'CHECKPOINT', 'FTX_CHECKPOINT_MODE_MISMATCH'
        assert mode in ('ORIGINAL_ENDPOINT_BLOCK', 'SOURCE_OPTOUT_AND_LOOPBACK_REDIRECT')
        approval = _ftx_digest(phase['approvalSHA256'])
        implementation = _ftx_digest(phase['implementationSHA256'])
        identities.add((mode, approval, implementation))
        _ftx_digest(phase['evidenceSHA256'])
        for key in ('actualKernelEnforced', 'connectionLoggingActive', 'allOtherEgressDenied', 'helperExecutionNamespaceMatches'):
            assert phase[key] is True, 'FTX_C2_PHASE_PROOF_MISSING'
        if mode == 'ORIGINAL_ENDPOINT_BLOCK':
            assert phase['encryptedPathBlocked'] is True and phase['corpusFeedbackEndpointBlocked'] is True
        else:
            assert phase['encryptedPathBlocked'] is False and phase['corpusFeedbackEndpointBlocked'] is False
            for key in ('sourceProvenOptOutApplied', 'feedbackEndpointLoopbackOnly', 'actualNativeFeedbackControlsPassed'):
                assert phase[key] is True, 'FTX_C2_SUBSTITUTE_NOT_PROVEN'
        if phase['phase'] == 'INSTALLER':
            assert phase['installerAndReleaseAllowlistOnly'] is True
        elif phase['phase'] == 'HUB':
            assert phase['hubCatalogueOnlyIfObserved'] is True
        else:
            assert phase['externalNetworkPhysicallyDisconnected'] is True
    assert len(identities) == 1, 'FTX_C2_MIXED_APPROVAL_OR_IMPLEMENTATION'
    if next(iter(identities))[0] == 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        assert len(fixed_identities) == 1 and fixed_processes > 0, 'FTX_FIXED_TOPOLOGY_OR_LIVE_CHILD_PROOF_MISSING'
        assert network['externalNetworkPhysicallyDisconnected'] is False
    return next(iter(identities))


def _ftx_fixed_final(before, after, comparison, accounting, binding):
    if binding['c2Mode'] != 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        return
    proof = comparison['c2FinalProof']
    assert proof == accounting['fixedContainmentFinal'], 'FTX_FINAL_CONTAINMENT_RECEIPT_MISMATCH'
    assert proof['mode'] == binding['c2Mode']
    assert proof['infrastructureHOLD'] is False, 'FTX_FINAL_CONTAINMENT_INFRA_HOLD'
    assert proof['sinkLiveUntilFTXClose'] is True, 'FTX_SINK_NOT_LIVE_ENTIRE_FTX'
    assert type(proof['unexpectedSinkRequests']) is int and proof['unexpectedSinkRequests'] == 0
    _ftx_digest(proof['sinkLogSHA256'])
    _ftx_digest(proof['receiptSHA256'])
    count = proof['checkpointCount']
    assert type(count) is int and sum(len(x['networkProof']['phases']) for x in (before, after)) <= count <= 2*FTX_EVIDENCE_CAP_PROFILE['containmentCheckpointsPerState']


def _ftx_resource_partition(value, binding):
    expected = {'globalCpuLimit': 2, 'globalMemoryLimitBytes': 8589934592,
                'targetCpuLimit': 1.75, 'targetMemoryLimitBytes': 8321499136,
                'proxyCpuLimit': .25, 'proxyMemoryLimitBytes': 268435456}
    assert binding['resourcePartition'] == expected
    assert expected['targetCpuLimit'] + expected['proxyCpuLimit'] == expected['globalCpuLimit']
    assert expected['targetMemoryLimitBytes'] + expected['proxyMemoryLimitBytes'] == expected['globalMemoryLimitBytes']
    resources = value['resources']
    for key in ('globalCpuLimit', 'globalMemoryLimitBytes', 'proxyCpuLimit', 'proxyMemoryLimitBytes'):
        assert resources[key] == expected[key], 'FTX_AGGREGATE_RESOURCE_PARTITION_MISMATCH'
    assert resources['cpuLimit'] == expected['targetCpuLimit']
    assert resources['memoryLimitBytes'] == expected['targetMemoryLimitBytes']
    assert resources['swapBytes'] == 0 and resources['pidsLimit'] == 4096
    assert resources['memoryMax'] == str(expected['targetMemoryLimitBytes'])
    assert resources['memorySwapMax'] == '0' and resources['pidsMax'] == '4096'
    assert type(resources['affinityCount']) is int and 1 <= resources['affinityCount'] <= 2
    actual = resources['actualCpuMax']
    assert isinstance(actual, str) and actual == actual.strip()
    parts = actual.split()
    assert len(parts) == 2 and all(part.isdigit() for part in parts), 'FTX_ACTUAL_CPU_MAX_UNVERIFIED'
    quota, period = map(int, parts)
    assert quota > 0 and period > 0 and quota / period == 1.75
    assert _ftx_digest(resources['actualCpuMaxSHA256']) == hashlib.sha256(actual.encode()).hexdigest()


def _ftx_state(value, state, binding):
    assert value['schemaVersion'] == 1 and value['state'] == state
    for key in ('decisionTableSHA256', 'corpusManifestSHA256', 'questionManifestSHA256'):
        assert _ftx_digest(value[key]) == binding[key]
    actions = value['personaActions']
    _ftx_ids(actions, 'actionId', FTX_ACTION_IDS)
    assert len(value['operatorActions']) + len(actions) <= 128
    sequences = [r['sequence'] for r in actions]
    assert len(sequences) == len(set(sequences))
    losses = []
    allowed = {'SUCCESS', 'LOSS_SOURCE_SPAN_MISSING', 'LOSS_REAL_FAILURE',
               'LOSS_ZERO_HIT', 'UNKNOWN', 'NOT_RUN_BUDGET',
               'NOT_ADVERTISED', 'ADVERTISED_NOT_EXERCISED'}
    for row in actions:
        assert row['state'] == state and row['outcome'] in allowed
        assert row['role'] in ('P2', 'P3')
        assert type(row['attempts']) is int and row['attempts'] in (0, 1)
        assert isinstance(row['fixedReasonCode'], str)
        assert isinstance(row['rawRecordIds'], list)
        if row['outcome'] == 'LOSS_SOURCE_SPAN_MISSING':
            assert row['attempts'] == 0  # A private loss-receipt ID is not an executed request.
        elif row['outcome'] == 'SUCCESS':
            assert row['attempts'] == 1 and row['rawRecordIds']
            assert row['provenance'], 'FTX_SUCCESS_WITHOUT_PROVENANCE'
        if row['outcome'] != 'SUCCESS':
            losses.append(row['actionId'])
    assert value['hubOutcome'] in ('NOT_ADVERTISED', 'ADVERTISED_NOT_EXERCISED', 'NOT_RUN_BUDGET', 'SUCCESS', 'LOSS_REAL_FAILURE', 'LOSS_ZERO_HIT', 'UNKNOWN')
    assert type(value['complete']) is bool
    if value['complete']:
        assert value['started'] is True
        assert value['freshStateProof']['freshOwnedDirectoriesCreated'] is True
        assert value['freshStateProof']['distinctState'] == state
        assert value['freshStateProof']['sameFixedCorpus'] is True
        assert value['freshStateProof']['sameVerifiedBinary'] is True
        assert value['hubOutcome'] != 'NOT_RUN_BUDGET'
        assert value['ownedStopProof']['allReaped'] is True
        assert value['ownedStopProof']['zeroLiveXerjAfterCleanup'] is True, 'FTX_OWNED_XERJ_CLEANUP_UNVERIFIED'
        wanted_cleanup = _ftx_digest(value['ownedStopProof']['zeroLiveXerjProofSHA256'])
        matches = [proof for proof in value['networkProof']['phases'] if hashlib.sha256(json.dumps(proof,sort_keys=True).encode()).hexdigest() == wanted_cleanup]
        assert len(matches) == 1, 'FTX_ZERO_LIVE_CHECKPOINT_HASH_NOT_UNIQUE'
        last_proof = matches[0]
        scan = last_proof['childEnvironmentCheckpoint']
        assert scan['scanPerformed'] is True and scan['allLiveXerjMatched'] is True
        assert scan['matchedCount'] == 0 and scan['processes'] == [], 'FTX_LIVE_XERJ_AFTER_CLEANUP'
        if (last_proof.get('mode') or last_proof.get('c2Mode')) == 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
            assert last_proof['phase'] == 'CHECKPOINT'
        assert _ftx_digest(value['ownedStopProof']['zeroLiveXerjProofSHA256']) == hashlib.sha256(json.dumps(last_proof,sort_keys=True).encode()).hexdigest()

        assert 0 <= value['wallSeconds'] <= 600
        assert value['finishedUTC'] >= value['startedUTC']
        assert abs(value['finishedUTC'] - value['startedUTC'] - value['wallSeconds']) < .05
        observed=value['listenerCompatibility']
        assert observed['actualRecordsRecognized']is True
        for name in ('nativeRecordSHA256','esRecordSHA256','stdoutSHA256','stderrSHA256'):_ftx_digest(observed[name])
        _ftx_resource_partition(value, binding)
        assert value['operatorActions'], 'FTX_COMPLETE_WITHOUT_REAL_CLI'
        _ftx_ids(value['tokenMetrics'], 'questionId', ('Q1', 'Q2', 'Q3', 'Q4', 'Q5'))
        for metric in value['tokenMetrics']:
            if metric.get('outcome') == 'LOSS_REAL_FAILURE':
                assert metric['ratio'] is None
                continue
            _ftx_question_top_one(metric)
            replies = metric['completeSearchResponseSet']
            assert replies and len({r['sequence'] for r in replies}) == len(replies)
            assert sum(r['armBBytes'] for r in replies) == metric['armBDecodedWireMinusHintsBytes']
            assert sum(r['hintsBytes'] for r in replies) == metric['hintsBytesSeparate']
            for row in replies:
                assert 0 <= row['rawBytes'] <= 8*1024**2
                assert 0 <= row['armBBytes'] <= row['decodedBytes'] <= 8*1024**2
                assert row['armBBytes'] + row['hintsBytes'] == row['decodedBytes']
            for field, token in (('armAAllUniqueFilesBytes', 'AAll'),
                                 ('armATopOnePerResponseUniqueBytes', 'ATop1'),
                                 ('armBDecodedWireMinusHintsBytes', 'B')):
                assert metric[field] >= 0 and metric['approxTokensAtFourBytes'][token] == metric[field]/4
            if metric['zeroHitRetained']:
                assert metric['allRatio'] is None and metric['top1Ratio'] is None
    return losses


def _ftx_response_sets(accounting, states):
    sets = accounting['responseSets']
    expected = accounting['expectedIDs']
    limits = {'cli': 128, 'rpc': 32, 'http': 336, 'forwarded': 320}
    per_state = {'cli': 64, 'rpc': 16, 'http': 168, 'forwarded': 160}
    for state in states:
        proof = state['rawEvidenceCountsAndHashes']
        intents = proof['requestIntentIDs']
        direct = proof['directHTTPIntentIDs'] if state.get('state') in ('BASELINE', 'CANDIDATE') else []
        assert isinstance(direct, list) and len(direct) == len(set(direct))
        assert set(direct) <= set(intents['http']), 'FTX_DIRECT_HTTP_NOT_ACCOUNTED'
        _ftx_cap_operation_counts({**{kind: len(intents[kind]) for kind in per_state}, 'directHTTP': len(direct)})
    count_keys = {'cli': 'actualCLICommandCount', 'rpc': 'actualRPCRequestCount',
                  'http': 'actualHTTPClientRequestCount', 'forwarded': 'actualForwardedPairCount'}
    for kind, count_key in count_keys.items():
        rows = sets[kind]
        intents = [item for state in states for item in
                   state['rawEvidenceCountsAndHashes']['requestIntentIDs'][kind]]
        assert len(intents) == len(set(intents)), 'FTX_DUPLICATE_INTENT_ID'
        assert set(intents) == set(expected[kind]), 'FTX_INTENT_RESPONSE_UNIVERSE_MISMATCH'
        ids = _ftx_ids(rows, 'id', expected[kind])
        assert len(ids) == accounting[count_key] <= limits[kind]
        for row in rows:
            if kind == 'cli':
                assert row['reaped'] is True and type(row['timeout']) is bool
                assert row['exit'] is None or type(row['exit']) is int
                for stream in ('stdout', 'stderr'):
                    assert 0 <= row[stream]['bytes'] <= 8*1024**2
                    _ftx_digest(row[stream]['sha256'])
            else:
                assert row['outcome'] in ('RESPONSE', 'ERROR', 'TIMEOUT', 'REFUSED',
                                          'NO_RESPONSE', 'EXPLICIT_REFUSAL', 'EXPLICIT_NONRESPONSE')
                if row['responseSHA256'] is not None:
                    _ftx_digest(row['responseSHA256'])
                else:
                    assert row['outcome'] != 'RESPONSE'
    assert accounting['actualCLIResponseSetCount'] == accounting['actualCLICommandCount']
    assert accounting['actualRPCResponseCount'] <= accounting['actualRPCRequestCount']
    assert accounting['actualRPCResponseCount'] == sum(r['outcome'] == 'RESPONSE' for r in sets['rpc'])
    _ftx_cap_sizes(accounting['privateRecordCount'], accounting['privateBytes'], [])
    _ftx_digest(accounting['privateInventorySHA256'])
    assert type(accounting['complete']) is bool


def _ftx_loss_ids(rows):
    assert isinstance(rows, list)
    ids = [row['actionId'] for row in rows]
    assert len(ids) == len(set(ids))
    return set(ids)


def _ftx_public_privacy(value):
    """A structural guard in addition to the producer's explicit allowlist."""
    forbidden = {'rawBody', 'rawRequest', 'rawResponse', 'body', 'nodeLog',
                 'proxyLog', 'environment', 'env', 'privatePath', 'commandLine',
                 'auditEntries', 'generatedMCPConfig'}
    if isinstance(value, dict):
        assert not forbidden.intersection(value), 'FTX_RAW_PRIVATE_FIELD_IN_PUBLIC'
        for item in value.values():
            _ftx_public_privacy(item)
    elif isinstance(value, list):
        for item in value:
            _ftx_public_privacy(item)
    elif isinstance(value, str):
        assert len(value) <= 2048, 'FTX_UNBOUNDED_PUBLIC_STRING'
        assert not any(x in value for x in ('/Users/', '/private/', '/tmp/',
                                           'github_pat_', 'ghp_', 'Authorization:'))


def verify_ftx(root, manifest=None):
    """Validate sanitized FTX evidence; honest losses are not an all-pass claim."""
    root = Path(root)
    if manifest is None:
        manifest = json.loads((root/'file-manifest.json').read_text())
    indexed = {r['path']: r for r in manifest}
    assert set(FTX_FILES) <= set(indexed), 'FTX_REQUIRED_EVIDENCE_MISSING'
    assert sum(indexed[n]['bytes'] for n in FTX_FILES) <= FTX_EVIDENCE_CAP_PROFILE['publicTotalBytes']
    values = {}
    for name in FTX_FILES:
        item = indexed[name]
        path = root/relative(name)
        assert not path.is_symlink() and path.is_file()
        assert path.stat().st_size == item['bytes'] <= FTX_EVIDENCE_CAP_PROFILE['publicFileBytes']
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        values[name] = json.loads(raw)
        assert values[name]['schemaVersion'] == 1
        _ftx_public_privacy(values[name])
    controls = values['ftx-controls.json']
    _ftx_ids(controls['controls'], 'id', FTX_CONTROL_IDS)
    controls_complete = controls['allExpectedOutcomesObserved'] is True
    assert controls['expectedCount'] == 27 and controls['observedCount'] <= 27
    assert controls['expectedIdsSHA256'] == hashlib.sha256(json.dumps(list(FTX_CONTROL_IDS)).encode()).hexdigest()
    for row in controls['controls']:
        assert type(row['expectedOutcomeObserved']) is bool
        if row['expectedOutcomeObserved']:
            assert row['attempts'] == 1
            _ftx_digest(row['evidenceSHA256'])
    if controls_complete:
        assert controls['observedCount'] == 27
        assert all(r['expectedOutcomeObserved'] for r in controls['controls'])
    binding = values['ftx-surface-corpus-bindings.json']
    assert binding['sourcePin'] == '50e4ffded5518b1822cfac5450fa34d3829ab8ab'
    assert binding['sourceCount'] == 120 and binding['sourceBytes'] == 9444700
    assert binding['sameOfferingMechanism'] is True
    hub_question=binding['hubPublicQuestion']
    assert hub_question['derivation']=='OFFERED_COVERED_CORPUS_TOPIC'
    assert hub_question['questionSHA256']=='76595d99c76169626e8cc58c3ad1d6f54f7b518afaf38f4ace752bdaa655cc7e'
    _ftx_digest(hub_question['rationaleSHA256'])
    assert set(hub_question['provenance'])=={'baseline','candidate'}
    for state,key in (('baseline','baselineSurfaces'),('candidate','candidateSurfaces')):
        span=hub_question['provenance'][state]
        assert span['surface_id']=='llms_full' and span['sha256']==binding[key]['llms_full']['sha256']
        assert span['start_line']==346 and span['end_line']==356
        _ftx_digest(span['sha256']);_ftx_digest(span['exactTextSHA256'])
    for key in ('decisionTableSHA256', 'corpusManifestSHA256', 'questionManifestSHA256', 'helperSHA256'):
        _ftx_digest(binding[key])
    assert controls['helperSHA256'] == binding['helperSHA256']
    before = values['ftx-before-summary.json']
    after = values['ftx-after-summary.json']
    before_losses = _ftx_state(before, 'BASELINE', binding)
    after_losses = _ftx_state(after, 'CANDIDATE', binding)
    comparison = values['ftx-comparison.json']
    assert comparison['beforeSummarySHA256'] == indexed['ftx-before-summary.json']['sha256']
    assert comparison['afterSummarySHA256'] == indexed['ftx-after-summary.json']['sha256']
    assert comparison['decisionTableSHA256'] == binding['decisionTableSHA256']
    assert comparison['sameCorpusAndQuestions'] is True
    assert comparison['actualActionsCompared'] == 15
    old = {r['actionId']: r['outcome'] for r in before['personaActions']}
    new = {r['actionId']: r['outcome'] for r in after['personaActions']}
    both_states_observed = before['complete'] is True and after['complete'] is True
    regressions = ({k for k, v in old.items() if v == 'SUCCESS' and new[k] != 'SUCCESS'}
                   if both_states_observed else set())
    assert set(comparison['regressions']) == regressions, 'FTX_UNREPORTED_REGRESSION'
    token_losses = []
    for state in (before, after):
        token_losses.append({r['questionId'] for r in state['tokenMetrics']
                             if r.get('outcome') in ('LOSS_REAL_FAILURE', 'LOSS_ZERO_HIT')})
    assert set(comparison['baselineTokenLosses']) == token_losses[0]
    assert set(comparison['candidateTokenLosses']) == token_losses[1]
    both_token_sets_observed = both_states_observed and all(
        {r['questionId'] for r in state['tokenMetrics']} == {'Q1', 'Q2', 'Q3', 'Q4', 'Q5'}
        for state in (before, after))
    token_regressions = token_losses[1] - token_losses[0] if both_token_sets_observed else set()
    assert set(comparison['tokenRegressions']) == token_regressions
    assert set(FTX_QUALIFICATIONS) <= set(comparison['qualifications'])
    assert _ftx_loss_ids(comparison['baselineLosses']) == set(before_losses)
    assert _ftx_loss_ids(comparison['candidateLosses']) == set(after_losses)
    allowed = {'NO_OBSERVED_REGRESSION_WITH_LOSSES', 'REGRESSION', 'INCOMPLETE', 'UNKNOWN'}
    assert comparison['outcome'] in allowed and type(comparison['complete']) is bool
    accounting = values['ftx-evidence-accounting.json']
    listed = {r['name']: r for r in accounting['publicFiles']}
    assert set(listed) == set(FTX_FILES) - {'ftx-evidence-accounting.json'}
    for name, row in listed.items():
        assert row['bytes'] == indexed[name]['bytes'] and row['sha256'] == indexed[name]['sha256']
    assert accounting['publicBytes'] == sum(r['bytes'] for r in listed.values())
    assert accounting['requiredFileSetSHA256'] == hashlib.sha256(json.dumps(list(FTX_FILES)).encode()).hexdigest()
    _ftx_cap_binding(binding, accounting)
    _ftx_cap_sizes(accounting['privateRecordCount'], accounting['privateBytes'], [indexed[n]['bytes'] for n in FTX_FILES])
    _ftx_response_sets(accounting, (before, after))
    full_scope = [_ftx_full_protocol(x, binding, accounting) for x in (before, after)]
    phase_old = {r['id']: r['outcome'] for r in before['fullProtocol']['records']}
    phase_new = {r['id']: r['outcome'] for r in after['fullProtocol']['records']}
    phase_regressions = ({k for k, v in phase_old.items() if v == 'RECORDED' and phase_new[k] != 'RECORDED'}
                         if before['complete'] and after['complete'] and all(full_scope) else set())
    assert set(comparison['fullProtocolRegressions']) == phase_regressions, 'FTX_UNREPORTED_FULL_PROTOCOL_REGRESSION'
    installer_recorded = all(next(r for r in x['fullProtocol']['records'] if r['id'] == 'P1_INSTALL')['outcome'] == 'RECORDED' for x in (before, after))
    assert binding['publicInstallerExercised'] is installer_recorded
    assert binding['publicInstallerSucceededAllStates'] is installer_recorded
    network_identities = [_ftx_full_network(value) for value in (before, after) if value['complete']]
    if len(network_identities) == 2:
        assert network_identities[0] == network_identities[1], 'FTX_C2_STATE_BINDING_MISMATCH'
    approved_identity = (binding['c2Mode'], _ftx_digest(binding['c2ApprovalReceiptSHA256']), _ftx_digest(binding['c2ImplementationSHA256']))
    for identity in network_identities:
        assert identity == approved_identity, 'FTX_C2_ACTUAL_APPROVAL_BINDING_MISMATCH'
    if before['complete'] and after['complete']:
        _ftx_fixed_final(before, after, comparison, accounting, binding)
    complete = controls_complete and before['complete'] and after['complete'] and accounting['complete'] and all(full_scope)
    if not complete:
        assert comparison['outcome'] in ('INCOMPLETE', 'UNKNOWN') and comparison['complete'] is False
    elif comparison['outcome'] == 'NO_OBSERVED_REGRESSION_WITH_LOSSES':
        assert comparison['complete'] is True and comparison['stateCount'] == 2
        assert not comparison['regressions'] and not token_regressions and not phase_regressions
        assert before['auditAlignment']['state'] == after['auditAlignment']['state'] == 'EXACT'
    complete = bool(complete and comparison['complete'] and comparison['outcome'] in ('NO_OBSERVED_REGRESSION_WITH_LOSSES', 'REGRESSION') and before['auditAlignment']['state'] == after['auditAlignment']['state'] == 'EXACT')
    return {'state': comparison['outcome'], 'complete': bool(complete),
            'controls': 27, 'actionsPerState': 15, 'fullProtocolPhasesPerState': 35, 'productPassClaim': False,
            'qualifiedFTXEvidenceOnly': True}



def verify_partial_ftx(root, manifest):
    """Sanitized incomplete diagnostics only; cannot establish a candidate claim."""
    root = Path(root)
    indexed = {r['path']: r for r in manifest}
    status = json.loads((root/'candidate-ftx-export-status.json').read_text())
    assert status['schemaVersion'] == 1 and status['fullCandidateClaim'] is False
    assert status['state'] == 'INCOMPLETE_NOT_CANDIDATE_PASS'
    present = set(FTX_FILES) & set(indexed)
    assert set(status['presentFTXProofs']) == present
    assert len(status['presentFTXProofs']) == len(present)
    assert status['expectedFTXProofs'] == list(FTX_FILES)
    _ftx_public_privacy(status)
    assert sum(indexed[n]['bytes'] for n in present) <= FTX_EVIDENCE_CAP_PROFILE['publicTotalBytes']
    for name in present:
        item = indexed[name]
        raw = (root/relative(name)).read_bytes()
        assert len(raw) == item['bytes'] <= FTX_EVIDENCE_CAP_PROFILE['publicFileBytes']
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        value = json.loads(raw)
        assert value['schemaVersion'] == 1
        _ftx_public_privacy(value)
    return {'state': status['state'], 'complete': False,
            'presentProofCount': len(present), 'expectedProofCount': 6,
            'productPassClaim': False}


def export_ftx(source, destination, names, required=()):
    """Explicit full-candidate producer: all six proofs remain mandatory."""
    selected = set(names) | set(FTX_FILES)
    required = set(required) | set(FTX_FILES)
    return export(source, destination, selected, required=required)


def ftx_fixture(root, clock):
    """Future Docker-only semantic reader controls; every input is synthetic."""
    import copy
    root = Path(root)
    root.mkdir(exist_ok=False)
    h = hashlib.sha256(b'SYNTHETIC_CONTROL_NOT_REAL_FTX').hexdigest()
    binding = {'schemaVersion': 1, 'sourcePin': '50e4ffded5518b1822cfac5450fa34d3829ab8ab',
               'sourceCount': 120, 'sourceBytes': 9444700, 'sameOfferingMechanism': True,
               'publicInstallerExercised': True, 'publicInstallerSucceededAllStates': True,
               'binarySHA256': h, 'releaseArchiveSHA256': h,
               **{k: h for k in ('decisionTableSHA256', 'corpusManifestSHA256',
                                'questionManifestSHA256', 'helperSHA256')}}
    binding['baselineSurfaces']={'llms_full':{'sha256':h,'bytes':1}}
    binding['candidateSurfaces']={'llms_full':{'sha256':h,'bytes':1}}
    binding['hubPublicQuestion']={'questionSHA256':'76595d99c76169626e8cc58c3ad1d6f54f7b518afaf38f4ace752bdaa655cc7e',
        'derivation':'OFFERED_COVERED_CORPUS_TOPIC','rationaleSHA256':h,
        'provenance':{state:{'surface_id':'llms_full','sha256':h,'start_line':346,'end_line':356,'exactTextSHA256':h}for state in ('baseline','candidate')}}
    controls = {'schemaVersion': 1, 'helperSHA256': h,
                'expectedIdsSHA256': hashlib.sha256(json.dumps(list(FTX_CONTROL_IDS)).encode()).hexdigest(),
                'expectedCount': 27, 'observedCount': 27, 'allExpectedOutcomesObserved': True,
                'controls': [{'id': k, 'expectedOutcomeObserved': True, 'attempts': 1,
                              'evidenceSHA256': h} for k in FTX_CONTROL_IDS]}
    binding['evidenceCaps'] = dict(FTX_EVIDENCE_CAP_PROFILE, approvalSHA256=h)
    binding.update(c2Mode='ORIGINAL_ENDPOINT_BLOCK', c2ApprovalReceiptSHA256=h, c2ImplementationSHA256=h)
    binding['resourcePartition'] = {'globalCpuLimit':2,'globalMemoryLimitBytes':8589934592,'targetCpuLimit':1.75,'targetMemoryLimitBytes':8321499136,'proxyCpuLimit':.25,'proxyMemoryLimitBytes':268435456}
    states = []
    cli = []
    for state in ('BASELINE', 'CANDIDATE'):
        ident = state+'-synthetic-cli'
        command = {'id': ident, 'reaped': True, 'timeout': False, 'exit': 0,
                   'stdout': {'bytes': 0, 'sha256': h}, 'stderr': {'bytes': 0, 'sha256': h}}
        cli.append(command)
        actions = [{'actionId': k, 'state': state, 'sequence': i,
                    'role': 'P2' if k.startswith('P2') else 'P3',
                    'attempts': 0 if k == 'P2_HUB_OBSERVATION' else 1,
                    'outcome': 'NOT_ADVERTISED' if k == 'P2_HUB_OBSERVATION' else 'SUCCESS',
                    'fixedReasonCode': 'SYNTHETIC', 'rawRecordIds': [] if k == 'P2_HUB_OBSERVATION' else [ident],
                    'provenance': {'surfaceSHA256': h}} for i, k in enumerate(FTX_ACTION_IDS)]
        states.append({'schemaVersion': 1, 'state': state,
                       **{k: binding[k] for k in ('decisionTableSHA256', 'corpusManifestSHA256', 'questionManifestSHA256')},
                       'personaActions': actions, 'operatorActions': [command],
                       'hubOutcome': 'NOT_ADVERTISED', 'complete': True, 'started': True,
                       'startedUTC': 0, 'finishedUTC': 1, 'wallSeconds': 1,
                       'freshStateProof': {'freshOwnedDirectoriesCreated': True, 'distinctState': state,
                                           'sameFixedCorpus': True, 'sameVerifiedBinary': True},
                       'networkProof': {'externalNetworkPhysicallyDisconnected': True, 'nonLoopbackInterfaces': 0},
                       'ownedStopProof': {'allReaped': True}, 'auditAlignment': {'state': 'EXACT'},
                       'listenerCompatibility': {'actualRecordsRecognized':True,**{k:h for k in ('nativeRecordSHA256','esRecordSHA256','stdoutSHA256','stderrSHA256')}},
                       'resources': {'cpuLimit': 1.75, 'memoryLimitBytes': 8321499136, 'swapBytes': 0, 'pidsLimit': 4096,
                                     'globalCpuLimit':2,'globalMemoryLimitBytes':8589934592,'proxyCpuLimit':.25,'proxyMemoryLimitBytes':268435456,
                                     'memoryMax':'8321499136','memorySwapMax':'0','pidsMax':'4096','affinityCount':2,
                                     'actualCpuMax':'175000 100000','actualCpuMaxSHA256':hashlib.sha256(b'175000 100000').hexdigest()},
                       'rawEvidenceCountsAndHashes': {'requestIntentIDs': {'cli': [ident], 'rpc': [], 'http': [], 'forwarded': []}, 'directHTTPIntentIDs': []},
                       'tokenMetrics': [{'questionId': 'Q'+str(i), 'outcome': 'LOSS_REAL_FAILURE', 'ratio': None} for i in range(1, 6)]})
    comparison = {'schemaVersion': 1, 'decisionTableSHA256': h, 'sameCorpusAndQuestions': True,
                  'stateCount': 2, 'actualActionsCompared': 15, 'qualifications': list(FTX_QUALIFICATIONS),
                  'baselineLosses': [{'actionId': 'P2_HUB_OBSERVATION'}],
                  'candidateLosses': [{'actionId': 'P2_HUB_OBSERVATION'}],
                  'baselineTokenLosses': ['Q'+str(i) for i in range(1, 6)],
                  'candidateTokenLosses': ['Q'+str(i) for i in range(1, 6)], 'tokenRegressions': [],
                  'regressions': [], 'fullProtocolRegressions': [], 'complete': True, 'outcome': 'NO_OBSERVED_REGRESSION_WITH_LOSSES'}
    accounting = {'schemaVersion': 1, 'responseSets': {'cli': cli, 'rpc': [], 'http': [], 'forwarded': []},
                  'expectedIDs': {'cli': [x['id'] for x in cli], 'rpc': [], 'http': [], 'forwarded': []},
                  'actualCLICommandCount': 2, 'actualCLIResponseSetCount': 2,
                  'actualRPCRequestCount': 0, 'actualRPCResponseCount': 0,
                  'actualHTTPClientRequestCount': 0, 'actualForwardedPairCount': 0,
                  'privateRecordCount': 2, 'privateBytes': 0, 'privateInventorySHA256': h,
                  'evidenceCapsApprovalSHA256': h,
                  'requiredFileSetSHA256': hashlib.sha256(json.dumps(list(FTX_FILES)).encode()).hexdigest(),
                  'complete': True}
    for state in states:
        phase_rows = []
        for phase in FTX_FULL_PROTOCOL_IDS:
            ident = state['state'] + '-synthetic-phase-' + phase
            receipt = {'id': ident, 'reaped': True, 'timeout': False, 'exit': 0,
                       'stdout': {'bytes': 1, 'sha256': h}, 'stderr': {'bytes': 0, 'sha256': h}}
            accounting['responseSets']['cli'].append(receipt)
            accounting['expectedIDs']['cli'].append(ident)
            state['rawEvidenceCountsAndHashes']['requestIntentIDs']['cli'].append(ident)
            phase_rows.append({'id': phase, 'outcome': 'RECORDED', 'failureClass': None, 'attempted': True,
                               'operationStatus': 'EXECUTED',
                               'operationIntentIDs': {'cli': [ident], 'rpc': [], 'http': [], 'forwarded': []},
                               'routedThroughCapture': phase not in ('P1_AUTOINDEX','P1_LITERAL_NEXT','P1_ZERO_FLAG_SEARCH','P1_ZERO_FLAG_DEF','GAIN_NAIVE_THEN_DOCUMENTED'),
                               'observationRefs': [], 'contentAssertions': {'checkedSynthetic': True},
                               'wallSeconds': 0, 'rawRecordSHA256': h})
        for record in phase_rows:
            if record['id'] in ('P1_HUB_COUNTERPART', 'P2_HUB_IF_ADVERTISED'):
                record['contentAssertions']['questionSHA256'] = h
            if record['id'] == 'P1_MAP':
                record['contentAssertions'].update(datasetIdentityObserved=True, perFieldTypesAndExamplesObserved=True,
                    readyQueryTemplatesObserved=True, observedFieldCount=1, observedQueryCount=1, actualMapOutputSHA256=h)
            if record['id'] == 'KNOWLEDGE_SEMANTICS':
                record['contentAssertions'].update(recordsFilesCompared=True, relationsLabelled=True, lexicalClaimsChecked=True,
                    explicitRuntimeModeLexical=True, explicitVectorClaimFalse=True, explicitSemanticClaimFalse=True, representationSHA256=h)
            if record['id'] == 'P2_SAME_HINTS':
                record['contentAssertions'].update(sameHints=True, mcpHintsSHA256=h, cliHintsSHA256=h)
        state['evidenceCaps'] = copy.deepcopy(binding['evidenceCaps'])
        for protocol_row in phase_rows:
            if protocol_row['id'] in ('P1_HUB_COUNTERPART','P2_HUB_IF_ADVERTISED'):
                protocol_row['contentAssertions']['questionSHA256']=binding['hubPublicQuestion']['questionSHA256']
            if protocol_row['id']=='GAIN_NAIVE_THEN_DOCUMENTED':
                protocol_row['contentAssertions'].update(naiveXerjURLAbsent=True,structuredXerjURLAbsent=True,operatorHelpXerjURLAbsent=True)
        state['fullProtocol'] = {'schemaVersion': 1, 'requiredIDs': list(FTX_FULL_PROTOCOL_IDS),
                                 'records': phase_rows, 'allRequiredAccounted': True,
                                 'fullMandatoryScopeExercised': True, 'sourceCount': 120, 'sourceBytes': 9444700}
        state['networkProof']['phases'] = [dict(
            phase=phase, c2Mode='ORIGINAL_ENDPOINT_BLOCK', approvalSHA256=h, implementationSHA256=h,
            evidenceSHA256=h, actualKernelEnforced=True, connectionLoggingActive=True,
            allOtherEgressDenied=True, helperExecutionNamespaceMatches=True,
            encryptedPathBlocked=True, corpusFeedbackEndpointBlocked=True,
            installerAndReleaseAllowlistOnly=True, hubCatalogueOnlyIfObserved=True,
            externalNetworkPhysicallyDisconnected=(phase == 'OFFLINE')) for phase in ('INSTALLER', 'HUB', 'OFFLINE')]
    for state in states:
        state['networkProof']['phases'][-1]['childEnvironmentCheckpoint'] = {'scanPerformed':True,'allLiveXerjMatched':True,'matchedCount':0,'processes':[]}
        state['ownedStopProof'].update(zeroLiveXerjAfterCleanup=True,zeroLiveXerjProofSHA256=hashlib.sha256(json.dumps(state['networkProof']['phases'][-1],sort_keys=True).encode()).hexdigest())
    accounting['actualCLICommandCount'] = accounting['actualCLIResponseSetCount'] = len(accounting['responseSets']['cli'])
    original = dict(zip(FTX_FILES, [controls, binding, *states, comparison, accounting]))
    results = []
    def check(label, mutate, accepted):
        clock()
        values = copy.deepcopy(original)
        mutate(values)
        source = root/label
        source.mkdir(exist_ok=False)
        def save(name):
            (source/name).write_text(json.dumps(values[name], sort_keys=True)+'\n')
        for name in FTX_FILES[:4]:
            if name in values:
                save(name)
        for key, name in (('beforeSummarySHA256', FTX_FILES[2]), ('afterSummarySHA256', FTX_FILES[3])):
            values[FTX_FILES[4]][key] = hashlib.sha256((source/name).read_bytes()).hexdigest() if (source/name).exists() else h
        save(FTX_FILES[4])
        listed = [{'name': n, 'bytes': (source/n).stat().st_size,
                   'sha256': hashlib.sha256((source/n).read_bytes()).hexdigest()}
                  for n in FTX_FILES[:-1] if (source/n).exists()]
        values[FTX_FILES[5]].update(publicFiles=listed, publicBytes=sum(r['bytes'] for r in listed))
        save(FTX_FILES[5])
        manifest = [{'path': f.name, 'bytes': f.stat().st_size,
                     'sha256': hashlib.sha256(f.read_bytes()).hexdigest()} for f in source.iterdir()]
        error = None
        try:
            verify_ftx(source, manifest)
        except (AssertionError, KeyError, TypeError, ValueError):
            error = True
        assert (error is None) == accepted, 'FTX_SEMANTIC_FIXTURE:'+label
        results.append({'id': label, 'expectedAccepted': accepted, 'accepted': error is None})
    check('synthetic-qualified-schema', lambda v: None, True)
    check('missing-proof', lambda v: v.pop(FTX_FILES[0]), False)
    check('missing-control', lambda v: v[FTX_FILES[0]]['controls'].pop(), False)
    check('duplicate-control', lambda v: v[FTX_FILES[0]]['controls'].append(v[FTX_FILES[0]]['controls'][0]), False)
    check('missing-action', lambda v: v[FTX_FILES[2]]['personaActions'].pop(), False)
    check('missing-intent-response', lambda v: v[FTX_FILES[5]]['responseSets']['cli'].pop(), False)
    check('missing-stdout-proof', lambda v: v[FTX_FILES[5]]['responseSets']['cli'][0].pop('stdout'), False)
    check('network-still-attached', lambda v: v[FTX_FILES[2]]['networkProof'].update(externalNetworkPhysicallyDisconnected=False), False)
    check('child-not-reaped', lambda v: v[FTX_FILES[3]]['ownedStopProof'].update(allReaped=False), False)
    check('omitted-loss', lambda v: v[FTX_FILES[4]].update(baselineLosses=[]), False)
    check('private-raw-field', lambda v: v[FTX_FILES[3]].update(rawBody='SYNTHETIC_NOT_EXPORTABLE'), False)
    check('missing-disclosure', lambda v: v[FTX_FILES[4]]['qualifications'].pop(), False)
    check('oversize-public-string', lambda v: v[FTX_FILES[4]].update(note='x'*2049), False)
    check('mismatched-source-count', lambda v: v[FTX_FILES[1]].update(sourceCount=115), False)
    check('full-phase-missing', lambda v: v[FTX_FILES[2]]['fullProtocol']['records'].pop(), False)
    check('full-phase-false-attempt', lambda v: v[FTX_FILES[2]]['fullProtocol']['records'][0].update(attempted=False), False)
    check('full-phase-unaccounted-operation', lambda v: v[FTX_FILES[2]]['fullProtocol']['records'][0]['operationIntentIDs']['cli'].append('not-an-intent'), False)
    def blocked_false(v):
        row = v[FTX_FILES[2]]['fullProtocol']['records'][0]
        row.update(attempted=False, operationStatus='BLOCKED_NO_OPERATION', outcome='LOSS', failureClass='REAL_OPERATION_OR_CONTRACT_FAILURE', operationIntentIDs={k: [] for k in ('cli', 'rpc', 'http', 'forwarded')})
    check('blocked-is-not-full-exercised', blocked_false, False)
    def labels_only(v):
        row = v[FTX_FILES[2]]['fullProtocol']['records'][0]
        row.update(attempted=False, operationStatus='OBSERVED_PRIOR_OUTPUT', operationIntentIDs={k: [] for k in ('cli', 'rpc', 'http', 'forwarded')}, observationRefs=[], contentAssertions={})
    check('full-phase-label-only', labels_only, False)
    check('full-phase-wrong-source', lambda v: v[FTX_FILES[2]]['fullProtocol'].update(sourceCount=119), False)
    check('network-phase-missing', lambda v: v[FTX_FILES[2]]['networkProof']['phases'].pop(0), False)
    check('network-false-substitute', lambda v: v[FTX_FILES[2]]['networkProof']['phases'][0].update(c2Mode='SOURCE_OPTOUT_AND_LOOPBACK_REDIRECT'), False)
    def recorded_failure(v):
        v[FTX_FILES[2]]['fullProtocol']['records'][1].update(outcome='LOSS', failureClass='REAL_OPERATION_OR_CONTRACT_FAILURE')
    check('real-operation-failure-is-recorded-loss', recorded_failure, True)
    def measured_top1(v):
        metric = {'questionId': 'Q1', 'outcome': 'MEASURED', 'ratio': 6.25,
                  'armAAllUniqueFilesBytes': 100, 'armATopOneQuestionFileBytes': 60,
                  'armATopOnePerResponseUniqueBytes': 60,
                  'top1Definition': 'SINGLE_FIRST_ACTUAL_CLI_DISPLAYED_FILE_PER_QUESTION',
                  'armBDecodedWireMinusHintsBytes': 16, 'hintsBytesSeparate': 4,
                  'completeSearchResponseSet': [{'sequence': 1, 'rawBytes': 20, 'decodedBytes': 20, 'armBBytes': 16, 'hintsBytes': 4}],
                  'approxTokensAtFourBytes': {'AAll': 25, 'ATop1': 15, 'B': 4},
                  'zeroHitRetained': False, 'allRatio': 6.25, 'top1Ratio': 3.75}
        for name in FTX_FILES[2:4]:
            v[name]['tokenMetrics'][0] = copy.deepcopy(metric)
        v[FTX_FILES[4]]['baselineTokenLosses'] = ['Q'+str(i) for i in range(2, 6)]
        v[FTX_FILES[4]]['candidateTokenLosses'] = ['Q'+str(i) for i in range(2, 6)]
    check('synthetic-measured-question-top1', measured_top1, True)
    def wrong_top1(v):
        measured_top1(v)
        v[FTX_FILES[2]]['tokenMetrics'][0]['armATopOnePerResponseUniqueBytes'] = 100
    check('question-level-not-per-response-top1', wrong_top1, False)
    def wrong_hints(v):
        measured_top1(v)
        v[FTX_FILES[2]]['tokenMetrics'][0]['completeSearchResponseSet'][0]['hintsBytes'] = 5
    check('complete-response-hints-byte-arithmetic', wrong_hints, False)
    def substitute_mode(v):
        v[FTX_FILES[1]]['c2Mode'] = 'SOURCE_OPTOUT_AND_LOOPBACK_REDIRECT'
        for name in FTX_FILES[2:4]:
            for phase in v[name]['networkProof']['phases']:
                phase.update(c2Mode='SOURCE_OPTOUT_AND_LOOPBACK_REDIRECT', encryptedPathBlocked=False,
                             corpusFeedbackEndpointBlocked=False, sourceProvenOptOutApplied=True,
                             feedbackEndpointLoopbackOnly=True, actualNativeFeedbackControlsPassed=True)
        for name in FTX_FILES[2:4]:
            v[name]['ownedStopProof']['zeroLiveXerjProofSHA256'] = hashlib.sha256(json.dumps(v[name]['networkProof']['phases'][-1],sort_keys=True).encode()).hexdigest()
    check('synthetic-proposed-source-optout-mode', substitute_mode, True)
    def false_encrypted_block(v):
        substitute_mode(v)
        v[FTX_FILES[2]]['networkProof']['phases'][0]['encryptedPathBlocked'] = True
    check('substitute-cannot-claim-encrypted-block', false_encrypted_block, False)
    def unreported_phase_regression(v):
        v[FTX_FILES[3]]['fullProtocol']['records'][1].update(outcome='LOSS', failureClass='REAL_OPERATION_OR_CONTRACT_FAILURE')
    check('full-protocol-unreported-regression', unreported_phase_regression, False)
    def reported_phase_regression(v):
        unreported_phase_regression(v)
        v[FTX_FILES[4]]['fullProtocolRegressions'] = [FTX_FULL_PROTOCOL_IDS[1]]
        v[FTX_FILES[4]]['outcome'] = 'REGRESSION'
    check('full-protocol-reported-regression', reported_phase_regression, True)
    def wrong_question(v):
        row = next(r for r in v[FTX_FILES[2]]['fullProtocol']['records'] if r['id'] == 'P1_HUB_COUNTERPART')
        row['contentAssertions']['questionSHA256'] = '0'*64
    check('same-hub-question-proof-mismatch', wrong_question, False)
    def wrong_hint_proof(v):
        row = next(r for r in v[FTX_FILES[2]]['fullProtocol']['records'] if r['id'] == 'P2_SAME_HINTS')
        row['contentAssertions']['cliHintsSHA256'] = '0'*64
    check('same-cli-mcp-hints-proof-mismatch', wrong_hint_proof, False)
    def harness_false_loss(v):
        v[FTX_FILES[2]]['fullProtocol']['records'][1].update(outcome='LOSS', failureClass='HARNESS_UNVERIFIED')
    check('harness-unverified-is-not-product-loss', harness_false_loss, False)
    def recorded_harness_failure(v):
        v[FTX_FILES[2]]['fullProtocol']['records'][1]['failureClass'] = 'HARNESS_UNVERIFIED'
    check('harness-unverified-is-not-recorded', recorded_harness_failure, False)
    cap_boundary_results = []
    for label, records, byte_count, sizes, accepted in (
        ('exact-private-record-max', 4096, 0, [], True),
        ('private-record-max-plus-one', 4097, 0, [], False),
        ('exact-private-byte-max', 0, 768*1024**2, [], True),
        ('private-byte-max-plus-one', 0, 768*1024**2+1, [], False),
        ('exact-public-file-and-total-max', 0, 0, [1024**2]*6, True),
        ('public-file-max-plus-one', 0, 0, [1024**2+1], False),
        ('public-six-file-count-plus-one', 0, 0, [1]*7, False)):
        clock(); refused = False
        try: _ftx_cap_sizes(records, byte_count, sizes)
        except AssertionError: refused = True
        assert (not refused) == accepted, 'FTX_CAP_BOUNDARY:' + label
        cap_boundary_results.append({'id': label, 'expectedAccepted': accepted, 'accepted': not refused, 'metadataOnlyNoAllocation': True})
    for kind, maximum in (('cli', 64), ('rpc', 16), ('http', 168), ('forwarded', 160), ('directHTTP', 8)):
        for extra in (0, 1):
            clock(); counts = {key: 0 for key in ('cli', 'rpc', 'http', 'forwarded', 'directHTTP')}
            counts[kind] = maximum + extra; refused = False
            try: _ftx_cap_operation_counts(counts)
            except AssertionError: refused = True
            assert refused is (extra == 1), 'FTX_OPERATION_CAP_BOUNDARY'
            cap_boundary_results.append({'id': kind+'-max'+('-plus-one' if extra else ''), 'expectedAccepted': extra == 0, 'accepted': not refused, 'metadataOnlyNoAllocation': True})
    check('cap-receipt-binding-mismatch', lambda v: v[FTX_FILES[5]].update(evidenceCapsApprovalSHA256='0'*64), False)
    check('cap-profile-private-byte-overclaim', lambda v: v[FTX_FILES[1]]['evidenceCaps'].update(privateBytes=768*1024**2+1), False)
    def fixed_proxy_mode(v):
        v[FTX_FILES[1]]['c2Mode'] = 'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'
        for name in FTX_FILES[2:4]:
            state = v[name]
            state['networkProof']['externalNetworkPhysicallyDisconnected'] = False
            for phase in state['networkProof']['phases']:
                phase.update(mode='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT', c2Mode='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT',
                    c2ApprovalReceiptSHA256=h, implementationSHA256=h, hostProofSHA256=h, evidenceSHA256=h,
                    targetContainerID=h, networkNamespaceInode=1, currentRouteSHA256=h, publicSnapshotSHA256=h,
                    nativeControlsSHA256=h, kernelProofSHA256=h, sourceParityReceiptSHA256=h, currentProxyLogSHA256=h,
                    actualTargetRoutingSHA256=h, publicPacketSHA256=h, offlineHandoffReceiptSHA256=h,
                    currentProxyLogBytes=0, unexpectedSinkRequests=0,
                    allowedHosts=['xerj.org', 'github.com', 'release-assets.githubusercontent.com', 'hub.xerj.org'],
                    limits={'totalBytes':268435456,'connectionBytes':67108864},
                    resourcePartition={'targetNanoCPUs':1750000000,'targetMemoryBytes':8321499136,'proxyNanoCPUs':250000000,'proxyMemoryBytes':268435456,'aggregateCPUs':2,'aggregateMemoryBytes':8589934592,'cpuSet':'0,1'},
                    actualKernelEnforced=True, connectionLoggingActive=True, allOtherEgressDenied=True,
                    helperExecutionNamespaceMatches=True, sourceProvenOptOutApplied=True, feedbackEndpointLoopbackOnly=True,
                    actualNativeFeedbackControlsPassed=True, fixedTopologyAcrossEntireFTX=True,
                    projectTestsSeparateOffline=True, allFourReviewedHostsPermittedFromStart=True, sinkLiveEntireFTX=True,
                    externalNetworkPhysicallyDisconnected=False, encryptedPathBlocked=False, corpusFeedbackEndpointBlocked=False,
                    hostAllowlistPhaseSpecific=False, projectTestsExecutionProvedByThisGuard=False,
                    childEnvironmentCheckpoint={'scanPerformed':True,'allLiveXerjMatched':True,
                        'shortLivedProcessesBetweenCheckpointsNotAttested':True,'matchedCount':1,
                        'processes':[{'pid':1,'startTimeTicks':1,'optoutCorrect':True,'sinkCorrect':True,
                            **{key:h for key in ('executablePathSHA256','environmentSHA256','optoutValueSHA256','sinkValueSHA256')}}]})
        for name in FTX_FILES[2:4]:
            for phase in v[name]['networkProof']['phases']:
                phase.pop('installerAndReleaseAllowlistOnly', None);phase.pop('hubCatalogueOnlyIfObserved', None)
        for name in FTX_FILES[2:4]:
            state=v[name];last=copy.deepcopy(state['networkProof']['phases'][-1]);last['phase']='CHECKPOINT'
            last['childEnvironmentCheckpoint'].update(matchedCount=0,processes=[])
            state['networkProof']['phases'].append(last)
            state['ownedStopProof'].update(zeroLiveXerjAfterCleanup=True,zeroLiveXerjProofSHA256=hashlib.sha256(json.dumps(last,sort_keys=True).encode()).hexdigest())
        final = {'mode':'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT', 'infrastructureHOLD':False,
                 'sinkLiveUntilFTXClose':True, 'unexpectedSinkRequests':0, 'sinkLogSHA256':h,
                 'checkpointCount':8, 'receiptSHA256':h}
        v[FTX_FILES[4]]['c2FinalProof'] = copy.deepcopy(final)
        v[FTX_FILES[5]]['fixedContainmentFinal'] = copy.deepcopy(final)
    for count in (128, 129):
        clock(); values = copy.deepcopy(original); fixed_proxy_mode(values)
        state = values[FTX_FILES[2]]
        extra = copy.deepcopy(state['networkProof']['phases'][0]); extra['phase'] = 'CHECKPOINT'
        state['networkProof']['phases'].extend(copy.deepcopy(extra) for _ in range(count-len(state['networkProof']['phases'])))
        refused = False
        try: _ftx_full_network(state)
        except AssertionError: refused = True
        assert refused is (count == 129), 'FTX_REAL_CHECKPOINT_CONSUMER_BOUNDARY'
        cap_boundary_results.append({'id':'containment-checkpoint-'+str(count),'expectedAccepted':count==128,'accepted':not refused,'metadataOnlyBoundedSyntheticRecords':True})
    check('synthetic-fixed-proxy-observation', fixed_proxy_mode, True)
    def fixed_bad(v, key, value):
        fixed_proxy_mode(v);v[FTX_FILES[2]]['networkProof']['phases'][0][key]=value
    check('fixed-proxy-no-offline-claim', lambda v: fixed_bad(v,'externalNetworkPhysicallyDisconnected',True), False)
    check('fixed-proxy-no-encrypted-block-claim', lambda v: fixed_bad(v,'encryptedPathBlocked',True), False)
    check('fixed-proxy-unexpected-sink-infra-hold', lambda v: fixed_bad(v,'unexpectedSinkRequests',1), False)
    check('fixed-proxy-sink-not-live', lambda v: fixed_bad(v,'sinkLiveEntireFTX',False), False)
    check('fixed-proxy-os-proof-missing', lambda v: fixed_bad(v,'kernelProofSHA256',None), False)
    check('fixed-proxy-topology-drift', lambda v: fixed_bad(v,'currentRouteSHA256','0'*64), False)
    check('fixed-proxy-child-env-mismatch', lambda v: fixed_bad(v,'childEnvironmentCheckpoint',{'scanPerformed':True,'allLiveXerjMatched':False}), False)
    check('fixed-partition-old-target-claim-refused', lambda v: v[FTX_FILES[2]]['resources'].update(cpuLimit=2), False)
    check('actual-cpu-max-ratio-mismatch', lambda v: v[FTX_FILES[2]]['resources'].update(actualCpuMax='200000 100000'), False)
    check('actual-cpu-max-hash-missing', lambda v: v[FTX_FILES[2]]['resources'].pop('actualCpuMaxSHA256'), False)
    check('aggregate-memory-partition-mismatch', lambda v: v[FTX_FILES[1]]['resourcePartition'].update(targetMemoryLimitBytes=8589934592), False)
    def fixed_final_false(v, key, value):
        fixed_proxy_mode(v)
        v[FTX_FILES[4]]['c2FinalProof'][key] = value
        v[FTX_FILES[5]]['fixedContainmentFinal'][key] = value
    check('fixed-proxy-final-sink-not-live', lambda v: fixed_final_false(v,'sinkLiveUntilFTXClose',False), False)
    check('fixed-proxy-final-infrastructure-hold', lambda v: fixed_final_false(v,'infrastructureHOLD',True), False)
    check('fixed-proxy-final-unexpected-post', lambda v: fixed_final_false(v,'unexpectedSinkRequests',1), False)
    check('fixed-proxy-final-checkpoint-count-gap', lambda v: fixed_final_false(v,'checkpointCount',1), False)
    check('naive-default-route-not-capture', lambda v: next(row for row in v[FTX_FILES[2]]['fullProtocol']['records']if row['id']=='P1_ZERO_FLAG_SEARCH').update(routedThroughCapture=True), False)
    check('gain-structured-default-env-proof-missing', lambda v: next(row for row in v[FTX_FILES[2]]['fullProtocol']['records']if row['id']=='GAIN_NAIVE_THEN_DOCUMENTED')['contentAssertions'].update(structuredXerjURLAbsent=False), False)
    check('hub-question-uncovered-derivation', lambda v: v[FTX_FILES[1]]['hubPublicQuestion'].update(derivation='LEXICAL_PUBLIC_HEADING'), False)
    check('hub-question-offered-span-mismatch', lambda v: v[FTX_FILES[1]]['hubPublicQuestion']['provenance']['candidate'].update(sha256='1'*64), False)
    check('phase-routing-proof-missing', lambda v: v[FTX_FILES[2]]['fullProtocol']['records'][0].pop('routedThroughCapture'), False)
    check('naive-gain-default-route-not-capture', lambda v: next(row for row in v[FTX_FILES[2]]['fullProtocol']['records']if row['id']=='GAIN_NAIVE_THEN_DOCUMENTED').update(routedThroughCapture=True), False)
    check('owned-hub-cleanup-not-proven', lambda v: v[FTX_FILES[2]]['ownedStopProof'].update(zeroLiveXerjAfterCleanup=False), False)
    check('owned-hub-cleanup-proof-missing', lambda v: v[FTX_FILES[2]]['ownedStopProof'].pop('zeroLiveXerjProofSHA256'), False)
    def map_empty(v):
        next(r for r in v[FTX_FILES[2]]['fullProtocol']['records'] if r['id']=='P1_MAP')['contentAssertions']['observedFieldCount']=0
    check('map-empty-is-not-content-proof', map_empty, False)
    def knowledge_unproved(v):
        next(r for r in v[FTX_FILES[2]]['fullProtocol']['records'] if r['id']=='KNOWLEDGE_SEMANTICS')['contentAssertions']['explicitSemanticClaimFalse']=False
    check('knowledge-absence-is-not-explicit-runtime-mode', knowledge_unproved, False)
    def role_shared(v):
        row=next(row for row in v[FTX_FILES[2]]['fullProtocol']['records']if row['id']=='P1_MAP')
        row['observationRefs']=[{'observedId':'offered:public','sha256':h,'role':'SHARED_PUBLIC','purpose':'DISCOVERY'}]
    check('shared-public-discovery-role', role_shared, True)
    def role_cross(v):
        role_shared(v)
        next(row for row in v[FTX_FILES[2]]['fullProtocol']['records']if row['id']=='P1_MAP')['observationRefs'][0]['role']='P2'
    check('other-persona-is-not-command-teacher', role_cross, False)
    def role_operator(v):
        role_shared(v)
        next(row for row in v[FTX_FILES[2]]['fullProtocol']['records']if row['id']=='P1_MAP')['observationRefs'][0].update(role='OPERATOR_MEASUREMENT',purpose='OPERATOR_COMPARISON_ONLY')
    check('operator-measurement-is-not-persona-teacher', role_operator, False)
    partial_results = []
    for label, missing, mutation, accepted in [
        ('partial-baseline-only', set(FTX_FILES[3:]), None, True),
        ('partial-no-ftx-started', set(FTX_FILES), None, True),
        ('partial-false-complete-claim', set(FTX_FILES[3:]), 'false-claim', False),
        ('partial-raw-field', set(FTX_FILES[3:]), 'raw-field', False),
    ]:
        clock()
        source = root/label; source.mkdir(exist_ok=False)
        values = copy.deepcopy(original)
        for name in missing: values.pop(name)
        for name, value in values.items():
            (source/name).write_text(json.dumps(value, sort_keys=True)+'\n')
        status = {'schemaVersion': 1, 'fullCandidateClaim': False,
                  'state': 'INCOMPLETE_NOT_CANDIDATE_PASS',
                  'presentFTXProofs': [n for n in FTX_FILES if n in values],
                  'expectedFTXProofs': list(FTX_FILES)}
        if mutation == 'false-claim': status['fullCandidateClaim'] = True
        if mutation == 'raw-field': status['rawBody'] = 'SYNTHETIC_PRIVATE_FIELD'
        (source/'candidate-ftx-export-status.json').write_text(json.dumps(status)+'\n')
        manifest = [{'path': q.name, 'bytes': q.stat().st_size,
                     'sha256': hashlib.sha256(q.read_bytes()).hexdigest()} for q in source.iterdir()]
        (source/'file-manifest.json').write_text(json.dumps(manifest)+'\n')
        refused = False
        try: verify(source)
        except (AssertionError, KeyError, TypeError, ValueError): refused = True
        assert (not refused) == accepted, 'FTX_PARTIAL_FIXTURE:'+label
        if accepted:
            strict_refused = False
            try: verify_ftx(source, manifest)
            except (AssertionError, KeyError, TypeError, ValueError): strict_refused = True
            assert strict_refused, 'PARTIAL_ACCEPTED_AS_COMPLETE_FTX'
        partial_results.append({'id': label, 'expectedAccepted': accepted, 'accepted': not refused})
    # Exercise the actual full-candidate export/verify/ZIP decoder branch early,
    # not only the six-file semantic reader. Every record below is synthetic.
    import zipfile
    import artifact_decode
    full_results=[]
    generated_names=['landing/answers/reciprocal-rank-fusion-when-to-use.html',
                     'landing/answers/reciprocal-rank-fusion-when-to-use.md',
                     'landing/answers/index.html','landing/answers/index.json']
    def synthetic_curated(source):
        for name in FTX_FIXED_ADJUNCTS:
            target=source/name
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text(json.dumps({'syntheticOnly':True,'notRuntimeEvidence':True})+'\n')
        destination=source/'fixed-topology';destination.mkdir(exist_ok=False)
        rows=[]
        def component(role,value,raw=False,name=None):
            name=name or role.lower()+('.jsonl' if raw else '.json')
            data=value if raw else (json.dumps(value,indent=2)+'\n').encode()
            target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            row={'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'role':role}
            rows.append(row);return row
        (source/'initial-runtime-controls/runtime-control-binary-proof.json').write_bytes((source/'runtime-control-binary-proof.json').read_bytes())
        (source/'initial-runtime-controls/preflight-binary-version.stdout').write_bytes((source/'preflight-binary-version.stdout').read_bytes())
        binding_path=source/'ftx-surface-corpus-bindings.json'
        binding_value=json.loads(binding_path.read_bytes())
        states_value=[json.loads((source/name).read_bytes())for name in FTX_FILES[2:4]]
        comp=json.loads((source/FTX_FILES[4]).read_bytes())
        account=json.loads((source/FTX_FILES[5]).read_bytes())
        if binding_value['c2Mode']!='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
            for role in FTX_FIXED_ROLES:component(role,{'syntheticOnly':True,'role':role})
        else:
            forwarded_required = list(FTX_FILES)+['ftx-route-completion.json','ftx-only-resources.json']
            (source/'fixed-ftx-forwarded-evidence.json').write_text(json.dumps({'present':forwarded_required,'missingRequired':[],
                'optionalMissing':['ftx-only-failure.json'],'missingNotTreatedAsPass':True,'rawPrivateTranscriptNotSelected':True})+'\n')
            host_final={'stopVerified':True,'sourceHandoffUnchanged':True,'infrastructureHOLD':False,
                'ownedStops':{name:{'Running':False,'Restarting':False,'Pid':0}for name in ('synthetic-target','synthetic-proxy')}}
            (source/'fixed-ftx-host-final.json').write_text(json.dumps(host_final)+'\n')
            component('HOST_FINAL',host_final)
            for index,name in enumerate(host_final['ownedStops']):
                for suffix,data in (
                    ('.json',(json.dumps({'argv':['docker','inspect',name],'expected':0,'exit':0,'complete':True})+'\n').encode()),
                    ('.stdout',(json.dumps([{'Name':'/'+name,'State':host_final['ownedStops'][name]}])+'\n').encode()),
                    ('.stdout.stderr',b'')):
                    filename=f'host/stops/{index}'+suffix
                    target=destination/filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
                    rows.append({'path':filename,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'role':'HOST_STOP'})
            early_stops={f'synthetic-early-{index}':{'Running':False,'Restarting':False,'Pid':0,'OOMKilled':False,'ExitCode':0}for index in range(9)}
            terminal=component('EARLY_TERMINAL',{'state':'PASS_EARLY_LOCAL_AND_KERNEL_CONTROLS','syntheticOnly':True,
                'stopVerified':True,'nativeFeedbackControlsPassed':True,'directEgressNegativePassed':True,'proxyCurlTLSControlPassed':True,'ownedStops':early_stops})
            for index,name in enumerate(early_stops):
                component('EARLY_STOP',{'argv':['docker','inspect',name],'expected':0,'exit':0,'complete':True},name=f'early/stops/{index}.json')
                component('EARLY_STOP',(json.dumps([{'Name':'/'+name,'State':early_stops[name]}])+'\n').encode(),True,name=f'early/stops/{index}.stdout')
                component('EARLY_STOP',b'',True,name=f'early/stops/{index}.stdout.stderr')
            component('EARLY_NATIVE',{'state':'PASS_REAL_LOCAL_SENDER_CONTROLS','positivePosts':1,'optoutAdditionalPosts':0,'binarySHA256':binding_value['binarySHA256'],'actualHelpGate':True,'sourceParityOrAllSendersProved':False},name='early/native/result.json')
            component('EARLY_NATIVE',[{'path':'/api/corpus-feedback','bytes':1,'sha256':h}],name='early/native/sink-requests.json')
            for label,disabled in (('real-local-positive','false'),('real-optout-negative','true')):
                component('EARLY_NATIVE',{'complete':True,'exit':0,'feedbackDisabled':disabled,'endpoint':'http://127.0.0.1:18765/api/corpus-feedback'},name='early/native/'+label+'.json')
            component('EARLY_NATIVE_PROXY',{'complete':True,'exit':1},name='early/native-proxy/real-native-https-proxy.json')
            component('EARLY_NATIVE_PROXY',{'state':'EXPECTED_SYNTHETIC_TLS_REFLECTOR_FAILURE','hostMustVerifyNewCONNECTEvent':True,'nativeTLSVerificationSuccessProved':False,'publicFeedback':False},name='early/native-proxy/result.json')
            transport_cases={key:{'tunnelRefused':True}for key in ('host-denied','literal-ip','port-denied','method','host-conflict','duplicate-host','auth','overlong')}
            transport_cases['allowed-reflector']={'tunnelAccepted':True}
            component('EARLY_TRANSPORT',{'state':'PASS_SYNTHETIC_CONNECT_CASES','cases':transport_cases},name='early/transport/transport.json')
            component('EARLY_TRANSPORT',{'state':'PASS_SAME_OWNED_UPSTREAM_PROXY_REACHABLE_DIRECT_DENIED','proxyPositive':{'tunnelAccepted':True},'directDenied':'OSError'},name='early/transport/paired.json')
            component('EARLY_TRANSPORT',{'state':'PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'},name='early/transport/direct.json')
            reasons={'connection-bytes':'CONNECTION_BYTE_CAP','total-bytes':'TOTAL_BYTE_CAP','header-time':'HEADER_TIMEOUT','connection-time':'CONNECTION_TIMEOUT'}
            for label in ('fixture-proxy','connection-bytes','total-bytes','header-time','connection-time','real-proxy'):
                prefix='early/proxy/'+label+'/'
                config_row=component('EARLY_PROXY',{'syntheticOnly':True},name=prefix+'config.json')
                log=(json.dumps({'kind':'synthetic','reason':reasons.get(label,'SYNTHETIC')})+'\n').encode()
                component('EARLY_PROXY',log,True,name=prefix+'proxy/connections.jsonl')
                component('EARLY_PROXY',{'configSHA256':config_row['sha256'],'logBytes':len(log),'logEvents':1,'daemonWorkersStillAlive':0},name=prefix+'proxy/summary.json')
                component('EARLY_PROXY',{'syntheticOnly':True},name=prefix+'actual-graceful-finalization.json')
                if label in reasons:component('EARLY_TRANSPORT',{'state':'CLOSED_BY_PROXY_OBSERVED'},name='early/transport/'+label+'.json')
            impl={'synthetic.py':h};implementation_sha=hashlib.sha256(json.dumps(impl,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            binding_value['c2ImplementationSHA256']=implementation_sha
            approval=component('C2_APPROVAL',{'mode':binding_value['c2Mode'],'implementationSHA256':implementation_sha,'syntheticOnly':True,
                'claudeApproved':True,'rootAgreement':True,'actualVerdictSHA256':h,'evidenceCaps':dict(FTX_EVIDENCE_CAP_PROFILE)})
            resource={'targetNanoCPUs':1750000000,'targetMemoryBytes':8321499136,'proxyNanoCPUs':250000000,'proxyMemoryBytes':268435456,'aggregateCPUs':2,'aggregateMemoryBytes':8589934592,'cpuSet':'0,1'}
            def synthetic_container(name,nano,memory,networks):
                return {'Name':'/'+name,'Id':h,'Image':'sha256:'+h,'Config':{'Env':['XERJ_DISABLE_FEEDBACK=true','XERJ_CORPUS_FEEDBACK_URL=http://127.0.0.1:18765/api/corpus-feedback']},'State':{'Running':True},'NetworkSettings':{'Networks':{key:{}for key in networks}},
                    'HostConfig':{'NanoCpus':nano,'Memory':memory,'MemorySwap':memory,'ReadonlyRootfs':True,'CpusetCpus':'0,1','Dns':['127.0.0.1'],'CapDrop':['ALL'],'Privileged':False,'PortBindings':{},'Devices':[],'CapAdd':None,'SecurityOpt':['no-new-privileges']}}
            target=synthetic_container('synthetic-target',1750000000,8321499136,['inside']);proxy_item=synthetic_container('synthetic-proxy',250000000,268435456,['inside','outside'])
            kernel=component('KERNEL_PROOF',{'kernel':{'inode':1,'routeSHA256':h,'CapEff':'0000000000000000','NoNewPrivs':'1'},'target':target,'proxy':proxy_item})
            direct_row=component('EARLY_TRANSPORT',{'state':'PASS_NO_DIRECT_EXTERNAL_TCP_OR_DNS_REPLY'},name='host/actual-target-direct-denial.json')
            positive_row=component('EARLY_TRANSPORT',b'x'*17290,True,name='host/actual-target-proxy-positive.stdout')
            component('EARLY_TRANSPORT',{'complete':True,'exit':0,'expected':0,'argv':['docker','exec','synthetic-target','curl','https://xerj.org/get']},name='host/actual-target-proxy-positive.json')
            routing=component('TARGET_ROUTING',{'targetContainerID':h,'directNegativeSHA256':direct_row['sha256'],'allowedProxyResponseSHA256':positive_row['sha256'],'actualPublicTLSPositive':True,'notInferredFromINTERNALLabel':True})
            parity=component('SOURCE_PARITY',{'state':'SIX_SCOPED_CACHED_TAG_TREE_IDENTITIES_MATCH_ALREADY_ADMITTED_MAIN_SOURCE','cachedTagRef':'refs/tags/v1.0.0-rc.102',
                'rows':[{'path':f'public-{index}.rs','gitOID':'0'*40,'bytes':1,'mode':'100644','sameAsAdmittedSource':True}for index in range(6)],'newSourceBodies':0,'newAPICalls':0,'runtimeAttemptsAdded':0})
            proxy_config=component('PROXY_CONFIG',{'allowedHosts':['xerj.org','github.com','release-assets.githubusercontent.com','hub.xerj.org'],'maxTotalBytes':268435456,'maxConnectionBytes':67108864})
            proxy_bytes=(json.dumps({'kind':'ready','configSHA256':proxy_config['sha256'],'allowedHosts':['xerj.org','github.com','release-assets.githubusercontent.com','hub.xerj.org']})+'\n').encode()
            proxy=component('PROXY_LOG',proxy_bytes,True)
            proxy_final=component('PROXY_FINAL',{'configSHA256':proxy_config['sha256'],'logBytes':len(proxy_bytes),'logEvents':1,'daemonWorkersStillAlive':0,'accountedBytes':0,'exhausted':False,'encryptedPathVisibility':False,'pathBlockProved':False,'productPass':False})
            host_final['proxyFinalProof']={'summarySHA256':proxy_final['sha256'],'logSHA256':proxy['sha256'],'finalSummaryReconciled':True,'noProxyLimitOrFailure':True}
            (source/'fixed-ftx-host-final.json').write_text(json.dumps(host_final)+'\n')
            final_host_row=next(row for row in rows if row['role']=='HOST_FINAL')
            final_host_bytes=(json.dumps(host_final,indent=2)+'\n').encode();(destination/final_host_row['path']).write_bytes(final_host_bytes)
            final_host_row.update(bytes=len(final_host_bytes),sha256=hashlib.sha256(final_host_bytes).hexdigest())
            sink=component('GUEST_SINK',b'',True)
            host=component('HOST_PROOF',{'mode':binding_value['c2Mode'],'targetContainerID':h,'targetImageID':'sha256:'+h,'targetCapEff':'0000000000000000',
                'networkNamespaceInode':1,'routeSHA256':h,'implementationSHA256':implementation_sha,'implementationFiles':impl,'guestCode':{'synthetic.py':{'sha256':h}},
                'proxyConfigSHA256':proxy_config['sha256'],'allowedHosts':['xerj.org','github.com','release-assets.githubusercontent.com','hub.xerj.org'],'feedbackSinkPort':18765,
                'publicSnapshotSHA256':h,'publicPacketSHA256':h,'offlineHandoffReceiptSHA256':h,'nativeControls':{'receiptSHA256':terminal['sha256']},'resourcePartition':resource})
            host_value=json.loads((destination/host['path']).read_bytes())
            host_value['guestCode']['release_head_PROPOSED.py']={'sha256':h}
            host_bytes=(json.dumps(host_value,indent=2)+'\n').encode();(destination/host['path']).write_bytes(host_bytes)
            host.update(bytes=len(host_bytes),sha256=hashlib.sha256(host_bytes).hexdigest())
            parser_cases=('allowed-redirect-and-no-signed-URL-leak','curl-failure','non200-final','foreign-redirect','redirect-count-mismatch','insecure-hop','duplicate-location','wrong-size','malformed-writeout','checksum-direct-200')
            parser_fixture={'schemaVersion':1,'parserSourceSHA256':h,'caseCount':10,'cases':{key:True for key in parser_cases},'actualNetworkCalls':0,'rawSignedURLExported':False}
            target=source/'fixture-target/release-route-parser-fixtures.json';target.parent.mkdir(exist_ok=True);target.write_text(json.dumps(parser_fixture)+'\n')
            target=source/'fixture-bootstrap/release-route-parser-fixtures.json';target.parent.mkdir(exist_ok=True);target.write_text(json.dumps(parser_fixture)+'\n')
            release_receipts={}
            for kind,expected_bytes in (('archive',33666646),('checksum',118)):
                archive_name='xerj-1.0.0-rc.102-aarch64-unknown-linux-musl.tar.gz'
                initial='https://github.com/xerj-org/xerj/releases/download/v1.0.0-rc.102/'+archive_name+('.sha256'if kind=='checksum'else'')
                release=component('RELEASE_ROUTE',{'schemaVersion':1,'assetKind':kind,'sourceTag':'v1.0.0-rc.102','archiveName':archive_name,'expectedBytes':expected_bytes,
                    'installerSourceSHA256':'158b53201b9c5ddaffd0afa5860307a6dd5c684902303aa9dff64978618cf14f','initialURLSHA256':hashlib.sha256(initial.encode()).hexdigest(),
                    'parserSourceSHA256':h,'rawHeadersSHA256':h,'rawWriteoutSHA256':h,'rawHeaderBytes':1,'rawWriteoutBytes':1,'maxRedirects':3,'headOnly':True,
                    'bodyDownloaded':False,'bodyIntegrityProved':False,'runtimeInstallerMustVerifySHA':True,'curlExit':0,'complete':True,
                    'classification':'PINNED_INSTALLER_RELEASE_ROUTE_VERIFIED_HEAD_ONLY','finalStatus':200,'redirectCount':0,'responseCount':1,'informationalCount':0,
                    'allRedirectHostsAllowed':True,'privateCommandReceiptSHA256':h,'kernelRawFileCapBytes':65536,'privateStderrSHA256':h,'childReaped':True,'headArgvSHA256':h,'chain':[{'scheme':'https','host':'github.com','pathSHA256':h,'queryPresent':False,'status':200}]},name='release-routes/'+kind+'.json')
                release_receipts[kind]=release['sha256']
            early_value=json.loads((destination/terminal['path']).read_bytes());early_value['releaseRoutePreflight']={'archiveAndChecksumHEADVerified':True,'headRequests':2,'beforeCostlyOfflineWork':True,'signedURLsPubliclyExported':False,'receipts':release_receipts}
            early_bytes=(json.dumps(early_value,indent=2)+'\n').encode();(destination/terminal['path']).write_bytes(early_bytes);terminal.update(bytes=len(early_bytes),sha256=hashlib.sha256(early_bytes).hexdigest())
            host_value['nativeControls']['receiptSHA256']=terminal['sha256'];host_bytes=(json.dumps(host_value,indent=2)+'\n').encode();(destination/host['path']).write_bytes(host_bytes);host.update(bytes=len(host_bytes),sha256=hashlib.sha256(host_bytes).hexdigest())
            binding_value['c2ApprovalReceiptSHA256']=approval['sha256']
            frames=[]
            for state in states_value:
                for phase in state['networkProof']['phases']:
                    phase.update(c2ApprovalReceiptSHA256=approval['sha256'],approvalSHA256=approval['sha256'],implementationSHA256=implementation_sha,
                        hostProofSHA256=host['sha256'],evidenceSHA256=host['sha256'],kernelProofSHA256=kernel['sha256'],
                        actualTargetRoutingSHA256=routing['sha256'],sourceParityReceiptSHA256=parity['sha256'],
                        nativeControlsSHA256=terminal['sha256'],
                        currentProxyLogBytes=len(proxy_bytes),currentProxyLogSHA256=proxy['sha256'],feedbackEndpointURLSHA256=hashlib.sha256(b'http://127.0.0.1:18765/api/corpus-feedback').hexdigest())
                    for process in phase['childEnvironmentCheckpoint']['processes']:
                        process.update(optoutValueSHA256=hashlib.sha256(b'true').hexdigest(),sinkValueSHA256=phase['feedbackEndpointURLSHA256'])
                    proof={key:value for key,value in phase.items()if key not in ('c2Mode','approvalSHA256')}
                    raw=(json.dumps({'phase':phase['phase'],'observedProof':proof},indent=2)+'\n').encode()
                    frames.append({'path':f'{len(frames)+1:03d}.json','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'rawUTF8':raw.decode()})
            for state in states_value:
                state['ownedStopProof']['zeroLiveXerjProofSHA256']=hashlib.sha256(json.dumps(state['networkProof']['phases'][-1],sort_keys=True).encode()).hexdigest()
            component('GUEST_CHECKPOINT_BUNDLE',{'schemaVersion':1,'frames':frames})
            final={key:value for key,value in comp['c2FinalProof'].items()if key!='receiptSHA256'}
            final.update(sinkLogSHA256=sink['sha256'],checkpointCount=len(frames))
            final_row=component('GUEST_FINAL',final)
            final=dict(final,receiptSHA256=final_row['sha256'])
            comp['c2FinalProof']=final;account['fixedContainmentFinal']=copy.deepcopy(final)
            for role in FTX_FIXED_ROLES:
                if role not in {row['role']for row in rows}:component(role,{'syntheticOnly':True,'role':role})
            binding_path.write_text(json.dumps(binding_value)+'\n')
            for name,state in zip(FTX_FILES[2:4],states_value):(source/name).write_text(json.dumps(state)+'\n')
            comp['beforeSummarySHA256']=hashlib.sha256((source/FTX_FILES[2]).read_bytes()).hexdigest()
            comp['afterSummarySHA256']=hashlib.sha256((source/FTX_FILES[3]).read_bytes()).hexdigest()
            (source/FTX_FILES[4]).write_text(json.dumps(comp)+'\n')
            for row in account['publicFiles']:
                target=source/row['name'];row.update(bytes=target.stat().st_size,sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            account['publicBytes']=sum(row['bytes']for row in account['publicFiles'])
            (source/FTX_FILES[5]).write_text(json.dumps(account)+'\n')
        (destination/'manifest.json').write_text(json.dumps({'schemaVersion':1,'files':rows,
            'requiredRoles':list(FTX_FIXED_ROLES),'missingExpectedPaths':[],'collectionComplete':True})+'\n')

    def full_check(label, mutate, accepted, after_curated=None):
        clock()
        source=root/label;source.mkdir(exist_ok=False)
        for name in FTX_FILES:
            (source/name).write_bytes((root/'synthetic-qualified-schema'/name).read_bytes())
        hashes={}
        for name in generated_names:
            path=source/'generated'/name;path.parent.mkdir(parents=True,exist_ok=True)
            raw=('SYNTHETIC_GENERATED_NOT_PRODUCT:'+name+'\n').encode();path.write_bytes(raw)
            hashes[name]=hashlib.sha256(raw).hexdigest()
        hashes = {name: hashes.get(name, h) for name in FTX_NINE_PATHS}
        proof={'syntheticOnly':True,'generatedPaths':generated_names,'finalNineHashes':hashes}
        (source/'candidate-source-proof.json').write_text(json.dumps(proof)+'\n')
        early={'schemaVersion':1,'syntheticOnly':True,'realDependencyGate':True,
               'childrenReaped':True,'beforeCandidateAndExpensiveChecks':True,
               'helperSHA256':h,'actualToolCount':1,'noFixedToolCount':True}
        early['realDecoderProbe'] = {'operatorOnly':True,'syntheticOwnedRustCorpus':True,
                                     'sameProductionDecoders':True,'complete':True,
                                     **{key:h for key in ('sourceSHA256','statusSchemaSHA256','gainSchemaSHA256','knowledgeSchemaSHA256','symbolDecoderActualEvidenceSHA256')}}
        early['realDecoderProbe']['mapContentAssertions'] = {'datasetIdentityObserved':True,
            'perFieldTypesAndExamplesObserved':True,'readyQueryTemplatesObserved':True,
            'observedFieldCount':1,'observedQueryCount':1,'actualMapOutputSHA256':h}
        early.update(copy.deepcopy(accounting))
        # The early gate is one real compatibility command/RPC, not a merged two-state FTX universe.
        early['responseSets']['cli'] = early['responseSets']['cli'][:1]
        early['expectedIDs']['cli'] = [row['id'] for row in early['responseSets']['cli']]
        early['actualCLICommandCount'] = early['actualCLIResponseSetCount'] = 1
        early['requestIntentIDs'] = early['expectedIDs']
        # A meaningful synthetic RPC positive, independent of persona traffic.
        early['responseSets']['rpc']=[{'id':'early-rpc','outcome':'RESPONSE','responseSHA256':h}]
        early['expectedIDs']['rpc']=['early-rpc'];early['actualRPCRequestCount']=early['actualRPCResponseCount']=1
        (source/'early-operator-compatibility.json').write_text(json.dumps(early)+'\n')
        (source/'candidate-ftx-export-status.json').write_text(json.dumps({'schemaVersion':1,'fullCandidateClaim':True})+'\n')
        # Actual full split consumer gets realistic synthetic public metadata only, never binary/source payloads.
        def split_save(name, value):
            (source/name).write_text(json.dumps(value,indent=2)+'\n')
        bind=json.loads((source/'ftx-surface-corpus-bindings.json').read_bytes())
        bind.update(binarySHA256=h,releaseArchiveSHA256=h)
        split_save('ftx-surface-corpus-bindings.json',bind)
        for name in ('candidate-source-manifest.json','final-source-manifest.json','post-ftx-source-manifest.json'):
            split_save(name,[{'path':key,'sha256':value,'bytes':1} for key,value in hashes.items()])
        file_rows=[{'path':'candidate/'+key,'sha256':value,'bytes':1}for key,value in hashes.items()]
        file_rows += [{'path':'baseline-surfaces/synthetic-'+str(i),'sha256':h,'bytes':1}for i in range(3)]
        file_rows += [{'path':'binary/xerj','sha256':h,'bytes':1}]
        file_rows += [{'path':'corpus/synthetic-'+str(i)+'.md','sha256':h,'bytes':1}for i in range(5)]
        file_rows += [{'path':name,'sha256':h,'bytes':1}for name in ('ftx-config.json','packaged-path-map.json','offline-handoff-receipt.json','receipts/ftx-pure-controls.json','receipts/early-operator-compatibility.json')]
        handoff={'schemaVersion':1,'sourcePin':bind['sourcePin'],'files':file_rows,'finalNineHashes':hashes,
                 'binarySHA256':h,'baselineSurfaceHashes':{str(i):h for i in range(3)},
                 'publicInputsOnly':True,'noGitOrCredentialsCopied':True,'sameDerivedImageRequired':True}
        split_save('ftx-handoff-manifest.json',handoff)
        handoff_sha=hashlib.sha256((source/'ftx-handoff-manifest.json').read_bytes()).hexdigest()
        split_save('ftx-handoff-identity.json',{'sha256':handoff_sha,'files':23,'bytes':23,'copiedBeforeOfflineStopRequired':True})
        offline={'state':'OFFLINE_REQUIRED_CHECKS_COMPLETE_FTX_PENDING','seoCommands':19,'lightCommands':9,'mechanicsCases':4,
                 'candidatePass':False,'ftxComplete':False,'baselineOnly':False,'sourcePin':bind['sourcePin'],
                 'ninePathHashes':hashes,'handoffSHA256':handoff_sha}
        split_save('offline-required-result.json',offline)
        split_save('ftx-route-completion.json',{'state':'FULL_FTX_COMPLETED_REQUIRES_FINAL_SOURCE_CHECK',
            'handoffSHA256':handoff_sha,'finalNineHashes':hashes,'c2Mode':bind['c2Mode'],
            'c2CloseProofRequired':True,'sourceInvariantNotClaimedYet':True})
        split_save('result.json',{'state':'CANDIDATE_REQUIRED_CHECKS_COMPLETED_FULL_FTX','ftxComplete':True,
            'postFTXAllSourceUnchanged':True,'ftxOutcome':'NO_OBSERVED_REGRESSION_WITH_LOSSES',
            'candidatePass':False,'fullFinalReviewPending':True,'ninePathHashes':hashes})
        split_save('runtime-control-binary-proof.json',{'sha256':h,'archiveSHA256':h,
            'versionSHA256':hashlib.sha256(b'SYNTHETIC_VERSION_NOT_PRODUCT').hexdigest(),
            'beforeCostlyOfflineSteps':True,'sameOriginalClock':True})
        split_save('offline-container-image-identity.json',{'actualImageID':'sha256:'+h,'identityVerifiedByHost':True})
        for name in ('runtime-control-offline-network.json','post-ftx-offline-network.json'):
            split_save(name,{'interfaces':{'lo':'unknown'},'non_loopback':{},'IPv4_default_routes':0,'IPv6_non_loopback_default_routes':0})
        (source/'preflight-binary-version.stdout').write_bytes(b'SYNTHETIC_VERSION_NOT_PRODUCT')
        (source/'preflight-binary-version.stdout.stderr').write_bytes(b'')
        for name in ('preflight-binary-version.json','prepare-runtime-controls-resources.json','finalize-ftx-resources.json','ftx-only-resources.json'):
            split_save(name,{'syntheticOnly':True,'notRealResourceOrRuntimeClaim':True})
        # Rebind only the six summary hashes after adding approved binary identity metadata.
        change = json.loads((source/'ftx-evidence-accounting.json').read_bytes())
        for row in change['publicFiles']:
            target=source/row['name'];row.update(bytes=target.stat().st_size,sha256=hashlib.sha256(target.read_bytes()).hexdigest())
        change['publicBytes']=sum(row['bytes']for row in change['publicFiles']);split_save('ftx-evidence-accounting.json',change)
        mutate(source)
        failure=None
        try:
            synthetic_curated(source)
            if after_curated: after_curated(source)
            names=[str(q.relative_to(source))for q in source.rglob('*')if q.is_file()]
            exported=root/(label+'-export')
            export(source,exported,names,required=names)
            archive=root/(label+'.zip')
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED)as z:
                for q in exported.rglob('*'):
                    if q.is_file():z.write(q,str(q.relative_to(exported)))
            artifact_decode.decode_ftx(archive,root/(label+'-decoded'),clock)
        except(AssertionError,KeyError,TypeError,ValueError,OSError)as exc:failure=type(exc).__name__
        assert (failure is None)==accepted,'FTX_FULL_PIPELINE_FIXTURE:'+label
        full_results.append({'id':label,'syntheticOnly':True,'expectedAccepted':accepted,'accepted':failure is None,'failure':failure})
    full_check('full-status-real-consumer-positive',lambda r:None,True)
    full_check('full-status-missing-early',lambda r:(r/'early-operator-compatibility.json').unlink(),False)
    def wrong_helper(r):
        q=r/'early-operator-compatibility.json';v=json.loads(q.read_text());v['helperSHA256']='0'*64;q.write_text(json.dumps(v))
    full_check('full-status-wrong-helper',wrong_helper,False)
    full_check('full-status-missing-generated',lambda r:(r/'generated'/generated_names[0]).unlink(),False)
    full_check('full-status-generated-hash-mismatch',lambda r:(r/'generated'/generated_names[0]).write_bytes(b'SYNTHETIC_TAMPER'),False)
    def change_state(r, fn):
        q = r/'ftx-before-summary.json'
        value = json.loads(q.read_text()); fn(value); q.write_text(json.dumps(value)+'\n')
        # Refresh outer comparison and accounting hashes: rejection must be semantic, not stale digests.
        c = r/'ftx-comparison.json'; comparison_value = json.loads(c.read_text())
        comparison_value['beforeSummarySHA256'] = hashlib.sha256(q.read_bytes()).hexdigest(); c.write_text(json.dumps(comparison_value)+'\n')
        a = r/'ftx-evidence-accounting.json'; av = json.loads(a.read_text())
        for row in av['publicFiles']:
            target = r/row['name']; row.update(bytes=target.stat().st_size, sha256=hashlib.sha256(target.read_bytes()).hexdigest())
        av['publicBytes'] = sum(x['bytes'] for x in av['publicFiles']); a.write_text(json.dumps(av)+'\n')
    def measured_pipeline(r, tamper=None):
        for name in FTX_FILES:
            (r/name).write_bytes((root/'synthetic-measured-question-top1'/name).read_bytes())
        if tamper:
            change_state(r, tamper)
    full_check('full-status-question-top1-positive', lambda r: measured_pipeline(r), True)
    full_check('full-status-question-top1-alias-wrong', lambda r: measured_pipeline(r, lambda v: v['tokenMetrics'][0].update(armATopOnePerResponseUniqueBytes=100)), False)
    full_check('full-status-hints-byte-count-wrong', lambda r: measured_pipeline(r, lambda v: v['tokenMetrics'][0]['completeSearchResponseSet'][0].update(hintsBytes=5)), False)
    def blocked_state(v):
        row = v['fullProtocol']['records'][0]
        row.update(attempted=False, operationStatus='BLOCKED_NO_OPERATION', outcome='LOSS', failureClass='REAL_OPERATION_OR_CONTRACT_FAILURE',
                   operationIntentIDs={k: [] for k in ('cli', 'rpc', 'http', 'forwarded')})
    full_check('full-status-blocked-not-exercised', lambda r: change_state(r, blocked_state), False)
    full_check('full-status-real-failed-operation-loss', lambda r: change_state(r, lambda v: v['fullProtocol']['records'][1].update(outcome='LOSS', failureClass='REAL_OPERATION_OR_CONTRACT_FAILURE')), True)
    def wrong_operation_count(r):
        q = r/'ftx-evidence-accounting.json'; value = json.loads(q.read_text())
        value['actualCLICommandCount'] += 1; q.write_text(json.dumps(value)+'\n')
    full_check('full-status-operation-count-mismatch', wrong_operation_count, False)
    def change_protocol_assertion(v, ident, key):
        next(row for row in v['fullProtocol']['records'] if row['id'] == ident)['contentAssertions'][key] = '0'*64
    full_check('full-status-hub-question-mismatch', lambda r: change_state(r, lambda v: change_protocol_assertion(v, 'P1_HUB_COUNTERPART', 'questionSHA256')), False)
    full_check('full-status-cli-mcp-hint-mismatch', lambda r: change_state(r, lambda v: change_protocol_assertion(v, 'P2_SAME_HINTS', 'cliHintsSHA256')), False)
    def unknown_pipeline(r):
        change_state(r, lambda v: v['auditAlignment'].update(state='UNKNOWN'))
        c = r/'ftx-comparison.json'; value = json.loads(c.read_text())
        value.update(outcome='UNKNOWN', complete=False); c.write_text(json.dumps(value)+'\n')
        change_state(r, lambda v: None)
    full_check('full-status-unknown-not-strict-complete', unknown_pipeline, False)
    full_check('full-status-harness-is-not-product-loss', lambda r: change_state(r, lambda v: v['fullProtocol']['records'][1].update(outcome='LOSS', failureClass='HARNESS_UNVERIFIED')), False)
    full_check('full-status-recorded-harness-error', lambda r: change_state(r, lambda v: v['fullProtocol']['records'][1].update(failureClass='HARNESS_UNVERIFIED')), False)
    def fixed_pipeline(r, mutate=None):
        for name in FTX_FILES:
            (r/name).write_bytes((root/'synthetic-fixed-proxy-observation'/name).read_bytes())
        completion_path=r/'ftx-route-completion.json'
        completion_value=json.loads(completion_path.read_text())
        completion_value['c2Mode']='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'
        completion_path.write_text(json.dumps(completion_value)+'\n')
        if mutate:
            change_state(r, mutate)
    full_check('full-status-fixed-proxy-positive', lambda r: fixed_pipeline(r), True)
    full_check('full-status-fixed-proxy-false-offline', lambda r: fixed_pipeline(r, lambda v: v['networkProof']['phases'][0].update(externalNetworkPhysicallyDisconnected=True)), False)
    full_check('full-status-fixed-proxy-unexpected-sink', lambda r: fixed_pipeline(r, lambda v: v['networkProof']['phases'][0].update(unexpectedSinkRequests=1)), False)
    full_check('full-status-fixed-proxy-unverified-env', lambda r: fixed_pipeline(r, lambda v: v['networkProof']['phases'][0]['childEnvironmentCheckpoint'].update(allLiveXerjMatched=False)), False)
    def fixed_final_pipeline(r, key, value):
        fixed_pipeline(r)
        for name, field in (('ftx-comparison.json','c2FinalProof'), ('ftx-evidence-accounting.json','fixedContainmentFinal')):
            q = r/name; data = json.loads(q.read_text()); data[field][key] = value; q.write_text(json.dumps(data)+'\n')
        change_state(r, lambda v: None)
    full_check('full-status-final-c2-sink-lifetime-missing', lambda r: fixed_final_pipeline(r,'sinkLiveUntilFTXClose',False), False)
    full_check('full-status-final-c2-unexpected-post', lambda r: fixed_final_pipeline(r,'unexpectedSinkRequests',1), False)
    def mutate_probe(r, missing=False):
        q = r/'early-operator-compatibility.json'; value = json.loads(q.read_text())
        if missing: value.pop('realDecoderProbe')
        else: value['realDecoderProbe']['sameProductionDecoders'] = False
        q.write_text(json.dumps(value)+'\n')
    full_check('full-status-real-decoder-probe-missing', lambda r: mutate_probe(r, True), False)
    full_check('full-status-real-decoder-probe-not-production', lambda r: mutate_probe(r), False)
    full_check('full-status-handoff-proof-missing', lambda r: (r/'ftx-handoff-identity.json').unlink(), False)
    full_check('full-status-post-source-mismatch', lambda r: (r/'post-ftx-source-manifest.json').write_text('[]'), False)
    def wrong_final_source(r):
        q=r/'result.json';value=json.loads(q.read_text());value['postFTXAllSourceUnchanged']=False;q.write_text(json.dumps(value))
    full_check('full-status-final-source-not-proven', wrong_final_source, False)
    full_check('full-status-curated-manifest-missing', lambda r: None, False,
               lambda r: (r/'fixed-topology/manifest.json').unlink())
    full_check('full-status-curated-component-missing', lambda r: None, False,
               lambda r: (r/'fixed-topology/host_proof.json').unlink())
    def corrupt_checkpoint_bundle(r):
        q=r/'fixed-topology/guest_checkpoint_bundle.json';value=json.loads(q.read_text());value['frames'].pop()
        q.write_text(json.dumps(value)+'\n')
        manifest_path=r/'fixed-topology/manifest.json';manifest=json.loads(manifest_path.read_text())
        row=next(row for row in manifest['files']if row['role']=='GUEST_CHECKPOINT_BUNDLE')
        row.update(bytes=q.stat().st_size,sha256=hashlib.sha256(q.read_bytes()).hexdigest())
        manifest_path.write_text(json.dumps(manifest)+'\n')
    full_check('full-status-raw-checkpoint-gap', lambda r: fixed_pipeline(r), False, corrupt_checkpoint_bundle)
    def corrupt_forwarded(source):
        path=source/'fixed-ftx-forwarded-evidence.json';value=json.loads(path.read_bytes())
        value['missingRequired']=['ftx-route-completion.json'];path.write_text(json.dumps(value)+'\n')
    full_check('full-status-forwarded-required-gap', lambda r: fixed_pipeline(r), False, corrupt_forwarded)
    def corrupt_host_stop(source):
        path=source/'fixed-ftx-host-final.json';value=json.loads(path.read_bytes())
        value['stopVerified']=False;path.write_text(json.dumps(value)+'\n')
    full_check('full-status-host-stop-unverified', lambda r: fixed_pipeline(r), False, corrupt_host_stop)
    def corrupt_raw_host_stop(source):
        path=source/'fixed-topology/host/stops/0.stdout';value=json.loads(path.read_bytes())
        value[0]['State']['Pid']=123;path.write_text(json.dumps(value)+'\n')
        manifest_path=source/'fixed-topology/manifest.json';manifest=json.loads(manifest_path.read_bytes())
        row=next(row for row in manifest['files']if row['path']=='host/stops/0.stdout')
        row.update(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest_path.write_text(json.dumps(manifest)+'\n')
    full_check('full-status-raw-host-stop-still-running', lambda r: fixed_pipeline(r), False, corrupt_raw_host_stop)
    full_check('full-status-owned-hub-cleanup-missing', lambda r: change_state(r, lambda v: v['ownedStopProof'].update(zeroLiveXerjAfterCleanup=False)), False)
    full_check('full-status-map-content-not-proven', lambda r: change_state(r, lambda v: next(row for row in v['fullProtocol']['records'] if row['id']=='P1_MAP')['contentAssertions'].update(observedQueryCount=0)), False)
    full_check('full-status-knowledge-mode-not-explicit', lambda r: change_state(r, lambda v: next(row for row in v['fullProtocol']['records'] if row['id']=='KNOWLEDGE_SEMANTICS')['contentAssertions'].update(explicitRuntimeModeLexical=False)), False)
    def full_cross_role(value):
        row=next(row for row in value['fullProtocol']['records']if row['id']=='P1_MAP')
        row['observationRefs']=[{'observedId':'P2-tools','sha256':h,'role':'P2','purpose':'DISCOVERY'}]
    full_check('full-status-release-head-proof-missing', lambda r: fixed_pipeline(r), False,
        lambda r:(r/'fixed-topology/release-routes/archive.json').unlink())
    def wrong_parser_fixture(r):
        path=r/'fixture-target/release-route-parser-fixtures.json';value=json.loads(path.read_bytes());value['cases']['foreign-redirect']=False;path.write_text(json.dumps(value)+'\n')
    full_check('full-status-release-parser-control-unverified', lambda r: fixed_pipeline(r), False, wrong_parser_fixture)
    full_check('full-status-naive-route-not-capture', lambda r: change_state(r,lambda v:next(row for row in v['fullProtocol']['records']if row['id']=='P1_ZERO_FLAG_DEF').update(routedThroughCapture=True)), False)
    full_check('full-status-naive-gain-not-capture', lambda r: change_state(r,lambda v:next(row for row in v['fullProtocol']['records']if row['id']=='GAIN_NAIVE_THEN_DOCUMENTED').update(routedThroughCapture=True)), False)
    full_check('full-status-gain-default-env-proof-missing', lambda r: change_state(r,lambda v:next(row for row in v['fullProtocol']['records']if row['id']=='GAIN_NAIVE_THEN_DOCUMENTED')['contentAssertions'].update(operatorHelpXerjURLAbsent=False)), False)
    def wrong_hub_span(r):
        path=r/FTX_FILES[1];value=json.loads(path.read_bytes());value['hubPublicQuestion']['provenance']['baseline']['end_line']=75;path.write_text(json.dumps(value)+'\n')
    full_check('full-status-hub-uncovered-heading-span', wrong_hub_span, False)
    full_check('full-status-cross-persona-command-teacher', lambda r: change_state(r,full_cross_role), False)
    full_check('full-status-missing-phase', lambda r: change_state(r, lambda v: v['fullProtocol']['records'].pop()), False)
    full_check('full-status-false-attempt', lambda r: change_state(r, lambda v: v['fullProtocol']['records'][0].update(attempted=False)), False)
    full_check('full-status-unaccounted-phase', lambda r: change_state(r, lambda v: v['fullProtocol']['records'][0]['operationIntentIDs']['cli'].append('unaccounted')), False)
    return {'syntheticOnly': True, 'productExecuted': False, 'cases': results,
            'partialExportCases': partial_results,'fullPipelineCases':full_results,'capBoundaryCases':cap_boundary_results}
