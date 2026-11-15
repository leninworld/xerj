"""PRIVATE UNRUN: bounded deterministic first-session replay, never novice-comprehension proof.

Only stdlib plus the unchanged reviewed bounded.command primitive. Importing this
file starts nothing. Every control and real-node action belongs in the later
approved Docker packet; authoring/AST checks are not execution authorization.
"""
from pathlib import Path
import base64
import gzip
import hashlib
import http.client
import http.server
import io
import json
import math
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import zlib

MAX_BODY = 2 * 1024**2
MAX_PRIVATE = 32 * 1024**2
MAX_HTTP = 160
HOP = {'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding',
       'te', 'trailer', 'upgrade', 'proxy-authenticate', 'proxy-authorization'}
CONTROL_IDS = (
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
    'real_node_success', 'real_wrong_port_loss', 'real_missing_flag_loss')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, obj):
    path = Path(path)
    require(not path.is_symlink() and not path.exists(), 'EXCLUSIVE_EVIDENCE_PATH')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f:
        json.dump(obj, f, indent=2, allow_nan=False)
        f.write('\n')


def unique_object(pairs):
    d = {}
    for key, value in pairs:
        require(key not in d, 'DUPLICATE_JSON_KEY')
        d[key] = value
    return d


def json_value(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def without_xerj(raw):
    """Remove one top-level member by original UTF-8 byte spans; never serialize."""
    require(len(raw) <= MAX_BODY, 'SCANNER_BODY_CAP')
    s = raw.decode('utf-8')
    value = json_value(s)
    require(isinstance(value, dict), 'SCANNER_REQUIRES_OBJECT')
    decoder = json.JSONDecoder(object_pairs_hook=unique_object)
    ws = lambda n: n + len(s[n:]) - len(s[n:].lstrip())
    pos = ws(0)
    require(s[pos] == '{', 'OBJECT_START')
    pos = ws(pos + 1)
    spans = []
    while s[pos] != '}':
        start = pos
        key, pos = decoder.raw_decode(s, pos)
        require(isinstance(key, str), 'JSON_KEY_STRING')
        pos = ws(pos)
        require(s[pos] == ':', 'JSON_COLON')
        _, end = decoder.raw_decode(s, ws(pos + 1))
        pos = ws(end)
        spans.append((key, start, end, pos))
        if s[pos] == ',':
            pos = ws(pos + 1)
        else:
            require(s[pos] == '}', 'JSON_MEMBER_SEPARATOR')
    require(not s[pos + 1:].strip(), 'TRAILING_JSON_DATA')
    chosen = [i for i, row in enumerate(spans) if row[0] == '_xerj']
    if not chosen:
        return raw, {'rawDecodedBytes': len(raw), 'hintsRemovedBytes': 0}
    i = chosen[0]
    if len(spans) == 1:
        left, right = spans[i][1], spans[i][3]
    elif i < len(spans) - 1:
        left, right = spans[i][1], spans[i + 1][1]
    else:
        left, right = spans[i - 1][3], spans[i][3]
    a, b = len(s[:left].encode('utf-8')), len(s[:right].encode('utf-8'))
    result = raw[:a] + raw[b:]
    require(json_value(result) == {k: v for k, v in value.items() if k != '_xerj'},
            'EXACT_MEMBER_REMOVAL_VERIFICATION')
    return result, {'rawDecodedBytes': len(raw), 'hintsRemovedBytes': b - a,
                    'memberByteSpan': [a, b]}


def decoded_json_body(raw, headers):
    encoding = next((v.lower() for k, v in headers if k.lower() == 'content-encoding'), 'identity')
    if encoding == 'identity':
        decoded = raw
    elif encoding in ('gzip', 'deflate'):
        decoder = zlib.decompressobj(31 if encoding == 'gzip' else zlib.MAX_WBITS)
        decoded = decoder.decompress(raw, MAX_BODY + 1)
        require(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
                'ENCODED_BODY_INCOMPLETE_OR_MULTIPLE_STREAM')
    else:
        raise ValueError('UNSUPPORTED_CONTENT_ENCODING')
    require(len(decoded) <= MAX_BODY, 'DECODED_JSON_CAP')
    json_value(decoded)
    return decoded


def interrupt_socket(sock):
    try:sock.shutdown(socket.SHUT_RDWR)
    except OSError:pass


def loopback_url(url):
    u = urllib.parse.urlsplit(url)
    require(u.scheme == 'http' and u.hostname == '127.0.0.1' and u.port and
            not u.username and not u.password and not u.query and not u.fragment,
            'OWNED_LITERAL_LOOPBACK_URL_ONLY')
    return u


def read_payload(stream, headers, guard):
    lengths = headers.get_all('Content-Length', [])
    transfers = headers.get_all('Transfer-Encoding', [])
    require(not (lengths and transfers), 'AMBIGUOUS_HTTP_FRAMING')
    if transfers:
        require(len(transfers) == 1 and transfers[0].lower().strip() == 'chunked',
                'UNSUPPORTED_REQUEST_TRANSFER_ENCODING')
        data = bytearray()
        while True:
            guard()
            line = stream.readline(1025)
            require(line.endswith(b'\r\n') and len(line) <= 1024, 'BAD_CHUNK_HEADER')
            token = line[:-2].split(b';', 1)[0]
            require(re.fullmatch(b'[0-9a-fA-F]+', token), 'BAD_CHUNK_SIZE')
            size = int(token, 16)
            require(size <= MAX_BODY - len(data), 'REQUEST_BODY_CAP')
            if size == 0:
                # Trailers are hop-by-hop framing, retained as a bounded record.
                trailers = []
                for _ in range(32):
                    tail = stream.readline(4097)
                    require(tail.endswith(b'\r\n') and len(tail) <= 4096, 'BAD_TRAILER')
                    if tail == b'\r\n':
                        return bytes(data), {'input': 'chunked', 'trailers': trailers}
                    trailers.append(tail.decode('latin1').rstrip())
                raise ValueError('TRAILER_CAP')
            part = stream.read(size)
            require(len(part) == size and stream.read(2) == b'\r\n', 'TRUNCATED_CHUNK')
            data.extend(part)
    require(len(lengths) <= 1, 'MULTIPLE_CONTENT_LENGTH')
    size = int(lengths[0]) if lengths else 0
    require(0 <= size <= MAX_BODY, 'REQUEST_BODY_CAP')
    data = stream.read(size)
    require(len(data) == size, 'TRUNCATED_CONTENT_LENGTH')
    return data, {'input': 'content-length' if lengths else 'empty'}


class Forwarder:
    """One fixed real loopback upstream. No probing or self-initiated HTTP."""
    def __init__(self, upstream, private, guard, cap=MAX_PRIVATE, seconds_left=lambda:15):
        self.upstream = loopback_url(upstream)
        self.private = Path(private)
        self.private.mkdir(exist_ok=False, parents=True)
        self.guard, self.cap = guard, cap
        self.seconds_left=seconds_left
        self.used, self.sequence = 0, 0
        self.records, self.errors = [], []
        self.lock = threading.Lock()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def handle_one_request(self):
                timer=threading.Timer(max(.001,min(15,owner.seconds_left())),interrupt_socket,args=(self.connection,))
                timer.daemon=True;timer.start()
                try:return super().handle_one_request()
                finally:timer.cancel();timer.join(1)

            def do_CONNECT(self):
                with owner.lock:
                    owner.sequence+=1
                    seq=owner.sequence
                    save(owner.private/f'{seq:03d}-intent.json',{'kind':'forwarded','id':'H'+digest((str(owner.private)+str(seq)).encode())[:24],
                         'pair':f'{seq:03d}-pair.json','refusal':f'{seq:03d}-refusal.json','role':'CONTROL'if'helper-controls'in str(owner.private)else'P2_P3_CLI'})
                    save(owner.private/f'{seq:03d}-refusal.json',{'sequence':seq,'method':'CONNECT','fixedReasonCode':'CONNECT_REFUSED','complete':True})
                self.send_error(405)
                self.close_connection = True

            def do_GET(self): self.forward()
            def do_POST(self): self.forward()
            def do_PUT(self): self.forward()
            def do_DELETE(self): self.forward()
            def do_HEAD(self): self.forward()

            def forward(self):
                connection = None;timer=None
                with owner.lock:
                    owner.sequence+=1;seq=owner.sequence
                    save(owner.private/f'{seq:03d}-intent.json',{'kind':'forwarded','id':'H'+digest((str(owner.private)+str(seq)).encode())[:24],
                         'pair':f'{seq:03d}-pair.json','refusal':f'{seq:03d}-refusal.json','role':'CONTROL'if'helper-controls'in str(owner.private)else'P2_P3_CLI'})
                try:
                    require(seq<=MAX_HTTP,'HTTP_REQUEST_COUNT_CAP')
                    owner.guard()
                    self.connection.settimeout(15)
                    parsed = urllib.parse.urlsplit(self.path)
                    if parsed.scheme or parsed.netloc:
                        allowed = {(owner.upstream.hostname, owner.upstream.port),
                                   ('127.0.0.1', owner.server.server_port)}
                        require(parsed.scheme == 'http' and (parsed.hostname, parsed.port) in allowed,
                                'EXTERNAL_ABSOLUTE_REQUEST_REFUSED')
                    path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
                    require(path.startswith('/') and not parsed.fragment, 'ORIGIN_PATH_REQUIRED')
                    incoming = list(self.headers.raw_items())
                    require(sum(len(k)+len(v)for k,v in incoming)<=65536,'HTTP_HEADER_CAP')
                    body, framing = read_payload(self.rfile, self.headers, owner.guard)
                    connection_tokens = {x.strip().lower() for k, v in incoming if k.lower() == 'connection'
                                         for x in v.split(',')}
                    require(not any('actor' in x or 'user-agent' == x or x.startswith('x-xerj')
                                    for x in connection_tokens), 'ACTOR_HEADER_CANNOT_BE_HOP_STRIPPED')
                    removed = HOP | connection_tokens | {'content-length'}
                    started = time.monotonic()
                    connection = http.client.HTTPConnection(owner.upstream.hostname, owner.upstream.port,
                                                            timeout=15)
                    connection.connect()
                    timer=threading.Timer(max(.001,min(15,owner.seconds_left())),interrupt_socket,args=(connection.sock,))
                    timer.daemon=True;timer.start()
                    connection.putrequest(self.command, path, skip_host=True, skip_accept_encoding=True)
                    for key, val in incoming:
                        if key.lower() not in removed:
                            connection.putheader(key, val)
                    connection.putheader('Content-Length', str(len(body)))
                    connection.endheaders(body)
                    response = connection.getresponse()
                    response_headers = response.getheaders()
                    raw = response.read(MAX_BODY + 1)
                    require(len(raw) <= MAX_BODY, 'RESPONSE_BODY_CAP')
                    owner.guard()
                    if 300 <= response.status < 400:
                        location = response.getheader('Location')
                        if location:
                            target = urllib.parse.urlsplit(urllib.parse.urljoin(
                                'http://127.0.0.1:'+str(owner.upstream.port)+path, location))
                            require(target.scheme == 'http' and target.hostname == '127.0.0.1' and
                                    target.port == owner.upstream.port, 'EXTERNAL_REDIRECT_REFUSED')
                    response_connection = {x.strip().lower() for k, v in response_headers
                                           if k.lower() == 'connection' for x in v.split(',')}
                    response_removed = HOP | response_connection | {'content-length'}
                    with owner.lock:
                        require(owner.used + len(body) + len(raw) <= owner.cap, 'FORWARDER_LOG_OVERFLOW_ABORT')
                        owner.used += len(body) + len(raw)
                        request_name, response_name = f'{seq:03d}-request.body', f'{seq:03d}-response.body'
                        for name, data in [(request_name, body), (response_name, raw)]:
                            with (owner.private/name).open('xb') as f: f.write(data)
                        row = {'sequence': seq, 'started': started, 'finished': time.monotonic(),
                               'method': self.command, 'path': path, 'requestHeaders': incoming,
                               'responseHeaders': response_headers, 'status': response.status,
                               'requestBody': request_name, 'responseBody': response_name,
                               'requestSHA256': digest(body), 'responseSHA256': digest(raw),
                               'requestBytes': len(body), 'responseBytes': len(raw),
                               'requestFraming': framing,
                               'framingChanges': {'requestRemoved': sorted(removed),
                                                  'responseRemoved': sorted(response_removed),
                                                  'output': 'content-length'},
                               'selfInitiated': False}
                        owner.records.append(row)
                        with (owner.private/f'{seq:03d}-pair.json').open('x') as f: json.dump(row, f)
                    self.send_response_only(response.status, response.reason)
                    for key, val in response_headers:
                        if key.lower() not in response_removed:
                            self.send_header(key, val)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    if self.command != 'HEAD': self.wfile.write(raw)
                    self.wfile.flush()
                except BaseException as exc:
                    with owner.lock:
                        owner.errors.append(type(exc).__name__+':'+str(exc))
                        save(owner.private/f'{seq:03d}-refusal.json',{'sequence':seq,'method':self.command,'path':self.path,
                             'reason':repr(exc),'complete':False,'noUpstreamReplacementResponse':True})
                    self.close_connection = True
                    try: self.send_error(502)
                    except OSError: pass
                finally:
                    if timer:timer.cancel();timer.join(1)
                    if connection: connection.close()

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = False
        self.server.block_on_close = True
        self.server.timeout = .2
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:'+str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        require(not self.thread.is_alive(), 'FORWARDER_NOT_STOPPED')


def stop_owned(process):
    """Same group TERM/reap/KILL/reap sequence as reviewed bounded.command."""
    if process.poll() is None:
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=2)
    require(process.poll() is not None, 'OWNED_CHILD_UNREAPED')
    return {'pid': process.pid, 'returncode': process.returncode, 'reaped': True}


class RPC:
    def __init__(self, command, env, cwd, private, guard):
        self.private, self.guard = Path(private), guard
        self.private.mkdir(parents=True, exist_ok=False)
        self.stderr = (self.private/'stderr.log').open('xb')
        self.stdout_log=(self.private/'stdout.log').open('xb')
        self.cli_intent_id='C'+digest(str(self.private/'process').encode())[:24]
        save(self.private/'process.intent.json',{'kind':'cli','id':self.cli_intent_id,'receipt':'process.receipt.json',
             'role':'CONTROL'if'helper-controls'in str(self.private)else'P2'})
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ, 'stdout')
        self.selector.register(self.process.stderr, selectors.EVENT_READ, 'stderr')
        self.stderr_bytes = 0
        self.pending, self.counter, self.total = bytearray(), 0, 0
        self.messages = []
        self.terminal_missing = []

    def send(self, method, params=None, notify=False, seconds=15):
        self.guard()
        require(not getattr(self,'failed',False),'RPC_SESSION_ALREADY_FAILED_NO_RETRY')
        require(self.counter<16,'RPC_SESSION_REQUEST_CAP')
        self.counter += 1
        ident = self.counter
        msg = {'jsonrpc': '2.0', 'method': method}
        if not notify: msg['id'] = ident
        if params is not None: msg['params'] = params
        raw = json.dumps(msg, separators=(',', ':')).encode()+b'\n'
        require(len(raw) <= 65536, 'RPC_REQUEST_LINE_CAP')
        save(self.private/f'{ident:03d}-intent.json',{'kind':'rpc','id':'M'+digest((str(self.private)+str(ident)).encode())[:24],
             'notification':notify,'response':f'{ident:03d}-response.body','role':'CONTROL'if'helper-controls'in str(self.private)else'P2'})
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        self.messages.append({'direction': 'request', 'message': msg})
        save(self.private/f'{ident:03d}-request.json',msg)
        if notify: return None
        end = time.monotonic()+seconds
        while True:
            self.guard()
            require(time.monotonic() < end, 'RPC_TIMEOUT')
            if b'\n' in self.pending:
                line, _, rest = self.pending.partition(b'\n'); self.pending = bytearray(rest)
                with(self.private/f'{ident:03d}-response.body').open('xb')as f:f.write(line+b'\n')
                value = json_value(line)
                require(isinstance(value, dict) and value.get('id') == ident, 'RPC_INTERLEAVED_REPLY_REFUSED')
                self.messages.append({'direction': 'response', 'message': value})
                save(self.private/f'{ident:03d}.json', {'request': msg, 'response': value})
                require('error' not in value, 'RPC_ERROR_RESPONSE')
                return value.get('result')
            events = self.selector.select(min(.1, max(0, end-time.monotonic())))
            for key, _ in events:
                data = os.read(key.fd, 65536)
                if not data:
                    self.selector.unregister(key.fileobj)
                    require(key.data != 'stdout', 'RPC_EOF')
                    continue
                if key.data == 'stderr':
                    self.stderr_bytes += len(data)
                    require(self.stderr_bytes <= MAX_BODY, 'RPC_STDERR_CAP')
                    self.stderr.write(data); self.stderr.flush()
                else:
                    self.total += len(data)
                    require(self.total <= 2*MAX_BODY and len(self.pending)+len(data)<=1048576, 'RPC_OUTPUT_CAP')
                    self.stdout_log.write(data);self.stdout_log.flush()
                    self.pending.extend(data)

    def close(self):
        requested={x['message']['id']for x in self.messages if x['direction']=='request'and'id'in x['message']}
        responded={x['message']['id']for x in self.messages if x['direction']=='response'}
        self.terminal_missing=sorted(requested-responded)
        save(self.private/'terminal-message-accounting.json',{'requestedIDs':sorted(requested),'respondedIDs':sorted(responded),
             'missingReplyIDs':self.terminal_missing,'notificationsNoReplyExpected':sum(x['direction']=='request'and'id'not in x['message']for x in self.messages)})
        self.selector.close()
        if self.process.stdin: self.process.stdin.close()
        result = stop_owned(self.process)
        for stream,kind in [(self.process.stderr,'stderr'),(self.process.stdout,'stdout')]:
            os.set_blocking(stream.fileno(),False)
            tail=bytearray()
            while True:
                try:part=os.read(stream.fileno(),65536)
                except BlockingIOError:break
                if not part:break
                tail.extend(part);require(len(tail)<=MAX_BODY,'RPC_TERMINAL_TAIL_CAP')
            if kind=='stderr':self.stderr.write(tail);self.stderr_bytes+=len(tail)
            elif tail or self.pending:
                self.stdout_log.write(tail)
                with(self.private/'terminal-stdout.body').open('xb')as f:f.write(self.pending+tail)
                self.failed=True
        result['unmatchedProtocolBytes']=bool(self.pending or(self.private/'terminal-stdout.body').exists())
        self.process.stdout.close()
        self.process.stderr.close()
        self.stderr.close();self.stdout_log.close()
        save(self.private/'process.receipt.json',{'intentId':self.cli_intent_id,'operatorAction':True,
             'actualExit':self.process.returncode,'timeout':False,'reapedByReviewedBoundedFinally':result['reaped'],
             'stdoutBytes':(self.private/'stdout.log').stat().st_size,'stderrBytes':(self.private/'stderr.log').stat().st_size,
             'stdoutSHA256':digest((self.private/'stdout.log').read_bytes()),'stderrSHA256':digest((self.private/'stderr.log').read_bytes())})
        require((self.private/'stderr.log').stat().st_size <= MAX_BODY, 'RPC_STDERR_CAP')
        return result


def classify_audit(audit):
    require(isinstance(audit.get('entries'), list), 'AUDIT_ENTRIES_REQUIRED')
    user, machine, other = [], [], []
    for entry in audit['entries']:
        if entry.get('op') != 'search':
            other.append(entry)
            continue
        tokens = dict(x.split('=', 1) for x in entry.get('note', '').split() if '=' in x)
        legacy_machine = entry.get('actor') is None and (
            tokens.get('size') == '0' or entry.get('resource') == 'autoindex-catalog')
        if entry.get('actor') == 'machine' or legacy_machine: machine.append(entry)
        else: user.append(entry)
    return {'user': user, 'machine': machine, 'other': other}


def align_audit(before, after, search_requests):
    recorded_searches=len(search_requests)
    a, b = before.get('entries', []), after.get('entries', [])
    # No inferred alignment when the server window evicts or reshuffles entries.
    if b[:len(a)] != a:
        return {'state': 'UNKNOWN', 'reason': 'AUDIT_WINDOW_NOT_APPEND_ALIGNED'}
    new = {'entries': b[len(a):]}
    classified = classify_audit(new)
    if len(classified['user'])+len(classified['machine']) != recorded_searches:
        return {'state': 'UNKNOWN', 'reason': 'NATIVE_SEARCH_COUNT_MISMATCH',
                'nativeSearchEntries': len(classified['user'])+len(classified['machine']),
                'observedSearchHTTPRequests': recorded_searches}
    entries=[x for x in new['entries']if x.get('op')=='search']
    identities=[]
    for req,entry in zip(search_requests,entries):
        path=urllib.parse.urlsplit(req['path']).path
        parts=path.strip('/').split('/')
        if len(parts)!=2 or parts[1]!='_search' or urllib.parse.unquote(parts[0])!=entry.get('resource'):
            return {'state':'UNKNOWN','reason':'AUDIT_RESOURCE_IDENTITY_NOT_ALIGNED'}
        identities.append({'requestSequence':req.get('sequence'),'auditEntrySHA256':digest(json.dumps(entry,sort_keys=True).encode())})
    return {'state': 'EXACT', 'identities':identities,'newSearchEntries': recorded_searches,
            'userSearches': len(classified['user']), 'excludedMachineSearches': len(classified['machine']),
            'otherNativeOperations': len(classified['other'])}


def bind_surface(table, state, action):
    item = action['states'][state]
    if item['status'] != 'SPAN_AVAILABLE':
        return {'allowed': False, 'loss': 'PLANNED_DISCOVERABILITY_LOSS', 'id': action['id']}
    require(item['provenance'], 'EMPTY_PROVENANCE')
    for span in item['provenance']:
        surface = table['surfaces'][state][span['surface_id']]
        raw = Path(surface['path']).read_bytes()
        require(digest(raw) == surface['sha256'] == span['sha256'], 'OFFERED_SURFACE_IDENTITY')
        lines = raw.decode().splitlines(keepends=True)
        require(len(lines) == surface['line_count'], 'OFFERED_LINE_COUNT')
        start, end = span['start_line'], span['end_line']
        require(1 <= start <= end <= len(lines), 'OFFERED_LINE_SPAN')
        require('\n'.join(raw.decode().splitlines()[start-1:end]) == span['exact_text'], 'OFFERED_SPAN_EXACT_TEXT')
    return {'allowed': True, 'id': action['id'], 'provenance': item['provenance'],
            'productPrerequisites': item.get('product_prerequisites', [])}


def token_measure(records, private, corpus):
    """Complete search-response SET for one CLI question; no equivalent-request shortcut."""
    selected = [r for r in records if r['method'] in ('GET', 'POST') and
                urllib.parse.urlsplit(r['path']).path.endswith(('/_search', '/_msearch'))]
    require(selected, 'CLI_NO_CAPTURED_SEARCH_RESPONSE')
    require(not any(r['path'].split('?', 1)[0].endswith('/_msearch') for r in selected),
            'MSEARCH_ACCOUNTING_NOT_YET_SUPPORTED')
    all_files, first_files, response_rows = set(), [], []
    btotal, hints = 0, 0
    for row in selected:
        raw = (Path(private)/row['responseBody']).read_bytes()
        require(digest(raw) == row['responseSHA256'], 'WIRE_RESPONSE_IDENTITY')
        decoded = decoded_json_body(raw, row['responseHeaders'])
        clean, removed = without_xerj(decoded)
        obj = json_value(decoded)
        hits = obj.get('hits', {}).get('hits')
        require(isinstance(hits, list), 'SEARCH_HITS_REQUIRED')
        current = []
        for hit in hits:
            source = hit.get('_source', {})
            path = source.get('ax_path', source.get('path'))
            require(path in corpus, 'HIT_FILE_OUTSIDE_BOUND_CORPUS_OR_PATH_NOT_RETURNED')
            current.append(path); all_files.add(path)
        if current: first_files.append(current[0])
        btotal += len(clean); hints += removed['hintsRemovedBytes']
        response_rows.append({'sequence': row['sequence'], 'rawBytes': len(raw),
                              'decodedBytes': len(decoded), 'decodedSHA256':digest(decoded),'rawSHA256':digest(raw),'memberByteSpan':removed.get('memberByteSpan'), 'armBBytes': len(clean),
                              'hintsBytes': removed['hintsRemovedBytes'], 'hits': len(hits)})
    a = sum(corpus[n]['bytes'] for n in all_files)
    # A multi-response CLI has a top-1 file per consumed response; deduplicate it.
    top = sum(corpus[n]['bytes'] for n in set(first_files))
    return {'completeSearchResponseSet': response_rows, 'armAAllUniqueFilesBytes': a,
            'armATopOnePerResponseUniqueBytes': top, 'armBDecodedWireMinusHintsBytes': btotal,
            'hintsBytesSeparate': hints, 'approxTokensAtFourBytes': {'AAll': a/4, 'ATop1': top/4, 'B': btotal/4},
            'allRatio': a/btotal if btotal and all_files else None,
            'top1Ratio': top/btotal if btotal and first_files else None,
            'zeroHitRetained': not all_files,'outcome':'LOSS_ZERO_HIT'if not all_files else'RECORDED',
            'auxiliaryResponses': len(records)-len(selected)}


def payload_object(value):
    """Use only actual product JSON; an unstructured output is an honest loss."""
    if isinstance(value, dict) and isinstance(value.get('structuredContent'), dict):
        return value['structuredContent']
    if isinstance(value, dict) and 'content' in value:
        blocks = [x['text'] for x in value['content'] if x.get('type') == 'text']
        require(len(blocks) == 1, 'PRODUCT_CONTENT_NOT_ONE_STRUCTURED_DOCUMENT')
        return json_value(blocks[0])
    require(isinstance(value, dict), 'PRODUCT_OBJECT_REQUIRED')
    return value


def product_index(value):
    """No hidden schema names: only a literal index returned by map/catalog."""
    if isinstance(value, dict):
        for key in ('index', 'index_name'):
            x = value.get(key)
            if isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_-]+', x): return x
        for x in value.values():
            try: return product_index(x)
            except ValueError: pass
    if isinstance(value, list):
        for x in value:
            try: return product_index(x)
            except ValueError: pass
    raise ValueError('ACTUAL_PRODUCT_INDEX_NOT_DISCOVERED')


def grounded_prompt(value):
    """A literal field/value from the observed catalog, never an invented value."""
    if isinstance(value, dict):
        field = value.get('name', value.get('field'))
        examples = value.get('examples')
        if isinstance(field, str) and isinstance(examples, list):
            for example in examples:
                if isinstance(example, (str, int, float)) and not isinstance(example, bool):
                    require(len(str(example)) <= 200 and len(field) <= 100, 'GROUNDING_SIZE')
                    return field+' equals '+str(example)
        for x in value.values():
            try: return grounded_prompt(x)
            except ValueError: pass
    if isinstance(value, list):
        for x in value:
            try: return grounded_prompt(x)
            except ValueError: pass
    raise ValueError('ACTUAL_CATALOG_FIELD_VALUE_NOT_DISCOVERED')


def checked_tool(tools, name, args):
    require(name in tools, 'TOOL_NOT_ADVERTISED')
    schema = tools[name]['inputSchema']
    require(set(schema.get('required', [])) <= set(args), 'SCHEMA_REQUIRED_ARGUMENT_MISSING')
    require(set(args) <= set(schema.get('properties', {})), 'ARGUMENT_NOT_IN_ACTUAL_SCHEMA')
    return {'name': name, 'arguments': args}


def http_exchange(url, method, path, body, guard, private, label, forwarder=None, deadline=None):
    u = loopback_url(url)
    require(path.startswith('/') and not urllib.parse.urlsplit(path).netloc, 'ORIGIN_PATH_ONLY')
    guard()
    Path(private).mkdir(parents=True,exist_ok=True)
    intent={'kind':'http-wrapper'if forwarder else'http','id':'D'+digest((str(private)+label).encode())[:24],
            'response':label+'.json','role':'CONTROL'if'helper-controls'in str(private)else'OPERATOR_OR_P3'}
    if forwarder:intent['coveredByForwardedId']='H'+digest((str(forwarder.private)+str(forwarder.sequence+1)).encode())[:24]
    save(Path(private)/(label+'-intent.json'),intent)
    connection = http.client.HTTPConnection(u.hostname, u.port, timeout=15)
    data = None if body is None else json.dumps(body).encode()
    started = time.monotonic();timer=None
    try:
        connection.connect()
        seconds=min(15,max(.001,deadline-time.time()))if deadline else 15
        timer=threading.Timer(seconds,interrupt_socket,args=(connection.sock,));timer.daemon=True;timer.start()
        connection.request(method, path, body=data,
                           headers={} if data is None else {'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(MAX_BODY + 1)
        require(len(raw) <= MAX_BODY, 'DIRECT_HTTP_CAP')
        guard()
        record = {'method': method, 'path': path, 'status': response.status,
                  'headers': response.getheaders(), 'started': started,
                  'elapsed': time.monotonic()-started, 'bytes': len(raw), 'sha256': digest(raw),'intentId':intent['id']}
        Path(private).mkdir(parents=True, exist_ok=True)
        with (Path(private)/(label+'.body')).open('xb') as f: f.write(raw)
        save(Path(private)/(label+'.json'), record)
        return record, raw
    finally:
        if timer:timer.cancel();timer.join(1)
        connection.close()


def verified_bindings(config):
    table_raw = Path(config['table']).read_bytes()
    corpus_raw = Path(config['corpusBindings']).read_bytes()
    require(digest(table_raw) == config['tableSHA256'], 'EXACT_DECISION_TABLE')
    require(digest(corpus_raw) == config['corpusBindingsSHA256'], 'EXACT_CORPUS_QUESTIONS')
    table, binding = json_value(table_raw), json_value(corpus_raw)
    require(table['schema_version'] == 1 and len(binding['corpus']) == 5 and
            len(binding['questions']) == 5 and binding['totalBytes'] == 3221615, 'BOUND_FIXED_WORKLOAD')
    # Packaging may change only physical source paths, never surface/corpus bytes.
    paths = config.get('packagedPathMap', {})
    for surfaces in table['surfaces'].values():
        for item in surfaces.values(): item['path'] = paths.get(item['path'], item['path'])
    for item in binding['corpus']:
        item['source'] = paths.get(item['source'], item['source'])
        raw = Path(item['source']).read_bytes()
        require(len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'CORPUS_BYTES')
    return table, binding


def observed_listeners(stdout, stderr):
    """Narrow source-backed expectation; verified only by actual future binary output."""
    require(isinstance(stdout,bytes) and isinstance(stderr,bytes) and len(stdout)<=MAX_BODY and len(stderr)<=MAX_BODY,'BANNER_CAPTURE_CAP')
    require(not any(line.startswith((b' Native REST  ',b' ES-compat    '))for line in stderr.splitlines()),'CONFLICTING_STDERR_LISTENER_RECORD_HOLD')
    rows=[line for line in stdout.splitlines(keepends=True) if b'Native REST' in line or b'ES-compat' in line]
    require(all(line.endswith(b'\n')for line in rows),'BANNER_COMPLETE_LINE_REQUIRED')
    rows=[line[:-1]for line in rows]
    require(len(rows)==2,'BANNER_MISSING_DUPLICATE_OR_DECORATED_RECORD')
    values={}
    for kind,label in [('native',b' Native REST  '),('es',b' ES-compat    ')]:
        selected=[line for line in rows if line.startswith(label)]
        require(len(selected)==1,'BANNER_EXACT_LABEL_REQUIRED')
        match=re.fullmatch(re.escape(label)+rb'(127\.0\.0\.1):([0-9]{1,5}) \[plain\]',selected[0])
        require(match is not None,'UNRECOGNIZED_REAL_BANNER_HOLD')
        port=int(match.group(2));require(1<=port<=65535,'BANNER_PORT_RANGE')
        values[kind]='http://'+match.group(1).decode()+':'+str(port)
        loopback_url(values[kind])
        values[kind+'RecordSHA256']=digest(selected[0])
    require(values['native']!=values['es'],'BANNER_LISTENERS_NOT_DISTINCT')
    values.update(stdoutSHA256=digest(stdout),stderrSHA256=digest(stderr),
                  expectation='SOURCE_BACKED_UNVERIFIED_UNTIL_REAL_OBSERVATION',actualRecordsRecognized=True)
    return values


def listener_controls():
    """Synthetic parser controls only; never establish real banner compatibility."""
    valid=b' Native REST  127.0.0.1:12345 [plain]\n ES-compat    127.0.0.1:12346 [plain]\n'
    result=observed_listeners(valid,b'')
    require(result['native']=='http://127.0.0.1:12345' and result['es']=='http://127.0.0.1:12346','LISTENER_PARSER_POSITIVE')
    negatives=[]
    cases={'duplicate':valid+valid,'ansi':b'\x1b[32m'+valid,'external':valid.replace(b'127.0.0.1',b'0.0.0.0'),
           'tls':valid.replace(b'[plain]',b'[TLS ]'),'zero_port':valid.replace(b'12345',b'0'),
           'missing':valid.splitlines(keepends=True)[0],'incomplete':valid.rstrip(b'\n')}
    for name,raw in cases.items():
        try:observed_listeners(raw,b'')
        except ValueError:negatives.append(name)
        else:raise ValueError('LISTENER_NEGATIVE_ACCEPTED:'+name)
    try:observed_listeners(valid,b' Native REST  127.0.0.1:12347 [plain]\n')
    except ValueError:negatives.append('stderr_conflict')
    else:raise ValueError('STDERR_CONFLICT_ACCEPTED')
    return {'syntheticOnly':True,'positive':1,'negative':negatives,'allExpectedOutcomesObserved':True}


def operator_registration(config, root, private, es_url, guard, seconds=120):
    """Early real dependency gate on the existing mechanics node, not an FTX state."""
    session=Session(config,'operator-compatibility',root,private,{}, {},guard)
    session.end=min(session.end,time.time()+seconds)
    session.root.mkdir(parents=True,exist_ok=False);session.private.mkdir(parents=True,exist_ok=False)
    (session.root/'home').mkdir();(session.root/'project').mkdir();(session.root/'tmp').mkdir();(session.root/'hub').mkdir()
    helps={};rpc=None;forwarder=None;cleanup=[]
    def bounded_guard():
        session.guard()
        require(sum(p.stat().st_size for p in session.private.rglob('*')if p.is_file())<=24*1024**2,'EARLY_OPERATOR_PRIVATE_CAP')
    try:
        version=session.command('binary-version',[session.binary,'--version'],cap=65536).decode().strip()
        require(version=='xerj v1.0.0-rc.102','EARLY_REAL_VERSION')
        for name in ('root','init','mcp','gain','autoindex','search'):
            argv=[session.binary,'--help']if name=='root'else[session.binary,name,'--help']
            raw=session.command(name+'-help',argv,seconds=20,cap=65536)
            require(raw,'EARLY_EMPTY_ACTUAL_HELP')
            helps[name]={'sha256':digest(raw),'bytes':len(raw)}
            if name=='root':require(all(token in raw for token in (b'--bind',b'--insecure',b'--data-dir',b'--disable-feedback')),'EARLY_OPERATOR_FLAGS_UNDOCUMENTED')
            if name=='search':require(b'XERJ_URL'in raw or b'--url'in raw,'EARLY_DOCUMENTED_SEARCH_ROUTING_ABSENT')
        forwarder=Forwarder(es_url,session.private/'forwarder',bounded_guard,seconds_left=lambda:session.end-time.time()-8)
        session.command('actual-init',[session.binary,'init','--url',forwarder.url,'--disable-feedback'],cwd=session.root/'project',cap=65536)
        raw=(session.root/'project/.mcp.json').read_bytes();require(len(raw)<=65536,'EARLY_REGISTRATION_CAP')
        save(session.private/'actual-registration.json',json_value(raw))
        entry=json_value(raw)['mcpServers']['xerj']
        require(Path(entry['command']).resolve()==Path(session.binary)and entry['args']==['mcp']and entry['env']=={'XERJ_URL':forwarder.url},'EARLY_GENERATED_REGISTRATION_MISMATCH')
        env=dict(session.env);env.update(entry['env'])
        rpc=RPC([entry['command'],*entry['args']],env,session.root/'project',session.private/'rpc',bounded_guard)
        initialized=rpc.send('initialize',{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'operator-compatibility','version':'1'}})
        rpc.send('notifications/initialized',notify=True)
        tools=rpc.send('tools/list');items=tools['tools']
        require(items and len({t['name']for t in items})==len(items)and all(isinstance(t['name'],str)and isinstance(t['inputSchema'],dict)for t in items),'EARLY_ACTUAL_TOOL_SCHEMA')
        proof={'schemaVersion':1,'realDependencyGate':True,'operatorOnly':True,'beforeCandidateAndExpensiveChecks':True,
               'versionSHA256':digest(version.encode()),'help':helps,'generatedRegistrationSHA256':digest(raw),
               'actualInitializeSHA256':digest(json.dumps(initialized,sort_keys=True).encode()),
               'actualToolsSHA256':digest(json.dumps(tools,sort_keys=True).encode()),'actualToolCount':len(items),
               'noFixedToolCount':True,'noPersonaKnowledgeTransferred':True}
        proof['realDecoderProbe']=real_operator_decoder_probe(session,forwarder)
    finally:
        errors=[]
        for name,obj in [('rpc',rpc),('forwarder',forwarder)]:
            if obj is not None:
                try:
                    value=obj.close()
                    if value:cleanup.append(value)
                except BaseException as exc:errors.append(type(exc).__name__)
        require(not errors and all(r['reaped']for r in cleanup),'EARLY_OPERATOR_CHILD_NOT_REAPED')
    proof['childrenReaped']=True
    sets,excluded,intents=set_accounting(session.private)
    inventory=file_inventory(session.private)
    save(session.private/'operator-raw-inventory.json',{'records':inventory,'excludesSelf':True})
    proof.update(responseSets=sets,expectedIDs=intents,requestIntentIDs=intents,
        actualCLICommandCount=len(sets['cli']),actualCLIResponseSetCount=len(sets['cli']),
        actualRPCRequestCount=len(sets['rpc']),actualRPCResponseCount=sum(r['outcome']=='RESPONSE'for r in sets['rpc']),
        actualHTTPClientRequestCount=len(sets['http']),actualForwardedPairCount=len(sets['forwarded']),
        privateRecordCount=len(inventory)+1,privateBytes=sum(r['bytes']for r in inventory)+(session.private/'operator-raw-inventory.json').stat().st_size,
        privateInventorySHA256=digest((session.private/'operator-raw-inventory.json').read_bytes()),complete=True,
        excludedDirectRequests=excluded,scope='EARLY_OPERATOR_ONLY_NOT_PERSONA_OR_FTX_ARM')
    require(proof['privateBytes']<=24*1024**2,'EARLY_FINAL_PRIVATE_CAP')
    return proof


class Session:
    def __init__(self, config, state, root, private, table, binding, guard):
        self.config, self.state, self.root = config, state, Path(root)
        self.private, self.table, self.binding = Path(private), table, binding
        self.outer_guard, self.started = guard, time.monotonic()
        self.end = min(time.time()+600, config['targetEpoch']-config['cleanupReserve']-config['exportReserve'])
        self.results, self.stops = [], []
        self.node, self.rpc, self.forwarder = None, None, None
        self.env = {'PATH':config['operator']['path'], 'HOME':str(self.root/'home'),
                    'XDG_CONFIG_HOME':str(self.root/'home/config'),
                    'XDG_CACHE_HOME':str(self.root/'home/cache'),
                    'XERJ_DISABLE_FEEDBACK':'true', 'LANG':'C.UTF-8'}
        self.binary = str(Path(config['binary']).resolve())
        self.sequence = 0

    def guard(self):
        self.outer_guard()
        if hasattr(self,'node_log'):
            require((self.private/'node.log').stat().st_size<=MAX_BODY and(self.private/'node.stderr').stat().st_size<=MAX_BODY,'PRIVATE_NODE_LOG_CAP')
        require(time.time() < self.end-8, 'FTX_STATE_DEADLINE')

    def command(self, label, args, seconds=60, expected=0, cwd=None, cap=MAX_BODY):
        from bounded import command
        self.guard()
        require(self.sequence<61,'PER_STATE_COMMAND_CAP_WITH_NODE_RPC_RESERVE')
        self.sequence += 1
        name = f'{self.sequence:03d}-'+label
        log = self.private/(name+'.stdout')
        argv = ['env','-i',*[k+'='+v for k,v in self.env.items()],*map(str,args)]
        started = time.monotonic()
        intent_id='C'+digest(str(self.private/name).encode())[:24]
        save(self.private/(name+'.intent.json'),{'kind':'cli','id':intent_id,'receipt':name+'.receipt.json','role':'OPERATOR'})
        error = None
        returned=False
        try:
            output=command(argv, min(seconds, self.end-time.time()-8), cap,
                           guard=self.guard, expected=expected, cwd=cwd or self.root, log=log)
            returned=True
            return output
        except BaseException as exc:
            error = type(exc).__name__+':'+str(exc)
            raise
        finally:
            save(self.private/(name+'.receipt.json'), {'operatorAction': True, 'label':label,
                 'argv':list(map(str,args)), 'expectedExit':expected, 'actualExit':expected if returned else(int(re.match(r'^RuntimeError:command exit (-?\d+),',error).group(1))if error and re.match(r'^RuntimeError:command exit (-?\d+),',error)else None), 'error':error,
                 'timeout':bool(error and ('Timeout' in error or 'DEADLINE' in error)),
                 'reapedByReviewedBoundedFinally':True, 'actualPIDNotProvidedByUnchangedPrimitive':True,
                 'elapsed':time.monotonic()-started,
                 'intentId':intent_id,'opaqueRecordId':name,'stdoutBytes':log.stat().st_size if log.exists()else 0,
                 'stderrBytes':Path(str(log)+'.stderr').stat().st_size if Path(str(log)+'.stderr').exists()else 0,
                 'stdoutSHA256':digest(log.read_bytes()) if log.exists() else None,
                 'stderrSHA256':digest(Path(str(log)+'.stderr').read_bytes())
                    if Path(str(log)+'.stderr').exists() else None})

    def provision(self):
        self.root.mkdir(exist_ok=False, parents=True)
        self.private.mkdir(exist_ok=False, parents=True)
        (self.root/'home').mkdir(); (self.root/'project').mkdir()
        corpus = self.root/'corpus'; corpus.mkdir()
        for item in self.binding['corpus']:
            rel = Path(item['corpusDestination'])
            require(not rel.is_absolute() and '..' not in rel.parts, 'CORPUS_DESTINATION')
            target = corpus/rel; target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as f: f.write(Path(item['source']).read_bytes())
        for sid,item in self.table['surfaces'][self.state].items():
            raw=Path(item['path']).read_bytes();require(digest(raw)==item['sha256'],'ACTUAL_OFFERED_SURFACE_HASH')
            with(self.private/('offered-'+sid+'.body')).open('xb')as f:f.write(raw)
        self.resources_before={'cpuLimit':2,'memoryLimitBytes':8*1024**3,'swapBytes':0,'pidsLimit':4096,'affinityCount':len(os.sched_getaffinity(0)),
            'memoryMax':Path('/sys/fs/cgroup/memory.max').read_text().strip(),
            'memorySwapMax':Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),
            'pidsMax':Path('/sys/fs/cgroup/pids.max').read_text().strip(),
            'freeDisk':__import__('shutil').disk_usage(self.root).free}
        require(self.resources_before['affinityCount']<=2 and self.resources_before['memoryMax']==str(8*1024**3)
                and self.resources_before['memorySwapMax']=='0'and self.resources_before['pidsMax']=='4096','ACTUAL_CONTAINER_RESOURCE_LIMITS')
        require(self.command('binary-version',[self.binary,'--version']).decode().strip()=='xerj v1.0.0-rc.102',
                'ACTUAL_RELEASE_VERSION_REQUIRED')
        for cmd in ('init','mcp','gain','autoindex','search'):
            raw = self.command(cmd+'-help',[self.binary,cmd,'--help'])
            if cmd == 'search': self.search_help = raw.decode()
        # Operator banner extraction is a root-bound, reviewed compatibility gate,
        # not a guessed persona endpoint or silent alternate port.
        self.node_log = (self.private/'node.log').open('xb')
        self.node_stderr=(self.private/'node.stderr').open('xb')
        self.node_intent_id='C'+digest(str(self.private/'node').encode())[:24]
        save(self.private/'node.intent.json',{'kind':'cli','id':self.node_intent_id,'receipt':'node.receipt.json','role':'OPERATOR'})
        args = [self.binary,'--insecure','--bind','127.0.0.1','--data-dir',str(self.root/'data'),'--disable-feedback']
        self.node_started=time.monotonic()
        self.node = subprocess.Popen(args,env=self.env,cwd=self.root,stdout=self.node_log,
                                     stderr=self.node_stderr,start_new_session=True)
        deadline = min(self.end-8,time.time()+30)
        while True:
            self.guard()
            require(self.node.poll() is None, 'REAL_NODE_START_EXITED')
            stdout=(self.private/'node.log').read_bytes();stderr=(self.private/'node.stderr').read_bytes()
            require(len(stdout)<=MAX_BODY and len(stderr)<=MAX_BODY,'PRIVATE_NODE_LOG_CAP')
            if b'Native REST'in stdout and b'ES-compat'in stdout and all(line.endswith(b'\n')for line in stdout.splitlines(keepends=True)if b'Native REST'in line or b'ES-compat'in line):
                observed=observed_listeners(stdout,stderr)
                self.es,self.native=observed['es'],observed['native']
                self.listener_proof={k:v for k,v in observed.items()if k not in ('es','native')}
                break
            require(time.time()<deadline, 'ACTUAL_BANNER_LISTENER_NOT_DISCOVERED')
            time.sleep(.05)
        self.node_startup_wall=time.monotonic()-self.node_started
        self.forwarder = Forwarder(self.es,self.private/'forwarder',self.guard,seconds_left=lambda:self.end-time.time()-8)
        self.env['XERJ_URL'] = self.forwarder.url
        self.command('init',[self.binary,'init','--url',self.forwarder.url,'--disable-feedback'],
                     cwd=self.root/'project')
        generated=(self.root/'project/.mcp.json').read_bytes()
        with(self.private/'generated-mcp-config.body').open('xb')as f:f.write(generated)
        registration = json_value(generated)
        entry = registration['mcpServers']['xerj']
        require(Path(entry['command']).resolve() == Path(self.binary) and entry['args'] == ['mcp'] and
                entry['env'] == {'XERJ_URL':self.forwarder.url}, 'ACTUAL_GENERATED_REGISTRATION')
        self.registration = entry
        first=next(x for x in self.table['actions']if x['id']=='P2_REGISTERED_SESSION')
        provenance=bind_surface(self.table,self.state,first)
        require(provenance['allowed'],'REGISTERED_SESSION_PUBLIC_SPAN_REQUIRED')
        save(self.private/'early-registered-provenance.json',provenance)
        env=dict(self.env);env.update(entry['env'])
        self.rpc=RPC([entry['command'],*entry['args']],env,self.root/'project',self.private/'rpc',self.guard)
        self.first_session={'initialize':self.rpc.send('initialize',{'protocolVersion':'2024-11-05',
            'capabilities':{},'clientInfo':{'name':'bounded-documented-replay','version':'1'}})}
        self.rpc.send('notifications/initialized',notify=True)
        self.first_session['toolsOutput']=self.rpc.send('tools/list')
        self.first_session['tools']={t['name']:t for t in self.first_session['toolsOutput']['tools']}
        require(self.first_session['tools'],'EMPTY_ACTUAL_TOOLS_LIST')
        index_start=time.monotonic()
        self.command('autoindex',[self.binary,'autoindex',str(corpus),'--disable-feedback'],seconds=180)
        self.index_wall=time.monotonic()-index_start
        self.command('status',[self.binary,'autoindex','status','--disable-feedback'])
        if self.state=='baseline':self.real_controls=self.real_controls_on_node()
        raw=http_exchange(self.native,'GET','/_audit/_search',None,self.guard,self.private,'audit-before',deadline=self.end-8)[1]
        self.audit_start_sequence=len(self.forwarder.records)
        return raw

    def action(self, item, context):
        provenance = bind_surface(self.table,self.state,item)
        if not provenance['allowed']: return dict(provenance,status='LOSS')
        action = item['id']
        before = len(self.forwarder.records)
        context.setdefault('_outputIDs',{})
        action_started=time.time()
        result = {'id':action,'provenance':provenance,'status':'LOSS','firstAttempt':True,
                  'startedUTC':action_started,'derivedProductOutputIDs':dict(context['_outputIDs'])}
        try:
            if action == 'P2_REGISTERED_SESSION':
                # The same exact generated-registration process was initialized
                # once before indexing as the real dependency compatibility gate.
                context.update(self.first_session)
                result['firstSessionUsedWithoutRestart']=True
            elif action in ('P2_MAP','P2_SEARCH','P2_PLAN','P2_SEARCH_PLANNED_QUERY'):
                require(self.rpc is not None and 'tools' in context,'PRIOR_REGISTERED_SESSION_REQUIRED')
                tools = context['tools']
                if action == 'P2_MAP':
                    args = {}; name = next(n for n in tools if n == 'xerj_map')
                elif action == 'P2_SEARCH':
                    observed = payload_object(context['P2_MAP'])
                    args = {'index':product_index(observed),'query':self.binding['questions'][0]['text']}
                    name = next(n for n in tools if n == 'xerj_search')
                elif action == 'P2_PLAN':
                    observed = payload_object(context['P2_MAP'])
                    args = {'index':product_index(observed),'prompt':grounded_prompt(observed)}
                    name = next(n for n in tools if n == 'xerj_plan')
                else:
                    plan = payload_object(context['P2_PLAN'])
                    require(isinstance(plan.get('query'),dict),'NO_ACTUAL_PLANNED_QUERY')
                    args = {'index':product_index(payload_object(context['P2_MAP'])),'query':plan['query']}
                    name = next(n for n in tools if n == 'xerj_search')
                context[action] = self.rpc.send('tools/call',checked_tool(tools,name,args))
                self.observed(action,json.dumps(context[action],sort_keys=True).encode())
                require(not context[action].get('isError',False),'ACTUAL_TOOL_ERROR_LOSS')
                if action=='P2_SEARCH':
                    actual=payload_object(context[action]);mhits=actual.get('hits',{}).get('hits')
                    require(isinstance(mhits,list),'ACTUAL_SEARCH_HITS_NOT_DISCOVERED')
                    if not mhits:result['zeroHit']=True
                    first=len(self.forwarder.records)
                    cli_display=self.command('same-question-cli',[self.binary,'search',self.binding['questions'][0]['text'],'--disable-feedback'])
                    self.observed('same-question-cli',cli_display)
                    replies=[r for r in self.forwarder.records[first:]if r['path'].split('?',1)[0].endswith('/_search')]
                    require(replies,'CLI_COMPARISON_NO_ACTUAL_SEARCH_RESPONSE')
                    last=replies[-1];raw=(self.private/'forwarder'/last['responseBody']).read_bytes()
                    chits=json_value(decoded_json_body(raw,last['responseHeaders'])).get('hits',{}).get('hits')
                    require(isinstance(chits,list),'CLI_COMPARISON_HITS_NOT_DISCOVERED')
                    result['sameQuestionTop3Match']=[x.get('_id')for x in mhits[:3]]==[x.get('_id')for x in chits[:3]]
                    require(result['sameQuestionTop3Match'],'CLI_MCP_TOP3_DIFFERENCE')
                    cli_hints=json_value(decoded_json_body(raw,last['responseHeaders'])).get('_xerj')
                    self.same_hints_verified=actual.get('_xerj')==cli_hints
                    self.same_hints_proof={'sameHints':self.same_hints_verified,'mcpHintsSHA256':digest(json.dumps(actual.get('_xerj'),sort_keys=True).encode()),'cliHintsSHA256':digest(json.dumps(cli_hints,sort_keys=True).encode())}
                    require(self.same_hints_verified,'CLI_MCP_HONEST_HINTS_DIFFERENCE')
            elif action == 'P2_HUB_OBSERVATION':
                require('tools' in context,'TOOLS_LIST_REQUIRED')
                advertised = [t for n,t in context['tools'].items() if n == 'xerj_hub_ask']
                result['status'] = 'LOSS'
                result['reason'] = 'ADVERTISED_NOT_EXERCISED' if advertised else 'NOT_ADVERTISED'
                result['noRemoteHubInvocation'] = True
                # Actual advertised schema remains only in private transcript.
                return result
            elif action == 'P2_CLI_BOUNDARY':
                result['scope'] = 'Offered CLI-only documentation span; no shell granted to P2'
            elif action == 'READ_OFFERED_RECIPE':
                surface = self.table['surfaces'][self.state]['recipe']
                require(surface.get('offered_text_mapping'),'BOUND_MAIN_TEXT_MAPPING_REQUIRED')
                save(self.private/'offered-recipe-text.json',{'mapping':surface['offered_text_mapping']})
            elif action.startswith('P3_'):
                template = item['request_template']
                require(isinstance(template,dict),'NO_PUBLIC_REQUEST_TEMPLATE')
                method,path,body = template['method'],template['path'],template['body']
                if action in ('P3_PROJECTED_SEARCH','P3_ASK'):
                    observed = payload_object(context['P3_CATALOG'])
                    index = product_index(observed)
                    path = path.replace('{actual_catalog_index}',index)
                    if action == 'P3_ASK':body={'index':index,'prompt':grounded_prompt(observed)}
                    else:
                        # A ready actual catalog query is used verbatim; do not
                        # invent hidden fields/projections when it is absent.
                        candidates=[]
                        def walk(x):
                            if isinstance(x,dict):
                                if isinstance(x.get('query'),dict) and '_source'in x:candidates.append(x)
                                for v in x.values():walk(v)
                            elif isinstance(x,list):
                                for v in x:walk(v)
                        walk(observed); require(candidates,'NO_ACTUAL_READY_PROJECTED_QUERY')
                        body=candidates[0]
                row,raw=http_exchange(self.forwarder.url,method,path,body,self.guard,
                                     self.private/'p3',action,forwarder=self.forwarder,deadline=self.end-8)
                require(200<=row['status']<300,'ORIGINAL_HTTP_ERROR_LOSS')
                if action!='P3_CONSOLE':context[action]=json_value(raw)
            else:
                raise ValueError('UNIMPLEMENTED_PREREGISTERED_ACTION')
            result['status']='LOSS'if result.get('zeroHit')else'RECORDED'
            if result.get('zeroHit'):result['reason']='ZERO_HIT'
        except (ValueError,KeyError,StopIteration,TimeoutError,OSError) as exc:
            if action.startswith('P2_')and self.rpc is not None:self.rpc.failed=True
            result['reason']=type(exc).__name__+':'+str(exc)
        finally:
            result['HTTPPairsObserved']=len(self.forwarder.records)-before
            result['finishedUTC']=time.time();result['wallSeconds']=result['finishedUTC']-action_started
            result['rawRecordId']='action-'+action
            context['_outputIDs'][action]='action-'+action
            save(self.private/('action-'+action+'.json'),result)
        return result

    def real_controls_on_node(self):
        controls={}
        before=json_value(http_exchange(self.native,'GET','/_audit/_search',None,self.guard,
                                       self.private,'control-audit-before',deadline=self.end-8)[1])
        start=len(self.forwarder.records)
        # Operator control, never a persona-discovered endpoint or source of
        # fields/values. Exact actual-existing path is sealed in operator config.
        path=self.config['operator']['realSearchControlPath']
        row,raw=http_exchange(self.forwarder.url,'POST',path,{'size':0},self.guard,
                              self.private,'real-node-positive',forwarder=self.forwarder,deadline=self.end-8)
        require(200<=row['status']<300,'REAL_NODE_POSITIVE_FAILED')
        after=json_value(http_exchange(self.native,'GET','/_audit/_search',None,self.guard,
                                      self.private,'control-audit-after',deadline=self.end-8)[1])
        alignment=align_audit(before,after,self.forwarder.records[start:])
        require(alignment['state']=='EXACT','REAL_FORWARDER_AUDIT_CONTROL_UNKNOWN')
        controls['real_node_success']={'expectedOutcomeObserved':True,'evidenceSHA256':digest(raw),
                                      'phase':'real-baseline','auditAlignment':alignment}
        # Reserve an owned, bound but non-listening port; no racy free-port guess.
        with socket.socket() as wrong:
            wrong.bind(('127.0.0.1',0));port=wrong.getsockname()[1]
            try:http_exchange('http://127.0.0.1:'+str(port),'GET','/',None,self.guard,
                              self.private,'real-wrong-port')
            except OSError as exc:
                save(self.private/'real-wrong-port-loss.json',{'expectedFailure':type(exc).__name__,
                     'noRetry':True,'operatorControlNotPersonaAction':True})
            else:raise ValueError('WRONG_PORT_CONTROL_UNEXPECTED_SUCCESS')
        controls['real_wrong_port_loss']={'expectedOutcomeObserved':True,'phase':'real-baseline',
            'evidenceSHA256':digest((self.private/'real-wrong-port-loss.json').read_bytes())}
        script='"$@"; code=$?; printf "\\nFTX_CHILD_EXIT=%s\\n" "$code"; [ "$code" -ge 1 ] && [ "$code" -le 125 ]'
        result=self.command('real-missing-flag',['/bin/sh','-c',script,'ftx-child',self.binary,'mcp','--url'])
        match=re.search(rb'\nFTX_CHILD_EXIT=(\d+)\n$',result)
        require(match and 1<=int(match.group(1))<=125,'ORDINARY_NONZERO_CHILD_EXIT_REQUIRED')
        files=list(self.private.glob('*-real-missing-flag.stdout.stderr'))
        require(len(files)==1 and b'--url requires a value'in files[0].read_bytes()+result,
                'REAL_MISSING_FLAG_INTENDED_DIAGNOSTIC')
        save(self.private/'real-missing-flag-actual-exit.json',{'actualChildExit':int(match.group(1)),
             'ordinaryNonzeroNotSignal':True,'noNumericExitGuessed':True,'noRetry':True})
        controls['real_missing_flag_loss']={'expectedOutcomeObserved':True,'phase':'real-baseline',
                                          'evidenceSHA256':digest(files[0].read_bytes()+result)}
        return controls

    def execute(self):
        context={};before_audit=None
        try:
            before_audit=json_value(self.provision())
            for item in self.table['actions']:
                self.guard();self.results.append(self.action(item,context))
            tokens=[]
            require('XERJ_URL'in self.search_help or '--url'in self.search_help,
                    'CLI_DOCUMENTED_URL_ROUTING_NOT_AVAILABLE')
            for question in self.binding['questions']:
                start=len(self.forwarder.records)
                try:
                    self.command('token-'+question['id'],[self.binary,'search',question['text'],
                                                        '--disable-feedback'])
                    selected=self.forwarder.records[start:]
                    files={str(self.root/'corpus'/x['corpusDestination']):x for x in self.binding['corpus']}
                    tokens.append({'id':question['id'],'measurement':token_measure(
                        selected,self.private/'forwarder',files)})
                except (ValueError,RuntimeError,TimeoutError,OSError)as exc:
                    tokens.append({'id':question['id'],'loss':type(exc).__name__+':'+str(exc)})
            after=json_value(http_exchange(self.native,'GET','/_audit/_search',None,self.guard,
                                           self.private,'audit-after',deadline=self.end-8)[1])
            gain=self.command('gain',[self.binary,'gain','--json','--url',self.native,'--disable-feedback'])
            gain_obj=json_value(gain)
            # Only actual _search operations count, not every forwarded HTTP pair.
            search_records=[r for r in self.forwarder.records[self.audit_start_sequence:]
                if r['path'].split('?',1)[0].endswith('/_search')and not r['path'].startswith('/_audit/')]
            searches=len(search_records)
            alignment=align_audit(before_audit,after,search_records)
            if alignment['state']=='EXACT':
                classified=classify_audit(after)
                if gain_obj.get('searches')!=len(classified['user']):
                    alignment={'state':'UNKNOWN','reason':'GAIN_COUNT_VS_SAME_WINDOW_MISMATCH'}
            require(not self.forwarder.errors,'FORWARDER_FATAL_OR_REFUSED_REQUEST')
            return {'state':self.state,'status':'LOSS'if any(x['status']=='LOSS'for x in self.results)
                    or any('loss'in x for x in tokens) or alignment['state']!='EXACT' else 'RECORDED',
                    'actions':self.results,'tokenQuestions':tokens,'audit':alignment,
                    'HTTPPairs':len(self.forwarder.records),'searchHTTPRequests':searches,
                    'operatorSetupTrafficExcludedFromPersonaCounts':True,
                    'singleRunNoVariance':True,'toolInventory':{'count':len(context.get('tools',{})),
                        'schemaSHA256':digest(json.dumps(context.get('toolsOutput'),sort_keys=True).encode()),'rawSchemaPrivate':True},'gain':gain_obj,'resources':{**self.resources_before,
                        'memoryPeak':Path('/sys/fs/cgroup/memory.peak').read_text().strip(),
                        'freeDiskAfter':__import__('shutil').disk_usage(self.root).free,
                        'nodeStartupSeconds':self.node_startup_wall,'corpusIndexSeconds':self.index_wall},
                    'realControls':getattr(self,'real_controls',{}),'listenerCompatibility':self.listener_proof}
        finally:
            errors=[]
            for label,closer in [('rpc',self.rpc.close if self.rpc else None),
                                 ('forwarder',self.forwarder.close if self.forwarder else None),
                                 ('node',(lambda:stop_owned(self.node))if self.node else None)]:
                if closer:
                    try:
                        row=closer()
                        if row:self.stops.append(row)
                    except BaseException as exc:errors.append({'kind':label,'error':repr(exc)})
            if hasattr(self,'node_log'):
                self.node_log.close();self.node_stderr.close()
                save(self.private/'node.receipt.json',{'operatorAction':True,'intentId':self.node_intent_id,
                     'actualExit':self.node.returncode if self.node else None,'timeout':False,
                     'reapedByReviewedBoundedFinally':bool(self.node and self.node.poll()is not None),
                     'stdoutBytes':(self.private/'node.log').stat().st_size,'stderrBytes':(self.private/'node.stderr').stat().st_size,
                     'stdoutSHA256':digest((self.private/'node.log').read_bytes()),'stderrSHA256':digest((self.private/'node.stderr').read_bytes())})
            self.cleanup_complete=not errors and all(x['reaped']and not x.get('unmatchedProtocolBytes',False)for x in self.stops)
            if self.private.exists():
                save(self.private/'owned-stop.json',{'children':self.stops,
                     'allReaped':self.cleanup_complete,'errors':errors})



def fixture_controls(root, guard):
    """24 actual helper controls on synthetic local data; future Docker ONLY."""
    root=Path(root);root.mkdir(parents=True,exist_ok=False)
    outcomes={}
    def passed(name):outcomes[name]={'expectedOutcomeObserved':True,'syntheticHelperControl':True}
    scanner=[('first',b'{"_xerj":{"hints":["x"]},"a":1}'),
             ('middle',b'{"a":1, "_xerj":{"hints":["x"]}, "b":2}'),
             ('last',b'{"a":1, "_xerj":{"hints":["x"]}}'),
             ('absent',b'{"a":"\\u00e9"}')]
    for name,raw in scanner:
        clean,_=without_xerj(raw);require('_xerj'not in json_value(clean),'SCANNER_CONTROL')
        if name=='absent':require(clean==raw,'ABSENT_BYTE_IDENTITY')
        passed('scanner_xerj_'+name)
    for name,raw in [('duplicate_xerj',b'{"_xerj":1,"_xerj":2}'),
                     ('duplicate_other_key',b'{"a":1,"a":2}'),('nonobject',b'[]')]:
        try:without_xerj(raw)
        except ValueError:passed('scanner_'+name+'_refused')
        else:raise AssertionError('SCANNER_NEGATIVE_ACCEPTED')
    fixture_received=[]
    class Upstream(http.server.BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_):pass
        def do_POST(self):
            body,_=read_payload(self.rfile,self.headers,guard)
            fixture_received.append({'body':body,'headers':list(self.headers.raw_items())})
            output=gzip.compress(body)if self.path=='/gzip'else body
            self.send_response_only(200)
            if self.path=='/gzip':self.send_header('Content-Encoding','gzip')
            if self.path=='/chunked':self.send_header('Transfer-Encoding','chunked')
            else:self.send_header('Content-Length',str(len(output)))
            self.end_headers()
            if self.path=='/chunked':self.wfile.write(f'{len(output):x}\r\n'.encode()+output+b'\r\n0\r\n\r\n')
            else:self.wfile.write(output)
            self.wfile.flush()
    server=http.server.HTTPServer(('127.0.0.1',0),Upstream)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
    proxy=None;tiny=None
    try:
        upstream='http://127.0.0.1:'+str(server.server_port)
        proxy=Forwarder(upstream,root/'forwarder',guard)
        require(not fixture_received and not proxy.records,'NO_SELF_TRAFFIC_CONTROL');passed('forwarder_no_self_traffic')
        def request(path,body,chunked=False):
            u=loopback_url(proxy.url);c=http.client.HTTPConnection(u.hostname,u.port,timeout=3)
            try:
                c.request('POST',path,body=iter([body[:2],body[2:]])if chunked else body,
                          headers={'User-Agent':'actual-control-agent','X-Xerj-Actor':'synthetic-preserved'},
                          encode_chunked=chunked)
                response=c.getresponse();data=response.read(MAX_BODY+1)
                return response.status,data,response.getheaders()
            finally:c.close()
        body=b'{"unicode":"\xc3\xa9","_xerj":{"hints":[]},"hits":{"hits":[]}}'
        status,data,_=request('/length',body)
        require(status==200 and data==body and fixture_received[-1]['body']==body,'LENGTH_BODY_CONTROL')
        passed('forwarder_content_length_request');passed('forwarder_content_length_response')
        status,data,_=request('/chunked',body,True)
        require(status==200 and data==body and fixture_received[-1]['body']==body,'CHUNKED_BODY_CONTROL')
        passed('forwarder_chunked_request');passed('forwarder_chunked_response')
        headers=dict((k.lower(),v)for k,v in fixture_received[-1]['headers'])
        require(headers['user-agent']=='actual-control-agent'and headers['x-xerj-actor']=='synthetic-preserved','ACTOR_CONTROL')
        passed('forwarder_actor_headers_preserved')
        status,data,headers=request('/gzip',body)
        require(status==200 and decoded_json_body(data,headers)==body,'ENCODING_CONTROL')
        passed('forwarder_encoded_json_decode')
        require(len(proxy.records)==len(fixture_received)==3,'NO_SELF_TRAFFIC_COMPLETE_SET')
        for method,path,name in [('GET','http://external.invalid/','forwarder_external_host_refused'),
                                  ('CONNECT','external.invalid:443','forwarder_connect_refused')]:
            count=len(fixture_received);u=loopback_url(proxy.url);c=http.client.HTTPConnection(u.hostname,u.port,timeout=3)
            try:
                c.request(method,path);resp=c.getresponse();resp.read(MAX_BODY)
                require(resp.status>=400 and len(fixture_received)==count,'REFUSED_NO_UPSTREAM_CALL')
                passed(name)
            finally:c.close()
        tiny=Forwarder(upstream,root/'overflow',guard,cap=1);u=loopback_url(tiny.url)
        c=http.client.HTTPConnection(u.hostname,u.port,timeout=3)
        try:
            c.request('POST','/',body=b'abc');resp=c.getresponse();resp.read(MAX_BODY)
            require(resp.status>=400 and any('OVERFLOW'in x for x in tiny.errors),'OVERFLOW_ABORT')
            passed('forwarder_log_overflow_abort')
        finally:c.close()
    finally:
        if tiny:tiny.close()
        if proxy:proxy.close()
        server.shutdown();server.server_close();thread.join(5)
        require(not thread.is_alive(),'FIXTURE_UPSTREAM_STOP')
    env={'PATH':os.environ.get('PATH',''),'PYTHONUNBUFFERED':'1'}
    for kind in ('matching','error','interleaved','timeout'):
        code='import sys,json,time\nm=json.loads(sys.stdin.readline())\n'
        code+=('time.sleep(2)\n'if kind=='timeout'else
               'print(json.dumps({"jsonrpc":"2.0","id":'+('999'if kind=='interleaved'else'm["id"]')+
               (',"error":{"code":-1}}))\n'if kind=='error'else',"result":{"ok":True}}))\n'))
        rpc=RPC([sys.executable,'-u','-c',code],env,root,root/('rpc-'+kind),guard)
        try:
            if kind=='matching':require(rpc.send('ping')=={'ok':True},'RPC_POSITIVE');passed('rpc_matching_id')
            else:
                try:rpc.send('ping',seconds=.2)
                except ValueError as exc:
                    marker={'error':'RPC_ERROR_RESPONSE','interleaved':'RPC_INTERLEAVED_REPLY_REFUSED','timeout':'RPC_TIMEOUT'}[kind]
                    require(marker in str(exc),'RPC_INTENDED_NEGATIVE')
                    passed({'error':'rpc_error_response','interleaved':'rpc_interleaved_reply_refused','timeout':'rpc_timeout'}[kind])
                else:raise AssertionError('RPC_NEGATIVE_ACCEPTED')
        finally:rpc.close()
    before={'entries':[]};after={'entries':[{'op':'search','actor':'user','note':'hits=1 size=10','resource':'a'},
        {'op':'search','actor':'machine','note':'hits=0 size=0','resource':'a'},
        {'op':'read_audit','actor':'user','resource':'audit'}]}
    search_fixture=[{'path':'/a/_search','sequence':1},{'path':'/a/_search','sequence':2}]
    require(align_audit(before,after,search_fixture)['state']=='EXACT','AUDIT_POSITIVE');passed('audit_exact_match')
    require(align_audit(before,after,search_fixture+[{'path':'/a/_search','sequence':3}])['state']=='UNKNOWN','AUDIT_MISMATCH');passed('audit_mismatch_unknown')
    classified=classify_audit(after);require(len(classified['user'])==1 and len(classified['machine'])==1,'ACTOR_CLASSIFICATION')
    passed('audit_machine_actor_classified')
    require(set(outcomes)==set(CONTROL_IDS[:24]),'EXACT_24_HELPER_CONTROL_SET')
    return outcomes


def offline_proof():
    interfaces=[p.name for p in Path('/sys/class/net').iterdir()]
    routes=Path('/proc/net/route').read_text().splitlines()[1:]
    require(set(interfaces)=={'lo'} and not any(x.split()[0]!='lo'for x in routes),'FTX_NETWORK_NOT_DISCONNECTED')
    return {'interfaces':['lo'],'nonLoopbackInterfaces':0,'externalNetworkPhysicallyDisconnected':True}




def file_inventory(private):
    refs=[]
    for n,p in enumerate(sorted(Path(private).rglob('*'))):
        if not p.is_file():continue
        require(not p.is_symlink(),'PRIVATE_EVIDENCE_SYMLINK')
        data=p.read_bytes();require(len(data)<=8*1024**2,'PRIVATE_FILE_CAP')
        refs.append({'opaqueRecordId':f'R{n:05d}','kind':p.suffix.lstrip('.')or'body',
                     'bytes':len(data),'sha256':digest(data),'complete':True,
                     'sourceActionId':'PRIVATE_TRANSCRIPT','_path':str(p)})
    budget_within({'privateRecords':len(refs),'privateBytes':sum(r['bytes']for r in refs)},PROPOSED_CAPS)
    return refs


def set_accounting(private):
    """Independent write-ahead intents, not response-derived expected sets."""
    sets={'cli':[],'rpc':[],'http':[],'forwarded':[]};expected={k:[]for k in sets};excluded=[]
    intents=[]
    for f in sorted(Path(private).rglob('*intent.json')):
        row=json_value(f.read_bytes())
        if row.get('role')=='CONTROL':continue
        intents.append((f,row))
    forwarded_ids={r['id']for _,r in intents if r['kind']=='forwarded'}
    for f,row in intents:
        ident,kind=row['id'],row['kind']
        if kind=='http-wrapper'and row.get('coveredByForwardedId')in forwarded_ids:continue
        if kind=='cli':
            expected['cli'].append(ident);receipt=f.parent/row['receipt']
            d=json_value(receipt.read_bytes())if receipt.exists()else{}
            sets['cli'].append({'id':ident,'stdout':{'bytes':d.get('stdoutBytes',0),'sha256':d.get('stdoutSHA256')},
                'stderr':{'bytes':d.get('stderrBytes',0),'sha256':d.get('stderrSHA256')},
                'exit':d.get('actualExit'),'timeout':d.get('timeout',False),
                'reaped':d.get('reapedByReviewedBoundedFinally',False),
                'outcome':'RESPONSE'if d.get('actualExit')is not None else'EXPLICIT_NONRESPONSE'})
        elif kind=='rpc':
            expected['rpc'].append(ident);response=f.parent/row['response']
            sets['rpc'].append({'id':ident,'outcome':'RESPONSE'if response.exists()else
                'NO_RESPONSE'if row['notification']else'EXPLICIT_NONRESPONSE',
                'responseSHA256':digest(response.read_bytes())if response.exists()else None})
        elif kind=='forwarded':
            expected['forwarded'].append(ident);expected['http'].append(ident)
            pair=f.parent/row['pair'];refusal=f.parent/row['refusal']
            if pair.exists():
                d=json_value(pair.read_bytes());answer={'id':ident,'outcome':'RESPONSE','responseSHA256':d['responseSHA256']}
            else:answer={'id':ident,'outcome':'EXPLICIT_REFUSAL'if refusal.exists()else'EXPLICIT_NONRESPONSE','responseSHA256':None}
            sets['forwarded'].append(answer);sets['http'].append(dict(answer))
        elif kind in ('http','http-wrapper'):
            expected['http'].append(ident);response=f.parent/row['response']
            d=json_value(response.read_bytes())if response.exists()else{}
            sets['http'].append({'id':ident,'outcome':'RESPONSE'if response.exists()else'EXPLICIT_NONRESPONSE',
                                 'responseSHA256':d.get('sha256')});excluded.append(ident)
        else:raise ValueError('UNKNOWN_REQUEST_INTENT_KIND')
    for key,rows in sets.items():
        require(len(rows)==len({x['id']for x in rows}),'DUPLICATE_RESPONSE_ID')
        require(set(expected[key])=={x['id']for x in rows}and len(expected[key])==len(rows),'INTENT_RESPONSE_SET_MISMATCH')
    require(len(sets['forwarded'])<=256,'FORWARDED_COUNT_CAP')
    return sets,excluded,expected


def public_state(state,session,result,table,config,binding,started,finished):
    actions=[];actual={x['id']:x for x in result.get('actions',[])}
    rawrefs=file_inventory(session.private)if session and session.private.exists()else[]
    for seq,item in enumerate(table['actions'],1):
        row=actual.get(item['id']);missing=item['states'][state]['status']!='SPAN_AVAILABLE'
        outcome=('NOT_RUN_BUDGET'if row is None else'LOSS_SOURCE_SPAN_MISSING'if missing else'SUCCESS')
        if row and row.get('status')=='LOSS':
            outcome=row.get('reason')if row.get('reason')in('NOT_ADVERTISED','ADVERTISED_NOT_EXERCISED')else'LOSS_REAL_FAILURE'
            if missing:outcome='LOSS_SOURCE_SPAN_MISSING'
            if row.get('reason')=='ZERO_HIT':outcome='LOSS_ZERO_HIT'
        if row is None and missing:outcome='LOSS_SOURCE_SPAN_MISSING'
        spans=[{'surfaceSHA256':x['sha256'],'lineStart':x['start_line'],'lineEnd':x['end_line']}
               for x in item['states'][state].get('provenance',[])]
        action_ref=next((r for r in rawrefs if Path(r['_path']).name=='action-'+item['id']+'.json'),None)
        actions.append({'actionId':item['id'],'state':state.upper(),'role':'P2'if item['persona']=='P2_AND_P3'else item['persona'],'applicablePersonas':['P2','P3']if item['persona']=='P2_AND_P3'else[item['persona']],
            'sequence':seq,'decisionTableRow':seq-1,'provenance':{'surface':spans,
            'productOutputIds':list(row.get('derivedProductOutputIDs',{}).values())if row else[]},
            'outcome':outcome,'attempts':1 if row and not missing else 0,
            'startedUTC':row.get('startedUTC')if row else None,'finishedUTC':row.get('finishedUTC')if row else None,
            'wallSeconds':row.get('wallSeconds',0)if row else 0,
            'rawRecordIds':[action_ref['opaqueRecordId']]if action_ref else[],
            'responseBytes':action_ref['bytes']if action_ref else 0,
            'responseSHA256':action_ref['sha256']if action_ref else None,
            'fixedReasonCode':'SOURCE_SPAN_MISSING'if missing else'NOT_RUN'if row is None else
                              'RECORDED'if outcome=='SUCCESS'else outcome})
    cleanup=bool(session and getattr(session,'cleanup_complete',False))
    complete=result.get('status')!='INCOMPLETE'and cleanup and len(actual)==len(table['actions'])and started is not None and finished-started<=600
    network=({'mode':'FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT','externalNetworkPhysicallyDisconnected':False,'fixedTopologyAcrossEntireFTX':True,'projectTestsSeparateOffline':True,'encryptedPathBlocked':False,'corpusFeedbackEndpointBlocked':False}if config.get('c2Mode')=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'else offline_proof())if session else{'externalNetworkPhysicallyDisconnected':False,'notStarted':True}
    tokens=[]
    for row in result.get('tokenQuestions',[]):
        if'measurement'in row:tokens.append({'questionId':row['id'],**row['measurement']})
        else:tokens.append({'questionId':row['id'],'outcome':'LOSS_REAL_FAILURE','ratio':None})
    inventory_hash=digest(json.dumps([{k:v for k,v in r.items()if k!='_path'}for r in rawrefs],sort_keys=True).encode())
    operators=[];request_intents={k:[]for k in ('cli','rpc','http','forwarded')}
    if session and session.private.exists():
        sets,_,request_intents=set_accounting(session.private);operators=sets['cli']
    return {'schemaVersion':1,'state':state.upper(),'started':session is not None,
        'offeredSurfaceHashes':{k:v['sha256']for k,v in table['surfaces'][state].items()},
        'decisionTableSHA256':config['tableSHA256'],'corpusManifestSHA256':config['corpusBindingsSHA256'],
        'questionManifestSHA256':config['corpusBindingsSHA256'],'startedUTC':started,'finishedUTC':finished,
        'wallSeconds':finished-started if started is not None else 0,
        'freshStateProof':{'freshOwnedDirectoriesCreated':bool(session and session.root.exists()),'freshOwnedState':bool(session and session.root.exists()),
             'sameFixedCorpus':True,'sameVerifiedBinary':True,'distinctState':state.upper()},
        'networkProof':network,'resources':result.get('resources',{}),'listenerCompatibility':result.get('listenerCompatibility',{}),'operatorActions':operators,
        'personaActions':actions,'toolInventory':result.get('toolInventory',{'count':0,'rawInPrivate':True,'noFixedToolCountAssumed':True}),
        'hubOutcome':next((x['outcome']for x in actions if x['actionId']=='P2_HUB_OBSERVATION'),'NOT_RUN_BUDGET'),
        'auditAlignment':result.get('audit',{'state':'UNKNOWN'}),'tokenMetrics':tokens,
        'rawEvidenceCountsAndHashes':{'count':len(rawrefs),'bytes':sum(x['bytes']for x in rawrefs),
                                      'inventorySHA256':inventory_hash,'requestIntentIDs':request_intents},
        'ownedStopProof':{'allReaped':cleanup,'children':len(session.stops)if session else 0},
        'outcome':'INCOMPLETE'if not complete else'QUALIFIED_REPLAY_WITH_LOSSES',
        'losses':[{'actionId':x['actionId'],'fixedReasonCode':x['fixedReasonCode']}
                  for x in actions if x['outcome']!='SUCCESS'],
        'complete':complete,'actualBudgetAdmission':result.get('budgetAdmission')}


def normalized_controls(observed):
    rows=[]
    for name in CONTROL_IDS:
        value=observed.get(name,{})
        ok=value.get('expectedOutcomeObserved')is True
        rows.append({'id':name,'phase':'synthetic'if name in CONTROL_IDS[:24]else'real-baseline',
            'expectedObservationCode':name.upper(),'actualObservationCode':'EXPECTED_OUTCOME_OBSERVED'if ok else'UNRUN_OR_FAILED',
            'expectedOutcomeObserved':ok,'evidenceSHA256':value.get('evidenceSHA256')or
            digest(json.dumps(value,sort_keys=True).encode())if value else None,'attempts':1 if value else 0})
    return {'schemaVersion':1,'helperSHA256':digest(Path(__file__).read_bytes()),'controls':rows,
        'expectedIdsSHA256':digest(json.dumps(list(CONTROL_IDS)).encode()),'expectedCount':27,
        'observedCount':sum(x['attempts']for x in rows),'allExpectedOutcomesObserved':all(x['expectedOutcomeObserved']for x in rows),
        'firstFailureId':next((x['id']for x in rows if not x['expectedOutcomeObserved']),None)}


def run(config,root,private,guard):
    """Code-complete private proposal: future exact Docker admission only."""
    require(config.get('executionApproved')is True and config.get('rootAgreement')is True and
            config.get('explicitAdditionalCandidateAttemptApproved')is True,'NO_EXECUTION_AUTHORITY')
    require(config['ordinaryConsumed']==2 and config['runtimeAttempt']==3,'EXACT_ADDITIONAL_CANDIDATE_ATTEMPT3')
    require(config['cpuLimit']==2 and config['memoryLimitBytes']==8*1024**3 and
            config['maxFTXSeconds']==1200,'EXACT_RESOURCE_LIMITS')
    config['_approvedCaps']=approved_caps(config)
    root,private=Path(root),Path(private)
    root.mkdir(parents=True,exist_ok=False);private.mkdir(parents=True,exist_ok=False);os.chmod(private,0o700)
    started=time.time();hard_stop=min(started+1200,config['targetEpoch']-config['cleanupReserve']-config['exportReserve'])
    def whole_guard():
        guard();require(time.time()<hard_stop-8,'ORIGINAL_FTX_CLOCK')
        files=[p for p in private.rglob('*')if p.is_file()]
        budget_within({'privateBytes':sum(p.stat().st_size for p in files),'privateRecords':len(files)},config['_approvedCaps'])
    early_operator=json_value(Path(config['earlyOperatorReceipt']).read_bytes())
    require(early_operator['realDependencyGate']is True and early_operator['childrenReaped']is True and early_operator['noPersonaKnowledgeTransferred']is True and early_operator['helperSHA256']==digest(Path(__file__).read_bytes()),'REAL_EARLY_OPERATOR_GATE_REQUIRED')
    table,binding=verified_bindings(config)
    binary=Path(config['binary']);require(binary.is_file()and digest(binary.read_bytes())==config['binarySHA256'],'ACTUAL_BINARY_HASH')
    helper_sha=digest(Path(__file__).read_bytes())
    early=json_value(Path(config['earlyControlsReceipt']).read_bytes())
    require(early['helperSHA256']==helper_sha and set(early['controls'])==set(CONTROL_IDS[:24])and
            all(x['expectedOutcomeObserved']for x in early['controls'].values()),'ACTUAL_EARLY24_HELPER_CONTROLS_REQUIRED')
    require(early.get('fullProtocolPrimitiveControls')and all(early['fullProtocolPrimitiveControls'].values()),'FULL_PROTOCOL_EARLY_PRIMITIVE_CONTROLS_REQUIRED')
    controls=dict(early['controls']);summaries={};sessions=[];fatal=None
    surface_info=lambda state:{k:{'sha256':v['sha256'],'bytes':v['bytes']}for k,v in table['surfaces'][state].items()}
    for state in ('baseline','candidate'):
        begin=time.time();session=None;result={'status':'INCOMPLETE'}
        if state=='candidate':
            baseline=summaries['BASELINE'];need=1.25*baseline['wallSeconds']
            admission={'baselineActualWall':baseline['wallSeconds'],'requiredFTXSeconds':need,
                'remainingFTXSeconds':started+1200-time.time(),'remainingOriginalSeconds':config['targetEpoch']-time.time(),
                'requiredOriginalSeconds':need+config['cleanupReserve']+config['exportReserve']}
            if not baseline['complete']or admission['remainingFTXSeconds']<need or admission['remainingOriginalSeconds']<admission['requiredOriginalSeconds']:
                result={'status':'INCOMPLETE','budgetAdmission':admission};begin=None
        if begin is not None:
            try:
                whole_guard()
                session=Session(config,state,root/('owned-state-'+state),private/('state-'+state),table,binding,whole_guard)
                sessions.append(session);result=session.execute()
            except BaseException as exc:
                fatal=type(exc).__name__
                if session and session.private.exists():save(session.private/'fatal-private.json',{'error':repr(exc)})
                result={'status':'INCOMPLETE'}
            if session and hasattr(session,'real_controls'):controls.update(session.real_controls)
        summary=public_state(state,session,result,table,config,binding,begin,time.time())
        summaries[state.upper()]=summary
        save(root/('ftx-before-summary.json'if state=='baseline'else'ftx-after-summary.json'),summary)
    c2_final=None
    if config.get('c2Mode')=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        require(callable(config.get('containmentClose')),'R2_LIFETIME_CLOSE_IMPLEMENTATION_REQUIRED')
        c2_final=config['containmentClose']()
        save(private/'fixed-containment-final.json',c2_final)
        c2_final={**c2_final,'receiptSHA256':digest((private/'fixed-containment-final.json').read_bytes())}
        require(c2_final.get('sinkLiveUntilFTXClose')is True and c2_final.get('unexpectedSinkRequests')==0 and c2_final.get('infrastructureHOLD')is False,'R2_FINAL_CONTAINMENT_HOLD')
    save(root/'ftx-controls.json',normalized_controls(controls))
    bindings={'schemaVersion':1,'sourcePin':'50e4ffded5518b1822cfac5450fa34d3829ab8ab',
        'releaseArchiveSHA256':config['releaseArchiveSHA256'],'publicInstallerSucceededAllStates':all(any(r['id']=='P1_INSTALL'and r['outcome']=='RECORDED'for r in x.get('fullProtocol',{}).get('records',[]))for x in summaries.values()),'publicInstallerExercised':all(any(r['id']=='P1_INSTALL'and r['outcome']=='RECORDED'for r in x.get('fullProtocol',{}).get('records',[]))for x in summaries.values()),'binarySHA256':config['binarySHA256'],
        'hubPublicQuestion':{'questionSHA256':config['hubPublicQuestion']['questionSHA256'],
            'derivation':config['hubPublicQuestion']['derivation'],
            'rationaleSHA256':digest(config['hubPublicQuestion']['rationale'].encode()),
            'provenance':{state:{**{key:span[key]for key in('surface_id','sha256','start_line','end_line')},
                'exactTextSHA256':digest(span['exact_text'].encode())}for state,span in config['hubPublicQuestion']['provenance'].items()}},
        'helperSHA256':helper_sha,'c2Mode':config['c2Mode'],'c2ApprovalReceiptSHA256':config['c2ApprovalReceiptSHA256'],'c2ImplementationSHA256':json_value(Path(config['c2ApprovalReceipt']).read_bytes())['implementationSHA256'],
        'resourcePartition':{'globalCpuLimit':2,'globalMemoryLimitBytes':8*1024**3,'targetCpuLimit':1.75,'targetMemoryLimitBytes':7936*1024**2,'proxyCpuLimit':.25,'proxyMemoryLimitBytes':256*1024**2},'evidenceCaps':config['_approvedCaps'],'decisionTableSHA256':config['tableSHA256'],
        'corpusManifestSHA256':config['corpusBindingsSHA256'],'questionManifestSHA256':config['corpusBindingsSHA256'],
        'baselineSurfaces':surface_info('baseline'),'candidateSurfaces':surface_info('candidate'),
        'sameOfferingMechanism':True,'sourceCount':120,'sourceBytes':9444700,'corpusFiles':5,'corpusBytes':3221615,'questions':5}
    save(root/'ftx-surface-corpus-bindings.json',bindings)
    before,after=summaries['BASELINE'],summaries['CANDIDATE']
    old={x['actionId']:x['outcome']for x in before['personaActions']};new={x['actionId']:x['outcome']for x in after['personaActions']}
    regressions=[n for n,v in old.items()if v=='SUCCESS'and new.get(n)!='SUCCESS']if before['complete']and after['complete']else[]
    token_loss=lambda summary:[r['questionId']for r in summary['tokenMetrics']if r.get('outcome')in('LOSS_REAL_FAILURE','LOSS_ZERO_HIT')]
    baseline_token_loss=token_loss(before);candidate_token_loss=token_loss(after)
    baseline_valid={r['questionId']for r in before['tokenMetrics']if r.get('completeSearchResponseSet')and not r.get('zeroHitRetained')}
    candidate_valid={r['questionId']for r in after['tokenMetrics']if r.get('completeSearchResponseSet')and not r.get('zeroHitRetained')}
    token_regressions=sorted(baseline_valid-candidate_valid)if before['complete']and after['complete']else[]
    full_old={r['id']:r['outcome']for r in before.get('fullProtocol',{}).get('records',[])}
    full_new={r['id']:r['outcome']for r in after.get('fullProtocol',{}).get('records',[])}
    full_regressions=sorted(n for n,v in full_old.items()if v=='RECORDED'and full_new.get(n)!='RECORDED')if before['complete']and after['complete']else[]
    all_complete=all(x['complete']and x['auditAlignment'].get('state')=='EXACT'for x in summaries.values())and all(x['expectedOutcomeObserved']for x in controls.values())and len(controls)==27
    comparison={'schemaVersion':1,'beforeSummarySHA256':digest((root/'ftx-before-summary.json').read_bytes()),
        'afterSummarySHA256':digest((root/'ftx-after-summary.json').read_bytes()),'decisionTableSHA256':config['tableSHA256'],
        'sameCorpusAndQuestions':True,'stateCount':sum(x['started']for x in summaries.values()),
        'actualActionsCompared':len(old.keys()&new.keys()),'comparisonIncludesPlannedLossAndNotRunStatuses':True,
        'actionsWithTwoActualAttempts':sum(x['attempts']==1 and next(y for y in after['personaActions']if y['actionId']==x['actionId'])['attempts']==1 for x in before['personaActions']),'regressions':regressions,
        'baselineLosses':before['losses'],'candidateLosses':after['losses'],'baselineTokenLosses':baseline_token_loss,'candidateTokenLosses':candidate_token_loss,'tokenRegressions':token_regressions,'fullProtocolRegressions':full_regressions,
        'qualifications':['SCRIPTED_CLIENT','ACTUAL_PUBLIC_INSTALLER_OUTCOMES_RECORDED','LOCAL_PROSPECTIVE_SURFACES',
             'CONDITIONAL_HUB_ACTUAL_OUTCOMES_RECORDED','PARTIAL_BINARY_PARITY','FORWARDER_FRAMING_CHANGES','SMALL_CORPUS','SINGLE_RUN_NO_VARIANCE'],
        'outcome':'UNKNOWN'if all(x['complete']for x in summaries.values())and any(x['auditAlignment'].get('state')!='EXACT'for x in summaries.values())else'INCOMPLETE'if not all_complete else'REGRESSION'if regressions or token_regressions or full_regressions else'NO_OBSERVED_REGRESSION_WITH_LOSSES',
        'complete':all_complete,'fatalFixedCode':fatal,'c2FinalProof':c2_final}
    save(root/'ftx-comparison.json',comparison)
    inventory=file_inventory(private);public_inventory=[{k:v for k,v in r.items()if k!='_path'}for r in inventory]
    save(private/'raw-private-inventory.json',{'records':inventory,'excludesSelfHashCycle':True})
    sets,excluded,expected_ids=set_accounting(private)
    names=['ftx-controls.json','ftx-surface-corpus-bindings.json','ftx-before-summary.json',
           'ftx-after-summary.json','ftx-comparison.json','ftx-evidence-accounting.json']
    pub=[{'name':n,'bytes':(root/n).stat().st_size,'sha256':digest((root/n).read_bytes())}for n in names[:-1]]
    accounting={'schemaVersion':1,'publicFiles':pub,'publicBytes':sum(x['bytes']for x in pub),
        'privateRecordCount':len(inventory)+1,'privateBytes':sum(x['bytes']for x in inventory)+(private/'raw-private-inventory.json').stat().st_size,
        'privateInventorySHA256':digest((private/'raw-private-inventory.json').read_bytes()),
        'actualCLICommandCount':len(sets['cli']),'actualCLIResponseSetCount':len(sets['cli']),
        'actualRPCRequestCount':len(sets['rpc']),'actualRPCResponseCount':sum(x['outcome']=='RESPONSE'for x in sets['rpc']),
        'actualHTTPClientRequestCount':len(sets['http']),'actualForwardedPairCount':len(sets['forwarded']),
        'explicitNonresponseRecords':[x['id']for group in sets.values()for x in group if x['outcome'].startswith('EXPLICIT')],
        'excludedDirectRequests':excluded,'requiredFileSetSHA256':digest(json.dumps(names).encode()),
        'responseSets':sets,'expectedIDs':expected_ids,'directHTTPIntentIDs':direct_http_intents(private),'evidenceCapsApprovalSHA256':config['_approvedCaps']['approvalSHA256'],
        'complete':all_complete,'rawPrivateNeverExported':True,'fixedContainmentFinal':c2_final}
    budget_within({'privateRecords':accounting['privateRecordCount'],'privateBytes':accounting['privateBytes']},config['_approvedCaps'])
    save(root/'ftx-evidence-accounting.json',accounting)
    for name in names:budget_within({'publicFileBytes':(root/name).stat().st_size},config['_approvedCaps'])
    budget_within({'publicTotalBytes':sum((root/n).stat().st_size for n in names)},config['_approvedCaps'])
    return comparison



# Full mandatory protocol amendment. The original A3 primitives above are reused;
# this is PRIVATE/UNRUN and requires a separately reviewed containment adapter.
A3Session = Session
A3PublicState = public_state
A3TokenMeasure = token_measure
FULL_PROTOCOL_IDS = (
    'P1_INSTALL','P1_PATH','P1_LLMS_FIRST_RUN','P1_NAIVE_NO_NODE_AUTOINDEX',
    'P1_FIRST_RUN_NODE','P1_AUTOINDEX','P1_LITERAL_NEXT','P1_ZERO_FLAG_SEARCH',
    'P1_ZERO_FLAG_DEF','P1_ZERO_HIT_RECOVERY','P1_MAP','P1_STATUS',
    'P1_AUTH_NODE','P1_AUTH_ZERO_FLAG_SEARCH','P1_AUTH_ZERO_FLAG_DEF',
    'P1_NO_NODE_RECOVERY','P1_INIT','P1_INIT_EXISTING','P1_HUB_COUNTERPART',
    'P2_FIRST_SESSION','P2_SEARCH_MAP_PLAN','P2_CLI_BOUNDARY','P2_SAME_HINTS',
    'P2_HUB_IF_ADVERTISED','P3_CURL_CONSOLE','P3_CURL_KNOWLEDGE',
    'P3_CURL_CATALOG','P3_CURL_PROJECTION','P3_CURL_ROOT_ASK',
    'P3_CURL_INDEX_ASK','P3_CLI_BOUNDARY','KNOWLEDGE_SEMANTICS',
    'GAIN_NAIVE_THEN_DOCUMENTED','GAIN_USER_MACHINE_POLLS','TOKEN_QUESTIONS')


class HarnessUnverified(ValueError):
    """Harness capability/schema/provenance unknown; never a product failure."""


class ProductContractFailure(ValueError):
    """Recorded real operation or observable documented contract failed."""


def contract(value,reason):
    if not value:raise ProductContractFailure(reason)


PROPOSED_CAPS = {'mode':'FULL_PROTOCOL_PROPOSED_CAPS_V1','privateRecords':4096,
    'privateBytes':768*1024**2,'publicFileBytes':1024**2,'publicTotalBytes':6*1024**2,
    'cliPerState':64,'rpcPerSession':16,'httpPerState':168,'forwardedPerState':160,'directHTTPPerState':8,'containmentCheckpointsPerState':128}


def budget_within(values,limits):
    for key,value in values.items():
        require(type(value)is int and 0<=value<=limits[key],'EVIDENCE_CAP_'+key)
    return True


def approved_caps(config):
    raw=Path(config['capApprovalReceipt']).read_bytes()
    require(digest(raw)==config['capApprovalReceiptSHA256'],'EXACT_CAP_ADOPTION_RECEIPT')
    row=json_value(raw)
    require(row.get('claudeApproved')is True and row.get('rootAgreement')is True and
            row.get('evidenceCaps')==PROPOSED_CAPS,'CASE_CAP_AMENDMENT_NOT_APPROVED')
    return {**PROPOSED_CAPS,'approvalSHA256':digest(raw)}


def cap_controls():
    out={}
    for key in ('privateRecords','privateBytes','publicFileBytes','publicTotalBytes',
                'cliPerState','rpcPerSession','httpPerState','forwardedPerState','directHTTPPerState','containmentCheckpointsPerState'):
        maximum=PROPOSED_CAPS[key]
        budget_within({key:maximum},PROPOSED_CAPS);out[key+'_at_limit']=True
        try:budget_within({key:maximum+1},PROPOSED_CAPS)
        except ValueError:out[key+'_over_limit_refused']=True
        else:raise ValueError('CAP_CONTROL_OVER_LIMIT_ACCEPTED')
    return out


def direct_http_intents(private):
    rows=[json_value(f.read_bytes())for f in Path(private).rglob('*intent.json')]
    forwarded={r['id']for r in rows if r.get('kind')=='forwarded'}
    return sorted(r['id']for r in rows if r.get('role')!='CONTROL'and
        (r.get('kind')=='http'or(r.get('kind')=='http-wrapper'and r.get('coveredByForwardedId')not in forwarded)))


def full_containment(config, phase, private, guard):
    """Both alternatives remain disabled until exact whole-review mode approval."""
    guard();mode=config.get('c2Mode')
    require(mode in ('ORIGINAL_ENDPOINT_BLOCK','SOURCE_OPTOUT_AND_LOOPBACK_REDIRECT','FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'),
            'C2_IMPLEMENTATION_AND_MODE_NOT_APPROVED')
    raw=Path(config['c2ApprovalReceipt']).read_bytes()
    require(digest(raw)==config['c2ApprovalReceiptSHA256'],'C2_EXACT_APPROVAL_RECEIPT')
    approval=json_value(raw)
    require(approval.get('mode'if mode=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'else'c2Mode')==mode and approval.get('claudeApproved')is True
            and approval.get('rootAgreement')is True,'C2_MODE_APPROVAL_PENDING')
    adapter=config.get('containmentGuard')
    require(callable(adapter),'C2_PROVEN_CONTAINMENT_IMPLEMENTATION_UNRESOLVED')
    proof=adapter(phase)
    index=len(list(Path(private).glob('containment-*.json')))
    budget_within({'containmentCheckpointsPerState':index+1},PROPOSED_CAPS)
    save(Path(private)/('containment-'+str(index)+'-'+phase.lower()+'.json'),proof)
    if mode=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'and isinstance(proof,dict):
        proof={**proof,'c2Mode':proof.get('mode'),'approvalSHA256':proof.get('c2ApprovalReceiptSHA256')}
    require(isinstance(proof,dict)and proof.get('c2Mode')==mode and
            proof.get('approvalSHA256')==digest(raw)and
            proof.get('implementationSHA256')==approval.get('implementationSHA256')and
            proof.get('actualKernelEnforced')is True and
            proof.get('connectionLoggingActive')is True and
            proof.get('allOtherEgressDenied')is True and
            proof.get('helperExecutionNamespaceMatches')is True,'C2_ACTUAL_TOPOLOGY_NOT_PROVEN')
    if mode=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        require(proof.get('externalNetworkPhysicallyDisconnected')is False and
            proof.get('encryptedPathBlocked')is False and proof.get('corpusFeedbackEndpointBlocked')is False and
            proof.get('fixedTopologyAcrossEntireFTX')is True and proof.get('projectTestsSeparateOffline')is True and
            proof.get('sourceProvenOptOutApplied')is True and proof.get('feedbackEndpointLoopbackOnly')is True and
            proof.get('actualNativeFeedbackControlsPassed')is True and proof.get('sinkLiveEntireFTX')is True and
            proof.get('unexpectedSinkRequests')==0,'FIXED_C2_CONTAINMENT_UNVERIFIED')
        child=proof.get('childEnvironmentCheckpoint',{})
        require(child.get('scanPerformed')is True and child.get('allLiveXerjMatched')is True,'R1_CHILD_ENV_UNVERIFIED')
    elif mode=='ORIGINAL_ENDPOINT_BLOCK':
        require(proof.get('corpusFeedbackEndpointBlocked')is True and
                proof.get('encryptedPathBlocked')is True,'C2_ORIGINAL_BLOCK_NOT_PROVEN')
    else:
        require(proof.get('encryptedPathBlocked')is False and
                proof.get('corpusFeedbackEndpointBlocked')is False and
                proof.get('sourceProvenOptOutApplied')is True and
                proof.get('feedbackEndpointLoopbackOnly')is True and
                proof.get('actualNativeFeedbackControlsPassed')is True,
                'C2_SUBSTITUTE_NOT_PROVEN_NO_ENCRYPTED_PATH_BLOCK_CLAIM')
        url=config['operator']['corpusFeedbackLoopbackURL'];loopback_url(url)
        require(proof.get('feedbackEndpointURLSHA256')==digest(url.encode()),'C2_ACTUAL_OPERATOR_REDIRECT_BINDING')
    require(proof.get('phase')==phase and isinstance(proof.get('evidenceSHA256'),str)
            and re.fullmatch('[0-9a-f]{64}',proof['evidenceSHA256']),'C2_PHASE_PROOF_BINDING')
    if mode=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        require(proof.get('allFourReviewedHostsPermittedFromStart')is True and proof.get('hostAllowlistPhaseSpecific')is False,'FIXED_TOPOLOGY_NOT_PHASE_RESTRICTED')
    elif phase=='INSTALLER':require(proof.get('installerAndReleaseAllowlistOnly')is True,'INSTALL_ALLOWLIST')
    elif phase=='HUB':require(proof.get('hubCatalogueOnlyIfObserved')is True,'HUB_ALLOWLIST')
    else:require(proof.get('externalNetworkPhysicallyDisconnected')is True,'OFFLINE_PROOF')
    return proof


def protocol_controls():
    """Pure controls authored for future Docker, not executed during authoring."""
    outcomes = {}
    sample='first\nnext: xerj search "public question"\nlast\n'
    require(literal_next(sample)==['xerj','search','public question'],'LITERAL_NEXT_POSITIVE')
    outcomes['literal_next_positive']=True
    for name,text in [('duplicate',sample+'next: xerj map\n'),('metachar','next: xerj search x; rm -rf y\n'),
                      ('substitution','next: xerj search "$(id)"\n')]:
        try: literal_next(text)
        except ValueError:outcomes['literal_next_'+name]=True
        else:raise ValueError('LITERAL_NEXT_NEGATIVE_ACCEPTED')
    sample_rows=[{'path':'/a','bytes':11},{'path':'/b','bytes':13}]
    require(question_top_one(b'first /b then /a',sample_rows)==13,'QUESTION_TOP1_POSITIVE')
    outcomes['question_top1_single']=True
    try: question_top_one(b'no actual file citation',sample_rows)
    except ValueError:outcomes['question_top1_missing']=True
    else:raise ValueError('QUESTION_TOP1_MISSING_ACCEPTED')
    return {'syntheticOnly':True,'controls':outcomes,'allExpectedOutcomesObserved':True}


def literal_next(text):
    import shlex
    rows=re.findall(r'^\s*next:\s*(.+?)\s*$',text,re.M|re.I)
    require(len(rows)==1,'LITERAL_NEXT_NOT_UNIQUE')
    line=rows[0]
    require(not any(x in line for x in (';','|','&','`','$','\n','\r','<','>')),'NEXT_SHELL_INTERPRETATION_REFUSED')
    argv=shlex.split(line)
    require(argv and argv[0]=='xerj','NEXT_NOT_PUBLIC_XERJ_COMMAND')
    return argv


def question_top_one(stdout, rows):
    # One question-level top file from the ACTUAL CLI's displayed citation order.
    # Never sum one winner from each internal HTTP response.
    found=[]
    for row in rows:
        marker=row['path'].encode();pos=stdout.find(marker)
        if pos>=0:found.append((pos,row['path'],row['bytes']))
    require(found,'TOP1_ACTUAL_CLI_FILE_ORDER_UNAVAILABLE')
    found.sort();require(len(found)==1 or found[0][0]!=found[1][0],'TOP1_AMBIGUOUS')
    return found[0][2]


class Session(A3Session):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.protocol=[];self.public_outputs=[];self.output_roles={};self.current_role='OPERATOR_ASSERT';self.context={};self.aux_nodes=[];self.active_refs=[]
        self.env.update(XERJ_HUB_HOME=str(self.root/'hub'),TMPDIR=str(self.root/'tmp'),
                        TMP=str(self.root/'tmp'),TEMP=str(self.root/'tmp'))
        self.installed=False;self.observations={};self.full_started=time.time()
        if self.config.get('c2Mode')in('SOURCE_OPTOUT_AND_LOOPBACK_REDIRECT','FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT'):
            url=self.config['operator']['corpusFeedbackLoopbackURL'];loopback_url(url)
            self.env['XERJ_CORPUS_FEEDBACK_URL']=url
        if self.config.get('c2Mode')=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
            proxy=self.config['operator']['proxyURL']
            parsed=urllib.parse.urlsplit(proxy)
            require(parsed.scheme=='http'and parsed.hostname and parsed.port and not parsed.username and not parsed.password,'FIXED_PROXY_PROOF_URL')
            for key in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy'):
                require(os.environ.get(key)==proxy,'FIXED_PROXY_ENV_NOT_PROOF_BOUND')
                self.env[key]=proxy
            for key in ('NO_PROXY','no_proxy'):
                require(os.environ.get(key)=='localhost,127.0.0.1,::1','FIXED_NO_PROXY_ENV_MISSING')
                self.env[key]='localhost,127.0.0.1,::1'
            require(os.environ.get('XERJ_DISABLE_FEEDBACK')=='true'and os.environ.get('XERJ_CORPUS_FEEDBACK_URL')==self.env['XERJ_CORPUS_FEEDBACK_URL'],'FIXED_ENV_OPERATOR_BINDING')

    def intent_snapshot(self):
        groups={k:set()for k in('cli','rpc','http','forwarded')};rows=[]
        for file in self.private.rglob('*intent.json'):
            row=json_value(file.read_bytes())
            if row.get('role')!='CONTROL':rows.append(row)
        forwarded={r['id']for r in rows if r.get('kind')=='forwarded'}
        for row in rows:
            kind=row.get('kind');ident=row['id']
            if kind=='http-wrapper'and row.get('coveredByForwardedId')in forwarded:continue
            if kind=='http-wrapper':kind='http'
            if kind in groups:groups[kind].add(ident)
            if kind=='forwarded':groups['http'].add(ident)
        return groups

    def observed(self,label,raw,role=None):
        require(isinstance(raw,bytes)and len(raw)<=MAX_BODY,'PERSONA_OUTPUT_CAP')
        if role is None:
            role=('SHARED_PUBLIC'if label.startswith('offered:')else'P2'if label.startswith('P2_')or label=='actual-first-tools-list'else'P3'if label.startswith('curl-')or label=='actual-catalog-schema'else'OPERATOR_MEASUREMENT'if label=='same-question-cli'else self.current_role)
        self.output_roles[label]=role
        self.public_outputs.append((label,raw))
        return raw

    def reference(self,label,oracle=False):
        rows=[(name,raw)for name,raw in self.public_outputs if name==label]
        require(rows,'PRIOR_ACTUAL_OUTPUT_UNAVAILABLE:'+label)
        name,raw=rows[-1];source_role=self.output_roles[name]
        require(oracle or role_can_observe(self.current_role,source_role),'CROSS_PERSONA_REFERENCE_REFUSED')
        ref={'observedId':name,'sha256':digest(raw),'role':source_role,'purpose':'OPERATOR_COMPARISON_ONLY'if oracle or self.current_role=='OPERATOR_ASSERT'else'DISCOVERY'}
        self.active_refs.append(ref);return ref

    def evidence(self, pattern):
        """Search ONLY offered surfaces/product output, never operator source/help."""
        for label,raw in self.public_outputs:
            if not role_can_observe(self.current_role,self.output_roles[label]):continue
            match=re.search(pattern,raw.decode('utf-8',errors='replace'),re.M)
            if match:
                ref={'observedId':label,'sha256':digest(raw),'matchedText':match.group(0),'role':self.output_roles[label],'purpose':'OPERATOR_COMPARISON_ONLY'if self.current_role=='OPERATOR_ASSERT'else'DISCOVERY'}
                self.active_refs.append({k:v for k,v in ref.items()if k!='matchedText'})
                return ref
        raise ValueError('DOCUMENTED_ROUTE_NOT_DISCOVERED')

    def attempt(self, action, fn):
        require(action in FULL_PROTOCOL_IDS and not any(r['id']==action for r in self.protocol),
                'UNIQUE_MANDATORY_PROTOCOL_ACTION')
        start=time.time();row={'id':action,'outcome':'INCOMPLETE','attempted':False,
            'routedThroughCapture':bool(action!='GAIN_NAIVE_THEN_DOCUMENTED'and self.forwarder is not None and self.env.get('XERJ_URL')==self.forwarder.url)}
        old_role=self.current_role
        self.current_role=('OPERATOR_ASSERT'if action in('P2_SEARCH_MAP_PLAN','P2_SAME_HINTS','KNOWLEDGE_SEMANTICS','GAIN_USER_MACHINE_POLLS')else'P2'if action.startswith('P2_')else'P3'if action.startswith('P3_')else'P1')
        before=self.intent_snapshot();observed_before=len(self.public_outputs);self.active_refs=[];self.active_assertions={}
        try:
            if action in('P1_AUTOINDEX','P1_LITERAL_NEXT','P1_ZERO_FLAG_SEARCH','P1_ZERO_FLAG_DEF'):
                require('XERJ_URL'not in self.env,'NAIVE_PUBLIC_DEFAULT_ROUTE_OVERRIDDEN')
            self.guard()
            full_containment(self.config,'CHECKPOINT',self.private,self.guard)
            result=fn()
            if isinstance(result,bytes): result={'bytes':len(result),'sha256':digest(result)}
            row.update(outcome='RECORDED',details=result or {})
        except (ValueError,KeyError,StopIteration,RuntimeError,TimeoutError,OSError)as exc:
            row.update(outcome='LOSS'if isinstance(exc,ProductContractFailure)else'INCOMPLETE',
                       failureClass='REAL_OPERATION_OR_CONTRACT_FAILURE'if isinstance(exc,ProductContractFailure)else'HARNESS_UNVERIFIED',
                       reason=type(exc).__name__+':'+str(exc))
        finally:
            try:full_containment(self.config,'CHECKPOINT',self.private,self.guard)
            except BaseException as containment_error:
                row.update(outcome='INCOMPLETE',failureClass='HARNESS_UNVERIFIED',reason='CONTAINMENT_CHECKPOINT:'+type(containment_error).__name__)
            after=self.intent_snapshot();new={k:sorted(after[k]-before[k])for k in before}
            refs=self.active_refs+[{'observedId':name,'sha256':digest(raw),'role':self.output_roles[name],'purpose':'ACTUAL_OUTPUT'}for name,raw in self.public_outputs[observed_before:]]
            refs=list({(x['observedId'],x['sha256']):x for x in refs}.values())
            executed=any(new.values());row['attempted']=executed
            row['operationIntentIDs']=new;row['observationRefs']=refs
            row['operationStatus']='EXECUTED'if executed else'OBSERVED_PRIOR_OUTPUT'if refs and row['outcome']=='RECORDED'else'BLOCKED_NO_OPERATION'
            row['contentAssertions']={**self.active_assertions,**row.pop('details',{})}
            if row['operationStatus']=='BLOCKED_NO_OPERATION':row['outcome']='INCOMPLETE'
            row.update(startedUTC=start,finishedUTC=time.time())
            row['wallSeconds']=row['finishedUTC']-start
            save(self.private/('protocol-'+action+'.json'),row);self.protocol.append(row)
            self.current_role=old_role
        return row

    def cli(self,label,args,cwd=None,seconds=45,persona=True):
        # Actual child exit, without predicting an exit code or interpreting hints.
        # The outer bounded shell exits0 after writing its own unique marker.
        marker='FTX_EXIT_'+digest((label+str(self.private)).encode())[:20]+'='
        script='"$@"; code=$?; printf "\\n'+marker+'%s\\n" "$code"; exit 0'
        raw=self.command(label,['/bin/sh','-c',script,'ftx-child',*args],cwd=cwd,seconds=seconds)
        m=re.search(('\n'+marker+r'(-?\d+)\n$').encode(),raw)
        require(m is not None,'ACTUAL_CHILD_EXIT_NOT_CAPTURED')
        code=int(m.group(1));require(0<=code<=255,'CHILD_EXIT_RANGE')
        stdout=raw[:m.start()]
        logs=list(self.private.glob('*-'+label+'.stdout.stderr'))
        require(len(logs)==1,'ACTUAL_CHILD_STDERR_SET')
        stderr=logs[0].read_bytes()
        obj={'label':label,'argv':list(map(str,args)),'actualExit':code,
             'stdoutSHA256':digest(stdout),'stderrSHA256':digest(stderr),
             'stdoutBytes':len(stdout),'stderrBytes':len(stderr),'rawExitMarkerPreserved':True,'operatorMeasurementNotPersonaCoaching':not persona,
             'routedThroughCapture':bool(self.forwarder is not None and self.env.get('XERJ_URL')==self.forwarder.url),
             'xerjURLAbsent':'XERJ_URL'not in self.env}
        save(self.private/('child-'+label+'.json'),obj)
        if persona:
            self.observed(label+':stdout',stdout);self.observed(label+':stderr',stderr)
        return code,stdout,stderr

    def documented_cli(self,label,args,pattern,cwd=None,seconds=45):
        proof=self.evidence(pattern)
        code,out,err=self.cli(label,args,cwd,seconds)
        contract(code==0,'PUBLIC_CLI_REAL_EXIT_'+str(code))
        return {'exit':code,'provenance':proof,'outputSHA256':digest(out+err)}

    def installer_proxy_snapshot(self):
        # Operator-only bounded topology evidence, never persona teaching.
        path=Path('/proxy-evidence/proxy/connections.jsonl')
        require(path.is_file()and not path.is_symlink(),'INSTALLER_PROXY_LOG_UNAVAILABLE')
        with path.open('rb')as stream:raw=stream.read(1048577)
        require(len(raw)<=1048576 and(not raw or raw.endswith(b'\n')),'INSTALLER_PROXY_LOG_BOUNDARY_UNVERIFIED')
        return raw

    def classify_installer_exit(self,code,before):
        if code==0:return
        after=self.installer_proxy_snapshot()
        require(after.startswith(before),'INSTALLER_PROXY_LOG_PREFIX_CHANGED')
        events=[json_value(line)for line in after[len(before):].splitlines()]
        require(all(isinstance(row,dict)and isinstance(row.get('kind'),str)for row in events),'INSTALLER_PROXY_EVENT_SHAPE_UNVERIFIED')
        refusals=sum(row['kind']=='refused-or-failed'for row in events)
        save(self.private/'installer-proxy-failure-classification.json',{
            'actualExit':code,'beforeBytes':len(before),'beforeSHA256':digest(before),
            'afterBytes':len(after),'afterSHA256':digest(after),'newEvents':len(events),
            'newRefusedOrFailedEvents':refusals,'rawURLsNeverExported':True})
        if refusals:raise HarnessUnverified('INSTALLER_NEW_PROXY_REFUSAL_OR_FAILURE')
        raise ProductContractFailure('PUBLIC_INSTALLER_FAILED_WITHOUT_NEW_PROXY_REFUSAL_'+str(code))

    def install(self):
        cfg=self.config.get('publicInstaller')
        require(isinstance(cfg,dict),'PINNED_PUBLIC_INSTALLER_INPUTS_REQUIRED')
        require(cfg.get('url')=='https://xerj.org/get'and cfg.get('version')=='v1.0.0-rc.102',
                'EXACT_PUBLIC_INSTALLER_VERSION')
        full_containment(self.config,'INSTALLER',self.private,self.guard)
        self.env['XERJ_VERSION']=cfg['version']
        dest=self.private/'public-installer.sh'
        code,body,_=self.cli('public-installer-download',['curl','--fail','--silent','--show-error',
            '--max-time','20',cfg['url']],seconds=25)
        require(code==0 and digest(body)==cfg['sha256']and len(body)==cfg['bytes'],'PUBLIC_INSTALLER_BYTE_PIN')
        with dest.open('xb')as f:f.write(body)
        proxy_before=self.installer_proxy_snapshot()
        code,out,err=self.cli('public-installer-sh',['/bin/sh',str(dest)],seconds=180)
        self.classify_installer_exit(code,proxy_before)
        require(re.search(rb'(?i)sha.?256|checksum|verified',out+err),'INSTALLER_NO_CHECKSUM_EVIDENCE')
        require(b'PATH'in out+err and b'.local/bin'in out+err,'INSTALLER_PATH_TEACHING_ABSENT')
        binary=self.root/'home/.local/bin/xerj'
        require(binary.is_file()and not binary.is_symlink()and digest(binary.read_bytes())==self.config['binarySHA256'],
                'INSTALLED_BINARY_MISMATCH')
        self.binary=str(binary);self.installed=True
        self.env.pop('XERJ_VERSION',None)
        # No proxy, credentials, XERJ_URL, AUTH or secret is inherited from host.
        return {'actualPublicInstaller':True,'checksumEvidence':True,'binarySHA256':digest(binary.read_bytes())}

    def teach_path(self):
        self.evidence(r'[^\n]*PATH[^\n]*\.local/bin[^\n]*|[^\n]*\.local/bin[^\n]*PATH[^\n]*')
        require(self.installed,'INSTALL_DEPENDENCY')
        self.env['PATH']=str(self.root/'home/.local/bin')+':'+self.config['operator']['path']
        code,out,_=self.cli('taught-path',['/bin/sh','-c','command -v xerj'])
        require(code==0 and out.strip().decode()==self.binary,'PATH_NOT_INSTALLED_BINARY')
        return {'installedPathObserved':True,'noHostPATHModification':True}

    def first_llms(self):
        # Actual public byte offering already bound per state; persona reads it here.
        require(self.installed,'INSTALL_DEPENDENCY')
        surface=self.table['surfaces'][self.state]['llms'];raw=Path(surface['path']).read_bytes()
        require(digest(raw)==surface['sha256'],'OFFERED_LLMS_HASH')
        self.observed('offered:llms',raw)
        # Follow only the directly documented llms-full link; no repo docs knowledge.
        if b'llms-full.txt'in raw:
            full=self.table['surfaces'][self.state]['llms_full'];body=Path(full['path']).read_bytes()
            require(digest(body)==full['sha256'],'OFFERED_FULL_HASH');self.observed('offered:llms_full',body)
        return {'localProspectiveStandInDisclosed':True,'noInternalSourceCoaching':True}

    def start_node(self,auth=False):
        full_containment(self.config,'OFFLINE',self.private,self.guard)
        self.env.pop('XERJ_URL',None)
        mode='auth'if auth else'first'
        self.evidence(r'xerj[^\n]*--data-dir'if auth else r'xerj[^\n]*--insecure[^\n]*--data-dir')
        args=[self.binary,'--data-dir',str(self.root/('data-'+mode))]
        if not auth:args.insert(1,'--insecure')
        # Loopback is operator containment, not a persona-learned recovery flag.
        args+=['--bind','127.0.0.1']
        self.node_log=(self.private/('node-'+mode+'.log')).open('xb')
        self.node_stderr=(self.private/('node-'+mode+'.stderr')).open('xb')
        self.node_started=time.monotonic();self.node_intent_id='C'+digest(str(self.private/mode).encode())[:24]
        save(self.private/('node-'+mode+'.intent.json'),{'kind':'cli','id':self.node_intent_id,
             'receipt':'node-'+mode+'.receipt.json','role':'P1_WITH_OPERATOR_LOOPBACK_CONFINEMENT'})
        self.node=subprocess.Popen(args,env=self.env,cwd=self.root,stdout=self.node_log,stderr=self.node_stderr,start_new_session=True)
        deadline=min(self.end-8,time.time()+30)
        while time.time()<deadline:
            self.guard();require(self.node.poll()is None,'ACTUAL_NODE_START_EXITED')
            raw=(self.private/('node-'+mode+'.log')).read_bytes()
            err=(self.private/('node-'+mode+'.stderr')).read_bytes()
            ready_lines=raw.splitlines(keepends=True)
            posture_ready=any(b'Auth:'in line and line.endswith(b'\n')for line in ready_lines)if auth else any(b'Xerj Console UI'in line and line.endswith(b'\n')for line in ready_lines)
            if b'ES-compat'in raw and b'Native REST'in raw and posture_ready:
                if auth:
                    require(b'Auth:'in raw and b'DISABLED'not in b'\n'.join(x for x in raw.splitlines()if b'Auth:'in x),
                            'AUTH_NODE_POSTURE_NOT_ESTABLISHED')
                    # No plaintext rewriting or guessed HTTPS endpoint in auth arm.
                    self.observed('auth-banner',raw)
                    return {'withoutInsecure':True,'postureObserved':True,'TLSNotBypassed':True}
                v=observed_listeners(raw,err);self.es=v['es'];self.native=v['native'];self.listener_proof={k:value for k,value in v.items()if k not in('native','es')}
                require(re.search(rb'Xerj Console UI\s+http://localhost:[0-9]+/_xerj-console/',raw),'CONSOLE_BANNER_URL_NOT_OBSERVED')
                self.node_startup_wall=time.monotonic()-self.node_started
                self.observed('first-run-banner',raw)
                self.forwarder=Forwarder(self.es,self.private/'forwarder',self.guard,seconds_left=lambda:self.end-time.time()-8)
                # Preserve naive native default routing. Capture is activated only
                # after all four required zero-configuration CLI operations.
                require('XERJ_URL'not in self.env,'NAIVE_NODE_ROUTE_OVERRIDDEN')
                return {'actualListenerObserved':True,'consoleURLNamed':True}
            time.sleep(.05)
        raise ValueError('NODE_BANNER_TIMEOUT')

    def stop_node(self):
        if self.node is None:return
        obj=self.node;row=stop_owned(obj);self.stops.append(row)
        self.node_log.close();self.node_stderr.close()
        mode='auth'if '--insecure'not in getattr(self,'last_node_args',[])else'first'
        # Select actual open-log names, never fabricate an exit from setup intent.
        out=Path(self.node_log.name);err=Path(self.node_stderr.name)
        receipt=out.with_suffix('.receipt.json')
        save(receipt,{'intentId':self.node_intent_id,'actualExit':obj.returncode,'timeout':False,
            'reapedByReviewedBoundedFinally':row['reaped'],'stdoutBytes':out.stat().st_size,'stderrBytes':err.stat().st_size,
            'stdoutSHA256':digest(out.read_bytes()),'stderrSHA256':digest(err.read_bytes())})
        self.node=None

    def naive_no_node(self):
        self.evidence(r'xerj\s+autoindex\s+')
        code,out,err=self.cli('naive-no-node',['xerj','autoindex',str(self.root/'corpus')],seconds=45)
        require(code!=0,'NAIVE_NO_NODE_UNEXPECTED_SUCCESS')
        require(re.search(rb'(?i)xerj[^\n]*(?:--data-dir|--insecure)|start[^\n]*node',out+err),
                'NO_NODE_FAILURE_NO_DOCUMENTED_RECOVERY')
        return {'actualExit':code,'failureRecordedBeforeRecovery':True}

    def autoindex(self):
        self.evidence(r'xerj\s+autoindex\s+')
        argv=['xerj','autoindex',str(self.root/'corpus')]
        start=time.monotonic();code,out,err=self.cli('public-autoindex',argv,seconds=180)
        self.active_assertions['naiveActualExit']=code
        if code==0:
            self.index_wall=time.monotonic()-start;self.autoindex_output=out+err
            return {'naiveActualExit':0,'documentedRecoveryUsed':False}
        # Original failure is retained even when ONE taught recovery succeeds.
        teaching=out+err;recovery=documented_autoindex_recovery(argv,teaching)
        if recovery is None and b'--help'in teaching:
            h,help_out,help_err=self.cli('autoindex-recovery-help',['xerj','autoindex','--help'])
            if h==0:teaching+=b'\n'+help_out+help_err
            recovery=documented_autoindex_recovery(argv,teaching,failure=out+err)
        self.active_assertions.update(documentedRecoveryOffered=recovery is not None,
            recoveryTeachingSHA256=digest(teaching),firstPathWasFailure=True)
        if recovery is not None:
            r,recovered,recovered_err=self.cli('public-autoindex-recovery',recovery,seconds=180)
            self.active_assertions.update(documentedRecoveryUsed=True,recoveryActualExit=r,
                recoveryOutputSHA256=digest(recovered+recovered_err),recoveredIndexObserved=r==0)
            if r==0:self.autoindex_output=recovered+recovered_err
        self.index_wall=time.monotonic()-start
        raise ProductContractFailure('NAIVE_AUTOINDEX_REAL_EXIT_'+str(code))

    def next_command(self):
        require(hasattr(self,'autoindex_output'),'AUTOINDEX_DEPENDENCY')
        argv=literal_next(self.autoindex_output.decode(errors='replace'))
        code,out,err=self.cli('literal-next',argv)
        contract(code==0,'LITERAL_NEXT_REAL_FAILURE')
        return {'pastedLiterallyNoFlagsAdded':True,'argvSHA256':digest(json.dumps(argv).encode())}

    def zero_query(self):
        self.evidence(r'xerj\s+search\s+')
        require(self.forwarder is not None,'ZERO_HIT_CAPTURE_DEPENDENCY')
        start=len(self.forwarder.records)
        code,out,err=self.cli('zero-hit',['xerj','search','FTX_ABSENT_9b76813c4bbf'])
        contract(code==0,'ZERO_HIT_COMMAND_FAILED')
        selected=[r for r in self.forwarder.records[start:]if r['path'].split('?',1)[0].endswith('/_search')and
            b'FTX_ABSENT_9b76813c4bbf'in(self.private/'forwarder'/r['requestBody']).read_bytes()]
        require(selected and all(json_value(decoded_json_body((self.private/'forwarder'/r['responseBody']).read_bytes(),r['responseHeaders'])).get('hits',{}).get('hits')==[]for r in selected),'ACTUAL_ZERO_HITS_NOT_ESTABLISHED')
        require(re.search(rb'(?i)semantic|hybrid|autoindex|next:|try ',out+err),'ZERO_HIT_RECOVERY_NOT_OFFERED')
        return {'actualZeroHitDiagnosticObserved':True,'syntheticAbsentQuestionDisclosed':True}

    def init_full(self,existing=False):
        self.evidence(r'xerj\s+init\b')
        project=self.root/('existing-project'if existing else'project')
        if existing:
            project.mkdir()
            fixtures={'.mcp.json':b'{"mcpServers":{"owned_fixture":{"command":"false","args":[]}}}\n',
                'AGENTS.md':b'# Owned fixture\n', '.claude/skills/xerj/SKILL.md':b'owned prior fixture\n',
                '.claude/skills/xerj-hub/SKILL.md':b'owned hub fixture\n',
                '.cursor/rules/xerj.mdc':b'owned prior fixture\n','.cursor/rules/xerj-hub.mdc':b'owned hub fixture\n'}
            for rel,raw in fixtures.items():
                p=project/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        else:
            (project/'.claude').mkdir(exist_ok=True);(project/'.cursor').mkdir(exist_ok=True)
        code,out,err=self.cli('init-existing'if existing else'init-first',['xerj','init'],cwd=project)
        contract(code==0,'INIT_REAL_FAILURE')
        paths=['.mcp.json','.claude/skills/xerj/SKILL.md','.claude/skills/xerj-hub/SKILL.md',
               '.cursor/rules/xerj.mdc','.cursor/rules/xerj-hub.mdc','AGENTS.md']
        rows=[]
        for rel in paths:
            p=project/rel;require(p.is_file()and not p.is_symlink(),'INIT_REQUIRED_FILE_MISSING')
            raw=p.read_bytes();require(len(raw)<=MAX_BODY,'INIT_FILE_CAP')
            require(not re.search(rb'(?i)(?:api[_-]?key|authorization)\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}',raw),'INIT_SECRET_WRITTEN')
            if existing:
                backups=list(p.parent.glob(p.name+'*.bak*'))
                require(any(b.read_bytes()==fixtures[rel]for b in backups),'INIT_ORIGINAL_BACKUP_MISSING')
            rows.append({'name':rel,'sha256':digest(raw),'bytes':len(raw)})
        require(all(t in out+err for t in (b'claude',b'mcpServers',b'servers')),'INIT_REGISTRATION_TEACHING_MISSING')
        generated=json_value((project/'.mcp.json').read_bytes())['mcpServers']['xerj']
        require(Path(generated['command']).resolve()==Path(self.binary)and generated['args']==['mcp'],'INIT_GENERATED_ENTRY')
        require(set(generated.get('env',{}))<= {'XERJ_URL'},'INIT_SECRET_OR_UNDECLARED_ENV')
        if not existing:self.registration=generated
        return {'files':rows,'existingOwnedFixtures':existing,'backupsVerified':existing}

    def registered_first(self):
        require(hasattr(self,'registration'),'ACTUAL_INIT_DEPENDENCY')
        self.observed('provided-generated-registration',json.dumps(self.registration,sort_keys=True).encode(),role='P2')
        env=dict(self.env);env.update(self.registration.get('env',{}))
        self.rpc=RPC([self.registration['command'],*self.registration['args']],env,self.root/'project',self.private/'rpc',self.guard)
        init=self.rpc.send('initialize',{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'scripted-first-session','version':'1'}})
        self.rpc.send('notifications/initialized',notify=True);tools=self.rpc.send('tools/list')
        require(tools['tools']and len({x['name']for x in tools['tools']})==len(tools['tools']),'ACTUAL_TOOLS_SCHEMA')
        self.first_session={'initialize':init,'toolsOutput':tools,'tools':{x['name']:x for x in tools['tools']}}
        self.observed('actual-first-tools-list',json.dumps(tools,sort_keys=True).encode())
        return {'actualFirstSession':True,'toolCount':len(tools['tools']),'noFixedLegacyCount':True}

    def hub_call(self):
        require(self.rpc is not None,'FIRST_SESSION_DEPENDENCY')
        tools=self.first_session['tools']
        if 'xerj_hub_ask'not in tools:
            self.hub_not_advertised=True
            self.reference('actual-first-tools-list',oracle=True)
            return {'notApplicableNotAdvertised':True,'actualInventorySHA256':digest(json.dumps(self.first_session['toolsOutput'],sort_keys=True).encode())}
        self.evidence(r'xerj_hub_ask')
        full_containment(self.config,'HUB',self.private,self.guard)
        require(self.env['XERJ_DISABLE_FEEDBACK']=='true','PROVEN_OPT_OUT_REQUIRED')
        question=self.config.get('hubPublicQuestion')
        require(isinstance(question,dict)and isinstance(question.get('text'),str)and question.get('text'),'BOUND_PUBLIC_HUB_QUESTION_REQUIRED')
        require(question.get('derivation')=='OFFERED_COVERED_CORPUS_TOPIC'and question.get('rationale'),'HUB_QUESTION_DERIVATION_NOT_SEALED')
        span=question['provenance'][self.state];surface=self.table['surfaces'][self.state][span['surface_id']]
        offered=Path(surface['path']).read_bytes();require(digest(offered)==surface['sha256']==span['sha256'],'PUBLIC_HUB_TEACHING_BYTES')
        text='\n'.join(offered.decode().splitlines()[span['start_line']-1:span['end_line']])
        require(text==span['exact_text']and all(term in text for term in question['coveredTerms']),'PUBLIC_HUB_QUESTION_TEACHING_SPAN')
        require(digest(question['text'].encode())==question['questionSHA256'],'PUBLIC_HUB_QUESTION_HASH')
        self.reference('offered:'+span['surface_id'])
        self.hub_question=question['text']
        self.active_assertions['questionSHA256']=digest(self.hub_question.encode())
        schema=tools['xerj_hub_ask']['inputSchema'];properties=schema.get('properties',{})
        require('question'in properties and set(schema.get('required',[]))<={'question'},'ACTUAL_HUB_SCHEMA_UNSUPPORTED_HOLD')
        result=self.rpc.send('tools/call',checked_tool(tools,'xerj_hub_ask',{'question':self.hub_question}))
        self.hub_result=result
        contract(not result.get('isError'),'HUB_REAL_CALL_FAILURE')
        texts=[x['text']for x in result.get('content',[])if x.get('type')=='text'];text='\n'.join(texts)
        shape=hub_answer_evidence(text)
        return {'oneActualToolCall':True,'answerShapeObserved':True,'noPackSeedOrSyncRequired':True,**shape}

    def hub_counterpart(self):
        if getattr(self,'hub_not_advertised',False):
            self.reference('actual-first-tools-list',oracle=True)
            return {'notApplicableNotAdvertised':True,'actualInventorySHA256':digest(json.dumps(self.first_session['toolsOutput'],sort_keys=True).encode())}
        require(hasattr(self,'hub_question'),'HUB_PUBLIC_QUESTION_DEPENDENCY')
        self.active_assertions['questionSHA256']=digest(self.hub_question.encode())
        self.evidence(r'xerj\s+["\'<]')
        full_containment(self.config,'HUB',self.private,self.guard)
        code,out,err=self.cli('hub-cli-counterpart',['xerj',self.hub_question])
        contract(code==0,'HUB_CLI_REAL_NONZERO_EXIT_'+str(code))
        shape=hub_answer_evidence(out.decode('utf-8',errors='strict'))
        return {'samePublicQuestion':True,'actualExit':code,**shape}

    def curl(self,label,method,path,body=None):
        # Endpoint templates are coverage targets, NOT persona knowledge.
        parts=path.strip('/').split('/')
        if len(parts)==2 and parts[-1]in('_search','_ask')and parts[0]!='autoindex-catalog':
            self.reference('actual-catalog-schema')
            try:self.evidence(re.escape(path))
            except ValueError:
                # A root /_ask example does NOT teach /{index}/_ask.
                # Only the actual index path or an explicit indexed template does.
                template=r'/(?:\{(?:index|actual_catalog_index)\}|<(?:index|index-name)>)/'+re.escape(parts[-1])
                self.evidence(template)
        else:self.evidence(re.escape(path))
        full_containment(self.config,'OFFLINE',self.private,self.guard)
        require(self.forwarder is not None,'RUNNING_CAPTURE_NODE_DEPENDENCY')
        url=self.forwarder.url+path
        args=['curl','--silent','--show-error','--max-time','20','--dump-header',str(self.private/(label+'.headers')),
              '--request',method,url]
        if body is not None:args+=['--header','Content-Type: application/json','--data-binary',json.dumps(body,separators=(',',':'))]
        start=len(self.forwarder.records)
        code,out,err=self.cli(label,args,seconds=25)
        contract(code==0,'CURL_TRANSPORT_REAL_FAILURE')
        pairs=self.forwarder.records[start:];require(len(pairs)==1,'CURL_ACTUAL_REQUEST_RESPONSE_PAIR')
        row=pairs[0];contract(200<=row['status']<300,'CURL_REAL_HTTP_STATUS_'+str(row['status']))
        if label=='curl-knowledge':return structured_knowledge(out)
        if label!='curl-console':return json_value(out)
        return out

    def p3(self,action):
        if action=='P3_CURL_CONSOLE':return self.curl('curl-console','GET','/_xerj-console/')
        if action=='P3_CURL_KNOWLEDGE':
            self.knowledge=self.curl('curl-knowledge','GET','/_xerj-console/api/v1/knowledge');return {'actualCurlKnowledge':True,'knowledgeResponseSHA256':digest(json.dumps(self.knowledge,sort_keys=True).encode())}
        if action=='P3_CURL_CATALOG':
            self.catalog=self.curl('curl-catalog','POST','/autoindex-catalog/_search',{'query':{'match_all':{}}});return {'actualCurlCatalog':True,'catalogResponseSHA256':digest(json.dumps(self.catalog,sort_keys=True).encode())}
        require(hasattr(self,'catalog'),'ACTUAL_CATALOG_DEPENDENCY')
        observed=payload_object(self.catalog);index=product_index(observed)
        self.observed('actual-catalog-schema',json.dumps(observed).encode())
        if action=='P3_CURL_ROOT_ASK':
            answer=self.curl('curl-root-ask','POST','/_ask',{'index':index,'prompt':grounded_prompt(observed)})
            return {'actualCurlRootAsk':True,'responseSHA256':digest(json.dumps(answer,sort_keys=True).encode())}
        if action=='P3_CURL_INDEX_ASK':
            answer=self.curl('curl-index-ask','POST','/'+urllib.parse.quote(index,safe='')+'/_ask',{'prompt':self.binding['questions'][0]['text']})
            return {'actualCurlIndexAsk':True,'responseSHA256':digest(json.dumps(answer,sort_keys=True).encode())}
        candidates=[]
        def walk(x):
            if isinstance(x,dict):
                if isinstance(x.get('query'),dict)and '_source'in x:candidates.append(x)
                for v in x.values():walk(v)
            elif isinstance(x,list):
                for v in x:walk(v)
        walk(observed);require(candidates,'NO_PRODUCT_OFFERED_PROJECTION')
        actual=self.curl('curl-projection','POST','/'+urllib.parse.quote(index,safe='')+'/_search',candidates[0])
        require(isinstance(actual.get('_savings'),dict),'ACTUAL_PROJECTION_SAVINGS_MISSING')
        return {'savingsObserved':True,'responseSHA256':digest(json.dumps(actual,sort_keys=True).encode())}

    def boundary(self):
        require(hasattr(self,'first_session'),'FIRST_SESSION_DEPENDENCY')
        refs=[self.evidence(r'[^\n]*'+x+r'[^\n]*(?:CLI|shell|command)|[^\n]*(?:CLI|shell|command)[^\n]*'+x)
              for x in ('autoindex','gain','init')]
        require(not any(n in self.first_session['tools']for n in ('xerj_autoindex','xerj_gain','xerj_init')),
                'MCP_CLI_BOUNDARY_DISAGREES')
        return {'offeredDocumentation':refs,'noShellGrantedToP2':True}

    def semantics(self):
        self.reference('curl-knowledge:stdout')
        require('status'in getattr(self,'measurement_refs',{}),'STATUS_STRUCTURED_MEASUREMENT_UNVERIFIED')
        self.active_refs.append(self.measurement_refs['status'])
        require(hasattr(self,'knowledge')and hasattr(self,'status_output'),'KNOWLEDGE_STATUS_DEPENDENCY')
        knowledge=self.knowledge;status=self.status_value
        # Explicit fields only: UNKNOWN is a loss, never guessed semantic aliases.
        require(isinstance(knowledge.get('datasets'),list)and isinstance(status.get('datasets'),list),'KNOWLEDGE_STATUS_SHAPE_UNKNOWN')
        counts_knowledge=dataset_counts(knowledge);counts_status=dataset_counts(status)
        contract(counts_knowledge==counts_status,'KNOWLEDGE_COUNTS_MISMATCH')
        relations=knowledge.get('relations')
        require(isinstance(relations,list),'KNOWLEDGE_RELATIONS_SCHEMA_UNKNOWN')
        require(all(isinstance(x,dict)for x in relations),'RELATION_OBJECT_SCHEMA_UNKNOWN')
        contract(all(x.get('inferred')is True or x.get('kind')=='inferred'for x in relations),
                'RELATION_NOT_LABELLED_INFERRED')
        capabilities=lexical_capability_assertions(knowledge)
        return {'recordsFilesCompared':True,'relationsLabelled':True,'lexicalClaimsChecked':True,**capabilities}

    def gain(self):
        saved_url=self.env.pop('XERJ_URL',None)
        self.active_assertions.update(naiveXerjURLAbsent=True,structuredXerjURLAbsent=True,operatorHelpXerjURLAbsent=True)
        try:
            self.evidence(r'xerj\s+gain\b')
            code,out,err=self.cli('gain-naive',['xerj','gain'])
            self.gain_naive={'actualExit':code,'outputSHA256':digest(out+err)}
            naive_error=code!=0
            # Always retain naive dashboard output. Documented structured evidence
            # is an operator measurement, not proof that the persona knew --json.
            h,help_out,help_err=self.cli('gain-measurement-help',['xerj','gain','--help'],persona=False)
            if h!=0 or b'--json'not in help_out+help_err:
                raise HarnessUnverified('GAIN_STRUCTURED_MODE_NOT_ADVERTISED_IN_ACTUAL_HELP')
            # Same default route as naive call. No source-derived native URL repair.
            c,raw,_=self.cli('gain-structured-measurement',['xerj','gain','--json'],persona=False)
            contract(c==0,'GAIN_STRUCTURED_MEASUREMENT_REAL_EXIT')
            self.gain_value=structured_gain(raw)
            self.measurement_refs=getattr(self,'measurement_refs',{})
            self.measurement_refs['gain']={'observedId':'operator:gain-structured-measurement','sha256':digest(raw),'role':'OPERATOR_MEASUREMENT','purpose':'OPERATOR_COMPARISON_ONLY'}
            self.active_assertions.update(naiveActualExit=code,structuredActualExit=c,
                publicHelpSHA256=digest(help_out+help_err),structuredResponseSHA256=digest(raw),
                noPersonaRepairCoaching=True)
            if naive_error:raise ProductContractFailure('NAIVE_GAIN_REAL_NONZERO_EXIT_'+str(code))
            return {'naiveActualExit':code,'structuredMeasurement':True,'noForcedHistoricalFailure':True,
                    'publicHelpSHA256':digest(help_out+help_err),'structuredResponseSHA256':digest(raw)}

        finally:
            if saved_url is not None:self.env['XERJ_URL']=saved_url

    def gain_accounting(self):
        require(self.audit_before is not None and self.forwarder is not None,'GAIN_AUDIT_DEPENDENCY')
        after=json_value(http_exchange(self.native,'GET','/_audit/_search',None,self.guard,self.private,'full-audit-after',deadline=self.end-8)[1])
        all_records=self.forwarder.records[self.audit_start_sequence:]
        searches=[r for r in all_records if r['path'].split('?',1)[0].endswith('/_search')and not r['path'].startswith('/_audit/')]
        align=align_audit(self.audit_before,after,searches)
        classified=classify_audit(after)
        self.full_audit=align
        require(align['state']=='EXACT','GAIN_AUDIT_UNCLASSIFIED_OR_EVICTED')
        gain=getattr(self,'gain_value',None);require(isinstance(gain,dict),'ACTUAL_GAIN_VALUES_UNKNOWN')
        require(isinstance(gain.get('searches'),int),'GAIN_MACHINE_SCHEMA_UNKNOWN')
        require('gain'in getattr(self,'measurement_refs',{}),'GAIN_STRUCTURED_MEASUREMENT_UNVERIFIED')
        self.active_refs.append(self.measurement_refs['gain'])
        contract(gain['searches']==len(classified['user']),'GAIN_COUNT_INCLUDES_POLLS_OR_MISMATCH')
        return {'alignment':align,'actualMachinePolls':len(classified['machine']),
                'actualUserSearches':len(classified['user']),'allNativeSearchEntries':len(classified['user'])+len(classified['machine']),
                'naiveOutcome':self.gain_naive,'noForcedHistoricalFailure':True}

    def token_questions(self):
        self.tokens=[]
        require(self.forwarder is not None,'TOKEN_CAPTURE_DEPENDENCY')
        for question in self.binding['questions']:
            self.guard();start=len(self.forwarder.records)
            try:
                self.evidence(r'xerj\s+search\s+')
                code,out,err=self.cli('token-'+question['id'],['xerj','search',question['text']])
                require(code==0,'ACTUAL_TOKEN_CLI_FAILURE')
                files={str(self.root/'corpus'/x['corpusDestination']):x for x in self.binding['corpus']}
                value=A3TokenMeasure(self.forwarder.records[start:],self.private/'forwarder',files)
                # Replace the known incorrect per-response union with a single
                # question-level displayed top file. Full response set stays intact.
                rows=[{'path':n,'bytes':v['bytes']}for n,v in files.items()]
                top=question_top_one(out,rows)
                value['armATopOneQuestionFileBytes']=top
                value['armATopOnePerResponseUniqueBytes']=top
                value['top1Definition']='SINGLE_FIRST_ACTUAL_CLI_DISPLAYED_FILE_PER_QUESTION'
                value['approxTokensAtFourBytes']['ATop1']=top/4
                value['top1Ratio']=top/value['armBDecodedWireMinusHintsBytes']if value['armBDecodedWireMinusHintsBytes']else None
                self.tokens.append({'id':question['id'],'measurement':value})
            except (ValueError,RuntimeError,TimeoutError,OSError)as exc:
                self.tokens.append({'id':question['id'],'loss':type(exc).__name__+':'+str(exc)})
        require(len(self.tokens)==5,'EXACT_QUESTION_COUNT')
        return {'questions':5,'allHitAndQuestionTop1':True,'losses':sum('loss'in r for r in self.tokens)}

    def guard(self):
        self.outer_guard()
        for fh in (getattr(self,'node_log',None),getattr(self,'node_stderr',None)):
            if fh is not None:require(Path(fh.name).stat().st_size<=MAX_BODY,'PRIVATE_NODE_LOG_CAP')
        require(time.time()<self.end-8,'FTX_STATE_DEADLINE')

    def prepare(self):
        self.root.mkdir(parents=True,exist_ok=False);self.private.mkdir(parents=True,exist_ok=False)
        for name in ('home','project','corpus','hub','tmp'):(self.root/name).mkdir()
        for item in self.binding['corpus']:
            rel=Path(item['corpusDestination']);require(not rel.is_absolute()and'..'not in rel.parts,'CORPUS_DESTINATION')
            raw=Path(item['source']).read_bytes();require(len(raw)==item['bytes']and digest(raw)==item['sha256'],'SAME_CORPUS_HASH')
            target=self.root/'corpus'/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        for sid,item in self.table['surfaces'][self.state].items():
            raw=Path(item['path']).read_bytes();require(digest(raw)==item['sha256'],'OFFERED_BYTES')
            (self.private/('offered-'+sid+'.body')).write_bytes(raw)
        self.resources_before={'cpuLimit':1.75,'memoryLimitBytes':7936*1024**2,'globalCpuLimit':2,'globalMemoryLimitBytes':8*1024**3,'proxyCpuLimit':.25,'proxyMemoryLimitBytes':256*1024**2,'swapBytes':0,'pidsLimit':4096,
            'affinityCount':len(os.sched_getaffinity(0)),'memoryMax':Path('/sys/fs/cgroup/memory.max').read_text().strip(),
            'memorySwapMax':Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),
            'pidsMax':Path('/sys/fs/cgroup/pids.max').read_text().strip()}
        require(self.resources_before['affinityCount']<=2 and self.resources_before['memoryMax']==str(7936*1024**2)
            and self.resources_before['memorySwapMax']=='0'and self.resources_before['pidsMax']=='4096','PROPOSED_PARTITION_TARGET_RESOURCE_LIMITS')
        cpu=Path('/sys/fs/cgroup/cpu.max').read_text().split()
        require(len(cpu)==2 and cpu[0]!='max'and int(cpu[0])==1.75*int(cpu[1]),'ACTUAL_TARGET_1_75CPU_QUOTA')
        self.resources_before['actualCpuMax']=' '.join(cpu)
        self.resources_before['actualCpuMaxSHA256']=digest(self.resources_before['actualCpuMax'].encode())

    def public_search(self):
        return self.documented_cli('public-search',['xerj','search',self.binding['questions'][0]['text']],r'xerj\s+search\s+')

    def public_def(self,auth=False):
        self.evidence(r'xerj\s+def\s+')
        # A symbol comes ONLY from an earlier actual search/map response, not corpus source.
        allowed=[(label,raw)for label,raw in self.public_outputs if label in('public-search:stdout','public-map:stdout')]
        selected=None
        for label,raw in allowed:
            try:symbol=returned_symbol([raw])
            except HarnessUnverified:continue
            selected=(label,symbol);break
        if selected is None:raise HarnessUnverified('NO_ACTUAL_PRIOR_P1_SEARCH_MAP_SYMBOL_VISIBLE')
        self.reference(selected[0]);self.known_symbol=selected[1]
        code,out,err=self.cli('auth-def'if auth else'public-def',['xerj','def',self.known_symbol])
        if auth and code!=0:
            require(re.search(rb'(?m)\b1[.)]\s',out+err)and b'admin.key'in out+err,
                    'AUTH_FAILURE_NUMBERED_RECOVERY_ABSENT')
        elif not auth:contract(code==0,'ZERO_FLAG_DEF_FAILURE')
        return {'actualExit':code,'symbolFromPriorProductOutput':True}

    def public_status(self):
        self.evidence(r'xerj\s+autoindex\s+status')
        c,out,err=self.cli('public-status',['xerj','autoindex','status'])
        contract(c==0,'STATUS_REAL_FAILURE');self.status_naive=out
        # Separate documented machine measurement; do not parse a text dashboard
        # as JSON, or teach a repair flag to a naive persona from internal source.
        h,help_out,help_err=self.cli('status-measurement-help',['xerj','autoindex','status','--help'],persona=False)
        if h!=0 or b'--json'not in help_out+help_err:
            raise HarnessUnverified('STATUS_STRUCTURED_MODE_NOT_ADVERTISED_IN_ACTUAL_HELP')
        c,raw,_=self.cli('status-structured-measurement',['xerj','autoindex','status','--json'],persona=False)
        contract(c==0,'STATUS_STRUCTURED_MEASUREMENT_REAL_EXIT')
        self.status_value=structured_status(raw)
        self.status_output=raw
        self.measurement_refs=getattr(self,'measurement_refs',{})
        self.measurement_refs['status']={'observedId':'operator:status-structured-measurement','sha256':digest(raw),'role':'OPERATOR_MEASUREMENT','purpose':'OPERATOR_COMPARISON_ONLY'}
        return {'actualNaiveExit':0,'structuredMeasurement':True,'publicHelpSHA256':digest(help_out+help_err),
                'structuredResponseSHA256':digest(raw),'noPersonaRepairCoaching':True}

    def public_map(self):
        self.evidence(r'xerj\s+autoindex\s+map')
        return map_from_actual_cli(self,'public-map',persona=True)

    def auth_search(self):
        self.evidence(r'xerj\s+search\s+')
        c,out,err=self.cli('auth-search',['xerj','search',self.binding['questions'][0]['text']])
        if c!=0:require(re.search(rb'(?m)\b1[.)]\s',out+err)and b'admin.key'in out+err,
                'AUTH_FAILURE_NUMBERED_RECOVERY_ABSENT')
        return {'actualExit':c,'numberedFixesObserved':c!=0,'nativeAutomaticAuthSuccess':c==0,'noTLSBypassOrKeyInjection':True}

    def action(self,item,context):
        # The original fixed15 remain comparison rows, not full-protocol coverage.
        if item['id']=='P2_HUB_OBSERVATION':
            row=self.attempt('P2_HUB_IF_ADVERTISED',self.hub_call)
            result={'id':item['id'],'status':'RECORDED'if row['outcome']=='RECORDED'else'LOSS',
                    'reason':row.get('reason'),'firstAttempt':True,'fullProtocolRecord':row['id']}
            save(self.private/('action-'+item['id']+'.json'),result);return result
        mapping={'P3_CONSOLE':'P3_CURL_CONSOLE','P3_KNOWLEDGE':'P3_CURL_KNOWLEDGE',
                 'P3_CATALOG':'P3_CURL_CATALOG','P3_PROJECTED_SEARCH':'P3_CURL_PROJECTION',
                 'P3_PROJECTION_SAVINGS':None,'P3_ASK':'P3_CURL_ROOT_ASK','P3_INDEX_SCOPED_ASK':'P3_CURL_INDEX_ASK'}
        if item['id']in mapping:
            action=mapping[item['id']]
            if action:
                row=self.attempt(action,lambda:self.p3(action))
            else:
                previous=next((r for r in self.protocol if r['id']=='P3_CURL_PROJECTION'),None)
                require(previous is not None,'PROJECTION_PROOF_NOT_RUN')
                row=previous
            result={'id':item['id'],'status':'RECORDED'if row['outcome']=='RECORDED'else'LOSS',
                    'firstAttempt':True,'fullProtocolRecord':row['id'],'reason':row.get('reason')}
            save(self.private/('action-'+item['id']+'.json'),result);return result
        if item['id']=='P2_REGISTERED_SESSION'and not hasattr(self,'first_session'):
            result={'id':item['id'],'status':'LOSS','reason':'FIRST_SESSION_DEPENDENCY_UNAVAILABLE','firstAttempt':True}
            save(self.private/('action-'+item['id']+'.json'),result);return result
        return super().action(item,context)

    def mcp_assertions(self,rows):
        for label in('P2_MAP','P2_SEARCH','P2_PLAN','P2_SEARCH_PLANNED_QUERY'):self.reference(label)
        require(all(rows.get(n,{}).get('status')=='RECORDED'for n in
            ('P2_MAP','P2_SEARCH','P2_PLAN','P2_SEARCH_PLANNED_QUERY')),'FIRST_SESSION_REQUIRED_TOOL_LOSS')
        return {'sameFirstSession':True,'mapSearchPlanActualResultsChecked':True}

    def hints_assertions(self):
        self.reference('P2_SEARCH');self.reference('same-question-cli')
        require(getattr(self,'same_hints_verified',False),'CLI_MCP_HINTS_NOT_COMPARED')
        return {'sameQuestionTop3Verified':True,'sameHonestHintsVerified':True,**self.same_hints_proof}

    def execute(self):
        self.tokens=[];self.audit_before=None;self.full_audit={'state':'UNKNOWN'};self.audit_start_sequence=0
        self.prepare();context={};result=None
        try:
            self.attempt('P1_INSTALL',self.install)
            self.attempt('P1_PATH',self.teach_path)
            self.attempt('P1_LLMS_FIRST_RUN',self.first_llms)
            self.attempt('P1_NAIVE_NO_NODE_AUTOINDEX',self.naive_no_node)
            self.attempt('P1_FIRST_RUN_NODE',self.start_node)
            self.attempt('P1_AUTOINDEX',self.autoindex)
            self.attempt('P1_LITERAL_NEXT',self.next_command)
            self.attempt('P1_ZERO_FLAG_SEARCH',self.public_search)
            self.attempt('P1_ZERO_FLAG_DEF',self.public_def)
            if self.node is not None and self.forwarder is not None:
                self.audit_before=json_value(http_exchange(self.native,'GET','/_audit/_search',None,self.guard,self.private,'full-audit-before',deadline=self.end-8)[1])
                self.audit_start_sequence=len(self.forwarder.records)
                self.env['XERJ_URL']=self.forwarder.url
            self.attempt('P1_ZERO_HIT_RECOVERY',self.zero_query)
            self.attempt('P1_MAP',self.public_map)
            self.attempt('P1_STATUS',self.public_status)
            self.attempt('P1_INIT',self.init_full)
            self.attempt('P1_INIT_EXISTING',lambda:self.init_full(existing=True))
            self.attempt('P2_FIRST_SESSION',self.registered_first)
            # Each action still drives the same first registered session.
            for item in self.table['actions']:
                self.guard();self.results.append(self.action(item,context))
            rows={r['id']:r for r in self.results}
            self.attempt('P2_SEARCH_MAP_PLAN',lambda:self.mcp_assertions(rows))
            self.attempt('P2_SAME_HINTS',self.hints_assertions)
            self.attempt('P2_CLI_BOUNDARY',self.boundary)
            self.attempt('P3_CLI_BOUNDARY',self.boundary)
            self.attempt('P1_HUB_COUNTERPART',self.hub_counterpart)
            self.attempt('KNOWLEDGE_SEMANTICS',self.semantics)
            self.attempt('TOKEN_QUESTIONS',self.token_questions)
            self.attempt('GAIN_NAIVE_THEN_DOCUMENTED',self.gain)
            self.attempt('GAIN_USER_MACHINE_POLLS',self.gain_accounting)
            if self.state=='baseline':self.real_controls=self.real_controls_on_node()
            # Auth arm is separate fresh data, no --insecure. All earlier operations
            # finish first; no secret copied into a persona to manufacture success.
            if self.rpc is not None:self.stops.append(self.rpc.close());self.rpc=None
            if self.forwarder is not None:self.forwarder.close();self.forwarder=None
            self.stop_node()
            self.attempt('P1_AUTH_NODE',lambda:self.start_node(auth=True))
            self.attempt('P1_AUTH_ZERO_FLAG_SEARCH',self.auth_search)
            self.attempt('P1_AUTH_ZERO_FLAG_DEF',lambda:self.public_def(auth=True))
            self.stop_node();self.env.pop('XERJ_URL',None)
            self.attempt('P1_NO_NODE_RECOVERY',self.naive_recovery_after_stop)
            result={'state':self.state,'status':'LOSS'if any(r['outcome']!='RECORDED'for r in self.protocol)else'RECORDED',
                'actions':self.results,'tokenQuestions':self.tokens,'audit':self.full_audit,
                'realControls':getattr(self,'real_controls',{}),'resources':self.resources_before,
                'listenerCompatibility':getattr(self,'listener_proof',{}),
                'toolInventory':{'count':len(getattr(self,'first_session',{}).get('tools',{})),
                    'schemaSHA256':digest(json.dumps(getattr(self,'first_session',{}).get('toolsOutput'),sort_keys=True).encode())},
                'fullProtocol':{'requiredIDs':list(FULL_PROTOCOL_IDS),'records':self.protocol,
                     'allRequiredAccounted':{r['id']for r in self.protocol}==set(FULL_PROTOCOL_IDS),
                     'fullMandatoryScopeExercised':all(r['operationStatus']!='BLOCKED_NO_OPERATION'and r['outcome']!='INCOMPLETE'for r in self.protocol),
                     'notGeneralNoviceComprehension':True,'allActualRawOutputsPrivate':True}}
            return result
        finally:
            errors=[]
            for closer in (self.rpc.close if self.rpc else None,self.forwarder.close if self.forwarder else None,self.stop_node):
                if closer:
                    try:
                        row=closer()
                        if isinstance(row,dict):self.stops.append(row)
                    except BaseException as exc:errors.append(type(exc).__name__)
            self.zero_live_xerj_after_cleanup=False;self.zero_xerj_proof=None
            try:
                if self.installed:
                    code,out,err=self.cli('hub-owned-state-stop',['xerj','hub','stop'],seconds=15,persona=False)
                    require(code==0,'OWNED_HUB_STOP_UNVERIFIED_EXIT')
                proof=full_containment(self.config,'CHECKPOINT',self.private,self.guard)
                scan=proof.get('childEnvironmentCheckpoint',{})
                require(scan.get('scanPerformed')is True and scan.get('matchedCount')==0 and not scan.get('processes'),
                        'LIVE_XERJ_REMAINS_AFTER_STATE_CLEANUP')
                self.zero_live_xerj_after_cleanup=True;self.zero_xerj_proof=proof
            except BaseException as exc:errors.append('OWNED_HUB_CLEANUP:'+type(exc).__name__)
            self.cleanup_complete=not errors and self.zero_live_xerj_after_cleanup and all(x.get('reaped',False)for x in self.stops)
            save(self.private/'owned-stop.json',{'children':self.stops,'allReaped':self.cleanup_complete,
                'zeroLiveXerjAfterCleanup':self.zero_live_xerj_after_cleanup,
                'zeroLiveXerjProofSHA256':digest(json.dumps(public_containment_proof(self.zero_xerj_proof),sort_keys=True).encode())if self.zero_xerj_proof else None,
                'errors':errors})

    def naive_recovery_after_stop(self):
        self.evidence(r'xerj\s+search\s+')
        c,out,err=self.cli('no-node-search',['xerj','search',self.binding['questions'][0]['text']])
        require(c!=0,'NO_NODE_SEARCH_UNEXPECTED_SUCCESS')
        require(re.search(rb'(?i)start[^\n]*node|xerj[^\n]*(?:--data-dir|--insecure)',out+err),
                'NO_NODE_SEARCH_RECOVERY_MISSING')
        return {'actualExit':c,'noForcedHistoricalFailure':True}


def public_state(state,session,result,table,config,binding,started,finished):
    row=A3PublicState(state,session,result,table,config,binding,started,finished)
    full=result.get('fullProtocol',{})
    records=full.get('records',[])
    caps=config.get('_approvedCaps')
    require(caps is not None,'CAP_PROFILE_NOT_ACTUALLY_ADOPTED')
    intents=row['rawEvidenceCountsAndHashes']['requestIntentIDs']
    direct=direct_http_intents(session.private)if session else[]
    budget_within({'cliPerState':len(intents['cli']),'rpcPerSession':len(intents['rpc']),
        'httpPerState':len(intents['http']),'forwardedPerState':len(intents['forwarded']),
        'directHTTPPerState':len(direct)},caps)
    row['rawEvidenceCountsAndHashes']['directHTTPIntentIDs']=direct
    row['evidenceCaps']=caps
    row['ownedStopProof']['zeroLiveXerjAfterCleanup']=bool(session and getattr(session,'zero_live_xerj_after_cleanup',False))
    row['ownedStopProof']['zeroLiveXerjProofSHA256']=digest(json.dumps(public_containment_proof(session.zero_xerj_proof),sort_keys=True).encode())if session and getattr(session,'zero_xerj_proof',None)else None
    row['fullProtocol']={'schemaVersion':1,'requiredIDs':list(FULL_PROTOCOL_IDS),
        'records':[{'id':r['id'],'outcome':r['outcome'],'attempted':r['attempted'],
                    'operationStatus':r['operationStatus'],'operationIntentIDs':r['operationIntentIDs'],
                    'routedThroughCapture':r['routedThroughCapture'],
                    'observationRefs':r['observationRefs'],
                    'contentAssertions':sanitize_assertions(r.get('contentAssertions',{})),
                    'failureClass':r.get('failureClass'),'wallSeconds':r['wallSeconds'],'rawRecordSHA256':digest((session.private/('protocol-'+r['id']+'.json')).read_bytes())}
                   for r in records],
        'allRequiredAccounted':full.get('allRequiredAccounted',False),
        'fullMandatoryScopeExercised':full.get('fullMandatoryScopeExercised',False),
        'sourceCount':120,'sourceBytes':9444700}
    row['complete']=row['complete']and full.get('allRequiredAccounted',False)and full.get('fullMandatoryScopeExercised',False)
    if session:
        phases=[json_value(p.read_bytes())for p in sorted(session.private.glob('containment-*.json'))]
        row['networkProof']['phases']=[public_containment_proof(x)for x in phases]

    row['outcome']='INCOMPLETE'if not row['complete']else'FULL_PROTOCOL_REPLAY_WITH_RECORDED_LOSSES'
    return row


def sanitize_assertions(value):
    if isinstance(value,bool)or value is None:return value
    if isinstance(value,(int,float)):return value
    if isinstance(value,list):return [sanitize_assertions(x)for x in value]
    if isinstance(value,dict):
        return {k:sanitize_assertions(v)for k,v in value.items()if k not in
            ('provenance','offeredDocumentation','name','matchedText','argv','naiveOutcome')}
    if isinstance(value,str)and re.fullmatch('[0-9a-f]{64}',value):return value
    return None


def fixture_full_controls(root,guard):
    """Future existing bootstrap caller uses this, retaining all original24 controls."""
    guard();old=fixture_controls(root,guard);new=protocol_controls()
    new['controls'].update(cap_controls());new['controls'].update(semantic_normalizer_controls())
    return {'helperSHA256':digest(Path(__file__).read_bytes()),'expectedCount':24,
            'controls':old,'fullProtocolPrimitiveControls':new['controls'],
            'additionalControlsSyntheticOnly':True}



def returned_symbol(outputs):
    """Only identifiers actually printed in prior product output, never corpus reads."""
    for raw in outputs:
        for pattern in (rb'"(?:symbol|name)"\s*:\s*"([A-Za-z_][A-Za-z_0-9]{2,})"',
                        rb'\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:fn|struct|enum|trait)\s+([A-Za-z_][A-Za-z_0-9]{2,})\b',
                        rb'\b(?:def|class)\s+([A-Za-z_][A-Za-z_0-9]{2,})\b'):
            found=re.search(pattern,raw)
            if found:return found.group(1).decode()
    raise HarnessUnverified('ACTUAL_RETURNED_SYMBOL_FORMAT_OR_EVIDENCE_UNAVAILABLE')


def structured_status(raw):
    try:value=json_value(raw)
    except (ValueError,UnicodeError)as exc:raise HarnessUnverified('STATUS_DOCUMENTED_JSON_NOT_PARSEABLE')from exc
    dataset_counts(value)
    return value


def structured_gain(raw):
    try:value=json_value(raw)
    except (ValueError,UnicodeError)as exc:raise HarnessUnverified('GAIN_DOCUMENTED_JSON_NOT_PARSEABLE')from exc
    require(isinstance(value,dict)and type(value.get('searches'))is int,'GAIN_MACHINE_SCHEMA_UNKNOWN')
    return value


def structured_knowledge(raw):
    try:value=json_value(raw)
    except (ValueError,UnicodeError)as exc:raise HarnessUnverified('KNOWLEDGE_JSON_UNVERIFIED')from exc
    dataset_counts(value)
    lexical_capability_assertions(value)
    require(isinstance(value.get('relations'),list),'RELATIONS_SCHEMA_UNVERIFIED')
    return value


def real_operator_decoder_probe(session,forwarder):
    """Real tiny dependency gate, operator-only. No source/persona state reused."""
    root=session.root/'operator-synthetic-corpus';root.mkdir()
    raw=b'pub fn ftx_operator_probe_12f() -> u32 { 7 }\n'
    (root/'probe.rs').write_bytes(raw)
    session.env['XERJ_URL']=forwarder.url
    for name in ('tmp','hub'):(session.root/name).mkdir(exist_ok=True)
    receipt={'operatorOnly':True,'syntheticOwnedRustCorpus':True,'sourceSHA256':digest(raw),
             'sameProductionDecoders':True,'commands':[],'complete':False}
    try:
        def capture(label,c,out,err):
            receipt['commands'].append({'label':label,'actualExit':c,'stdoutSHA256':digest(out),'stderrSHA256':digest(err),'stdoutShape':sanitized_output_shape(out),'stderrShape':sanitized_output_shape(err)})
        def invoke(label,argv):
            c,out,err=session.cli('operator-probe-'+label,argv,seconds=45,persona=False)
            capture(label,c,out,err)
            require(c==0,'EARLY_OPERATOR_REAL_DEPENDENCY_EXIT:'+label)
            return out,err
        invoke('autoindex',[session.binary,'autoindex',str(root)])
        search,_=invoke('search',[session.binary,'search','ftx_operator_probe_12f'])
        symbol=returned_symbol([search]);require(symbol=='ftx_operator_probe_12f','EARLY_ACTUAL_SYMBOL_DECODER_MISMATCH')
        invoke('def',[session.binary,'def',symbol])
        receipt['mapContentAssertions']=map_from_actual_cli(session,'operator-probe-map',persona=False,diagnostic=capture)
        for name,base in [('status',[session.binary,'autoindex','status']),('gain',[session.binary,'gain'])]:
            invoke(name+'-naive',base)
            help_out,help_err=invoke(name+'-help',base+['--help'])
            require(b'--json'in help_out+help_err,'EARLY_STRUCTURED_HELP_UNVERIFIED:'+name)
            data,_=invoke(name+'-structured',base+['--json'])
            value=structured_status(data)if name=='status'else structured_gain(data)
            receipt[name+'SchemaSHA256']=digest(json.dumps(value,sort_keys=True).encode())
        row,body=http_exchange(forwarder.url,'GET','/_xerj-console/api/v1/knowledge',None,
            session.guard,session.private,'operator-knowledge',forwarder=forwarder,deadline=session.end-8)
        receipt['knowledgeHTTPStatus']=row['status'];receipt['knowledgeStructure']=sanitized_output_shape(body)
        require(200<=row['status']<300,'EARLY_KNOWLEDGE_ROUTE_OR_SCHEMA_UNVERIFIED')
        value=structured_knowledge(body);receipt['knowledgeSchemaSHA256']=digest(json.dumps(value,sort_keys=True).encode())
        receipt['symbolDecoderActualEvidenceSHA256']=digest(search)
        receipt['complete']=True
        return {k:v for k,v in receipt.items()if k not in('commands',)}
    finally:
        # Full bounded real outputs and actual exit metadata already exist;
        # snapshot partial progress BEFORE propagating any assertion failure.
        save(session.private/'real-decoder-dependency-probe.json',receipt)
        public=Path(session.config['earlyDecoderDiagnosticPath'])
        require(public==Path('/out/early-real-decoder-probe.json'),'EXACT_SANITIZED_EARLY_DIAGNOSTIC_PATH')
        if len(json.dumps(receipt).encode())>256*1024:
            for item in receipt.get('commands',[]):
                for stream in('stdoutShape','stderrShape'):
                    shape=item.get(stream,{}).get('structure',{})
                    item.get(stream,{})['structure']={k:v for k,v in shape.items()if k in('type','length','keyNames','truncated')}
            receipt['structuralDetailTruncatedToPreserveAllCommandRows']=True
        require(len(json.dumps(receipt).encode())<=256*1024,'EARLY_SANITIZED_STRUCTURE_CAP')
        save(public,receipt)



def dataset_counts(value):
    rows=value.get('datasets')if isinstance(value,dict)else None
    require(isinstance(rows,list)and rows,'DATASET_LIST_SCHEMA_UNVERIFIED')
    result={}
    for row in rows:
        require(isinstance(row,dict)and isinstance(row.get('index'),str)and row['index'],
                'DATASET_ID_SCHEMA_UNVERIFIED')
        require(row['index']not in result,'DUPLICATE_DATASET_ID_UNVERIFIED')
        require(all(type(row.get(k))is int and row[k]>=0 for k in('records','files')),
                'RECORDS_FILES_SCHEMA_UNVERIFIED')
        result[row['index']]={'records':row['records'],'files':row['files']}
    contract(sum(r['records']for r in result.values())>0 and sum(r['files']for r in result.values())>0,
             'SUCCESSFUL_AUTOINDEX_HAS_NO_OBSERVED_CORPUS')
    return result


def lexical_capability_assertions(value):
    # Explicit supported runtime representation, not absent-field inference.
    # Compatibility with the shipped response is UNVERIFIED until the tiny
    # real operator probe. Unknown representation never becomes a product loss.
    cap=value.get('capabilities')if isinstance(value,dict)else None
    require(isinstance(cap,dict)and cap.get('mode')=='lexical'and
            type(cap.get('vectors'))is bool and type(cap.get('semantic'))is bool,
            'CURRENT_RETRIEVAL_CAPABILITY_REPRESENTATION_UNVERIFIED')
    contract(cap['vectors']is False and cap['semantic']is False,'EXPLICIT_LEXICAL_CAPABILITY_CONTRADICTION')
    return {'explicitRuntimeModeLexical':True,'explicitVectorClaimFalse':True,
            'explicitSemanticClaimFalse':True,'representationSHA256':digest(json.dumps(cap,sort_keys=True).encode())}


def map_content_assertions(raw, structured=None):
    """Recognize actual printed JSON or JSON blocks; never use hidden wire data."""
    text=raw.decode('utf-8');objects=[]
    try:objects=[json_value(raw)]
    except ValueError:
        decoder=json.JSONDecoder(object_pairs_hook=unique_object)
        offset=0
        while offset<len(text)and len(objects)<64:
            match=re.search(r'[\[{]',text[offset:])
            if match is None:break
            at=offset+match.start()
            try:value,end=decoder.raw_decode(text,at)
            except ValueError:offset=at+1;continue
            objects.append(value);offset=end
    require(objects,'MAP_PRINTED_STRUCTURE_UNVERIFIED')
    fields=[];queries=[];dataset_rows=[]
    def visit(x):
        if isinstance(x,dict):
            if isinstance(x.get('datasets'),list):dataset_rows.extend(x['datasets'])
            if isinstance(x.get('name',x.get('field')),str)and'type'in x:fields.append(x)
            if isinstance(x.get('query'),dict):queries.append(x)
            for v in x.values():visit(v)
        elif isinstance(x,list):
            for v in x:visit(v)
    visible_objects=list(objects)
    if structured is not None:objects=[structured]
    for obj in objects:visit(obj)
    require(dataset_rows and all(isinstance(d,dict)and isinstance(d.get('index'),str)and d['index']for d in dataset_rows),'MAP_DATASET_TABLE_SCHEMA_UNVERIFIED')
    require(len({d['index']for d in dataset_rows})==len(dataset_rows),'MAP_DUPLICATE_DATASET_UNVERIFIED')
    index=product_index(dataset_rows)
    require(fields and all(isinstance(f.get('type'),str)and f['type']and
            isinstance(f.get('examples'),list)and f['examples']for f in fields),
            'MAP_PER_FIELD_TYPES_EXAMPLES_UNVERIFIED')
    require(queries,'MAP_READY_QUERY_UNVERIFIED')
    prompt=grounded_prompt(objects)
    if structured is not None:
        require(index in text,'DATASET_ID_NOT_VISIBLE_IN_NAIVE_MAP')
        require(all(str(f.get('name',f.get('field')))in text and f['type']in text and
            all(str(example)in text for example in f['examples'])for f in fields),'FIELD_TYPE_EXAMPLE_NOT_VISIBLE_IN_NAIVE_MAP')
        visible_queries=[]
        def query_walk(x):
            if isinstance(x,dict):
                if isinstance(x.get('query'),dict):visible_queries.append(x['query'])
                for v in x.values():query_walk(v)
            elif isinstance(x,list):
                for v in x:query_walk(v)
        for obj in visible_objects:query_walk(obj)
        require(any(q['query']in visible_queries for q in queries),'READY_QUERY_NOT_VISIBLE_IN_NAIVE_MAP')
    return {'datasetIdentityObserved':True,'observedDatasetCount':len(dataset_rows),'datasetIdentitySHA256':digest(index.encode()),
        'perFieldTypesAndExamplesObserved':True,'observedFieldCount':len(fields),
        'readyQueryTemplatesObserved':True,'observedQueryCount':len(queries),
        'groundedFieldValueSHA256':digest(prompt.encode()),'actualMapOutputSHA256':digest(raw)}



def map_from_actual_cli(session,label,persona,diagnostic=None):
    def invoke(name,argv,visible):
        c,out,err=session.cli(name,argv,persona=visible)
        if diagnostic is not None:diagnostic(name,c,out,err)
        return c,out,err
    c,out,err=invoke(label,[session.binary,'autoindex','map'],persona)
    contract(c==0,'MAP_REAL_FAILURE')
    try:return map_content_assertions(out)
    except ValueError as original:
        h,help_out,help_err=invoke(label+'-help-measurement',[session.binary,'autoindex','map','--help'],False)
        require(h==0 and b'--json'in help_out+help_err,'MAP_STRUCTURED_MODE_UNVERIFIED')
        c,machine,_=invoke(label+'-json-measurement',[session.binary,'autoindex','map','--json'],False)
        contract(c==0,'MAP_STRUCTURED_MEASUREMENT_REAL_FAILURE')
        try:value=json_value(machine)
        except ValueError as exc:raise HarnessUnverified('MAP_DOCUMENTED_JSON_UNVERIFIED')from exc
        proof=map_content_assertions(out,value)
        proof.update(actualMachineMeasurementSHA256=digest(machine),actualHelpSHA256=digest(help_out+help_err),noPersonaRepairCoaching=True)
        return proof

def semantic_normalizer_controls():
    """Future same-path schema negatives; not executed during private authoring."""
    out={};good={'datasets':[{'index':'owned','records':1,'files':1}],
        'capabilities':{'mode':'lexical','vectors':False,'semantic':False},'relations':[]}
    dataset_counts(good);lexical_capability_assertions(good);out['semantic_explicit_positive']=True
    for label,value in [('missing-records',{'datasets':[{'index':'owned','files':1}]}),
                        ('missing-files',{'datasets':[{'index':'owned','records':1}]}),
                        ('bool-count',{'datasets':[{'index':'owned','records':True,'files':1}]}),
                        ('duplicate-index',{'datasets':good['datasets']*2}),
                        ('empty-datasets',{'datasets':[]})]:
        try:dataset_counts(value)
        except ValueError:out['semantic_'+label+'_refused']=True
        else:raise ValueError('SEMANTIC_MISSING_FIELD_CONTROL_ACCEPTED')
    try:lexical_capability_assertions({'capabilities':{}})
    except ValueError:out['semantic_unknown_capability_refused']=True
    else:raise ValueError('OPAQUE_CAPABILITY_ACCEPTED')
    sample={'datasets':[{'index':'owned','fields':[{'name':'kind','type':'keyword','examples':['function']}],
        'ready_query':{'query':{'term':{'kind':'function'}}}}]}
    map_content_assertions(json.dumps(sample).encode());out['map_content_positive']=True
    for label,value in [('no-types',{'datasets':[{'index':'owned','fields':[{'name':'kind','examples':['function']}]}]}),
                        ('empty-map',{}),('no-ready-query',{'datasets':[{'index':'owned','fields':[{'name':'kind','type':'keyword','examples':['function']}]}]})]:
        try:map_content_assertions(json.dumps(value).encode())
        except ValueError:out['map_'+label+'_refused']=True
        else:raise ValueError('MAP_CONTENT_NEGATIVE_ACCEPTED')
    secret='SYNTHETIC_PRIVATE_VALUE_DO_NOT_EXPORT'
    structure=sanitized_output_shape(json.dumps({'admin_api_key':secret,'ordinary':secret,'nested':[secret]}).encode())
    require(secret not in json.dumps(structure)and 'admin_api_key'not in json.dumps(structure),'SANITIZED_STRUCTURE_VALUE_LEAK')
    out['sanitized_structure_no_string_values']=True
    original=['xerj','autoindex','/owned/corpus']
    require(documented_autoindex_recovery(original,b'graph journal guard: rerun with --no-graph')==original+['--no-graph'],'TAUGHT_RECOVERY_CONTROL')
    require(documented_autoindex_recovery(original,b'generic failure')is None,'UNTOLD_RECOVERY_CONTROL')
    out['documented_recovery_positive']=True;out['undocumented_recovery_absent']=True
    require(role_can_observe('P3','SHARED_PUBLIC')and role_can_observe('P2','P2'),'ROLE_PUBLIC_POSITIVE')
    require(not role_can_observe('P3','P2')and not role_can_observe('P1','OPERATOR_MEASUREMENT'),'ROLE_CROSS_PERSONA_REFUSED')
    out['role_shared_positive']=True;out['role_cross_persona_refused']=True
    return out




def public_containment_proof(value):
    proof=dict(value)
    if proof.get('mode')=='FIXED_INTERNAL_PROXY_WITH_SOURCE_OPTOUT':
        proof['c2Mode']=proof['mode'];proof['approvalSHA256']=proof['c2ApprovalReceiptSHA256']
    allowed={'hubCatalogueOnlyIfObserved', 'helperExecutionNamespaceMatches', 'phase', 'nativeControlsSHA256', 'offlineHandoffReceiptSHA256', 'implementationSHA256', 'mode', 'currentProxyLogSHA256', 'kernelProofSHA256', 'hostProofSHA256', 'corpusFeedbackEndpointBlocked', 'sinkLiveEntireFTX', 'currentProxyLogBytes', 'connectionLoggingActive', 'hostAllowlistPhaseSpecific', 'projectTestsExecutionProvedByThisGuard', 'unexpectedSinkRequests', 'actualNativeFeedbackControlsPassed', 'childEnvironmentCheckpoint', 'externalNetworkPhysicallyDisconnected', 'allFourReviewedHostsPermittedFromStart', 'limits', 'evidenceSHA256', 'feedbackEndpointURLSHA256', 'publicPacketSHA256', 'publicSnapshotSHA256', 'targetContainerID', 'actualTargetRoutingSHA256', 'c2ApprovalReceiptSHA256', 'allOtherEgressDenied', 'projectTestsSeparateOffline', 'currentRouteSHA256', 'networkNamespaceInode', 'approvalSHA256', 'feedbackEndpointLoopbackOnly', 'actualKernelEnforced', 'installerAndReleaseAllowlistOnly', 'sourceProvenOptOutApplied', 'encryptedPathBlocked', 'fixedTopologyAcrossEntireFTX', 'allowedHosts', 'sourceParityReceiptSHA256', 'c2Mode'}
    allowed.add('resourcePartition')
    return {k:v for k,v in proof.items()if k in allowed}


def sanitized_structure(value,depth=0):
    if depth>=4:return {'type':type(value).__name__,'truncated':True}
    if isinstance(value,dict):
        keys=[];children={}
        for key,item in list(value.items())[:32]:
            safe=key if isinstance(key,str)and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',key)and not re.search(r'(?i)token|password|authorization|api.?key|credential|secret|admin\.key',key)else'<redacted-key-name>'
            keys.append(safe)
            if safe not in children:children[safe]=sanitized_structure(item,depth+1)
        return {'type':'object','length':len(value),'keyNames':keys,'children':children,'truncated':len(value)>32}
    if isinstance(value,list):return {'type':'list','length':len(value),'sampleTypes':[sanitized_structure(x,depth+1)for x in value[:2]]}
    if isinstance(value,str):return {'type':'string','length':len(value)}
    return {'type':type(value).__name__}


def sanitized_output_shape(raw):
    result={'bytes':len(raw),'sha256':digest(raw),
        'syntheticSymbolMarkerPresent':b'ftx_operator_probe_12f'in raw,
        'jsonFlagAdvertised':b'--json'in raw,'datasetWordPresent':b'dataset'in raw.lower()}
    try:
        result['structure']=sanitized_structure(json_value(raw))
        if len(json.dumps(result['structure']).encode())>4096:
            shape=result['structure'];result['structure']={k:v for k,v in shape.items()if k in('type','length','keyNames')}
            result['structure']['truncated']=True
    except (ValueError,UnicodeError):result['structure']={'type':'NON_JSON_TEXT','length':len(raw)}
    return result




def documented_autoindex_recovery(original,teaching,failure=None):
    """ONE literal taught flag, never a source-derived smarter default."""
    require(len(original)==3 and original[:2]==['xerj','autoindex'],'RECOVERY_ORIGINAL_ARGV')
    text=teaching.decode('utf-8',errors='replace')
    if '--no-graph'not in text:return None
    diagnostic=(failure if failure is not None else teaching).decode('utf-8',errors='replace')
    if not re.search(r'(?i)retry|re-run|rerun|again|journal|graph.{0,40}guard',diagnostic):return None
    import shlex
    # Reuse the same metacharacter-refusing literal argv parser as next:.
    argv=literal_next('next: '+shlex.join(original+['--no-graph']))
    require(argv==original+['--no-graph'],'DOCUMENTED_RECOVERY_ARGV_CHANGED')
    return argv




def role_can_observe(persona,source):
    if persona=='OPERATOR_ASSERT':return True
    return source=='SHARED_PUBLIC'or source==persona




def hub_answer_evidence(text):
    # Public llms68-75 teaches real no-cache/no-match outcomes as failures.
    # Its header contains the corpus SLUG, not the literal word "corpus".
    lines=[line.strip()for line in text.splitlines()if line.strip()]
    contract('answered from:'in text.lower(),'HUB_REAL_NO_ANSWER_OR_CACHE_MISS')
    require(len(lines)>=3,'HUB_ANSWER_RENDERING_UNVERIFIED')
    header=re.fullmatch(r'(\S+)\s+pin\s+(\d{4}-\d{2}-\d{2})\s+\([^)]*\)\s+(.+?)\s+(\S+):(\d+)',lines[0])
    require(header is not None,'HUB_ANSWER_HEADER_FORMAT_UNVERIFIED')
    require(lines[-1].lower().startswith('answered from:'),'HUB_ANSWER_TRAILER_FORMAT_UNVERIFIED')
    return {'headerCorpusPinLicenseFileObserved':True,'passageObserved':True,
            'answerTrailerObserved':True,'licenseSHA256':digest(header.group(3).encode())}


if __name__=='__main__':
    cfg=json_value(Path(sys.argv[1]).read_bytes())
    def original_guard():
        require(time.time()<cfg['targetEpoch']-cfg['cleanupReserve'],'ORIGINAL_TARGET_CLEANUP')
    run(cfg,Path(cfg['publicOutput']),Path(cfg['privateOutput']),original_guard)
