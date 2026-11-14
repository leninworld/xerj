"""Public anonymous auth plus digest HEAD; no credential or layer retention."""
import http.server
import json
import re
import threading
import sys

if sys.flags.optimize:
    raise RuntimeError("OPTIMIZATION_NOT_ALLOWED")

MEDIA_TYPES = {"application/vnd.oci.image.manifest.v1+json",
               "application/vnd.docker.distribution.manifest.v2+json",
               "application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('REGISTRY_REDIRECT_REFUSED')


def check(digest, observer, media_type, fixture_urls=None):
    assert media_type in MEDIA_TYPES
    assert re.fullmatch('sha256:[a-f0-9]{64}',digest)
    urls = fixture_urls or (
        'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull',
        'https://registry-1.docker.io/v2/library/python/manifests/'+digest)
    for url in urls:
        parsed = urllib.parse.urlsplit(url)
        assert not parsed.username and not parsed.password
        if fixture_urls:
            assert parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
        else:
            assert parsed.scheme == 'https' and parsed.hostname in ('auth.docker.io','registry-1.docker.io')
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(urls[0],timeout=20) as response:
        raw = response.read(131073)
        assert response.status == 200 and len(raw) <= 131072
    auth = json.loads(raw)
    assert isinstance(auth.get('token'),str) and auth['token']
    # Neither token bytes, token hash nor raw response is an evidence field.
    observer({'operation':'public-auth','bytes':len(raw),'raw_token_retained':False})
    request = urllib.request.Request(urls[1],method='HEAD',headers={
        'Authorization':'Bearer '+auth['token'],
        'Accept':media_type})
    with opener.open(request,timeout=20) as response:
        assert response.status == 200
        assert response.headers.get('Docker-Content-Digest') == digest
        assert response.headers.get('Content-Type','').split(';')[0].strip() == media_type
        remaining = response.headers.get('ratelimit-remaining')
        limit = response.headers.get('ratelimit-limit')
    for value in (remaining,limit):
        assert value is None or re.fullmatch(r'\d+(?:;w=\d+)?',value)
    observer({'operation':'manifest-HEAD','digest':digest,
              'remaining':remaining,'limit':limit,'media_type':media_type,'response_body_retained':False})
    return remaining


def fixture():
    digest = 'sha256:'+'a'*64
    seen = []
    media_type = 'application/vnd.oci.image.manifest.v1+json'
    class Handler(http.server.BaseHTTPRequestHandler):
        wrong_digest = False
        malformed = False
        redirect = False
        wrong_media = False
        def log_message(self,*args):
            pass
        def do_GET(self):
            if self.redirect:
                self.send_response(302)
                self.send_header('Location','https://not-a-permitted-registry.invalid/token')
                self.end_headers()
                return
            body = b'not-json' if self.malformed else b'{"token":"public-fixture-token"}'
            self.send_response(200);self.end_headers();self.wfile.write(body)
        def do_HEAD(self):
            assert self.headers.get('Authorization') == 'Bearer public-fixture-token'
            assert self.headers.get('Accept') == media_type
            seen.append('authorized-HEAD')
            self.send_response(200)
            self.send_header('Docker-Content-Digest','sha256:'+'b'*64 if self.wrong_digest else digest)
            self.send_header('Content-Type','application/json' if self.wrong_media else media_type)
            self.send_header('ratelimit-remaining','90;w=21600')
            self.send_header('ratelimit-limit','100;w=21600');self.end_headers()
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base = 'http://127.0.0.1:'+str(server.server_port)
    rows = []
    try:
        assert check(digest,rows.append,media_type,(base+'/token',base+'/manifest')) == '90;w=21600'
        Handler.wrong_digest = True
        try:
            check(digest,rows.append,media_type,(base+'/token',base+'/manifest'))
        except AssertionError:
            pass
        else:
            raise AssertionError('BAD_DIGEST_ACCEPTED')
        Handler.wrong_digest=False;Handler.malformed=True
        try:
            check(digest,rows.append,media_type,(base+'/token',base+'/manifest'))
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError('MALFORMED_AUTH_ACCEPTED')
        assert seen == ['authorized-HEAD','authorized-HEAD']
        Handler.malformed=False;Handler.redirect=True
        try:
            check(digest,rows.append,media_type,(base+'/token',base+'/manifest'))
        except ValueError as exc:
            assert str(exc) == 'REGISTRY_REDIRECT_REFUSED'
        else:
            raise AssertionError('REDIRECT_FOLLOWED')
        assert 'public-fixture-token' not in json.dumps(rows)
        Handler.redirect=False;Handler.wrong_media=True
        try:
            check(digest,rows.append,media_type,(base+'/token',base+'/manifest'))
        except AssertionError:
            pass
        else:
            raise AssertionError('BAD_MEDIA_TYPE_ACCEPTED')
        return {'real_HTTP_cases':5,'authorization_header_checked':True,
                'bad_digest_and_malformed_auth_refused':True,'observer_token_leak':False}
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)
        assert not thread.is_alive()


if __name__ == '__main__':
    import sys
    events=[]
    remaining=check(sys.argv[1],events.append,sys.argv[2])
    print(json.dumps({'remaining':remaining,'events':events,'raw_token_retained':False}))
