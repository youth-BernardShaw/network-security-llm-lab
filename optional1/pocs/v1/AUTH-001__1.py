#!/usr/bin/env python3
"""AUTH-001 D: read-only check that a non-admin session can list all users."""

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


def fetch(url, cookie, timeout):
    req = urllib.request.Request(url, method="GET")
    req.add_header("Cookie", cookie)
    req.add_header("Accept", "application/json")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise SystemExit("connection_error: {}".format(exc.reason))


def summarize(body):
    try:
        data = json.loads(body)
    except ValueError:
        return "non_json", body[:300]
    if isinstance(data, list):
        ids = [row.get("user_id") for row in data if isinstance(row, dict)]
        return "array", {"count": len(data), "first_ids": ids[:5]}
    return "object", data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True,
                        help="authbypass dir, e.g. http://127.0.0.1:8080/vulnerabilities/authbypass/")
    parser.add_argument("--cookie-file", required=True,
                        help="file holding only the low-privilege session cookie, e.g. PHPSESSID=<value>")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    with open(args.cookie_file, "r", encoding="utf-8") as fh:
        session = fh.read().strip()
    if not session:
        raise SystemExit("cookie file is empty")
    url = build_url(args.base, "get_user_data.php")
    for level in ("low", "impossible"):
        status, body = fetch(url, session + "; security=" + level, args.timeout)
        kind, detail = summarize(body)
        print("security={} status={} json_kind={} detail={}".format(level, status, kind, detail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
