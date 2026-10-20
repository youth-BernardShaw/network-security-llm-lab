#!/usr/bin/env python3
"""AUTH-001 A/C: same session, only the security cookie changes."""

import argparse
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
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise SystemExit("connection_error: {}".format(exc.reason))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--cookie-file", required=True,
                        help="file holding only the low-privilege session cookie")
    parser.add_argument("--page", default="index.php")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    with open(args.cookie_file, "r", encoding="utf-8") as fh:
        session = fh.read().strip()
    if not session:
        raise SystemExit("cookie file is empty")
    url = build_url(args.base, args.page)
    results = {}
    for level in ("impossible", "low"):
        status, body = fetch(url, session + "; security=" + level, args.timeout)
        denied = "Unauthorised" in body
        results[level] = (status, denied, len(body))
        print("security={} status={} unauthorised_text={} body_len={}".format(
            level, status, denied, len(body)))
    imp_status, imp_denied, _ = results["impossible"]
    low_status, low_denied, _ = results["low"]
    print("control_blocked:", imp_status == 403 or imp_denied)
    print("test_page_rendered:", low_status == 200 and not low_denied)
    return 0


if __name__ == "__main__":
    sys.exit(main())
