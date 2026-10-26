#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-002 反射型 XSS 教学验证草案（HTTP 回读 + 浏览器人工触发）。

- 参数名 name、GET 方法、输出位置 <pre>Hello {$name}</pre> 均来自审计片段。
- 实际请求路径片段未给出，必须用 --path 显式提供。
- 仅允许 localhost / 127.0.0.1 / ::1，且禁止自动跟随重定向。
- 脚本只负责提交与回读业务区域；浏览器是否执行脚本需人工在同会话浏览器观察。
"""

import argparse
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

MARKER = "LLM_LAB_XSS"
PAYLOAD = "<img src=x onerror=\"console.log('LLM_LAB_XSS')\">"
REGION_RE = re.compile(r"<pre>\s*Hello\s*(.*?)</pre>", re.IGNORECASE | re.DOTALL)
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_target(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("仅允许 http/https: %r" % url)
    if (parsed.hostname or "").lower() not in ALLOWED_HOSTS:
        raise ValueError("仅允许本机目标: %r" % (parsed.hostname,))


def build_url(base, path):
    return base.rstrip("/") + path + "?" + urlencode({"name": PAYLOAD})


def fetch(url, cookie, timeout):
    headers = {"User-Agent": "llm-lab-xss002/1.0", "Accept": "text/html"}
    if cookie:
        headers["Cookie"] = cookie
    req = Request(url, headers=headers, method="GET")
    opener = build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.status, body.decode(charset, errors="replace")
    except HTTPError as exc:
        body = exc.read()
        return exc.code, body.decode("utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser(description="XSS-002 反射型 XSS 教学验证草案")
    ap.add_argument("--base", required=True, help="靶场基址，如 http://127.0.0.1:8080")
    ap.add_argument("--path", required=True, help="片段所在请求路径（片段未给出，需人工确认）")
    ap.add_argument("--cookie-env", default="", help="保存 Cookie 头的环境变量名，可为空")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--save-response", default="", help="可选：把响应体保存为文件")
    args = ap.parse_args()

    try:
        url = build_url(args.base, args.path)
        validate_target(url)
    except ValueError as exc:
        print("PARAM_ERROR: %s" % exc, file=sys.stderr)
        return 2

    cookie = os.environ.get(args.cookie_env, "") if args.cookie_env else ""
    try:
        status, body = fetch(url, cookie, args.timeout)
    except URLError as exc:
        print("NETWORK_ERROR: %s" % exc.reason, file=sys.stderr)
        return 3
    except OSError as exc:
        print("NETWORK_ERROR: %s" % exc, file=sys.stderr)
        return 3

    if status in (301, 302, 303, 307, 308):
        print("AUTH_OR_REDIRECT: HTTP %d，未跟随重定向；请检查登录状态或路径"
              "（属于前置条件失败，不能证明过滤生效）" % status, file=sys.stderr)
        return 4

    match = REGION_RE.search(body)
    region = match.group(1) if match else None
    raw_hit = bool(region is not None and PAYLOAD in region)
    encoded_hit = bool(region is not None and (
        "&lt;img" in region or "&#60;" in region or "&quot;" in region))
    result = {
        "url": url,
        "http_status": status,
        "region_found": match is not None,
        "region_text": region,
        "raw_payload_present": raw_hit,
        "encoded_payload_present": encoded_hit,
        "marker_in_region": bool(region is not None and MARKER in region),
        "note": "HTTP 回读只证明响应业务区域是否原样包含载荷；浏览器是否执行需人工在同会话浏览器打开同一 URL 观察控制台。",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if args.save_response:
        with open(args.save_response, "w", encoding="utf-8") as fh:
            fh.write(body)
        print("响应体已保存: %s" % args.save_response, file=sys.stderr)

    if match is None:
        print("REGION_NOT_FOUND: 未找到 <pre>Hello ...</pre> 业务区域；不要据此判定安全。",
              file=sys.stderr)
        return 5
    if not raw_hit:
        print("NO_RAW_REFLECTION: 业务区域内未原样出现载荷（可能被编码或路径不同）。",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
