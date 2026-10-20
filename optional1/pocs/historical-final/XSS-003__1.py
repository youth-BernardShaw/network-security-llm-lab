#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-003 反射型 XSS 无害验证草案（仅限本地授权靶场）。

约束：只提交无害标记 console.log('LLM_LAB_XSS')；不读取 Cookie 内容用于输出、
不外传数据、不植入持久控制。本脚本负责 HTTP 提交与响应回读；
浏览器是否真正执行脚本仍需人工在 DevTools 中观察。
"""

import argparse
import http.client
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PAYLOAD = "<img src=x onerror=console.log('LLM_LAB_XSS')>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随 3xx，避免被带到未授权主机。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        print("[!] 收到重定向 %s -> %s；按约束不跟随，请人工确认登录/路由。" % (code, newurl))
        return None


def check_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("仅允许 http/https，收到: %r" % parts.scheme)
    host = parts.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError("目标主机 %r 不在本地授权范围 %s" % (host, sorted(ALLOWED_HOSTS)))
    return parts


def build_url(base, path, param, value):
    url = base.rstrip("/") + "/" + path.lstrip("/")
    sep = "&" if "?" in url else "?"
    return url + sep + urllib.parse.urlencode({param: value})


def main():
    ap = argparse.ArgumentParser(description="XSS-003 反射型 XSS 无害验证草案")
    ap.add_argument("--base", required=True, help="靶场基址，例如 http://127.0.0.1:8080（仅本机）")
    ap.add_argument("--path", required=True, help="承载该片段的请求路径（部署相关，需人工确认，不提供默认值）")
    ap.add_argument("--param", default="name", help="请求参数名，片段中为 name")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="无害测试载荷")
    ap.add_argument("--cookie-file", default=None, help="本地 Cookie 头文件路径；内容不打印、不写入版本库")
    ap.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    ap.add_argument("--insecure", action="store_true", help="仅本地自签名 HTTPS 时跳过证书校验")
    args = ap.parse_args()

    try:
        url = build_url(args.base, args.path, args.param, args.payload)
        check_local(url)
    except ValueError as exc:
        print("[x] 参数/范围校验失败: %s" % exc)
        return 2

    headers = {
        "User-Agent": "llm-lab-xss003-draft/1.0",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    if args.cookie_file:
        try:
            with open(args.cookie_file, "r", encoding="utf-8") as fh:
                headers["Cookie"] = fh.read().strip()
        except OSError as exc:
            print("[x] 无法读取 Cookie 文件: %s" % exc)
            return 2

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers=headers, method="GET")

    print("[i] 提交 URL（Cookie 不显示）: %s" % url)
    try:
        with opener.open(req, timeout=args.timeout) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
        raw = exc.read(300000) if hasattr(exc, "read") else b""
        body = raw.decode("utf-8", "replace")
        print("[!] HTTP 错误状态 %s（可能是登录跳转、403 或路径错误，需人工确认会话）" % status)
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
        print("[x] 连接/协议失败: %s: %s" % (type(exc).__name__, exc))
        return 2

    reflected = args.payload in body
    print("[i] HTTP %s, Content-Type=%r, 响应长度=%d" % (status, ctype, len(body)))
    print("[i] 载荷是否原样出现在响应体: %s" % reflected)
    if reflected:
        idx = body.find(args.payload)
        window = body[max(0, idx - 100): idx + len(args.payload) + 100]
        print("[i] 命中上下文: %s" % window.replace("\n", " "))
        print("[!] 回显不等于浏览器执行；请在浏览器 DevTools Console 确认是否打印 LLM_LAB_XSS。")
    else:
        print("[i] 未见原样回显：可能是被编码、未进入该分支或路径/会话不符，需人工核对。")

    print("[i] 浏览器人工验证 URL（需已登录会话，同难度配置）: %s" % url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
