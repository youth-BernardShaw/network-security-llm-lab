#!/usr/bin/env python3
# AUTH-001 F03 draft: page-level access check for vulnerabilities/authbypass/.
# Read-only, loopback only, no redirect following, credentials from local files.
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAGE_PATH = "/vulnerabilities/authbypass/"
PAGE_MARKERS = ("Vulnerability: Authorisation Bypass", "user_table", "Welcome to the user manager")


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
    host = urllib.parse.urlsplit(base).hostname
    jar.set_cookie(http.cookiejar.Cookie(
        version=0, name="security", value=level, port=None, port_specified=False,
        domain=host, domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True, secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False))


def login(opener, base, username, password):
    body = urllib.parse.urlencode(
        {"username": username, "password": password, "Login": "Login"}).encode("utf-8")
    request = urllib.request.Request(base + "/login.php", data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(request, timeout=10) as response:
        return response.status


def fetch_page(opener, base):
    request = urllib.request.Request(base + PAGE_PATH)
    request.add_header("Accept", "text/html")
    with opener.open(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def describe(status, body):
    return {
        "status": status,
        "unauthorised_text": "Unauthorised" in body,
        "markers": {marker: (marker in body) for marker in PAGE_MARKERS},
        "length": len(body),
        "snippet": body[:300].replace("\n", " "),
    }


def run(base, user, password, level):
    jar, opener = build_opener()
    login(opener, base, user, password)
    set_level_cookie(jar, base, level)
    status, body = fetch_page(opener, base)
    return describe(status, body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--user", required=True, help="low-privilege dedicated lab account")
    parser.add_argument("--password-file", required=True, help="local file with that account password")
    parser.add_argument("--security", default="low", choices=["low", "medium", "high", "impossible"])
    parser.add_argument("--control-user", default=None, help="optional admin account for the control request")
    parser.add_argument("--control-password-file", default=None)
    parser.add_argument("--out", default="auth001_f03_evidence.json")
    args = parser.parse_args()

    base = normalise_base(args.base)
    password = read_secret(args.password_file)

    try:
        observed = run(base, args.user, password, args.security)
    except urllib.error.HTTPError as exc:
        print("low-privilege page request: HTTP %s"% exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error: %s" % exc.reason)
        return 2

    print("low_privilege: status=%s unauthorised=%s markers=%s"
          % (observed["status"], observed["unauthorised_text"], observed["markers"]))

    control = None
    if args.control_user and args.control_password_file:
        control_password = read_secret(args.control_password_file)
        try:
            control = run(base, args.control_user, control_password, args.security)
            print("control: status=%s unauthorised=%s markers=%s"
                  % (control["status"], control["unauthorised_text"], control["markers"]))
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            print("control request failed, continuing: %s" % exc)

    evidence = {"target": base, "security": args.security,
                "low_privilege": observed, "control": control}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    print("evidence=%s" % args.out)

    served = observed["status"] == 200 and not observed["unauthorised_text"] and observed["markers"].get("user_table")
    if served:
        print("RESULT: the user-manager page body was served to a non-admin principal")
        return 0
    if observed["unauthorised_text"] or observed["status"] in (401, 403):
        print("RESULT: the page rejected this principal under this condition")
        return 1
    print("RESULT: inconclusive; inspect the saved evidence")
    return 1


if __name__ == "__main__":
    sys.exit(main())
