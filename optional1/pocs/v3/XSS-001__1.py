#!/usr/bin/env python3
"""XSS-001 reflected-XSS verification draft (inert marker only)."""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
PAYLOAD = "<img src=x onerror=console.log('LLM_LAB_XSS')>"


def build_url(base, path, param, payload):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("base URL must be http(s)")
    if (parts.hostname or "") not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-loopback host: %r" % (parts.hostname,))
    query = urllib.parse.urlencode({param: payload})
    path = path if path.startswith("/") else "/" + path
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    ap = argparse.ArgumentParser(description="Reflected XSS smoke check (local lab only)")
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--path", required=True, help="route that includes the audited fragment")
    ap.add_argument("--param", default="name", help="GET parameter from the audited code (default: name)")
    ap.add_argument("--payload", default=PAYLOAD)
    ap.add_argument("--cookie", default=None, help="optional session cookie; never commit it")
    args = ap.parse_args()

    url = build_url(args.base_url, args.path, args.param, args.payload)
    req = urllib.request.Request(url, method="GET")
    if args.cookie:
        req.add_header("Cookie", args.cookie)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print("HTTP error: %s" % exc.code)
        sys.exit(2)
    except urllib.error.URLError as exc:
        print("connection/protocol error: %s" % exc.reason)
        sys.exit(3)

    raw = args.payload in body
    escaped = "&lt;img" in body or "&lt;" in body
    print("request: GET %s" % url)
    print("status: %s" % status)
    print("payload_verbatim_in_body: %s" % raw)
    print("payload_looks_html_encoded: %s" % escaped)
    print("next: open the same URL in the browser and watch the console for LLM_LAB_XSS")
    return 0 if raw else 1


if __name__ == "__main__":
    sys.exit(main())
