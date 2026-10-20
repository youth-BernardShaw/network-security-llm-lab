#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XSS-002 reflected-XSS verification draft (harmless marker only).

Authorized local teaching lab only. The draft:
  - accepts only http/https URLs whose host is localhost / 127.0.0.1 / ::1;
  - does not follow redirects automatically;
  - sends one GET request carrying an inert payload;
  - reports whether the payload is reflected unencoded (HTTP echo only).

It never reads cookies from the target, never exfiltrates data and
never stores content on the server.
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PAYLOAD = '<img src=x onerror="console.log(`LLM_LAB_XSS`)">'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_target(base_url, param, payload):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("ABORT: only http/https URLs are allowed")
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise SystemExit("ABORT: host %r is not an authorized local target" % host)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = payload
    return parsed._replace(query=urllib.parse.urlencode(query)).geturl()


def main():
    parser = argparse.ArgumentParser(description="XSS-002 harmless reflection check")
    parser.add_argument("--base-url", required=True,
                        help="authorized local page, e.g. http://127.0.0.1:8080/vulnerabilities/xss_r/")
    parser.add_argument("--param", default="name")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD)
    parser.add_argument("--cookie-file", default=None,
                        help="local file holding the Cookie header value (never committed)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--raw-out", default=None, help="write the raw response body here")
    args = parser.parse_args()

    url = build_target(args.base_url, args.param, args.payload)
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", "llm-lab-xss002-audit-draft/1.0")
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as handle:
            cookie = handle.read().strip()
        if cookie:
            request.add_header("Cookie", cookie)

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=args.timeout) as response:
            status = response.status
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print("CONNECT_ERROR: %s" % exc, file=sys.stderr)
        return 2

    if args.raw_out:
        with open(args.raw_out, "w", encoding="utf-8") as handle:
            handle.write(body)

    print("HTTP_STATUS: %s" % status)
    reflected = args.payload in body
    encoded = "&lt;img" in body
    print("PAYLOAD_REFLECTED_VERBATIM: %s" % reflected)
    print("HTML_ENCODED_MARKER_SEEN: %s" % encoded)
    if reflected:
        index = body.find(args.payload)
        window = body[max(0, index - 40): index + len(args.payload) + 40]
        print("REFLECTION_CONTEXT: %s" % window.replace(chr(10), " "))
        print("NOTE: HTTP echo only; browser execution must be observed separately.")
    else:
        print("NOTE: no verbatim reflection; the value may be encoded or dropped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
