"""Execute the 40 original POCs against the local lab and capture raw output.

No POC source is modified. Environment-dependent values (URLs, ports, session
cookies, dedicated account names) are supplied through existing CLI options.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_common as L

P = L.ROOT / "optional1" / "pocs"
S = L.SESSIONS


def ck(name):
    return L.cookie_text(name)


def sid(name):
    return ck(name).split(";")[0].split("=", 1)[1]


def specs():
    D, Q = L.DVWA, L.SQLI
    out = []

    def add(cohort, stem, args):
        out.append({"cohort": cohort, "stem": stem, "poc": P / cohort / f"{stem}.py", "args": args})

    # ---------------- v1 ----------------
    add("v1", "AUTH-001__1", ["--base", D + "/vulnerabilities/authbypass/", "--cookie-file", str(S / "gordonb_plain.cookie")])
    add("v1", "AUTH-001__2", ["--base", D + "/vulnerabilities/authbypass/", "--cookie-file", str(S / "gordonb_plain.cookie"), "--target-id", "6"])
    add("v1", "AUTH-001__3", ["--base", D, "--cookie-file", str(S / "gordonb_plain.cookie"), "--page", "/vulnerabilities/authbypass/"])
    add("v1", "CMD-001__1", ["--base-url", D, "--path", "/vulnerabilities/exec/", "--cookie-file", str(S / "admin_low.cookie")])
    add("v1", "CMD-002__1", ["--url", D + "/vulnerabilities/exec/", "--cookie", ck("admin_medium.cookie")])
    add("v1", "CMD-003__1", ["--base-url", D, "--path", "/vulnerabilities/exec/", "--cookie-file", str(S / "admin_high.cookie")])
    add("v1", "SQLI-001__1", ["--base-url", Q + "/Less-1/?id=1", "--param", "id"])
    add("v1", "SQLI-002__1", ["--url", Q + "/Less-11/"])
    add("v1", "SQLI-003__1", ["--base-url", Q, "--path", "/Less-25/?id=1"])
    add("v1", "SQLI-005__1", ["--base-url", Q, "--register-path", "/Less-24/login_create.php",
                              "--login-path", "/Less-24/login.php", "--change-path", "/Less-24/pass_change.php",
                              "--victim-user", "v", "--victim-password", "Orig!005Pw", "--probe-prefix", "x",
                              "--probe-password", "Probe!005Pw", "--new-victim-password", "Changed!005Pw"])
    add("v1", "XSS-001__1", ["--base-url", D, "--path", "/vulnerabilities/xss_r/", "--cookie", ck("admin_low.cookie")])
    add("v1", "XSS-002__1", ["--base", D, "--path", "/vulnerabilities/xss_r/", "--session-cookie", sid("admin_medium.cookie") + "; security=medium"])
    add("v1", "XSS-003__1", ["--base", D, "--path", "/vulnerabilities/xss_r/", "--cookie", ck("admin_high.cookie")])
    add("v1", "XSS-005__1", ["--base-url", D, "--cookie-file", str(S / "admin_low.cookie"), "--security-level", "low", "--name", "wp4x5"])

    # ---------------- v2 ----------------
    add("v2", "AUTH-001__1", ["--base-url", D, "--session-file", str(S / "gordonb_low.cookie"),
                              "--admin-session-file", str(S / "admin_low.cookie")])
    add("v2", "AUTH-001__2", ["--base-url", D, "--session-file", str(S / "gordonb_low.cookie"),
                              "--test-user-id", "6", "--confirm-write"])
    add("v2", "CMD-001__1", ["--base-url", D, "--path", "/vulnerabilities/exec/",
                             "--cookie-file", str(S / "admin_low.cookie"), "--os-branch", "linux"])
    add("v2", "CMD-002__1", ["--base-url", D, "--path", "/vulnerabilities/exec/",
                             "--cookie-file", str(S / "admin_medium.cookie"), "--os", "linux"])
    add("v2", "CMD-003__1", ["--url", D + "/vulnerabilities/exec/",
                             "--cookie-file", str(S / "admin_high.cookie"), "--os", "linux"])
    add("v2", "SQLI-001__1", ["--base-url", Q, "--path", "/Less-1/?id=1"])
    add("v2", "SQLI-002__1", ["--base-url", Q, "--path", "/Less-11/"])
    add("v2", "SQLI-003__1", ["--base-url", Q, "--path", "/Less-25/"])
    add("v2", "SQLI-005__1", ["--base-url", Q, "--register-path", "/Less-24/login_create.php",
                              "--login-path", "/Less-24/login.php", "--change-path", "/Less-24/pass_change.php",
                              "--victim-old-password", "Orig!005Pw", "--victim-new-password", "Changed!005Pw",
                              "--control-password", "Control!005Pw", "--attacker-password", "Attacker!005Pw",
                              "--i-have-authorization"])
    add("v2", "XSS-001__1", ["--base", D, "--path", "/vulnerabilities/xss_r/", "--cookie", ck("admin_low.cookie")])
    add("v2", "XSS-002__1", ["--base-url", D + "/vulnerabilities/xss_r/", "--cookie-file", str(S / "admin_medium.cookie")])
    add("v2", "XSS-003__1", ["--base", D, "--path", "/vulnerabilities/xss_r/", "--cookie", ck("admin_high.cookie")])
    add("v2", "XSS-005__1", ["--base-url", D, "--username", "admin", "--password", "password", "--security", "low"])

    # ---------------- v3 ----------------
    add("v3", "AUTH-001__1", ["--base", D, "--cookie-file", str(S / "gordonb_plain.cookie"),
                              "--admin-cookie-file", str(S / "admin_plain.cookie"), "--security", "low"])
    add("v3", "AUTH-001__2", ["--base", D, "--cookie-file", str(S / "gordonb_plain.cookie"),
                              "--target-id", "6", "--security", "low"])
    add("v3", "CMD-001__1", ["--base-url", D, "--path", "/vulnerabilities/exec/",
                             "--cookie-file", str(S / "admin_low.cookie"), "--os", "nix"])
    add("v3", "CMD-002__1", ["--base-url", D, "--path", "/vulnerabilities/exec/",
                             "--cookie-file", str(S / "admin_medium.cookie"), "--os", "linux"])
    add("v3", "CMD-003__1", ["--url", D + "/vulnerabilities/exec/",
                             "--cookie-file", str(S / "admin_high.cookie"), "--os", "linux"])
    add("v3", "SQLI-001__1", ["--base", Q, "--path", "/Less-1/?id=1"])
    add("v3", "SQLI-002__1", ["--base-url", Q, "--path", "/Less-11/", "--valid-user", "Dumb", "--valid-pass", "Dumb"])
    add("v3", "SQLI-003__1", ["--base", Q, "--path", "/Less-25/"])
    add("v3", "SQLI-005__1", ["--base-url", Q, "--register-path", "/Less-24/login_create.php",
                              "--login-path", "/Less-24/login.php", "--change-path", "/Less-24/pass_change.php",
                              "--victim", "v", "--orig-password", "Orig!005Pw", "--new-password", "Changed!005Pw"])
    add("v3", "XSS-001__1", ["--base-url", D, "--path", "/vulnerabilities/xss_r/", "--cookie", ck("admin_low.cookie")])
    add("v3", "XSS-002__1", ["--base", D, "--path", "/vulnerabilities/xss_r/", "--cookie-file", str(S / "admin_medium.cookie")])
    add("v3", "XSS-003__1", ["--url", D + "/vulnerabilities/xss_r/", "--cookie-file", str(S / "admin_high.cookie")])
    add("v3", "XSS-005__1", ["--base-url", D, "--cookie-file", str(S / "admin_low.cookie"), "--security", "low"])

    assert len(out) == 40, len(out)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--skip-xss", action="store_true")
    args = ap.parse_args()

    L.ensure_sessions()
    L.reset_auth_target()
    L.reset_sqli_users()
    L.reset_guestbook()
    print(json.dumps(L.check_lab(), ensure_ascii=False))

    for s in specs():
        if args.only and args.only not in f"{s['cohort']}/{s['stem']}":
            continue
        if args.skip_xss and s["stem"].startswith("XSS"):
            continue
        print(f"== {s['cohort']}/{s['stem']}")
        if s["cohort"] == "v1" and s["stem"] == "SQLI-005__1":
            L.reset_sqli_users()
            L.register_sqli_user("v", "Orig!005Pw")
        try:
            r = L.run_poc(s["poc"], s["args"], timeout=90)
        except Exception as exc:  # timeout and the like
            r = {"cmd": [str(s["poc"])] + s["args"], "returncode": None,
                 "started_at": None, "elapsed_seconds": None, "stdout": "",
                 "stderr": f"{type(exc).__name__}: {exc}"}
        if s["cohort"] == "v1" and s["stem"] == "SQLI-005__1":
            L.sql_exec("DELETE FROM security.users WHERE username='v'")
        r.update({"cohort": s["cohort"], "stem": s["stem"], "poc": str(s["poc"]),
                  "args_redacted": [L.redact(str(a)) for a in s["args"]]})
        L.save_raw(s["cohort"], s["stem"], r)
        print(f"   rc={r['returncode']} elapsed={r['elapsed_seconds']}")
        print("   " + (r["stdout"].strip().splitlines() or [""])[-1][:180])


if __name__ == "__main__":
    main()
