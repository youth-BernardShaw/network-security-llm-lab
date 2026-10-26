# -*- coding: utf-8 -*-
"""OPT4-SO-02: DVWA xss_s medium level -- dual-field second-order XSS.

Same request, same security level: name (blocklist only) stays literal and is
rendered raw; message (pre-encoded on write) renders as text. Low level is
re-checked as the main-body-consistent control; impossible rejects the request
without a token.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opt4lib as lib  # noqa: E402
from opt4lib import (  # noqa: E402
    BATCH_ID, BASE_DVWA, SOURCE_COMMIT_DVWA, Client, Run, db_query,
    dvwa_login, redact_text,
)

NAME_MARK = "onerror=window.__opt4nm=1"
MSG_MARK = "onerror=window.__opt4ms=1"
NAME_PAYLOAD = f"<img src=x {NAME_MARK}>"
MSG_PAYLOAD = f"<img src=x {MSG_MARK}>"


def sign(client: Client, level: str) -> object:
    return client.post("/vulnerabilities/xss_s/", data={
        "txtName": NAME_PAYLOAD, "mtxMessage": MSG_PAYLOAD,
        "btnSign": "Sign Guestbook",
    })


def main() -> int:
    run = Run("opt4-20261020-so02", {
        "case_id": "OPT4-SO-02",
        "batch_id": BATCH_ID,
        "deployment_id": "dvwa-wsl-02",
        "source_commit": SOURCE_COMMIT_DVWA,
        "base": BASE_DVWA,
    })
    obs: dict = {"steps": {}}
    baseline = int(db_query("SELECT COUNT(*) FROM dvwa.guestbook")[0][0])
    obs["baseline_guestbook"] = baseline

    # --- medium level: dual-field write + read back
    c_med = Client(BASE_DVWA)
    dvwa_login(c_med, "gordonb", "abc123")
    c_med.set_cookie("security", "medium")
    med_post = sign(c_med, "medium")
    rows = db_query(
        "SELECT comment, name FROM dvwa.guestbook WHERE name LIKE '%__opt4nm%'")
    obs["steps"]["medium_write"] = {
        "post_status": med_post.status,
        "rows": len(rows),
        "name_stored_literal": bool(rows) and rows[0][1] == NAME_PAYLOAD,
        "message_element_stripped": bool(rows) and "<img" not in rows[0][0] and "__opt4ms" not in rows[0][0],
    }
    med_read = c_med.get("/vulnerabilities/xss_s/")
    med_name_raw = f"<img src=x {NAME_MARK}>" in med_read.text
    # strip_tags removes the whole element from message, so the executable
    # construct must not reach the page for that field at this level
    med_msg_no_element = f"<img src=x {MSG_MARK}>" not in med_read.text
    obs["steps"]["medium_read"] = {
        "name_rendered_raw": med_name_raw,
        "message_no_executable_element": med_msg_no_element,
    }

    # --- low level control (matches main body XSS-005 conclusion)
    c_low = Client(BASE_DVWA)
    dvwa_login(c_low, "gordonb", "abc123")
    c_low.set_cookie("security", "low")
    low_post = sign(c_low, "low")
    low_read = c_low.get("/vulnerabilities/xss_s/")
    obs["steps"]["low_control"] = {
        "post_status": low_post.status,
        "name_rendered_raw": f"<img src=x {NAME_MARK}>" in low_read.text,
        "message_rendered_raw": f"<img src=x {MSG_MARK}>" in low_read.text,
    }

    # --- impossible control: no token -> rejected, nothing stored
    c_imp = Client(BASE_DVWA)
    dvwa_login(c_imp, "gordonb", "abc123")
    c_imp.set_cookie("security", "impossible")
    marker_rows_before = int(db_query(
        "SELECT COUNT(*) FROM dvwa.guestbook WHERE name LIKE '%__opt4nm%'")[0][0])
    imp_post = sign(c_imp, "impossible")
    marker_rows_after = int(db_query(
        "SELECT COUNT(*) FROM dvwa.guestbook WHERE name LIKE '%__opt4nm%'")[0][0])
    obs["steps"]["impossible_control"] = {
        "post_status": imp_post.status,
        "rejected_by_token_check": imp_post.status in (301, 302),
        "not_stored": marker_rows_after == marker_rows_before,
    }

    # --- cleanup by marker
    db_query("DELETE FROM dvwa.guestbook WHERE name LIKE '%__opt4nm%' OR comment LIKE '%__opt4ms%'")
    after = int(db_query("SELECT COUNT(*) FROM dvwa.guestbook")[0][0])
    run.write_restore({
        "baseline_guestbook": baseline,
        "after_cleanup_guestbook": after,
        "restored": after == baseline,
    })
    obs["restore"] = {"guestbook_after": after}

    verdict = (
        obs["steps"]["medium_write"]["name_stored_literal"]
        and obs["steps"]["medium_write"]["message_element_stripped"]
        and med_name_raw
        and med_msg_no_element
        and obs["steps"]["low_control"]["name_rendered_raw"]
        and obs["steps"]["impossible_control"]["rejected_by_token_check"]
        and after == baseline
    )
    obs["verdict"] = "触发" if verdict else "未触发"
    run.dump_clients({"medium": c_med, "low": c_low, "impossible": c_imp})
    run.artifact("xss_s.medium.read.html", redact_text(med_read.text))
    run.artifact("xss_s.low.read.html", redact_text(low_read.text))
    run.artifact("xss_s.medium.db_readback.txt",
                 "\n".join("\t".join(r) for r in rows) or "(none)")
    record = run.finish(obs)
    print(f"verdict={obs['verdict']}")
    print(f"evidence={record['run_id']} artifacts={len(run.artifact_hashes())}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
