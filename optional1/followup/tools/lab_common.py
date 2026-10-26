"""Shared helpers for the optional1 POC follow-up execution.

All actions are local-only: WSL MariaDB via `wsl.exe`, and HTTP to 127.0.0.1.
"""
from __future__ import annotations

from http.cookiejar import CookieJar
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FOLLOWUP = ROOT / "optional1" / "followup"
EVIDENCE = FOLLOWUP / "evidence"
RAW = FOLLOWUP / "raw"
SESSIONS = FOLLOWUP / "sessions"
LOGS = FOLLOWUP / "logs"
DVWA = "http://127.0.0.1:9080"
SQLI = "http://127.0.0.1:9081"
WSL_DISTRO = "Ubuntu-22.04"

for d in (EVIDENCE, RAW, SESSIONS, LOGS):
    d.mkdir(parents=True, exist_ok=True)


def wsl(args, timeout=60):
    """Run a command inside WSL as root and return CompletedProcess(text)."""
    cmd = ["wsl.exe", "-d", WSL_DISTRO, "-u", "root", "--"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def sql(query, timeout=60):
    p = wsl(["mariadb", "-N", "-B", "-e", query], timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"SQL failed: {p.stderr.strip()}")
    return [line.split("\t") for line in p.stdout.splitlines() if line]


def sql_exec(query, timeout=60):
    p = wsl(["mariadb", "-e", query], timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"SQL failed: {p.stderr.strip()}")
    return p.stdout


def http(method, url, data=None, cookie=None, timeout=15, headers=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        req.add_header("Cookie", cookie)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def dvwa_login(user, password):
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    html = opener.open(DVWA + "/login.php", timeout=15).read().decode("utf-8", "replace")
    m = re.search(r"name='user_token' value='([0-9a-f]+)'", html)
    if not m:
        raise RuntimeError("DVWA login token not found")
    data = urllib.parse.urlencode(
        {"username": user, "password": password, "Login": "Login", "user_token": m.group(1)}
    ).encode()
    body = opener.open(DVWA + "/login.php", data=data, timeout=15).read().decode("utf-8", "replace")
    if "You have logged in as" not in body:
        raise RuntimeError(f"DVWA login failed for {user}")
    sid = [c.value for c in jar if c.name == "PHPSESSID"][0]
    return sid


def ensure_sessions():
    """Create fresh DVWA session files (plain + per-security variants)."""
    for user, pw, tag in (("admin", "password", "admin"), ("gordonb", "abc123", "gordonb")):
        sid = dvwa_login(user, pw)
        (SESSIONS / f"{tag}_plain.cookie").write_text(f"PHPSESSID={sid}", encoding="utf-8")
        for lvl in ("low", "medium", "high", "impossible"):
            (SESSIONS / f"{tag}_{lvl}.cookie").write_text(
                f"PHPSESSID={sid}; security={lvl}", encoding="utf-8"
            )
        print(f"session {tag}: {sid}")


def cookie_text(name):
    return (SESSIONS / name).read_text(encoding="utf-8").strip()


def reset_auth_target():
    sql_exec(
        "INSERT INTO dvwa.users (user_id, first_name, last_name, user, password, avatar, last_login, failed_login) "
        "VALUES (6,'Wp4','Target','wp4target',MD5('wp4target'),NULL,NOW(),0) "
        "ON DUPLICATE KEY UPDATE first_name='Wp4', last_name='Target'"
    )


def reset_sqli_users():
    names = [
        "v", "v_ctl", "v'#", "wp4v", "x' OR username='v'#", "wp2probe' OR username='wp4v'#",
        "sqli005_victim", "sqli005_control", "sqli005_victim'#",
        "sqli005_victim_ctl", "sqli005_victim_ctl'#",
    ]
    for n in names:
        esc = n.replace("'", "''")
        sql_exec(f"DELETE FROM security.users WHERE username='{esc}'")


def register_sqli_user(user, password):
    status, body, headers = http(
        "POST",
        SQLI + "/Less-24/login_create.php",
        {"submit": "Register", "username": user, "password": password,
         "re_password": password},
    )
    return status, ("Less-24-user-created.jpg" in body or "Redirecting you to login page" in body)


def reset_guestbook():
    sql_exec("DELETE FROM dvwa.guestbook WHERE name IN ('wp4x5','wp4x5h','poc')")


def check_lab():
    sql_exec("SELECT 1")
    s1, b1, _ = http("GET", SQLI + "/Less-1/?id=1")
    s2, b2, _ = http("GET", DVWA + "/login.php")
    return {
        "sqli_status": s1,
        "sqli_login_marker": "Your Login name:" in b1,
        "dvwa_status": s2,
        "dvwa_login_page": s2 == 200 and "login" in b2.lower(),
    }


def redact(text: str) -> str:
    text = re.sub(r"PHPSESSID=[^;\s\"']+", "PHPSESSID=<redacted>", text)
    text = re.sub(r"security=(low|medium|high|impossible)", "security=<level>", text)
    return text


def run_poc(path: Path, args, timeout=60, env=None):
    cmd = [os.environ.get("PYTHON", "python"), str(path)] + [str(a) for a in args]
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.time()
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    elapsed = time.time() - started
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    return {
        "cmd": cmd,
        "started_at": started_at,
        "returncode": p.returncode,
        "elapsed_seconds": round(elapsed, 3),
        "stdout": out,
        "stderr": err,
    }


def save_raw(cohort, stem, result):
    d = RAW / cohort
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{stem}.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
