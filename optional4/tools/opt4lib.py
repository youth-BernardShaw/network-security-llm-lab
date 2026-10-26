# -*- coding: utf-8 -*-
"""Shared helpers for optional-challenge-4 local validation runs.

Standard library only. All HTTP traffic is restricted to the declared local
origins (127.0.0.1:9080 for DVWA, 127.0.0.1:9081 for SQLi-Labs), mirroring
verification/tools/wp4lib.py conventions used by the main body.
"""
from __future__ import annotations

import hashlib
import http.cookiejar
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
BATCH_ID = "opt4-poc-02"
TZ = timezone(timedelta(hours=8))
BASE_DVWA = "http://127.0.0.1:9080"
BASE_SQLI = "http://127.0.0.1:9081"

SOURCE_COMMIT_DVWA = "068d974487a297c155c48722f9fcf7180a83adc4"
SOURCE_COMMIT_SQLI = "e96f21776372c8613a7e565106e62bc01a59355e"

SENSITIVE_KEYS = {
    "password", "passwd", "current_password", "re_password",
    "login_password", "password_new", "password_conf", "pwd",
}
SENSITIVE_PATTERNS = [
    (re.compile(r"(PHPSESSID=)[^;,\s]+"), r"\1<redacted>"),
    (re.compile(r"(Auth=)[^;,\s]+"), r"\1<redacted>"),
    (re.compile(r"(security=)[^;,\s]+"), r"\1<low|medium|impossible>"),
]


def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_text(text: str) -> str:
    for pattern, repl in SENSITIVE_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_body(obj):
    if isinstance(obj, dict):
        return {
            key: ("<redacted>" if key.lower() in SENSITIVE_KEYS else redact_body(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [redact_body(item) for item in obj]
    return obj


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    def __init__(self, status: int, headers, body: bytes, url: str):
        self.status = status
        self.headers = dict(headers.items())
        self.body = body
        self.url = url

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Client:
    """Cookie-carrying HTTP client bound to one declared origin."""

    def __init__(self, base: str):
        if base not in (BASE_DVWA, BASE_SQLI):
            raise ValueError(f"origin not declared: {base}")
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.trace: list[dict] = []

    def request(self, method: str, path: str, *, data=None, headers=None) -> Response:
        url = self.base + path
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, method=method)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            resp = self.opener.open(req, timeout=15)
            response = Response(resp.status, resp.headers, resp.read(), url)
        except urllib.error.HTTPError as err:  # includes blocked 30x
            response = Response(err.code, err.headers, err.read(), url)
        self.trace.append({
            "method": method,
            "url": url,
            "request_headers": redact_body(dict(headers or {})),
            "request_body": redact_body(data),
            "status": response.status,
            "response_headers": redact_body(response.headers),
        })
        return response

    def get(self, path: str, **kw) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, data=None, **kw) -> Response:
        return self.request("POST", path, data=data, **kw)

    def set_cookie(self, name: str, value: str) -> None:
        """Force a client-controlled cookie (e.g. DVWA security level)."""
        self.jar.clear(domain="127.0.0.1", path="/", name=name)
        self.jar.set_cookie(http.cookiejar.Cookie(
            version=0, name=name, value=value,
            port=None, port_specified=False, domain="127.0.0.1",
            domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False,
            expires=None, discard=True, comment=None, comment_url=None,
            rest={}, rfc2109=False,
        ))


def db_query(sql: str) -> list[list[str]]:
    """Run one SQL statement via the local mariadb CLI (root, unix socket)."""
    proc = subprocess.run(
        ["mariadb", "-N", "-B", "-e", sql],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"mariadb failed: {proc.stderr.strip()}")
    rows = [line.split("\t") for line in proc.stdout.splitlines() if line]
    return rows


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


class Run:
    """Evidence writer: request/response/observation/restore per run_id."""

    def __init__(self, run_id: str, meta: dict):
        self.run_id = run_id
        self.dir = EVIDENCE / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.meta = meta
        self.started_at = now_iso()

    def finish(self, observations: dict) -> dict:
        finished = now_iso()
        record = {
            "run_id": self.run_id,
            "batch_id": BATCH_ID,
            "started_at": self.started_at,
            "finished_at": finished,
            "meta": self.meta,
            "observations": observations,
        }
        (self.dir / "observation.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        return record

    def write_restore(self, payload: dict) -> None:
        (self.dir / "restore_result.json").write_text(
            json.dumps({"run_id": self.run_id, "restored_at": now_iso(), **payload},
                       ensure_ascii=False, indent=2), encoding="utf-8")

    def dump_clients(self, clients: dict) -> None:
        requests_doc = {name: redact_body(c.trace) for name, c in clients.items()}
        (self.dir / "request.redacted.json").write_text(
            json.dumps(requests_doc, ensure_ascii=False, indent=2), encoding="utf-8")
        parts = []
        for name, c in clients.items():
            for entry in c.trace:
                parts.append(f"### {name} {entry['method']} {entry['url']} -> {entry['status']}")
        (self.dir / "response.redacted.txt").write_text(
            "\n".join(parts) + "\n", encoding="utf-8")

    def artifact(self, name: str, content: str) -> Path:
        path = self.dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def artifact_hashes(self) -> list[dict]:
        out = []
        for path in sorted(self.dir.iterdir()):
            if path.is_file():
                out.append({
                    "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "sha256": sha256_file(path),
                    "description": path.name,
                })
        return out


def dvwa_login(client: Client, username: str, password: str) -> Response:
    """Login helper: fetch token, post credentials, return index check."""
    page = client.get("/login.php")
    token = re.search(r"name='user_token' value='([0-9a-f]+)'", page.text)
    if not token:
        raise RuntimeError("DVWA login token not found")
    return client.post("/login.php", data={
        "username": username, "password": password,
        "Login": "Login", "user_token": token.group(1),
    })
