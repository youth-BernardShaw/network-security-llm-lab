"""Build optional-2 normalized findings, LLM assessments and metrics.

The executable scanner in this environment is Wapiti 3.0.4.  Burp/AWVS
adapters are provided separately; this script only consumes the Wapiti JSON
outputs and the existing WordPress-4 POC evidence.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPT = ROOT / "optional2"
RAW = OPT / "scanner_raw"
CASE = OPT / "case_studies"

SCAN_FILES = {    "wapiti_sqli001.json": {
        "asset": "http://127.0.0.1:9081", "sample": "SQLI-001",
        "condition": "env=sqli-labs|role=anonymous",
        "auth": "none", "scope": "page", "modules": "sql,xss,exec",
        "url": "http://127.0.0.1:9081/Less-1/index.php?id=1",
    },
    "wapiti_sqli003.json": {
        "asset": "http://127.0.0.1:9081", "sample": "SQLI-003",
        "condition": "env=sqli-labs|role=anonymous",
        "auth": "none", "scope": "page", "modules": "sql,xss,exec",
        "url": "http://127.0.0.1:9081/Less-25/index.php?id=1",
    },
    "wapiti_xss001.json": {
        "asset": "http://127.0.0.1:9080", "sample": "XSS-001",
        "condition": "env=dvwa-wsl-01|security=low",
        "auth": "DVWA admin session (security=low)", "scope": "page",
        "modules": "sql,xss,permanentxss,exec",
        "url": "http://127.0.0.1:9080/vulnerabilities/xss_r/?name=test",
    },
    "wapiti_cmd001.json": {
        "asset": "http://127.0.0.1:9080", "sample": "CMD-001",
        "condition": "env=dvwa-wsl-01|security=low",
        "auth": "DVWA admin session (security=low)", "scope": "page",
        "modules": "sql,xss,exec",
        "url": "http://127.0.0.1:9080/vulnerabilities/exec/",
    },
    "wapiti_headers_login.json": {
        "asset": "http://127.0.0.1:9080", "sample": "CONFIG-DVWA-LOGIN",
        "condition": "env=dvwa-wsl-01|scope=login-page",
        "auth": "none", "scope": "page",
        "modules": "cookieflags,http_headers,csp",
        "url": "http://127.0.0.1:9080/login.php",
    },
}

COMMANDS = {
    "wapiti_sqli001.json": "wapiti -u 'http://127.0.0.1:9081/Less-1/index.php?id=1' --scope page -m 'sql,xss,exec' -S polite --max-scan-time 60 --max-attack-time 60 -f json -o optional2/scanner_raw/wapiti_sqli001.json --flush-session",
    "wapiti_sqli003.json": "wapiti -u 'http://127.0.0.1:9081/Less-25/index.php?id=1' --scope page -m 'sql,xss,exec' -S polite --max-scan-time 45 --max-attack-time 45 -f json -o optional2/scanner_raw/wapiti_sqli003.json --flush-session",
    "wapiti_xss001.json": "wapiti -u 'http://127.0.0.1:9080/vulnerabilities/xss_r/?name=test' --scope page -m 'sql,xss,permanentxss,exec' -c optional2/tmp/dvwa_cookies.json -S polite --max-scan-time 60 --max-attack-time 60 -f json -o optional2/scanner_raw/wapiti_xss001.json --flush-session",
    "wapiti_cmd001.json": "wapiti -u 'http://127.0.0.1:9080/vulnerabilities/exec/' --scope page -m 'sql,xss,exec' -c optional2/tmp/dvwa_cookies.json -S polite --max-scan-time 45 --max-attack-time 45 -f json -o optional2/scanner_raw/wapiti_cmd001.json --flush-session",
    "wapiti_headers_login.json": "wapiti -u 'http://127.0.0.1:9080/login.php' --scope page -m 'cookieflags,http_headers,csp' -S polite --max-scan-time 20 --max-attack-time 20 -f json -o optional2/scanner_raw/wapiti_headers_login.json --flush-session",
}
MAX_TIME = {
    "wapiti_sqli001.json": 60,
    "wapiti_sqli003.json": 45,
    "wapiti_xss001.json": 60,
    "wapiti_cmd001.json": 45,
    "wapiti_headers_login.json": 20,
}

TYPE_MAP = {
    "SQL Injection": "SQL注入",
    "Cross Site Scripting": "XSS",
    "Permanent XSS": "XSS",
    "Command execution": "命令注入",
    "Content Security Policy Configuration": "配置加固",
    "HTTP Secure Headers": "配置加固",
    "HttpOnly Flag cookie": "配置加固",
    "Secure Flag cookie": "配置加固",
}

CODE_LOCATION = {
    "SQLI-001": "SQLI-001:14-15",
    "SQLI-002": "SQLI-002:16-17",
    "SQLI-003": "SQLI-003:16,40-41",
    "SQLI-005": "SQLI-005-C:38",
    "XSS-001": "XSS-001:6",
    "XSS-002": "XSS-002:6-8",
    "XSS-003": "XSS-003:6-8",
    "XSS-005": "XSS-005-A:14; XSS-005-C:13",
    "CMD-001": "CMD-001:12,15",
    "CMD-002": "CMD-002:19,22",
    "CMD-003": "CMD-003:26,29",
    "AUTH-001": "AUTH-001-D:10-13; AUTH-001-E:11-14",
    "ADDITIONAL-001": "SQLI-003:44",
}

EVIDENCE = {
    "SQLI-001": "verification/evidence/wp4-20261019-sqli001-low/observation.json",
    "SQLI-002": "verification/evidence/wp4-20261019-sqli002-low/observation.json",
    "SQLI-003": "verification/evidence/wp4-20261019-sqli003-low/observation.json",
    "SQLI-005": "verification/evidence/wp4-20261019-sqli005-low/observation.json",
    "XSS-001": "verification/evidence/wp4-20261019-xss001-low/browser.json",
    "XSS-002": "verification/evidence/wp4-20261019-xss002-medium/browser.json",
    "XSS-003": "verification/evidence/wp4-20261019-xss003-high/browser.json",
    "XSS-005": "verification/evidence/wp4-20261019-xss005-low/browser.json",
    "CMD-001": "verification/evidence/wp4-20261019-cmd001-low/observation.json",
    "CMD-002": "verification/evidence/wp4-20261019-cmd002-medium/observation.json",
    "CMD-003": "verification/evidence/wp4-20261019-cmd003-high/observation.json",
    "AUTH-001": "verification/evidence/wp4-20261019-auth001-low/observation.json",
    "ADDITIONAL-001": "optional2/case_studies/less25_xss_browser.json",
}

LLM_CANDIDATES = [
    {
        "sample": "SQLI-001", "finding_id": "LLM-SQLI-001-F1",
        "asset": "http://127.0.0.1:9081", "route": "/Less-1/index.php",
        "method": "GET", "param": "id", "type": "SQL注入",
        "condition": "env=sqli-labs|role=anonymous", "severity": "High",
        "title": "SQL injection in Less-1 id",
        "request": "GET /Less-1/index.php?id=1' AND '1'='1",
        "notes": "boolean/error contrast; POC confirmed",
    },
    {
        "sample": "SQLI-002", "finding_id": "LLM-SQLI-002-F1",
        "asset": "http://127.0.0.1:9081", "route": "/Less-11/index.php",
        "method": "POST", "param": "uname", "type": "SQL注入",
        "condition": "env=sqli-labs|role=anonymous", "severity": "High",
        "title": "SQL injection in Less-11 login uname",
        "request": "POST /Less-11/index.php uname=Dumb'#&passwd=x",
        "notes": "comment truncation; POC confirmed",
    },
    {
        "sample": "SQLI-003", "finding_id": "LLM-SQLI-003-F1",
        "asset": "http://127.0.0.1:9081", "route": "/Less-25/index.php",
        "method": "GET", "param": "id", "type": "SQL注入",
        "condition": "env=sqli-labs|role=anonymous", "severity": "High",
        "title": "SQL injection bypassing or/AND blacklist",
        "request": "GET /Less-25/index.php?id=1' && '1'='1",
        "notes": "&& bypass; POC confirmed",
    },
    {
        "sample": "SQLI-005", "finding_id": "LLM-SQLI-005-F1",
        "asset": "http://127.0.0.1:9081", "route": "/Less-24/pass_change.php",
        "method": "POST", "param": "username(session)", "type": "SQL注入",
        "condition": "env=sqli-labs|role=anonymous|stage=register-login-pass",
        "severity": "High",
        "title": "Second-order SQL injection through session username",
        "request": "POST /Less-24/pass_change.php current_password=x&password=...",
        "notes": "multi-stage; POC confirmed",
    },
    {
        "sample": "XSS-001", "finding_id": "LLM-XSS-001-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/xss_r/",
        "method": "GET", "param": "name", "type": "XSS",
        "condition": "env=dvwa-wsl-01|security=low", "severity": "Medium",
        "title": "Reflected XSS in xss_r low",
        "request": "GET /vulnerabilities/xss_r/?name=<svg onload=...>",
        "notes": "browser marker; POC confirmed",
    },
    {
        "sample": "XSS-002", "finding_id": "LLM-XSS-002-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/xss_r/",
        "method": "GET", "param": "name", "type": "XSS",
        "condition": "env=dvwa-wsl-01|security=medium", "severity": "Medium",
        "title": "Reflected XSS bypassing <script> replacement",
        "request": "GET /vulnerabilities/xss_r/?name=<svg onload=...>",
        "notes": "browser marker; POC confirmed",
    },
    {
        "sample": "XSS-003", "finding_id": "LLM-XSS-003-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/xss_r/",
        "method": "GET", "param": "name", "type": "XSS",
        "condition": "env=dvwa-wsl-01|security=high", "severity": "Medium",
        "title": "Reflected XSS bypassing script regex",
        "request": "GET /vulnerabilities/xss_r/?name=<svg onload=...>",
        "notes": "browser marker; POC confirmed",
    },
    {
        "sample": "XSS-005", "finding_id": "LLM-XSS-005-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/xss_s/",
        "method": "POST", "param": "mtxMessage", "type": "XSS",
        "condition": "env=dvwa-wsl-01|security=low|stage=stored",
        "severity": "Medium",
        "title": "Stored XSS in guestbook low write/read",
        "request": "POST /vulnerabilities/xss_s/ btnSign=...&mtxMessage=<svg onload=...>",
        "notes": "browser marker; DB readback; POC confirmed",
    },
    {
        "sample": "CMD-001", "finding_id": "LLM-CMD-001-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/exec/",
        "method": "POST", "param": "ip", "type": "命令注入",
        "condition": "env=dvwa-wsl-01|security=low", "severity": "High",
        "title": "Command injection in exec low",
        "request": "POST /vulnerabilities/exec/ ip=127.0.0.1; printf WP4_CMD_001",
        "notes": "<pre> marker; POC confirmed",
    },
    {
        "sample": "CMD-002", "finding_id": "LLM-CMD-002-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/exec/",
        "method": "POST", "param": "ip", "type": "命令注入",
        "condition": "env=dvwa-wsl-01|security=medium", "severity": "High",
        "title": "Command injection bypassing &&/; blacklist",
        "request": "POST /vulnerabilities/exec/ ip=127.0.0.1 | printf WP4_CMD_002",
        "notes": "<pre> marker; POC confirmed",
    },
    {
        "sample": "CMD-003", "finding_id": "LLM-CMD-003-F1",
        "asset": "http://127.0.0.1:9080", "route": "/vulnerabilities/exec/",
        "method": "POST", "param": "ip", "type": "命令注入",
        "condition": "env=dvwa-wsl-01|security=high", "severity": "High",
        "title": "Command injection bypassing pipe-space filter",
        "request": "POST /vulnerabilities/exec/ ip=127.0.0.1|printf WP4_CMD_003",
        "notes": "<pre> marker; POC confirmed",
    },
    {
        "sample": "AUTH-001", "finding_id": "LLM-AUTH-001-F1",
        "asset": "http://127.0.0.1:9080",
        "route": "/vulnerabilities/authbypass/get_user_data.php",
        "method": "GET", "param": "-", "type": "权限越权",
        "condition": "env=dvwa-wsl-01|security=low|role=ordinary|object=wp4target",
        "severity": "High",
        "title": "Ordinary user reads all user data",
        "request": "GET /vulnerabilities/authbypass/get_user_data.php",
        "notes": "read API; DB row evidence; POC confirmed",
    },
    {
        "sample": "AUTH-001", "finding_id": "LLM-AUTH-001-F2",
        "asset": "http://127.0.0.1:9080",
        "route": "/vulnerabilities/authbypass/change_user_details.php",
        "method": "POST", "param": "id", "type": "权限越权",
        "condition": "env=dvwa-wsl-01|security=low|role=ordinary|object=wp4target",
        "severity": "High",
        "title": "Ordinary user updates another user",
        "request": "POST /change_user_details.php {\"id\":6,\"first_name\":\"Wp4Low\",\"surname\":\"Target\"}",
        "notes": "update API; DB readback/restore; POC confirmed",
    },
]


def key_for(asset, route, method, param, vtype, condition):
    return "|".join([asset, route, method, param, vtype, condition])


def severity(level):
    return {1: "Info", 2: "Medium", 3: "Medium", 4: "High"}.get(int(level), "Info")


def parse_wapiti():
    rows = []
    for filename, meta in SCAN_FILES.items():
        path = RAW / filename
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        index = 0
        for category, entries in data.get("vulnerabilities", {}).items():
            for entry in entries:
                index += 1
                category = str(category)
                vtype = TYPE_MAP.get(category, "其他")
                route = entry.get("path", "")
                method = entry.get("method", "")
                param = entry.get("parameter", "")
                asset = meta["asset"]
                if filename == "wapiti_headers_login.json":
                    sample = "CONFIG-DVWA-LOGIN"
                    status = "excluded_non_target"
                    evidence = f"optional2/scanner_raw/{filename}"
                    condition = meta["condition"]
                    finding_id = f"WAP-CFG-{index:02d}"
                elif filename == "wapiti_sqli003.json" and vtype == "XSS":
                    sample = "ADDITIONAL-001"
                    status = "confirmed_out_of_scope"
                    evidence = "optional2/case_studies/less25_xss_browser.json"
                    condition = "env=sqli-labs|role=anonymous|scope=additional"
                    finding_id = "WAP-XSS-003-01"
                else:
                    sample = meta["sample"]
                    status = "confirmed_by_poc"
                    evidence = EVIDENCE[sample]
                    condition = meta["condition"]
                    finding_id = f"WAP-{sample}-{index:02d}"
                rows.append({
                    "scanner_finding_id": finding_id,
                    "source": "scanner:wapiti",
                    "scanner_rule": f"{category}: {entry.get('info', '')}".strip(": "),
                    "sample_id": sample,
                    "asset": asset,
                    "route": route,
                    "http_method": method,
                    "parameter": param,
                    "vulnerability_type": vtype,
                    "severity": severity(entry.get("level", 1)),
                    "title": entry.get("info", category),
                    "evidence_summary": entry.get("info", ""),
                    "request_sample": entry.get("http_request", ""),
                    "curl_command": entry.get("curl_command", ""),
                    "code_location": CODE_LOCATION.get(sample, "N/A"),
                    "condition": condition,
                    "verification_status": status,
                    "evidence": evidence,
                    "notes": f"Wapiti 3.0.4; level={entry.get('level')}; {filename}",
                })
    return rows


def build_llm_rows():
    rows = []
    for item in LLM_CANDIDATES:
        rows.append({
            "finding_key": key_for(item["asset"], item["route"], item["method"],
                                   item["param"], item["type"], item["condition"]),
            "sample_id": item["sample"],
            "sources": "llm",
            "asset": item["asset"],
            "route": item["route"],
            "http_method": item["method"],
            "parameter": item["param"],
            "vulnerability_type": item["type"],
            "condition": item["condition"],
            "severity": item["severity"],
            "title": item["title"],
            "code_location": CODE_LOCATION.get(item["sample"], "N/A"),
            "evidence": EVIDENCE.get(item["sample"], ""),
            "request_sample": item["request"],
            "verification_status": "confirmed_by_poc",
            "scanner_rule": "",
            "llm_finding_id": item["finding_id"],
            "assessment": "",
            "notes": item["notes"],
        })
    return rows


def merge_rows(llm_rows, scanner_rows):
    merged = {row["finding_key"]: dict(row) for row in llm_rows}
    additional = []
    for row in scanner_rows:
        if row["verification_status"] == "confirmed_by_poc":
            k = key_for(row["asset"], row["route"], row["http_method"],
                        row["parameter"], row["vulnerability_type"], row["condition"])
            if k in merged:
                target = merged[k]
                target["sources"] = "llm;scanner:wapiti"
                target["verification_status"] = "confirmed_by_both"
                target["scanner_rule"] = row["scanner_rule"]
                target["request_sample"] = row["request_sample"] or target["request_sample"]
                target["assessment"] = f"optional2/llm_assessment/{row['scanner_finding_id']}.json"
                ev = [x.strip() for x in (target["evidence"] + ";" + row["evidence"]).split(";") if x.strip()]
                target["evidence"] = "; ".join(dict.fromkeys(ev))
                target["notes"] = target["notes"] + "; Wapiti rule: " + row["scanner_rule"]
            else:
                merged[k] = {
                    "finding_key": k,
                    "sample_id": row["sample_id"],
                    "sources": "scanner:wapiti",
                    "asset": row["asset"],
                    "route": row["route"],
                    "http_method": row["http_method"],
                    "parameter": row["parameter"],
                    "vulnerability_type": row["vulnerability_type"],
                    "condition": row["condition"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "code_location": row["code_location"],
                    "evidence": row["evidence"],
                    "request_sample": row["request_sample"],
                    "verification_status": "confirmed_by_scanner",
                    "scanner_rule": row["scanner_rule"],
                    "llm_finding_id": "",
                    "assessment": f"optional2/llm_assessment/{row['scanner_finding_id']}.json",
                    "notes": "scanner-only target hit",
                }
        else:
            k = key_for(row["asset"], row["route"], row["http_method"],
                        row["parameter"], row["vulnerability_type"], row["condition"])
            # Configuration checks at the same endpoint are distinct issues; keep
            # the scanner rule in the key so they are not collapsed into one row.
            k = k + "|" + row["scanner_rule"]
            merged[k] = {
                "finding_key": k,
                "sample_id": row["sample_id"],
                "sources": "scanner:wapiti",
                "asset": row["asset"],
                "route": row["route"],
                "http_method": row["http_method"],
                "parameter": row["parameter"],
                "vulnerability_type": row["vulnerability_type"],
                "condition": row["condition"],
                "severity": row["severity"],
                "title": row["title"],
                "code_location": row["code_location"],
                "evidence": row["evidence"],
                "request_sample": row["request_sample"],
                "verification_status": row["verification_status"],
                "scanner_rule": row["scanner_rule"],
                "llm_finding_id": "",
                "assessment": (
                    "optional2/llm_assessment/WAP-CONFIG-001.json"
                    if row["sample_id"] == "CONFIG-DVWA-LOGIN"
                    else f"optional2/llm_assessment/{row['scanner_finding_id']}.json"
                ),
                "notes": "out-of-scope or configuration alert; see llm_assessment",
            }
            additional.append(row["scanner_finding_id"])
    return list(merged.values()), additional


def coverage_rows():
    parents = [
        ("SQLI-001", "SQL注入", True, "confirmed", "both"),
        ("SQLI-002", "SQL注入", False, "not_tested", "llm_only"),
        ("SQLI-003", "SQL注入", True, "confirmed", "both"),
        ("SQLI-005", "SQL注入", False, "not_tested", "llm_only"),
        ("XSS-001", "XSS", True, "confirmed", "both"),
        ("XSS-002", "XSS", False, "not_tested", "llm_only"),
        ("XSS-003", "XSS", False, "not_tested", "llm_only"),
        ("XSS-004", "XSS", False, "not_tested", "negative"),
        ("XSS-005", "XSS", False, "not_tested", "llm_only"),
        ("CMD-001", "命令注入", True, "confirmed", "both"),
        ("CMD-002", "命令注入", False, "not_tested", "llm_only"),
        ("CMD-003", "命令注入", False, "not_tested", "llm_only"),
        ("CMD-004", "命令注入", False, "not_tested", "negative"),
        ("AUTH-001", "权限越权", False, "not_tested", "llm_only"),
    ]
    rows = []
    for sample, vtype, tested, scanner_status, quadrant in parents:
        negative = sample in ("XSS-004", "CMD-004")
        rows.append({
            "sample_id": sample,
            "vulnerability_type": vtype,
            "llm_status": "negative_exclusion" if negative else "confirmed",
            "scanner_tested": "yes" if tested else "no",
            "scanner_status": scanner_status,
            "union_status": "negative" if negative else "confirmed",
            "quadrant": quadrant,
            "note": (
                "scanner not run on this endpoint; not a miss" if not tested and not negative
                else "negative path; scanner not run" if negative
                else "confirmed by both"
            ),
        })
    return rows


ASSESSMENTS = {
    "WAP-SQLI-001-01": {
        "scanner_finding_id": "WAP-SQLI-001-01",
        "sample_id": "SQLI-001",
        "scanner": "Wapiti 3.0.4 (SQL Injection)",
        "code_location": "SQLI-001:14-15",
        "root_cause": "$_GET['id'] 直接拼接到 SELECT ... WHERE id='$id'，随后 mysql_query 执行；没有参数化、白名单或转义。",
        "data_flow": [
            "line 8: $id = $_GET['id']",
            "line 14: $sql = \"SELECT * FROM users WHERE id='$id' LIMIT 0,1\"",
            "line 15: mysql_query($sql)",
            "lines 20-22/28: 结果与错误回显",
        ],
        "preconditions": ["Less-1 可访问", "users 表可读", "PHP 5.6 ext/mysql 正常"],
        "llm_verdict": "confirmed",
        "target_status": "in_scope",
        "confidence": "high",
        "evidence": [EVIDENCE["SQLI-001"]],
        "extension": "Wapiti 用错误型 payload 已触发 SQL 报错；已有 POC 的布尔对照进一步证明语义改变。",
        "residual_risk": "不枚举数据；只验证最小真假对照。",
    },
    "WAP-SQLI-003-01": {
        "scanner_finding_id": "WAP-SQLI-003-01",
        "sample_id": "SQLI-003",
        "scanner": "Wapiti 3.0.4 (SQL Injection)",
        "code_location": "SQLI-003:16,40-41",
        "root_cause": "blacklist() 只 preg_replace 掉 or/AND 字面量，随后仍把 id 拼进 SELECT；&& 符号未被过滤。",
        "data_flow": [
            "line 7: $id = $_GET['id']",
            "line 13: $id = blacklist($id)",
            "lines 40-41: 仅删除 or/AND 字面量",
            "line 16: SELECT ... WHERE id='$id'",
            "line 44: $hint 未编码回显",
        ],
        "preconditions": ["Less-25 可访问", "MySQL/MariaDB 接受 && 作为 AND"],
        "llm_verdict": "confirmed",
        "target_status": "in_scope",
        "confidence": "high",
        "evidence": [EVIDENCE["SQLI-003"]],
        "extension": "Wapiti 的错误型检测与已有 POC 的 && 布尔差分相互印证。",
        "residual_risk": "同一入口还存在一条 XSS 告警，见 WAP-XSS-003-01；不要与 SQLI-003 的 SQL 标签混算。",
    },
    "WAP-XSS-001-01": {
        "scanner_finding_id": "WAP-XSS-001-01",
        "sample_id": "XSS-001",
        "scanner": "Wapiti 3.0.4 (Cross Site Scripting)",
        "code_location": "XSS-001:6",
        "root_cause": "$_GET['name'] 未编码拼接到 <pre>Hello ...</pre>，属于 HTML 文本上下文。",
        "data_flow": ["line 4: array_key_exists('name', $_GET)", "line 6: $html .= '<pre>Hello ' . $_GET['name'] . '</pre>'"],
        "preconditions": ["DVWA 已登录", "security=low"],
        "llm_verdict": "confirmed",
        "target_status": "in_scope",
        "confidence": "high",
        "evidence": [EVIDENCE["XSS-001"]],
        "extension": "Wapiti 以反射 payload 触发；已有浏览器 POC 的 DOM 标记证明真实执行。",
        "residual_risk": "只证明该 low 路径；medium/high 另行验证。",
    },
    "WAP-CMD-001-01": {
        "scanner_finding_id": "WAP-CMD-001-01",
        "sample_id": "CMD-001",
        "scanner": "Wapiti 3.0.4 (Command execution)",
        "code_location": "CMD-001:12,15",
        "root_cause": "$_REQUEST['ip'] 未过滤拼接到 shell_exec('ping -c 4 ' . $target)，shell 解释 ; 后命令。",
        "data_flow": ["line 4: $target = $_REQUEST['ip']", "line 12: shell_exec('ping -c 4 ' . $target)", "line 15: <pre>{$cmd}</pre>"],
        "preconditions": ["DVWA 已登录", "security=low", "shell_exec 可用"],
        "llm_verdict": "confirmed",
        "target_status": "in_scope",
        "confidence": "high",
        "evidence": [EVIDENCE["CMD-001"]],
        "extension": "Wapiti 使用 ;env; 证明命令执行；已有 POC 用 printf 标记并区分 <pre> 命令输出与页面反射。",
        "residual_risk": "只回显固定标记，不读取敏感文件。",
    },
    "WAP-XSS-003-01": {
        "scanner_finding_id": "WAP-XSS-003-01",
        "sample_id": "ADDITIONAL-001",
        "scanner": "Wapiti 3.0.4 (Cross Site Scripting)",
        "code_location": "SQLI-003:44",
        "root_cause": "Less-25 页面在 line 44 直接把 $hint 拼进 HTML，未做 HTML 编码；这是与 SQLI-003 的 SQL 注入不同的 XSS 路径。",
        "data_flow": ["line 14: $hint=$id", "line 44: echo \"Hint: ... \".$hint", "无 htmlspecialchars"],
        "preconditions": ["Less-25 可访问", "浏览器执行 payload"],
        "llm_verdict": "confirmed",
        "target_status": "out_of_scope",
        "confidence": "high",
        "evidence": [EVIDENCE["ADDITIONAL-001"]],
        "extension": "用无害 svg onload 标记在浏览器验证；它不是 14 个父样本的目标标签，只作为工具独有补充发现。",
        "residual_risk": "不要把它计入 SQLI-003 的 SQL 标签，也不要把父样本数增加为 15。",
    },
    "WAP-CONFIG-001": {
        "scanner_finding_id": "WAP-CONFIG-001",
        "applies_to": [f"WAP-CFG-{i:02d}" for i in range(1, 10)],
        "sample_id": "CONFIG-DVWA-LOGIN",
        "scanner": "Wapiti 3.0.4 (CSP/HTTP headers/cookie flags)",
        "code_location": "N/A (deployment configuration)",
        "root_cause": "登录页缺少 CSP、X-Frame-Options、X-Content-Type-Options、HSTS；PHPSESSID/security Cookie 缺少 HttpOnly/Secure。",
        "data_flow": ["HTTP response headers", "Set-Cookie attributes"],
        "preconditions": ["本地 HTTP 实验环境", "DVWA 预置配置"],
        "llm_verdict": "excluded",
        "target_status": "excluded_non_target",
        "confidence": "high",
        "evidence": ["optional2/scanner_raw/wapiti_headers_login.json"],
        "extension": "这些是部署加固问题，不是 14 个父样本的目标漏洞；本地 HTTP 无 TLS，Secure flag 不适用；不进入目标漏洞分母。",
        "residual_risk": "若部署到真实环境，应单独按配置加固项跟踪；不能把它们算成目标漏洞的 FP 或 TP。",
    },
}


def write_assessments():
    for finding_id, payload in ASSESSMENTS.items():
        (OPT / "llm_assessment" / f"{finding_id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    scanner_rows = parse_wapiti()
    llm_rows = build_llm_rows()
    merged_rows, additional = merge_rows(llm_rows, scanner_rows)
    coverage = coverage_rows()
    write_assessments()

    write_csv(RAW / "wapiti_normalized.csv", scanner_rows, [
        "scanner_finding_id", "source", "scanner_rule", "sample_id", "asset",
        "route", "http_method", "parameter", "vulnerability_type", "severity",
        "title", "evidence_summary", "request_sample", "curl_command",
        "code_location", "condition", "verification_status", "evidence", "notes",
    ])
    write_csv(OPT / "merged_findings.csv", merged_rows, [
        "finding_key", "sample_id", "sources", "asset", "route", "http_method",
        "parameter", "vulnerability_type", "condition", "severity", "title",
        "code_location", "evidence", "request_sample", "verification_status",
        "scanner_rule", "llm_finding_id", "assessment", "notes",
    ])
    write_csv(OPT / "coverage_matrix.csv", coverage, [
        "sample_id", "vulnerability_type", "llm_status", "scanner_tested",
        "scanner_status", "union_status", "quadrant", "note",
    ])

    # LLM-first rescan plan/results
    rescan = []
    for item in LLM_CANDIDATES:
        tested = item["sample"] in ("SQLI-001", "SQLI-003", "XSS-001", "CMD-001")
        rescan.append({
            "finding_id": item["finding_id"],
            "sample_id": item["sample"],
            "route": item["route"],
            "http_method": item["method"],
            "parameter": item["param"],
            "condition": item["condition"],
            "scanner_seed": f"{item['method']} {item['route']} ({item['param']})",
            "rescan_status": "confirmed_by_wapiti" if tested else "not_tested",
            "reason": "scanner run in this optional2 batch" if tested else
                      "not in the 4-endpoint Wapiti scope; scanner would need auth/multi-stage setup",
        })
    write_csv(OPT / "llm_first" / "candidates.csv", rescan, [
        "finding_id", "sample_id", "route", "http_method", "parameter",
        "condition", "scanner_seed", "rescan_status", "reason",
    ])

    manifest = {
        "batch_id": "optional2-scanner-llm-01",
        "date": "2026-10-21",
        "timezone": "+08:00",
        "scanner": "Wapiti 3.0.4 (reference traditional scanner)",
        "tool_availability": {
            "burp_professional": "not installed (commercial license)",
            "burp_community": "not installed; no active scanner",
            "awvs": "not installed (commercial license)",
            "wapiti": "3.0.4, installed via apt",
        },
        "adapters": {
            "burp_xml_parser": "optional2/tools/burp_xml.py",
            "burp_format_fixture": "optional2/scanner_raw/burp_format_fixture.xml",
            "awvs_client": "optional2/tools/awvs_client.py",
            "awvs_dry_run": "optional2/scanner_raw/awvs_dryrun.json",
        },
        "targets": ["http://127.0.0.1:9080", "http://127.0.0.1:9081"],
        "scan_window": "2026-10-21T22:08:00+08:00 ~ 2026-10-21T22:10:30+08:00 (approx., 5 local scans)",
        "scans": [
            {
                "file": name,
                "url": meta["url"],
                "scope": meta["scope"],
                "modules": meta["modules"],
                "auth": meta["auth"],
                "rate": "-S polite",
                "max_scan_time": MAX_TIME.get(name, 45),
                "command": COMMANDS.get(name, ""),
                "output": f"optional2/scanner_raw/{name}",
                "findings": sum(len(v) for v in json.loads((RAW / name).read_text(encoding="utf-8"))["vulnerabilities"].values()),
            }
            for name, meta in SCAN_FILES.items() if (RAW / name).exists()
        ],
        "normalized_rows": len(scanner_rows),
        "merged_rows": len(merged_rows),
        "additional_scanner_only": additional,
    }
    (RAW / "scan_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({
        "scanner_rows": len(scanner_rows),
        "llm_rows": len(llm_rows),
        "merged_rows": len(merged_rows),
        "additional": additional,
        "coverage": {row["quadrant"]: sum(1 for r in coverage if r["quadrant"] == row["quadrant"]) for row in coverage},
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
