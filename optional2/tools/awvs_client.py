"""Minimal Acunetix/Invicti (AWVS) REST API client for optional2.

The client is intentionally small and standard-library only.  It can:
  * print the exact create-target/schedule-scan payload (--dry-run), or
  * create a target, schedule a scan, poll it and export vulnerabilities.

No API key is written to disk or printed.  Set AWVS_API_KEY in the environment.
This environment does not have an AWVS license; the dry-run output documents the
integration contract and should be replaced with a real run when licensed.

API shape follows the public Acunetix example:
https://www.acunetix.com/blog/docs/managing-scans-bash-api/
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

FULL_SCAN_PROFILE = "11111111-1111-1111-1111-111111111111"


def api(method, base, path, api_key, payload=None, insecure=False, timeout=30):
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"X-Auth": api_key, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def vuln_type(name):
    lower = (name or "").lower()
    if "sql injection" in lower:
        return "SQL注入"
    if "cross site scripting" in lower or "xss" in lower:
        return "XSS"
    if "command injection" in lower or "os command" in lower:
        return "命令注入"
    if "authorization" in lower or "access control" in lower or "privilege" in lower:
        return "权限越权"
    return "配置加固"


def normalize(vulns, output):
    rows = []
    for index, vuln in enumerate(vulns, 1):
        url = vuln.get("affects_url", "")
        detail = vuln.get("affects_detail", "") or ""
        request = vuln.get("request", "") or ""
        method = "GET"
        for token in request.split():
            if token.isupper() and token in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                method = token
                break
        parameter = ""
        if "parameter" in detail.lower():
            parameter = detail.split("parameter", 1)[1].strip().split()[0].strip("'\"")
        rows.append({
            "scanner_finding_id": f"AWVS-{index:03d}",
            "source": "scanner:awvs",
            "scanner_rule": vuln.get("vt_name", ""),
            "sample_id": "",
            "asset": url.split("/", 3)[0] + "//" + url.split("/", 3)[2] if url else "",
            "route": "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/",
            "http_method": method,
            "parameter": parameter,
            "vulnerability_type": vuln_type(vuln.get("vt_name", "")),
            "severity": vuln.get("severity", ""),
            "confidence": vuln.get("confidence", ""),
            "title": vuln.get("vt_name", ""),
            "evidence_summary": detail[:500],
            "request_sample": request,
            "code_location": "",
            "condition": "env=imported|scope=awvs",
            "verification_status": "unverified",
            "evidence": "AWVS API export",
            "notes": f"status={vuln.get('status', '')}; last_seen={vuln.get('last_seen', '')}",
        })
    fields = ["scanner_finding_id", "source", "scanner_rule", "sample_id", "asset",
              "route", "http_method", "parameter", "vulnerability_type", "severity",
              "confidence", "title", "evidence_summary", "request_sample",
              "code_location", "condition", "verification_status", "evidence", "notes"]
    with open(output, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="https://127.0.0.1:3443/api/v1")
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", default=FULL_SCAN_PROFILE)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--max-polls", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("awvs_normalized.csv"))
    parser.add_argument("--plan", type=Path, default=Path("awvs_dryrun.json"))
    args = parser.parse_args()

    target_payload = {
        "address": args.target,
        "description": "optional2 local lab",
        "type": "default",
        "criticality": 10,
    }
    scan_payload = {
        "profile_id": args.profile,
        "incremental": False,
        "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        "user_authorized_to_scan": "yes",
        "target_id": "<target_id>",
    }
    if args.dry_run:
        plan = {
            "base": args.base,
            "create_target": {"method": "POST", "path": "/targets", "body": target_payload},
            "schedule_scan": {"method": "POST", "path": "/scans", "body": scan_payload},
            "poll": {"method": "GET", "path": "/scans/{scan_id}"},
            "results": {"method": "GET", "path": "/scans/{scan_id}/results"},
            "vulnerabilities": {
                "method": "GET",
                "path": "/scans/{scan_id}/results/{result_id}/vulnerabilities",
            },
            "note": "Set AWVS_API_KEY and drop --dry-run for a licensed instance.",
        }
        args.plan.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return

    api_key = os.environ.get("AWVS_API_KEY", "")
    if not api_key:
        raise SystemExit("AWVS_API_KEY is not set; use --dry-run or set the environment variable")

    status, headers, body = api("POST", args.base, "/targets", api_key, target_payload, args.insecure)
    if status not in (200, 201):
        raise SystemExit(f"create target failed: HTTP {status} {body[:300]}")
    target_id = json.loads(body)["target_id"]
    scan_payload["target_id"] = target_id
    status, headers, body = api("POST", args.base, "/scans", api_key, scan_payload, args.insecure)
    scan_id = headers.get("Location", "").rstrip("/").split("/")[-1]
    if not scan_id:
        raise SystemExit(f"scan scheduling did not return Location: HTTP {status} {body[:300]}")

    for _ in range(args.max_polls):
        status, _, body = api("GET", args.base, f"/scans/{scan_id}", api_key, None, args.insecure)
        data = json.loads(body)
        state = data.get("current_session", {}).get("status", "")
        if state == "completed":
            break
        if state not in ("processing", "scheduled"):
            raise SystemExit(f"invalid scan state: {state}")
        time.sleep(args.poll_seconds)
    else:
        raise SystemExit("scan did not complete within max polls")

    _, _, body = api("GET", args.base, f"/scans/{scan_id}/results", api_key, None, args.insecure)
    results = json.loads(body).get("results", [])
    if not results:
        raise SystemExit("scan has no result")
    result_id = results[0]["result_id"]
    _, _, body = api("GET", args.base,
                     f"/scans/{scan_id}/results/{result_id}/vulnerabilities",
                     api_key, None, args.insecure)
    vulns = json.loads(body).get("vulnerabilities", [])
    normalize(vulns, args.output)
    print(f"exported {len(vulns)} AWVS vulnerabilities -> {args.output}")


if __name__ == "__main__":
    main()
