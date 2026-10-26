"""Parse a Burp Suite Professional XML report into optional2 normalized rows.

Usage:
    python burp_xml.py --input report.xml --output burp_normalized.csv

The parser only reads the XML; it does not run Burp or send requests.  It is
tested against optional2/scanner_raw/burp_format_fixture.xml (a format fixture,
not a real Burp scan).
"""
from __future__ import annotations

import argparse
import base64
import csv
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def text(node, path, default=""):
    child = node.find(path)
    return (child.text or default).strip() if child is not None else default


def method_of(req):
    match = re.match(r"\s*([A-Z]+)\s+", req or "")
    return match.group(1) if match else ""


def decode_request(node):
    if node is None:
        return ""
    raw = (node.text or "").strip()
    if node.get("base64", "false").lower() == "true":
        try:
            raw = base64.b64decode(raw).decode("utf-8", "replace")
        except Exception:
            pass
    return raw


def vuln_type(name: str) -> str:
    lower = name.lower()
    if "sql injection" in lower or "sql-injection" in lower:
        return "SQL注入"
    if "cross-site scripting" in lower or "xss" in lower:
        return "XSS"
    if "command injection" in lower or "os command" in lower:
        return "命令注入"
    if "authorization" in lower or "access control" in lower or "privilege" in lower:
        return "权限越权"
    return "配置加固"


def parse(path: Path):
    tree = ET.parse(path)
    root = tree.getroot()
    rows = []
    for index, issue in enumerate(root.findall("issue"), 1):
        name = text(issue, "name")
        host = text(issue, "host")
        route = text(issue, "path") or text(issue, "location")
        location = text(issue, "location")
        parameter = ""
        if "[" in location and "]" in location:
            parameter = location.split("[", 1)[1].split("]", 1)[0].split()[0]
        request = decode_request(issue.find("requestresponse/request"))
        method = method_of(request)
        severity = text(issue, "severity", "Information")
        confidence = text(issue, "confidence", "")
        rows.append({
            "scanner_finding_id": f"BURP-{index:03d}",
            "source": "scanner:burp",
            "scanner_rule": name,
            "sample_id": "",
            "asset": host,
            "route": route,
            "http_method": method,
            "parameter": parameter,
            "vulnerability_type": vuln_type(name),
            "severity": severity,
            "confidence": confidence,
            "title": name,
            "evidence_summary": text(issue, "issueDetail")[:500],
            "request_sample": request,
            "code_location": "",
            "condition": "env=imported|scope=burp",
            "verification_status": "unverified",
            "evidence": str(path.name),
            "notes": "Burp XML import; requires dedup + human verification",
        })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = parse(args.input)
    fields = ["scanner_finding_id", "source", "scanner_rule", "sample_id", "asset",
              "route", "http_method", "parameter", "vulnerability_type", "severity",
              "confidence", "title", "evidence_summary", "request_sample",
              "code_location", "condition", "verification_status", "evidence", "notes"]
    with open(args.output, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"parsed {len(rows)} Burp issues -> {args.output}")


if __name__ == "__main__":
    main()
