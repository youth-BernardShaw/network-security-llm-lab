"""Read-only acceptance check for optional2 deliverables."""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPT = ROOT / "optional2"


def rows(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    errors = []
    merged = rows(OPT / "merged_findings.csv")
    coverage = rows(OPT / "coverage_matrix.csv")
    scanner = rows(OPT / "scanner_raw" / "wapiti_normalized.csv")
    if len(scanner) != 14:
        errors.append(f"scanner rows={len(scanner)}")
    if len(merged) != 23:
        errors.append(f"merged rows={len(merged)}")
    if len(coverage) != 14:
        errors.append(f"coverage rows={len(coverage)}")
    status = {r["verification_status"] for r in merged}
    for required in ("confirmed_by_both", "confirmed_out_of_scope", "excluded_non_target"):
        if required not in status:
            errors.append(f"missing status {required}")
    if sum(1 for r in coverage if r["quadrant"] == "both") != 4:
        errors.append("both quadrant != 4")
    if sum(1 for r in coverage if r["quadrant"] == "llm_only") != 8:
        errors.append("llm_only quadrant != 8")
    if sum(1 for r in coverage if r["union_status"] == "negative") != 2:
        errors.append("negative count != 2")
    for row in merged:
        assessment = row.get("assessment", "")
        if assessment and not (ROOT / assessment).exists():
            errors.append(f"missing assessment {assessment}")
        for evidence in row.get("evidence", "").split(";"):
            evidence = evidence.strip()
            if evidence and not (ROOT / evidence).exists():
                errors.append(f"{row['sample_id']} missing evidence {evidence}")
    for path in [OPT / "integration_architecture.png", OPT / "comparison_report.md",
                 OPT / "burp_or_awvs_config.md", OPT / "scope.md"]:
        if not path.exists() or path.stat().st_size < 500:
            errors.append(f"missing/small {path.relative_to(ROOT)}")
    raw_text = "\n".join((OPT / "scanner_raw" / p.name).read_text(encoding="utf-8", errors="replace")
                         for p in (OPT / "scanner_raw").glob("*.json"))
    if re.search(r"PHPSESSID=[A-Za-z0-9]{8,}", raw_text):
        errors.append("unredacted PHPSESSID value in scanner_raw")
    report = {
        "status": "passed" if not errors else "failed",
        "scanner_rows": len(scanner),
        "merged_rows": len(merged),
        "coverage_rows": len(coverage),
        "quadrants": {q: sum(1 for r in coverage if r["quadrant"] == q)
                      for q in ("both", "llm_only", "scanner_only", "neither", "negative")},
        "statuses": sorted(status),
        "errors": errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
