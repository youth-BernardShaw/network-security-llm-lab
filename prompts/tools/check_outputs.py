"""Check draft protocol, code citations and Python syntax; do not execute POCs."""
from pathlib import Path
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
ROOT_FIELDS = {
    "schema_version", "sample_id", "input_version", "prompt_version", "analysis_stage",
    "received_packet_ids", "prediction", "verdict", "confidence", "findings",
    "exclusion_evidence", "missing_context", "risk_notes", "quality_notes", "limitations", "runtime_evidence",
}
FINDING_FIELDS = {"finding_id", "vulnerability_type", "locations", "data_flow", "principle", "impact", "preconditions", "counterexamples", "poc"}
POC_FIELDS = {"status", "language", "code", "artifact_path", "dependencies", "parameters", "steps", "expected_observation", "success_criteria", "limitations", "execution_status"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strings(value, label):
    require(isinstance(value, list) and all(isinstance(s, str) for s in value), f"{label} must be a string array")


def repository_path(value):
    p = (ROOT / value).resolve()
    require(p.is_relative_to(ROOT.resolve()) and p.is_file(), f"Missing or external artifact: {value}")
    return p


def check(data, data_root=None, prompt_versions=None):
    data_root = Path(data_root) if data_root is not None else ROOT / "workpackage1"
    require(data_root.resolve().is_relative_to(ROOT.resolve()), "Dataset must be inside repository")
    require(isinstance(data, dict) and ROOT_FIELDS <= data.keys(), "Missing root protocol fields")
    require(data["schema_version"] == "wp2-output-v1", "Unsupported schema")
    require(data["input_version"] == "v2", "Unexpected input version")
    # final-wp4-v1/v2 are explicit work-package-4 variants; old batches keep their versions.
    allowed_versions = prompt_versions or ("v1", "v2", "final", "final-wp4-v1", "final-wp4-v2")
    require(data["prompt_version"] in allowed_versions, "Invalid prompt version")
    sid = data["sample_id"]
    require(isinstance(sid, str) and sid.replace("-", "").isalnum(), "Invalid sample ID")
    meta_path = repository_path((data_root / "sample_metadata" / f"{sid}.json").relative_to(ROOT).as_posix())
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("fragments"):
        fragments = {f["fragment_id"]: f["normalized_file"] for f in meta["fragments"]}
        packets = {p["packet_id"]: set(p["fragment_ids"]) for p in meta["packets"]}
    else:
        fragments = {sid: f"normalized_samples/{sid}.php"}
        packets = {sid: {sid}}
    received = data["received_packet_ids"]
    strings(received, "received_packet_ids")
    require(len(set(received)) == len(received) and set(received) <= packets.keys(), "Invalid received packet IDs")
    available = set().union(*(packets[p] for p in received))
    require(data["analysis_stage"] in ("partial", "parent"), "Invalid analysis stage")
    require(data["prediction"] in ("存在候选", "未检出候选", "无法判定"), "Invalid prediction")
    require(data["verdict"] in ("确认", "待验证", "排除"), "Invalid verdict")
    if data["analysis_stage"] == "parent":
        require(set(received) == set(packets), "Parent verdict lacks input packets")
    else:
        require(data["prediction"] == "无法判定" and data["verdict"] == "待验证", "Partial results cannot be scored as final verdicts")
    confidence = data["confidence"]
    require(isinstance(confidence, dict) and confidence.get("level") in ("high", "medium", "low") and isinstance(confidence.get("reason"), str) and confidence["reason"], "Invalid confidence")
    for field in ("missing_context", "risk_notes", "quality_notes", "limitations", "runtime_evidence"):
        strings(data[field], field)
    if data["verdict"] == "确认":
        require(bool(data["runtime_evidence"]), "Confirmation lacks actual runtime evidence")
    for artifact in data["runtime_evidence"]:
        repository_path(artifact)
    require(isinstance(data["findings"], list) and isinstance(data["exclusion_evidence"], list), "Invalid evidence arrays")
    require(data["prediction"] != "存在候选" or bool(data["findings"]), "Candidate prediction has no findings")
    require(data["prediction"] != "未检出候选" or not data["findings"], "Negative prediction conflicts with findings")
    if data["verdict"] == "排除":
        require(data["prediction"] == "未检出候选" and bool(data["exclusion_evidence"]), "Exclusion lacks evidence or conflicts with prediction")

    def location(loc):
        require(isinstance(loc, dict) and {"fragment_id", "line_start", "line_end", "quote"} <= loc.keys(), "Missing location fields")
        fid = loc["fragment_id"]
        require(fid in fragments and fid in available, f"Unknown or unreceived fragment: {fid}")
        code = repository_path((data_root / fragments[fid]).relative_to(ROOT).as_posix()).read_text(encoding="utf-8").splitlines()
        start, end = loc["line_start"], loc["line_end"]
        require(type(start) is int and type(end) is int and 1 <= start <= end <= len(code), f"Out-of-range citation: {fid}")
        quote = loc["quote"]
        require(isinstance(quote, str) and bool(quote.strip()) and quote in "\n".join(code[start - 1:end]), f"Quote does not match source: {fid}:{start}-{end}")

    for loc in data["exclusion_evidence"]:
        location(loc)
    ids = set()
    poc_count = 0
    for finding in data["findings"]:
        require(isinstance(finding, dict) and FINDING_FIELDS <= finding.keys(), "Missing finding fields")
        require(isinstance(finding["finding_id"], str) and finding["finding_id"] and finding["finding_id"] not in ids, "Duplicate or empty finding ID")
        ids.add(finding["finding_id"])
        require(finding["vulnerability_type"] == meta["audit_scope"], "Finding outside target scope")
        require(isinstance(finding["locations"], list) and bool(finding["locations"]), "Finding lacks location evidence")
        for loc in finding["locations"]:
            location(loc)
        for field in ("data_flow", "preconditions", "counterexamples"):
            strings(finding[field], field)
        for field in ("principle", "impact"):
            require(isinstance(finding[field], str) and bool(finding[field]), f"Empty {field}")
        poc = finding["poc"]
        require(isinstance(poc, dict) and POC_FIELDS <= poc.keys(), "Missing POC fields")
        require(poc["status"] in ("可直接运行", "需人工适配", "不提供"), "Invalid POC status")
        require(poc["execution_status"] in ("未运行", "已运行"), "Invalid execution status")
        for field in ("dependencies", "parameters", "steps", "limitations"):
            strings(poc[field], field)
        for field in ("expected_observation", "success_criteria"):
            require(isinstance(poc[field], str), f"Invalid {field}")
        if poc["execution_status"] == "已运行":
            require(bool(data["runtime_evidence"]), "Executed POC lacks runtime evidence")
        if poc["status"] != "不提供":
            code = poc["code"]
            artifact = repository_path(poc["artifact_path"]) if poc["artifact_path"] is not None else None
            if code is None:
                require(artifact is not None, "Missing full POC code or artifact")
                code = artifact.read_text(encoding="utf-8")
            require(isinstance(code, str) and bool(code.strip()), "Missing full POC code")
            if poc["language"] == "python":
                compile(code, "<poc-draft>", "exec")
                poc_count += 1
            if artifact is not None:
                require(artifact.read_text(encoding="utf-8") == code, "POC artifact differs from inline code")
    return {"sample_id": sid, "prompt_version": data["prompt_version"], "status": "passed_static_protocol", "finding_count": len(ids), "python_poc_syntax_count": poc_count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    paths = [args.path] if args.path.is_file() else sorted(args.path.rglob("*.json"))
    require(bool(paths), "No JSON output files found")
    results = []
    for path in paths:
        try:
            result = check(json.loads(path.read_text(encoding="utf-8-sig")))
            result["file"] = path.resolve().relative_to(ROOT.resolve()).as_posix()
            result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except (ValueError, OSError, SyntaxError, KeyError, TypeError) as exc:
            result = {"file": str(path), "status": "failed_static_protocol", "error": str(exc)}
        results.append(result)
    passed = sum(r["status"] == "passed_static_protocol" for r in results)
    report = {"scope": "Protocol, quote/line consistency and Python compilation only; no model calls or POC execution", "output_count": len(results), "passed_count": passed, "results": results}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
