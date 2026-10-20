"""Rebuild optional task 1 from immutable historical records; never execute a POC."""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import shutil
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "optional1"
COHORTS = [
    ("v1", "wp2-eval-42", "v1", True),
    ("v2", "wp2-eval-42", "v2", True),
    ("v3", "wp4-final-wp4-v2", "final-wp4-v2", True),
    ("historical-final", "wp2-eval-42", "final", False),
    ("wp4-baseline-final", "wp4-baseline-final", "final", False),
    ("wp4-intermediate", "wp4-final-wp4-v1", "final-wp4-v1", False),
]
SOURCE_COMMIT = "533b87dd1225d6bd11cb8bdc98b0f2f91eb69617"
SOURCE_ZIP_SHA256 = "5de86d0de9be93aed2308d557d5322a8960bde423fa82d6af5f7ec63e549f200"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_csv(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fields or list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ratio(n, d):
    return n / d if d else None


def classification(prediction: str, truth: str):
    if truth not in ("有漏洞", "无所关注漏洞"):
        return "U"
    if prediction == "存在候选":
        return "TP" if truth == "有漏洞" else "FP"
    if prediction == "未检出候选":
        return "FN" if truth == "有漏洞" else "TN"
    return "U"


def classification_metrics(counts):
    tp, fp, fn, tn = (counts.get(k, 0) for k in ("TP", "FP", "FN", "TN"))
    return {
        "precision": (tp, tp + fp),
        "recall": (tp, tp + fn),
        "f1": (2 * tp, 2 * tp + fp + fn),
        "accuracy": (tp + tn, tp + fp + fn + tn),
        "false_positive_rate": (fp, fp + tn),
    }


def nonempty_strings(x):
    return isinstance(x, list) and bool(x) and all(isinstance(s, str) and s.strip() for s in x)


def audit_block(text: str):
    match = re.search(r"BEGIN_AUDIT_DATA_([0-9a-f]+)\n(.*?)\nEND_AUDIT_DATA_\1", text, re.S)
    if not match:
        raise ValueError("Missing audit data boundary")
    return match.group(2)


def field_completeness(data):
    """Literal four-field completeness. Negative narrative is not silently inferred."""
    fs = data.get("findings", [])
    locations = [x for f in fs for x in f.get("locations", [])] if fs else data.get("exclusion_evidence", [])
    has_lines = bool(locations) and all(
        isinstance(x.get("line_start"), int) and isinstance(x.get("line_end"), int)
        and x["line_start"] > 0 and x["line_end"] >= x["line_start"]
        and bool(x.get("fragment_id")) and bool(x.get("quote")) for x in locations
    )
    has_flow = bool(fs) and all(nonempty_strings(f.get("data_flow")) for f in fs)
    has_preconditions = bool(fs) and all(nonempty_strings(f.get("preconditions")) for f in fs)
    has_status = data.get("verdict") in ("确认", "待验证", "排除")
    return dict(line_fields=int(has_lines), data_flow_fields=int(has_flow),
                precondition_fields=int(has_preconditions), conclusion_field=int(has_status),
                evidence_complete=int(has_lines and has_flow and has_preconditions and has_status))


def build():
    checker = load_module("optional1_protocol", ROOT / "prompts/tools/check_outputs.py")
    gt_all = read_csv(ROOT / "results/batches/wp4-poc-01/ground_truth.csv")
    gt = {r["sample_id"]: r for r in gt_all if r["main_condition"] == "yes"}
    if len(gt) != 14 or len(gt_all) != 17:
        raise ValueError("Unexpected ground-truth population")
    source_manifest = {}
    source_audit = []
    records, pocs, frozen_inputs, failures = [], [], [], []
    same_data = {}
    snapshots = {}

    def remember(path):
        source_manifest[path.relative_to(ROOT).as_posix()] = sha(path.read_bytes())

    remember(ROOT / "results/batches/wp4-poc-01/ground_truth.csv")
    remember(ROOT / "prompts/tools/check_outputs.py")
    for path in (ROOT / "workpackage1").rglob("*"):
        if path.is_file() and path.suffix in (".php", ".js", ".json", ".md", ".csv"):
            remember(path)
    for g in gt_all:
        d = ROOT / g["evidence_dir"]
        if not d.is_dir():
            raise ValueError(f"Missing evidence: {d}")
        for p in d.iterdir():
            if p.is_file():
                remember(p)
    for alias, batch_name, version, primary in COHORTS:
        batch = ROOT / "results/batches" / batch_name
        runs_path = batch / "model_runs.csv"
        remember(runs_path)
        runs = [r for r in read_csv(runs_path) if r["prompt_version"] == version]
        if len(runs) != 14 or {r["sample_id"] for r in runs} != set(gt):
            raise ValueError(f"Incomplete or duplicate cohort: {alias}")
        manifest_path = ROOT / "prompts/prepared" / (
            f"{version}/manifest.json" if version.startswith("final-wp4") else "manifest.json")
        remember(manifest_path)
        manifest = read_json(manifest_path)
        entries = [e for e in manifest["entries"] if e["prompt_version"] == version]
        if len(entries) != 17:
            raise ValueError(f"Unexpected prompt population: {alias}")
        full_prompt_sections = []
        for run in sorted(runs, key=lambda x: x["sample_id"]):
            sid = run["sample_id"]
            source = ROOT / run["raw_output_path"]
            remember(source)
            data = read_json(source)
            if (data["sample_id"], data["prompt_version"], data["analysis_stage"]) != (sid, version, "parent"):
                raise ValueError(f"Output identity mismatch: {source}")
            if data["prediction"] != run["prediction"]:
                raise ValueError(f"Run prediction mismatch: {source}")
            snapshots[(alias, sid)] = data
            dest = OUT / "raw_outputs" / alias / f"{sid}.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
            input_entries = sorted([e for e in entries if e["sample_id"] == sid], key=lambda e: e["packet_id"])
            input_texts, packet_hashes = [], []
            for e in input_entries:
                p = ROOT / e["prompt_file"]
                remember(p)
                raw = p.read_bytes()
                # Historical manifests sometimes hashed canonical LF text rather than stored CRLF bytes.
                text = p.read_text(encoding="utf-8-sig")
                canonical_sha = sha(text.encode("utf-8"))
                valid = e["prompt_sha256"] in (sha(raw), canonical_sha)
                if not valid:
                    raise ValueError(f"Prompt manifest mismatch: {p}")
                block = audit_block(text)
                data_hash = sha(block.encode("utf-8"))
                packet = e["packet_id"]
                if packet in same_data and same_data[packet] != data_hash:
                    raise ValueError(f"Audited data changed across versions: {packet}")
                same_data[packet] = data_hash
                dst = OUT / "raw_inputs" / alias / p.name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, dst)
                input_texts.append(text)
                packet_hashes.append(e["prompt_sha256"])
                frozen_inputs.append(dict(cohort=alias, sample_id=sid, packet_id=packet,
                    source_path=p.relative_to(ROOT).as_posix(), copy_path=dst.relative_to(OUT).as_posix(),
                    bytes_sha256=sha(raw), lf_text_sha256=canonical_sha,
                    recorded_prompt_sha256=e["prompt_sha256"], audit_data_sha256=data_hash))
                full_prompt_sections.append(f"## {packet}\n\n{text}")
            # The original scripts used two distinct bundle-hash algorithms.
            bundle_algorithm = ("sha256_json_packet_hashes" if batch_name in
                                ("wp2-eval-42", "wp4-final-wp4-v2") else "sha256_concatenated_prompt_bytes")
            bundle_hash = (sha(json.dumps(packet_hashes).encode()) if
                           bundle_algorithm == "sha256_json_packet_hashes" else
                           sha(b"".join((ROOT/e["prompt_file"]).read_bytes() for e in input_entries)))
            if bundle_hash != run["prompt_bundle_sha256"]:
                raise ValueError(f"Historical input bundle hash mismatch: {alias}/{sid}")
            source_audit.append(dict(cohort=alias, sample_id=sid,
                historical_bundle_sha256=run["prompt_bundle_sha256"],
                hash_algorithm=bundle_algorithm, recomputed_bundle_hash=bundle_hash,
                matches_historical_hash=int(run["prompt_bundle_sha256"] == bundle_hash),
                packet_manifest_verified=1))
            try:
                checker.check(data)
                strict_ok, strict_error = 1, ""
            except (ValueError, KeyError, TypeError, SyntaxError, OSError) as exc:
                strict_ok, strict_error = 0, str(exc)
            if not strict_ok:
                failures.append(dict(cohort=alias, sample_id=sid, error=strict_error,
                    source_output=source.relative_to(ROOT).as_posix()))
            complete = field_completeness(data)
            generated = 0
            for idx, finding in enumerate(data.get("findings", []), 1):
                pc = finding.get("poc") or {}
                code = pc.get("code")
                artifact = pc.get("artifact_path")
                if not code and artifact:
                    ap = (ROOT / artifact).resolve()
                    if not ap.is_relative_to(ROOT) or not ap.is_file():
                        raise ValueError("Invalid POC reference")
                    remember(ap)
                    code = ap.read_text(encoding="utf-8-sig")
                if not isinstance(code, str) or not code.strip():
                    continue
                generated += 1
                fid = finding["finding_id"]
                code_path = OUT / "pocs" / alias / f"{sid}__{idx}.py"
                code_path.parent.mkdir(parents=True, exist_ok=True)
                code_path.write_text(code, encoding="utf-8", newline="\n")
                syntax = "not_python"
                if str(pc.get("language", "")).lower().startswith("python"):
                    try:
                        compile(code, str(code_path), "exec")
                        syntax = "pass"
                    except SyntaxError:
                        syntax = "fail"
                if pc.get("execution_status") != "未运行":
                    raise ValueError("New execution evidence requires explicit review")
                pocs.append(dict(cohort=alias, sample_id=sid, finding_id=fid,
                    code_path=code_path.relative_to(OUT).as_posix(), code_sha256=sha(code.encode()),
                    syntax_status=syntax, execution_status="not_run",
                    success="", failure_category="", runtime_evidence="",
                    source_output=source.relative_to(ROOT).as_posix()))
            g = gt[sid]
            records.append(dict(cohort=alias, primary=int(primary), source_batch=batch_name,
                prompt_version=version, sample_id=sid, vulnerability_type=g["vulnerability_type"],
                input_version=run["input_version"], condition_key=g["condition_key"],
                historical_model_condition=run["condition_key"], ground_truth=g["parent_ground_truth"],
                prediction=data["prediction"], verdict=data["verdict"],
                classification=classification(data["prediction"], g["parent_ground_truth"]),
                model_name=run["model_name"], model_snapshot=run["model_version"],
                model_parameters=run["model_parameters"], run_date=run["run_date"],
                elapsed_seconds="", tokens="", api_call_count="",
                recorded_parent_tasks=1, packets=len(input_entries),
                input_characters=sum(map(len, input_texts)),
                output_characters=len(source.read_text(encoding="utf-8-sig")),
                generated_pocs=generated, strict_protocol_pass=strict_ok,
                strict_protocol_error=strict_error, **complete,
                exclusion_evidence_count=len(data.get("exclusion_evidence", [])),
                source_output=source.relative_to(ROOT).as_posix(),
                output_sha256=sha(source.read_bytes()),
                historical_bundle_sha256=run["prompt_bundle_sha256"],
                evidence_dir=g["evidence_dir"], label_review=g["review_status"]))
        if primary:
            version_doc = (
                f"# 选做1 {alias} 完整 Prompt 快照\n\n"
                f"报告代号 {alias} 对应源版本 `{version}`，源批次 `{batch_name}`。"
                "下列17包是历史实测输入全文的可读汇编；逐字节原件见 raw_inputs 对应目录，"
                "原输出版本名保持不变。此汇编不是新的模型输入或新运行证据。\n\n"
            )
            path = OUT / "prompts" / f"{alias}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(version_doc + "\n\n".join(full_prompt_sections), encoding="utf-8")
    if len(records) != 84 or len(same_data) != 17:
        raise ValueError("Unexpected analysis population")
    write_csv(OUT / "labeled_results.csv", records)
    write_csv(OUT / "input_manifest.csv", frozen_inputs)
    write_csv(OUT / "source_hash_audit.csv", source_audit)
    write_csv(OUT / "poc_execution.csv", pocs)
    followup_template = []
    for p in pocs:
        if p["cohort"] not in ("v1", "v2", "v3"):
            continue
        followup_template.append(dict(
            cohort=p["cohort"], sample_id=p["sample_id"], finding_id=p["finding_id"],
            code_sha256=p["code_sha256"], environment_id="", condition_key="", reviewer="",
            started_at="", elapsed_seconds="", execution_status="not_run", success="",
            failure_category="", command_redacted="", evidence_path="", restore_status="",
            adaptation_level="original", notes=""))
    write_csv(OUT / "followup_poc_results.template.csv", followup_template)
    write_csv(OUT / "protocol_failures.csv", failures)
    write_csv(OUT / "ground_truth.csv", gt_all)
    metrics = []

    def metric(alias, scope, name, n, d, status="observed", note=""):
        val = ratio(n, d) if status == "observed" else None
        metrics.append(dict(cohort=alias, scope=scope, metric=name, numerator=n,
            denominator=d, value="" if val is None else f"{val:.8f}",
            display="待测" if status == "not_measured" else ("不适用" if val is None else f"{val*100:.2f}%"),
            status=status, note=note))

    for alias, _, _, _ in COHORTS:
        group = [r for r in records if r["cohort"] == alias]
        for scope in ["ALL"] + sorted({r["vulnerability_type"] for r in group}):
            rows = [r for r in group if scope == "ALL" or r["vulnerability_type"] == scope]
            counts = Counter(r["classification"] for r in rows)
            for name, (n, d) in classification_metrics(counts).items():
                metric(alias, scope, name, n, d, note="父样本主条件与历史实测标签的一致性；非独立泛化成绩")
            metric(alias, scope, "strict_protocol", sum(r["strict_protocol_pass"] for r in rows), len(rows))
            metric(alias, scope, "evidence_complete", sum(r["evidence_complete"] for r in rows), len(rows),
                   note="四项显式字段同时齐全；负例缺data_flow/preconditions计不齐，不自动从叙述推断")
            metric(alias, scope, "unknown_fraction", counts["U"], len(rows))
            n_poc = sum(r["generated_pocs"] for r in rows)
            metric(alias, scope, "poc_runnable_rate", "", n_poc, "not_measured",
                   "分母为生成POC总数；原稿未执行，分子未知，不填0%")
        by_poc = [p for p in pocs if p["cohort"] == alias]
        metric(alias, "ALL", "poc_syntax", sum(p["syntax_status"] == "pass" for p in by_poc), len(by_poc),
               note="只编译，不执行；不是POC可运行率")
    write_csv(OUT / "metrics.csv", metrics)
    costs = []
    for alias, _, _, _ in COHORTS:
        rows = [r for r in records if r["cohort"] == alias]
        costs.append(dict(cohort=alias, recorded_parent_tasks=len(rows),
            extra_preserved_attempts=1 if alias == "v1" else 0,
            prompt_packets=sum(r["packets"] for r in rows),
            average_input_characters=round(sum(r["input_characters"] for r in rows)/len(rows), 2),
            average_output_characters=round(sum(r["output_characters"] for r in rows)/len(rows), 2),
            mean_latency_seconds="", total_tokens="", total_api_calls="",
            note="任务数不是API内部调用数；字符数不是Token；耗时和Token未保存"))
    write_csv(OUT / "costs.csv", costs)
    deltas = []
    for left, right in [("v1", "v2"), ("v2", "v3"), ("v1", "v3"),
                        ("v2", "historical-final"), ("wp4-baseline-final", "wp4-intermediate"),
                        ("wp4-intermediate", "v3")]:
        for name in ["precision", "recall", "f1", "strict_protocol", "evidence_complete"]:
            a, b = [next(m for m in metrics if m["cohort"] == c and m["scope"] == "ALL" and m["metric"] == name)
                    for c in (left, right)]
            av, bv = float(a["value"]), float(b["value"])
            deltas.append(dict(baseline=left, comparison=right, metric=name,
                baseline_value=av, comparison_value=bv, percentage_point_change=round((bv-av)*100, 2),
                relative_change_percent=round((bv-av)/av*100, 2) if av else "",
                interpretation="历史观察差值，非随机受控因果估计"))
    write_csv(OUT / "deltas.csv", deltas)
    strict_counts = {alias: sum(r["strict_protocol_pass"] for r in records if r["cohort"] == alias)
                     for alias, *_ in COHORTS}
    classification_ids = {
        alias: {cl: [r["sample_id"] for r in records if r["cohort"] == alias and r["classification"] == cl]
                for cl in ("TP", "FP", "FN", "TN", "U")} for alias, *_ in COHORTS
    }
    summary = dict(source_commit=SOURCE_COMMIT, source_zip_sha256=SOURCE_ZIP_SHA256,
        historical_records=84, primary_records=42, parent_samples=14, condition_rows=17,
        unique_audit_packets=17, audit_input_equal_across_versions=True,
        strict_counts=strict_counts, classification_ids=classification_ids,
        poc_counts=dict(Counter(p["cohort"] for p in pocs)),
        poc_executed=0, assignment_fully_satisfied=False,
        missing_requirements=["各版本模型POC原稿的实测可运行率",
                              "历史单次运行耗时及可核验的模型采样参数",
                              "人工成员独立复核记录及预先冻结标签的时间证据"],
        v3_caveat="CR-008对CMD-004提出负例最小条数，含样本特定提示；属于同集调优，不能当作盲测泛化",
        raw_outputs_modified=False)
    write_json(OUT / "checks/summary.json", summary)
    write_json(OUT / "checks/source_manifest.json", dict(source_commit=SOURCE_COMMIT,
        zip_sha256=SOURCE_ZIP_SHA256, files=source_manifest))
    write_json(OUT / "checks/rebuild_checks.json", dict(
        status="pass", historical_outputs_checked=len(records), copied_inputs=len(frozen_inputs),
        unique_audit_packets_checked=len(same_data), all_packet_hashes_verified=True,
        source_files_hashed=len(source_manifest), strict_protocol_counts=strict_counts))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def verify_sources():
    manifest = read_json(OUT / "checks/source_manifest.json")
    changed = [name for name, digest in manifest["files"].items()
               if not (ROOT/name).is_file() or sha((ROOT/name).read_bytes()) != digest]
    if changed:
        raise ValueError(f"Frozen sources changed: {changed}")
    print(f"Frozen sources verified: {len(manifest['files'])}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-sources", action="store_true")
    args = parser.parse_args()
    if args.verify_sources:
        verify_sources()
    else:
        if (OUT / "checks/source_manifest.json").exists():
            verify_sources()
        build()
