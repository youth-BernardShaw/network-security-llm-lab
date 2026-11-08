"""One entry for baseline and optional4 inputs, model receipts and result pairing.

This is a provenance/validation adapter, not a model engine. It does not call an
unconfigured model or execute model-generated code. Pending stages remain pending.
"""
from pathlib import Path
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / "workflow/datasets.json"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def json_read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def config(name):
    registry = json_read(REGISTRY)
    if name not in registry:
        raise ValueError(f"Unknown dataset: {name}")
    return registry[name]

def under_root(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError("Path escapes repository")
    return path

def write_immutable(path, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    if path.exists() and path.read_bytes() != data:
        raise ValueError(f"Existing evidence differs; use a new attempt ID: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def save_json(path, data, immutable=False):
    body = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    if immutable:
        write_immutable(path, body)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

def csv_write(path, rows, fields):
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(buf.getvalue(), encoding="utf-8", newline="\n")

def metadata(cfg):
    data = under_root(cfg["data_root"])
    return [json_read(p) for p in sorted((data / "sample_metadata").glob("*.json"))]

def check_inputs(cfg):
    data = under_root(cfg["data_root"])
    result = []
    for meta in metadata(cfg):
        fragments = {f["fragment_id"]: f for f in meta.get("fragments", [])}
        if not fragments:
            fragments = {meta["sample_id"]: dict(raw_file=f"raw_samples/{meta['sample_id']}.php", normalized_file=f"normalized_samples/{meta['sample_id']}.php", line_map=f"line_maps/{meta['sample_id']}.csv", raw_sha256=meta["raw_sha256"], normalized_sha256=meta["normalized_sha256"])}
        for fid, fragment in fragments.items():
            raw = (data / fragment["raw_file"]).read_bytes()
            norm = (data / fragment["normalized_file"]).read_bytes()
            if sha(raw) != fragment["raw_sha256"] or sha(norm) != fragment["normalized_sha256"]:
                raise ValueError(f"Source hash mismatch: {fid}")
            original_lines = raw.decode("utf-8").splitlines()
            lines = norm.decode("utf-8").splitlines()
            with (data / fragment["line_map"]).open(encoding="utf-8-sig", newline="") as fh:
                maps = list(csv.DictReader(fh))
            if len(maps) != len(lines):
                raise ValueError(f"Incomplete mapping: {fid}")
            for n, item in enumerate(maps, 1):
                if int(item["normalized_line"]) != n:
                    raise ValueError(f"Nonsequential mapping: {fid}")
                if item["operation"] == "wrapper":
                    if item["original_line"] or lines[n - 1] not in ("<?php", "?>"):
                        raise ValueError(f"Invalid wrapper: {fid}")
                elif item["operation"] != "retained" or lines[n - 1] != original_lines[int(item["original_line"]) - 1]:
                    raise ValueError(f"Mapped content differs: {fid}:{n}")
        for packet in meta.get("packets", []):
            text = (data / packet["input_file"]).read_text(encoding="utf-8")
            blocks = re.findall(r"```(?:php|javascript)\n(.*?)\n```", text, re.S)
            if len(blocks) != len(packet["fragment_ids"]):
                raise ValueError(f"Input code block mismatch: {packet['packet_id']}")
            for fid, block in zip(packet["fragment_ids"], blocks):
                expected = (data / fragments[fid]["normalized_file"]).read_text(encoding="utf-8")
                if block != expected.rstrip("\r\n") and block != expected.rstrip():
                    raise ValueError(f"Input differs from normalized code: {fid}")
            if sum(len((data / fragments[f]["normalized_file"]).read_text(encoding="utf-8").splitlines()) for f in packet["fragment_ids"]) > 220:
                raise ValueError("Packet exceeds code budget")
        result.append(dict(sample_id=meta["sample_id"], fragment_count=len(fragments), status="passed_static_integrity"))
    return result

def prepare(name, sources=None):
    cfg = config(name)
    if name == "baseline":
        return subprocess.run([sys.executable, str(ROOT / "prompts/tools/prepare_inputs.py"), "--check"], check=True).returncode
    builder = module("optional4_builder", ROOT / "workpackage1/tools/build_optional4_inputs.py")
    builder.build(Path(sources) if sources else ROOT.parent / "source_projects")
    check_inputs(cfg)
    data = under_root(cfg["data_root"])
    template = (ROOT / "prompts/versions/final.md").read_text(encoding="utf-8")
    template = template.replace("# final 父样本综合审计Prompt", "# 选做四主流程综合审计Prompt").replace("Prompt版本final", "Prompt版本" + cfg["prompt_version"])
    template += "\n补充输出约束：每条finding的vulnerability_type精确等于本次审计范围；POC代码须完整，artifact_path填null，由导入工具归档；success_criteria与expected_observation均为字符串。此轮只做静态分析，runtime_evidence为空、POC为未运行；不读取历史验证材料。\n"
    entries = []
    for meta in metadata(cfg):
        packet_order = [p["packet_id"] for p in meta["packets"]]
        for index, packet in enumerate(meta["packets"], 1):
            input_path = data / packet["input_file"]
            source = input_path.read_text(encoding="utf-8")
            values = dict(SAMPLE_ID=meta["sample_id"], INPUT_VERSION="v2", AUDIT_SCOPE=meta["audit_scope"], PACKET_ID=packet["packet_id"], PACKET_INDEX=str(index), PACKET_COUNT=str(len(packet_order)), PACKET_ORDER=" → ".join(packet_order), COMPLETENESS_RULE="未实际收到并保有全部输入包时保持partial；收齐后形成parent结论。", SCENARIO_RULES=(ROOT / "prompts/rules" / meta["scenario_rule"]).read_text(encoding="utf-8"), OUTPUT_PROTOCOL=(ROOT / "prompts/output_schema.md").read_text(encoding="utf-8"), POC_CONSTRAINTS=(ROOT / "prompts/poc_constraints.md").read_text(encoding="utf-8"), INPUT_BLOCK="BEGIN_AUDIT_DATA\n" + source + "\nEND_AUDIT_DATA")
            body = re.sub(r"\{\{([A-Z_]+)\}\}", lambda m: values[m.group(1)], template).rstrip() + "\n"
            target = under_root(cfg["prompt_root"]) / f"{packet['packet_id']}.md"
            write_immutable(target, body)
            entries.append(dict(sample_id=meta["sample_id"], packet_id=packet["packet_id"], fragment_ids=packet["fragment_ids"], source_input=input_path.relative_to(ROOT).as_posix(), source_sha256=sha(input_path.read_bytes()), prompt_file=target.relative_to(ROOT).as_posix(), prompt_sha256=sha(target.read_bytes()), code_lines=packet["code_lines"]))
    # The complete per-parent bundle is what is actually submitted to a model.
    for sid in sorted({e["sample_id"] for e in entries}):
        own = [e for e in entries if e["sample_id"] == sid]
        body = "本文件包含本父样本的全部逐包输入。按下面顺序阅读，最终仅输出一个parent级JSON；不得访问仓库其他文件、历史标签、POC或运行证据。\n\n"
        body += "\n\n".join(under_root(e["prompt_file"]).read_text(encoding="utf-8") for e in own)
        path = under_root(cfg["prompt_root"]) / "parent_bundles" / f"{sid}.md"
        write_immutable(path, body)
    manifest = dict(dataset_id=name, input_version="v2", input_dataset_version="optional4-v1", prompt_version=cfg["prompt_version"], parent_sample_count=len(metadata(cfg)), prepared_prompt_count=len(entries), execution_status="not_run", entries=entries)
    save_json(under_root(cfg["prompt_root"]) / "manifest.json", manifest, True)
    batch = under_root(cfg["batch_root"])
    for sub in ("raw_outputs", "structured_outputs", "receipts", "pocs/original", "pocs/adapted", "verification", "checks"):
        (batch / sub).mkdir(parents=True, exist_ok=True)
    save_json(batch / "batch_manifest.json", dict(batch_id=batch.name, dataset_id=name, prompt_version=cfg["prompt_version"], created_date="2026-11-02", model_execution_status="not_run", model_name=None, model_version=None, historical_evidence_reused_as_new_run=False), True)
    return manifest

def import_output(args):
    cfg = config(args.dataset)
    if args.dataset == "baseline":
        raise ValueError("Historical baseline is immutable; select the new extension batch")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.attempt):
        raise ValueError("Invalid attempt ID")
    meta = {m["sample_id"]: m for m in metadata(cfg)}
    if args.sample not in meta:
        raise ValueError("Unknown sample")
    batch = under_root(cfg["batch_root"])
    stem = f"{args.sample}__{args.attempt}"
    raw = args.raw.read_bytes()
    raw_path = batch / "raw_outputs" / f"{stem}.txt"
    write_immutable(raw_path, raw)
    text = raw.decode("utf-8-sig").strip()
    if text.startswith("```json\n") and text.endswith("```"):
        text = text[len("```json\n"):-3].strip()
    data = json.loads(text)
    if data.get("sample_id") != args.sample or data.get("prompt_version") != cfg["prompt_version"]:
        raise ValueError("Output sample or prompt version does not match submission")
    if data.get("runtime_evidence") or data.get("verdict") == "确认":
        raise ValueError("Initial static model output cannot claim runtime confirmation")
    checker = module("output_checker", ROOT / "prompts/tools/check_outputs.py")
    check = checker.check(data, under_root(cfg["data_root"]), (cfg["prompt_version"],))
    extracted = []
    for n, finding in enumerate(data["findings"], 1):
        poc = finding["poc"]
        if poc["code"]:
            target = batch / "pocs/original" / f"{stem}__{n}.py"
            write_immutable(target, poc["code"])
            extracted.append(dict(finding_id=finding["finding_id"], path=target.relative_to(ROOT).as_posix(), sha256=sha(target.read_bytes())))
    structured = batch / "structured_outputs" / f"{stem}.json"
    save_json(structured, data, True)
    bundle = under_root(cfg["prompt_root"]) / "parent_bundles" / f"{args.sample}.md"
    receipt = dict(sample_id=args.sample, attempt_id=args.attempt, model_name=args.model_name, model_version=args.model_version, model_parameters=args.model_parameters, execution_channel=args.channel, provenance_kind="operator_supplied_original_response", imported_at=datetime.now(timezone.utc).isoformat(), source_executed_at=args.executed_at, prompt_bundle=bundle.relative_to(ROOT).as_posix(), prompt_bundle_sha256=sha(bundle.read_bytes()), raw_output=raw_path.relative_to(ROOT).as_posix(), raw_output_sha256=sha(raw), structured_output=structured.relative_to(ROOT).as_posix(), parsed_json_unchanged=True, static_protocol=check, extracted_pocs=extracted, execution_status="model_response_imported_poc_not_run", limitations=["导入回执记录操作者提供的原始回复；不冒充本工具完成API调用。", "模型身份及执行时间按实际渠道登记，未知信息保留unknown。"])
    receipt_path = batch / "receipts" / f"{stem}.json"
    if receipt_path.exists():
        old = json_read(receipt_path)
        receipt["imported_at"] = old["imported_at"]
    save_json(receipt_path, receipt, True)
    return receipt

def status(name):
    cfg = config(name)
    batch = under_root(cfg["batch_root"])
    receipts = [json_read(p) for p in sorted((batch / "receipts").glob("*.json"))]
    rows = []
    for meta in metadata(cfg):
        sid = meta["sample_id"]
        own = [r for r in receipts if r["sample_id"] == sid]
        runs = list((batch / "verification").glob(f"{sid}__*.json"))
        rows.append(dict(sample_id=sid, scope=meta["audit_scope"], input="prepared" if (under_root(cfg["prompt_root"]) / "parent_bundles" / f"{sid}.md").exists() else "historical" if name == "baseline" else "not_prepared", model_response_count=len(own), new_validation_count=len(runs), status="ready_for_comparison" if own and runs else "awaiting_poc" if own else "awaiting_model"))
    return dict(dataset_id=name, batch=cfg["batch_root"], rows=rows)

def compare(name):
    if name == "baseline":
        raise ValueError("Use the existing baseline comparison tables; historical metrics are not rewritten")
    cfg = config(name)
    batch = under_root(cfg["batch_root"])
    receipts = [json_read(p) for p in sorted((batch / "receipts").glob("*.json"))]
    runs = [json_read(p) for p in sorted((batch / "verification").glob("*.json"))]
    rows = []
    for meta in metadata(cfg):
        sid = meta["sample_id"]
        own = [r for r in receipts if r["sample_id"] == sid]
        for receipt in own or [None]:
            data = json_read(under_root(receipt["structured_output"])) if receipt else None
            matched = [r for r in runs if r.get("sample_id") == sid and receipt and r.get("attempt_id") == receipt["attempt_id"] and r.get("original_model_poc_sha256") in {p["sha256"] for p in receipt["extracted_pocs"]}]
            if not matched:
                rows.append(dict(sample_id=sid, attempt_id=receipt["attempt_id"] if receipt else "", model_prediction=data["prediction"] if data else "", model_verdict=data["verdict"] if data else "", trigger_result="未测", comparison="待验证" if receipt else "待模型运行", evidence_path="", failure_kind=""))
            for run in matched:
                if run.get("prompt_bundle_sha256") != receipt["prompt_bundle_sha256"]:
                    raise ValueError("Validation prompt identity mismatch")
                trigger = run["trigger_result"]
                pred = data["prediction"]
                observed = trigger == "触发" if trigger in ("触发", "未触发") and run.get("evidence_sufficient") else None
                predicted = True if pred == "存在候选" else False if pred == "未检出候选" else None
                cell = "U" if observed is None or predicted is None else "TP" if observed and predicted else "FN" if observed else "FP" if predicted else "TN"
                rows.append(dict(sample_id=sid, attempt_id=receipt["attempt_id"], model_prediction=pred, model_verdict=data["verdict"], trigger_result=trigger, comparison=cell, evidence_path=run["record_path"], failure_kind=run.get("failure_kind", "")))
    path = batch / "comparison.csv"
    csv_write(path, rows, ("sample_id", "attempt_id", "model_prediction", "model_verdict", "trigger_result", "comparison", "evidence_path", "failure_kind"))
    metrics = dict(scope="Only exact prompt/attempt/original-POC paired runs in this extension; no historical pooling", total_parent_count=len(metadata(cfg)), model_response_count=len(receipts), paired_condition_count=sum(r["comparison"] in ("TP", "FP", "FN", "TN", "U") for r in rows), counts={cell:sum(r["comparison"] == cell for r in rows) for cell in ("TP", "FP", "FN", "TN", "U")}, classification_rate=None, reason="不同条件/多finding不自动当作独立父样本；未形成父样本核验前不计算总体准确率")
    save_json(batch / "metrics.json", metrics)
    return dict(comparison=path.relative_to(ROOT).as_posix(), metrics=metrics)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("list", "prepare", "check", "status", "import-output", "compare"))
    parser.add_argument("--dataset", choices=("baseline", "optional4"), default="optional4")
    parser.add_argument("--sources")
    parser.add_argument("--sample")
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--attempt", default="a01")
    parser.add_argument("--model-name")
    parser.add_argument("--model-version", default="unknown")
    parser.add_argument("--model-parameters", default="unknown")
    parser.add_argument("--channel", choices=("manual_conversation", "external_api", "codex_subagent", "current_assistant"))
    parser.add_argument("--executed-at", help="Actual source execution time, not import time")
    args = parser.parse_args()
    if args.action == "list":
        result = json_read(REGISTRY)
    elif args.action == "prepare":
        result = prepare(args.dataset, args.sources)
    elif args.action == "check":
        result = check_inputs(config(args.dataset))
    elif args.action == "status":
        result = status(args.dataset)
    elif args.action == "compare":
        result = compare(args.dataset)
    else:
        if not all((args.sample, args.raw, args.model_name, args.channel, args.executed_at)):
            parser.error("import-output requires --sample, --raw, --model-name, --channel and --executed-at")
        result = import_output(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
