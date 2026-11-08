"""Build the optional4 extension from pinned Git objects, without labels or POCs."""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "workpackage1/extensions/optional4-v1"
PINS = {"DVWA": "068d974487a297c155c48722f9fcf7180a83adc4", "sqli-labs": "e96f21776372c8613a7e565106e62bc01a59355e"}
URLS = {"DVWA": "https://github.com/digininja/DVWA", "sqli-labs": "https://github.com/Audi-1/sqli-labs"}
CONTEXT = ["dvwaSessionGrab", "dvwaPageStartup", "dvwaIsLoggedIn", "dvwaCurrentUser", "dvwaSecurityLevelGet", "checkToken", "generateSessionToken"]

def unit(key, source, role, functions=None):
    return dict(key=key, source=source, role=role, functions=functions)

CASES = [
    dict(id="O4-XSS-01", project="sqli-labs", scope="XSS", rule="second_order.md",
         business="用户注册、登录后显示用户名；所有显示内容按HTML文本处理。", paths="注册、登录和登录后的用户名输出页面；在同一会话中关联数据库返回值。",
         conditions="已提供相关注册、登录、显示与数据库连接代码；本地路径和数据库字段长度由验证阶段确认。",
         units=[unit("A", "Less-24/login_create.php", "注册处理"), unit("B", "Less-24/login.php", "登录处理"), unit("C", "Less-24/logged-in.php", "登录后页面"), unit("D", "sql-connections/sql-connect.php", "数据库连接依赖")],
         packets=[["A", "D"], ["B", "C", "D"]]),
    dict(id="O4-XSS-02", project="DVWA", scope="XSS", rule="second_order.md",
         business="用户提交姓名与留言，页面再次读取历史记录并展示；每个字段分别追踪。", paths="留言写入处理器、页面入口、读取渲染与配置选择。",
         conditions="分别检查配置对应的实际处理器，不能把某配置的写入逻辑套用到其他配置。",
         units=[unit("A", "vulnerabilities/xss_s/source/medium.php", "处理器一"), unit("B", "vulnerabilities/xss_s/index.php", "页面入口"), unit("C", "dvwa/includes/dvwaPage.inc.php", "读取与配置", ["dvwaGuestbook", "dvwaSecurityLevelGet"]), unit("D", "vulnerabilities/xss_s/source/impossible.php", "处理器二"), unit("E", "dvwa/includes/dvwaPage.inc.php", "会话和Token依赖", CONTEXT)],
         packets=[["A", "B", "C"], ["D", "E"]]),
    dict(id="O4-LOGIC-01", project="DVWA", scope="业务逻辑", rule="business_logic.md",
         business="改密须由当前登录用户完成验证码验证后确认；后续步骤应由服务端验证其前置条件。", paths="验证码改密入口和各配置处理器。",
         conditions="验证码服务是否配置、页面提示是否可见需要实测；当前口令和步骤参数以源码为准。",
         units=[unit("A", "vulnerabilities/captcha/index.php", "页面入口"), unit("B", "vulnerabilities/captcha/source/low.php", "处理器一"), unit("C", "vulnerabilities/captcha/source/medium.php", "处理器二"), unit("D", "vulnerabilities/captcha/source/impossible.php", "处理器三"), unit("E", "dvwa/includes/dvwaPage.inc.php", "会话和Token依赖", CONTEXT)],
         packets=[["A", "E"], ["B", "C"], ["D", "E"]]),
    dict(id="O4-LOGIC-02", project="DVWA", scope="CSRF", rule="business_logic.md",
         business="当前用户的口令变更须绑定有效会话与用户主动发起的操作；来源、Token和当前口令等条件逐项核对。", paths="改密入口、各配置处理器及身份和Token函数。",
         conditions="服务端接收请求与真实浏览器跨站携带Cookie分开验证；不假定浏览器策略。",
         units=[unit("A", "vulnerabilities/csrf/index.php", "页面入口"), unit("B", "vulnerabilities/csrf/source/low.php", "处理器一"), unit("C", "vulnerabilities/csrf/source/impossible.php", "处理器二"), unit("D", "dvwa/includes/dvwaPage.inc.php", "会话和Token依赖", CONTEXT)],
         packets=[["A", "B", "C"], ["D"]]),
]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    content = text.encode("utf-8")
    if path.exists() and path.read_bytes() != content:
        raise ValueError(f"Input already exists with different bytes; create a new version: {path}")
    path.write_bytes(content)

def table(path, rows):
    import io
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    write(path, buf.getvalue())

def source(project, path, sources):
    return subprocess.check_output(["git", "-C", str(sources / project), "show", f"{PINS[project]}:{path}"])

def select(raw, functions):
    lines = raw.decode("utf-8").splitlines()
    if functions:
        spans = []
        for name in functions:
            pattern = re.compile(r"^function\s+&?" + re.escape(name) + r"\s*\(")
            start = next(i for i, text in enumerate(lines) if pattern.search(text))
            end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
            spans.append((start + 1, end + 1))
        spans.sort()
    else:
        spans = [(1, len(lines))]
    selected = [(lines[n - 1], n) for a, b in spans for n in range(a, b + 1)]
    code = (["<?php"] if functions else []) + [line for line, _ in selected] + (["?>"] if functions else [])
    mapping = []
    if functions:
        mapping.append(dict(normalized_line=1, original_line="", operation="wrapper"))
    mapping += [dict(normalized_line=i, original_line=n, operation="retained") for i, (_, n) in enumerate(selected, 1 + bool(functions))]
    if functions:
        mapping.append(dict(normalized_line=len(code), original_line="", operation="wrapper"))
    return "\n".join(code) + "\n", mapping, spans

def build(sources):
    ledger, all_meta = [], []
    for case in CASES:
        sid = case["id"]
        fragments = []
        for spec in case["units"]:
            raw = source(case["project"], spec["source"], sources)
            code, mapping, spans = select(raw, spec["functions"])
            key = spec["key"]
            raw_path = f"raw_samples/{sid}/{key}.php"
            norm_path = f"normalized_samples/{sid}/{key}.php"
            target = OUT / raw_path
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != raw:
                raise ValueError(f"Raw source changed: {target}")
            target.write_bytes(raw)
            write(OUT / norm_path, code)
            map_path = f"line_maps/{sid}-{key}.csv"
            table(OUT / map_path, mapping)
            fragments.append(dict(fragment_id=f"{sid}-{key}", code_id=key, role=spec["role"], source_file=spec["source"], selected_spans=spans, raw_file=raw_path, normalized_file=norm_path, line_map=map_path, raw_sha256=sha(raw), normalized_sha256=sha(code.encode()), normalized_lines=len(code.splitlines())))
        lookup = {f["code_id"]: f for f in fragments}
        packets = []
        for i, keys in enumerate(case["packets"], 1):
            packet_id = f"{sid}-P{i}"
            count = sum(lookup[k]["normalized_lines"] for k in keys)
            if count > 220:
                raise ValueError(f"{packet_id}: {count} lines exceeds 220")
            body = f"样本ID：{sid}\n输入包：{packet_id}\n输入版本：v2；扩展集：optional4-v1\n审计范围：{case['scope']}\n业务规格：{case['business']}\n调用范围：{case['paths']}\n条件与限制：{case['conditions']}\n来源通过内部同ID台账追溯；当前输入不含历史结论、POC和实测证据。\n\n"
            for key in keys:
                fragment = lookup[key]
                code = (OUT / fragment["normalized_file"]).read_text(encoding="utf-8")
                body += f"片段：{fragment['fragment_id']}；作用：{fragment['role']}；局部行号从1起始。\n```php\n{code.rstrip()}\n```\n\n"
            body += "收到同一父样本全部包后综合判断；缺包时只记录局部证据，不虚构外部实现或运行结果。\n"
            input_file = f"llm_inputs/{packet_id}.md"
            write(OUT / input_file, body)
            packets.append(dict(packet_id=packet_id, input_file=input_file, fragment_ids=[f"{sid}-{k}" for k in keys], code_lines=count))
        meta = dict(sample_id=sid, dataset_id="optional4", preprocess_version="v2", input_dataset_version="optional4-v1", project=case["project"], commit=PINS[case["project"]], source_url=URLS[case["project"]], audit_scope=case["scope"], scenario_rule=case["rule"], business_specification=case["business"], fragments=fragments, packets=packets, runtime_validation="pending_new_batch", limitations=[case["conditions"], "历史选做四证据不进入模型输入；本次输出与历史标签分开。"])
        write(OUT / f"sample_metadata/{sid}.json", json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
        ledger.append(dict(sample_id=sid, dataset_id="optional4", audit_scope=case["scope"], project=case["project"], commit=meta["commit"], metadata_file=f"sample_metadata/{sid}.json", fragment_count=len(fragments), packet_count=len(packets)))
        all_meta.append(meta)
    table(OUT / "samples.csv", ledger)
    manifest = dict(dataset_id="optional4", version="optional4-v1", parent_sample_count=len(ledger), fragment_count=sum(len(m["fragments"]) for m in all_meta), input_packet_count=sum(len(m["packets"]) for m in all_meta), max_packet_code_lines=max(p["code_lines"] for m in all_meta for p in m["packets"]), source_pins=PINS, scope="Pinned source extraction and mappings only; not model execution or vulnerability confirmation")
    write(OUT / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=ROOT.parent / "source_projects")
    args = parser.parse_args()
    print(json.dumps(build(args.sources), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
