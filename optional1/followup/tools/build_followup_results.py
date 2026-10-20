"""Build followup_poc_results.csv and per-POC evidence from the raw runs."""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_common as L

P = L.ROOT / "optional1" / "pocs"
OUT = L.ROOT / "optional1" / "followup"
EV = OUT / "evidence"
EV.mkdir(parents=True, exist_ok=True)

V = {}  # key -> dict(success, category, observation, restore, condition, env)


def add(key, success, observation, category="", restore="not_applicable",
        condition="", env="dvwa-wsl-01"):
    V[key] = {"success": success, "category": category, "observation": observation,
              "restore": restore, "condition": condition, "env": env}


AUTH_LOW = "env=dvwa-wsl-01|role=ordinary|security=low|object=wp4target|state=initialized"
SQLI = "env=sqli-labs-wsl-01|role=anonymous|security=n/a|object=none|state=initialized"
SQLI5 = "env=sqli-labs-wsl-01|role=anonymous|security=n/a|object=dedicated-wp4v|state=initialized"


def cmd(security):
    return ("env=dvwa-wsl-01|role=admin|security=" + security +
            "|object=none|state=initialized")


def xss(security, obj="none"):
    return ("env=dvwa-wsl-01|role=admin|security=" + security +
            "|object=" + obj + "|state=initialized")


# ---------------- v1 ----------------
add("v1/AUTH-001__1", True,
    "低权限 gordonb 在 security=low 读取 get_user_data.php 返回 6 条用户记录（含 admin 等他人记录）；"
    "security=impossible 控制组返回 Access denied。", condition=AUTH_LOW)
add("v1/AUTH-001__2", True,
    "gordonb 在 low 将 user_id=6 的 first_name/surname 改为 AUTH001-POC-F/S，独立回读确认变化，"
    "随后恢复为 Wp4/Target。", restore="restored", condition=AUTH_LOW)
add("v1/AUTH-001__3", True,
    "gordonb 打开 authbypass 页面：security=low 返回 200 并渲染管理页；impossible 返回 403 Unauthorised。",
    condition=AUTH_LOW)
add("v1/CMD-001__1", True,
    "control 请求无 marker；test 请求响应含 wp2_cmd001_marker，且该 marker 不在请求字面量中，"
    "说明是命令回显而非反射。", condition=cmd("low"))
add("v1/CMD-002__1", True,
    "medium 过滤下 `127.0.0.1|echo CMD002_MARKER` 的 <pre> 仅为 marker（无 ping 输出），"
    "control 请求无 marker。", condition=cmd("medium"))
add("v1/CMD-003__1", True,
    "high 黑名单下 marker 出现在命令输出块，control 无 marker，原始 payload 未被页面反射。",
    condition=cmd("high"))
add("v1/SQLI-001__1", True,
    "id=1 基线 721B；单引号触发 SQL 语法错误；布尔真 721B、布尔假 670B，重复三次稳定，"
    "构成布尔差分。", condition=SQLI)
add("v1/SQLI-002__1", True,
    "Less-11 基线（无效用户）返回 slap.jpg；恒真 `' OR '1'='1' -- ` 返回 flag.jpg；恒假仍 slap.jpg。",
    condition=SQLI)
add("v1/SQLI-003__1", False,
    "基线、布尔真、布尔假三个请求均返回同一行：false 分支 `1'||'1'='2` 中 `id='1'` 先为真，"
    "整体仍命中；仅单引号出现语法错误，没有可用的真假业务差分。",
    category="script_logic", condition=SQLI)
add("v1/SQLI-005__1", True,
    "注册 `x' OR username='v'#` 后以错误 current_password 改密成功；victim v 新口令可登录、旧口令失败；"
    "专用账号随后删除。", restore="restored", condition=SQLI5)
add("v1/XSS-001__1", True,
    "headless Chrome 打开同一 URL，CDP 捕获 alert('XSS001')。", condition=xss("low"))
add("v1/XSS-002__1", True,
    "headless Chrome 捕获 alert('XSS002')；medium 仅删除 `<script>` 字面量，img onerror 仍执行。",
    condition=xss("medium"))
add("v1/XSS-003__1", True,
    "headless Chrome 捕获 alert('XSS003')；high 的正则只过滤 script 字母序列，img onerror 仍执行。",
    condition=xss("high"))
add("v1/XSS-005__1", True,
    "存储的 `<svg/onload=alert('XSS-005-POC')>` 在 xss_s 页面加载时触发 alert；"
    "随后删除专用留言。", restore="restored", condition=xss("low", "dedicated-guestbook"))

# ---------------- v2 ----------------
add("v2/AUTH-001__1", True,
    "gordonb 在 low 读取 6 条用户记录，与 admin 控制组返回的行集完全一致。", condition=AUTH_LOW)
add("v2/AUTH-001__2", True,
    "gordonb 在 low 更新 user_id=6 为 audit-mark-6，独立回读确认，随后恢复 Wp4/Target。",
    restore="restored", condition=AUTH_LOW)
add("v2/CMD-001__1", True,
    "linux 分支 `127.0.0.1; echo CMDINJ_MARKER_7f3a91` 的 marker 出现在响应，正常 ping 输出也存在。",
    condition=cmd("low"))
add("v2/CMD-002__1", True,
    "`127.0.0.1|echo CMD002_MARKER` 的 <pre> 仅含 marker；脚本因要求 ping 输出而自判 rc=1。"
    "独立对照 `127.0.0.1|echo CMD002_CTRL_UNIQUE` 的 <pre> 恰为 marker、基线 <pre> 仅 ping 输出，"
    "确认是命令执行而非反射。", condition=cmd("medium"))
add("v2/CMD-003__1", True,
    "high 下换行 payload `127.0.0.1\\necho CMD003_MARKER` 的 marker 出现在响应，基线无 marker。",
    condition=cmd("high"))
add("v2/SQLI-001__1", True,
    "布尔真 721B 含行，布尔假 670B 无行，与基线 721B 一致；同一参数改变 WHERE 真值。", condition=SQLI)
add("v2/SQLI-002__1", True,
    "基线无效账号无登录行；恒真 `' OR '1'='1' -- ` 返回登录行；语法探针触发 SQL 错误。", condition=SQLI)
add("v2/SQLI-003__1", False,
    "四个请求均无可区分差分；`1' UNION SELECT 1,2,3-- -` 因原查询先返回 id=1 行且 LIMIT 0,1 截断，"
    "marker 列未渲染；脚本只打印标记是否存在，没有成功判据。",
    category="script_logic", condition=SQLI)
add("v2/SQLI-005__1", True,
    "三账号注册、基线正/负控制、二阶改密、victim 新旧口令回查均通过，且 victim_restore=verified。",
    restore="restored", condition=SQLI5)
add("v2/XSS-001__1", True,
    "headless Chrome 捕获 console `LLM_LAB_XSS`（svg onload）。", condition=xss("low"))
add("v2/XSS-002__1", True,
    "headless Chrome 捕获 console `LLM_LAB_XSS`（medium 下 img onerror）。", condition=xss("medium"))
add("v2/XSS-003__1", True,
    "headless Chrome 捕获 console `LLM_LAB_XSS`（high 下 img onerror）。", condition=xss("high"))
add("v2/XSS-005__1", False,
    "运行即崩溃：模块内函数 `http()` 覆盖了导入的 `http` 包，`http.cookiejar.CookieJar()` 触发 "
    "AttributeError/NameError，请求尚未发出；无反射或浏览器执行证据。",
    category="script_logic", condition=xss("low", "dedicated-guestbook"))

# ---------------- v3 ----------------
add("v3/AUTH-001__1", True,
    "gordonb 在 low 读取 6 条记录，与 admin 控制组行集完全一致；至少一个 user_id 与操作者不同。",
    condition=AUTH_LOW)
add("v3/AUTH-001__2", True,
    "gordonb 在 low 更新 user_id=6，独立回读看到 wp2-lab-marker，随后恢复 Wp4/Target。",
    restore="restored", condition=AUTH_LOW)
add("v3/CMD-001__1", True,
    "`127.0.0.1; echo CMDINJ_MARKER_7f3a` 的 marker 出现在 <pre> 输出区，基线仅 ping 输出。",
    condition=cmd("low"))
add("v3/CMD-002__1", True,
    "`127.0.0.1 | echo CMD002_MARK_OK` 的 <pre> 恰为 marker；脚本把同名 marker 当主机名做反射控制，"
    "ping 也回显该串，导致控制组被污染并自判 rc=2。独立对照确认 pipe 执行。",
    condition=cmd("medium"))
add("v3/CMD-003__1", True,
    "high 下 `127.0.0.1|echo DSH_MARK_CM'D003'` 的 marker 作为独立行出现在 <pre>，"
    "baseline 与 `;` 控制均无 marker。", condition=cmd("high"))
add("v3/SQLI-001__1", True,
    "baseline/true/false 三项检查全为 true；false 分支无行，true 与基线同摘要。", condition=SQLI)
add("v3/SQLI-002__1", True,
    "有效基线 Dumb/Dumb 返回登录行；恒真返回同一行；恒假无行；UNION 探针把 marker 渲染到用户名/口令位。",
    condition=SQLI)
add("v3/SQLI-003__1", True,
    "基线命中 Dumb；真条件同摘要；假条件无行；单引号触发 SQL 语法错误，形成布尔差分。", condition=SQLI)
add("v3/SQLI-005__1", True,
    "基线错误口令被 failed.php 拒绝；注入账号以错误 current_password 改密成功；"
    "victim 新口令登录成功、旧口令失败；已恢复。", restore="restored", condition=SQLI5)
add("v3/XSS-001__1", True,
    "headless Chrome 捕获 console `LLM_LAB_XSS`（img onerror）。", condition=xss("low"))
add("v3/XSS-002__1", True,
    "headless Chrome 捕获 console `LLM_LAB_XSS`（medium，双引号+模板字符串）。", condition=xss("medium"))
add("v3/XSS-003__1", True,
    "headless Chrome 捕获 console `LLM_LAB_XSS`（high，img onerror）。", condition=xss("high"))
add("v3/XSS-005__1", True,
    "存储的 img onerror 在 xss_s 页面加载时输出 console `LLM_LAB_XSS`；随后删除专用留言。",
    restore="restored", condition=xss("low", "dedicated-guestbook"))


def load_inventory():
    rows = list(csv.DictReader((L.ROOT / "optional1" / "poc_execution.csv").open(encoding="utf-8-sig")))
    inv = {}
    for r in rows:
        if r["cohort"] in ("v1", "v2", "v3"):
            inv[(r["cohort"], Path(r["code_path"]).name)] = r
    return inv


def main():
    inv = load_inventory()
    assert len(V) == 40, len(V)
    out_rows = []
    for cohort in ("v1", "v2", "v3"):
        for stem in sorted(p.stem for p in (P / cohort).glob("*.py")):
            key = f"{cohort}/{stem}"
            v = V[key]
            inv_row = inv[(cohort, stem + ".py")]
            poc = P / cohort / (stem + ".py")
            sha = hashlib.sha256(poc.read_bytes()).hexdigest()
            if sha != inv_row["code_sha256"]:
                raise SystemExit(f"hash mismatch {key}")
            raw = json.loads((L.RAW / cohort / f"{stem}.json").read_text(encoding="utf-8"))
            browser = None
            bp = L.RAW / "browser" / f"{cohort}__{stem}.json"
            if bp.exists():
                browser = json.loads(bp.read_text(encoding="utf-8"))

            cmdline = " ".join([Path(raw["cmd"][0]).name] + [str(a) for a in raw["cmd"][1:]])
            cmdline = cmdline.replace(str(L.ROOT) + "\\", ".\\").replace(str(L.ROOT), ".")
            cmdline = L.redact(cmdline)

            ev_dir = EV / cohort
            ev_dir.mkdir(parents=True, exist_ok=True)
            ev = ev_dir / f"{stem}.md"
            lines = [
                f"# {cohort}/{stem}", "",
                f"- finding: {inv_row['sample_id']} / {inv_row['finding_id']}",
                f"- condition: `{v['condition']}`",
                f"- code_sha256: `{sha}`",
                f"- started_at: {raw.get('started_at')}",
                f"- elapsed_seconds: {raw.get('elapsed_seconds')}",
                f"- returncode: {raw.get('returncode')}",
                f"- command: `{cmdline}`",
                "- adaptation_level: original (only CLI/environment values supplied)", "",
                "## POC output", "", "```text",
                (raw.get("stdout") or "").strip()[-6000:],
                "```", "",
            ]
            if raw.get("stderr"):
                lines += ["## POC stderr", "", "```text", raw["stderr"].strip()[-3000:], "```", ""]
            if browser:
                lines += ["## Browser (headless Chrome / CDP)", "", "```json",
                          json.dumps({k: browser.get(k) for k in
                                      ("url", "expected_marker", "dialogs", "console",
                                       "exceptions", "success")},
                                     ensure_ascii=False, indent=2), "```", ""]
            lines += [
                "## Independent observation", "",
                v["observation"], "",
                "## Verdict", "",
                ("- success: **true**" if v["success"] else
                 f"- success: **false** (failure_category: {v['category']})"),
                f"- restore_status: {v['restore']}",
                "- Note: the POC source was not edited. URLs, ports, session cookies and dedicated "
                "account names were supplied through existing CLI options and are recorded above.", "",
            ]
            ev.write_text("\n".join(lines), encoding="utf-8")

            out_rows.append({
                "cohort": cohort,
                "sample_id": inv_row["sample_id"],
                "finding_id": inv_row["finding_id"],
                "code_sha256": sha,
                "environment_id": v["env"],
                "condition_key": v["condition"],
                "reviewer": "dsh-agent (automated local run; human sign-off pending)",
                "started_at": raw.get("started_at") or "",
                "elapsed_seconds": raw.get("elapsed_seconds") if raw.get("elapsed_seconds") is not None else "",
                "execution_status": "executed",
                "success": "true" if v["success"] else "false",
                "failure_category": "" if v["success"] else v["category"],
                "command_redacted": cmdline,
                "evidence_path": f"optional1/followup/evidence/{cohort}/{stem}.md",
                "restore_status": v["restore"],
                "adaptation_level": "original",
                "notes": v["observation"][:300],
            })

    target = L.ROOT / "optional1" / "followup_poc_results.csv"
    cols = ["cohort", "sample_id", "finding_id", "code_sha256", "environment_id",
            "condition_key", "reviewer", "started_at", "elapsed_seconds",
            "execution_status", "success", "failure_category", "command_redacted",
            "evidence_path", "restore_status", "adaptation_level", "notes"]
    with target.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, cols)
        w.writeheader()
        w.writerows(out_rows)
    print(target, len(out_rows))


if __name__ == "__main__":
    main()
