"""Create figures and an offline HTML report from recomputed CSVs."""
from pathlib import Path
import csv
import html
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "optional1"
local_deps = ROOT.parent / ".analysis_deps"
if local_deps.exists():
    sys.path.insert(0, str(local_deps))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter, StrMethodFormatter
from matplotlib import font_manager
import markdown


def rows(name):
    with (OUT / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


metrics = rows("metrics.csv")
records = rows("labeled_results.csv")
costs = {r["cohort"]: r for r in rows("costs.csv")}
summary = json.loads((OUT / "checks/summary.json").read_text(encoding="utf-8"))
versions = ["v1", "v2", "v3"]
colors = ["#40638B", "#D58B2B", "#267C70"]
figures = OUT / "figures"
figures.mkdir(exist_ok=True)
available_fonts = {f.name for f in font_manager.fontManager.ttflist}
font = next((f for f in ("Microsoft YaHei", "SimHei", "Noto Sans CJK SC", "Arial Unicode MS")
             if f in available_fonts), "DejaVu Sans")
plt.rcParams.update({"font.family": font, "axes.unicode_minus": False, "font.size": 11,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.facecolor": "white", "svg.fonttype": "path"})


def metric(v, name, scope="ALL"):
    return next(r for r in metrics if r["cohort"] == v and r["metric"] == name and r["scope"] == scope)


def save(fig, name):
    fig.savefig(figures / f"{name}.png", dpi=170, bbox_inches="tight")
    fig.savefig(figures / f"{name}.svg", bbox_inches="tight")
    plt.close(fig)


fig, axes = plt.subplots(1, 3, figsize=(13, 4.8))
for ax, key, title in zip(axes, ["f1", "strict_protocol", "evidence_complete"],
                          ["分类 F1 保持不变", "严格静态协议通过率", "四项显式证据字段完整率"]):
    values = [float(metric(v, key)["value"]) for v in versions]
    ax.bar(versions, values, color=colors, width=.56)
    for i, (v, val) in enumerate(zip(versions, values)):
        r = metric(v, key)
        label = r["display"] + (f"\n{r['numerator']}/{r['denominator']}" if key != "f1" else "")
        ax.text(i, val+.025, label, ha="center", fontsize=10)
    ax.set_ylim(0, 1.2)
    ax.set_yticks([0, .25, .5, .75, 1])
    ax.yaxis.set_major_formatter(PercentFormatter(1))
    ax.set_title(title, pad=12)
    ax.set_xlabel("报告版本")
fig.suptitle("14 个父样本的历史对比结果", fontsize=17, y=1.02)
fig.text(.5, -.06, "v3 = final-wp4-v2；跨批次同集调优，非独立盲测。字段完整不等于语义正确或 POC 可运行。",
         ha="center", fontsize=10, color="#525D6B")
fig.tight_layout()
save(fig, "01_primary_comparison")

fig, ax = plt.subplots(figsize=(11, 5))
sequence = ["v1", "v2", "historical-final", "wp4-baseline-final", "wp4-intermediate", "v3"]
labels = ["v1\n原三版", "v2\n原三版", "final\n原三版", "final\nWP4基线", "final-wp4-v1\nWP4中间版", "v3\nWP4修正版"]
vals = [float(metric(v, "strict_protocol")["value"]) for v in sequence]
ax.bar(range(6), vals, color=[colors[0], colors[1], "#8993A0", "#8993A0", "#A86B5F", colors[2]], width=.6)
for i, val in enumerate(vals):
    r = metric(sequence[i], "strict_protocol")
    ax.text(i, val+.025, f"{r['numerator']}/14\n{r['display']}", ha="center")
ax.axvline(2.5, linestyle="--", color="#7F8B99", linewidth=1)
ax.set_xticks(range(6), labels)
ax.set_ylim(0, 1.23)
ax.set_yticks([0,.25,.5,.75,1])
ax.yaxis.set_major_formatter(PercentFormatter(1))
ax.set_ylabel("严格静态协议通过率")
ax.set_title("保留中间退步与同名 final 的两批记录", fontsize=16, pad=15)
fig.text(.5, -.015, "原三版 5/14 → 8/14 → 4/14；WP4 闭环 5/14 → 4/14 → 14/14。不同批次不能合并。", ha="center", fontsize=10)
fig.tight_layout()
save(fig, "02_all_cohorts")

fig, ax = plt.subplots(figsize=(10,5))
x = list(range(3))
for offset, key, color, label in [(-.18, "average_input_characters", "#40638B", "平均输入字符"),
                                 (.18, "average_output_characters", "#267C70", "平均输出字符")]:
    values = [float(costs[v][key]) for v in versions]
    bars=ax.bar([i+offset for i in x], values, width=.34, color=color, label=label)
    ax.bar_label(bars, labels=[f"{v:,.0f}" for v in values], padding=4)
ax.set_xticks(x, versions)
ax.set_ylim(0,16000)
ax.yaxis.set_major_formatter(StrMethodFormatter("{x:,.0f}"))
ax.set_ylabel("Unicode 字符数")
ax.set_xlabel("报告版本")
ax.set_title("v3 输入文本比 v1 增加约 31.61%", fontsize=16, pad=15)
ax.legend(loc="upper left")
fig.text(.5,-.01,"每版记录14个父样本任务；v1另有1次保留预试验。字符数不是Token，未记录时延与计费。",ha="center",fontsize=10)
fig.tight_layout()
save(fig,"03_text_cost")

fig, ax = plt.subplots(figsize=(10,5))
scopes = ["SQL注入","XSS","命令注入","权限越权"]
for j, v in enumerate(versions):
    values = [float(metric(v,"strict_protocol",s)["value"]) for s in scopes]
    ax.bar([i+(j-1)*.24 for i in range(4)],values,width=.22,label=v,color=colors[j])
ax.set_xticks(range(4),["SQL注入\nn=4","XSS\nn=5","命令注入\nn=4","权限越权\nn=1"])
ax.set_ylim(0,1.2);ax.set_yticks([0,.25,.5,.75,1]);ax.yaxis.set_major_formatter(PercentFormatter(1))
ax.set_title("按漏洞类型检查输出协议",fontsize=16,pad=15)
ax.set_ylabel("严格静态协议通过率");ax.legend(ncol=3,loc="upper center")
fig.tight_layout();save(fig,"04_by_type")

def fmt(v, name):
    m=metric(v,name)
    return f"{m['display']}（{m['numerator']}/{m['denominator']}）"

table_rows=[]
for title,key in [("精确率","precision"),("召回率","recall"),("F1","f1"),
                  ("严格静态协议","strict_protocol"),("四项证据字段完整率","evidence_complete"),
                  ("Python 语法通过率","poc_syntax")]:
    table_rows.append("| "+title+" | "+" | ".join(fmt(v,key) for v in versions)+" |")
table_rows.append("| POC 原稿可运行率 | 待测，分母 14 | 待测，分母 13 | 待测，分母 13 |")
type_rows=[]
for scope in scopes:
    for v in versions:
        rs=[r for r in records if r["cohort"]==v and r["vulnerability_type"]==scope]
        counts={c:sum(r["classification"]==c for r in rs) for c in ("TP","FP","FN","TN")}
        type_rows.append(f"| {scope} | {v} | {len(rs)} | {counts['TP']} | {counts['FP']} | {counts['FN']} | {counts['TN']} | {metric(v,'f1',scope)['display']} | {metric(v,'strict_protocol',scope)['display']} |")
report=f"""# 选做1 多版本 Prompt 挖掘效果对比报告

本实验比较同一组14个父样本在三个 Prompt 版本下的漏洞分类、证据完整性、输出协议与文本成本。三版与项目已有主条件标签均完全一致，分类精确率、召回率和 F1 没有提高；严格静态协议通过率由 v1 的35.71%上升至 v3 的100.00%，四项显式证据字段完整率由78.57%上升至85.71%。这些结果支持已知样本上的输出约束改善，不支持泛化能力或模型 POC 可运行性提高。

**交付状态：历史证据分析与可复现材料已完成；完整实验验收仍有缺项。** 三版模型 POC 原稿尚未执行，历史时延、Token及具体采样参数未保存，原始标签的预先冻结时间与人工独立复核记录不足。因此 POC 可运行率与未记录成本保持待测，不能以人工适配脚本的成功率代替。

## 1 项目基线与版本选择

基线为用户提供的完整项目 ZIP，与 GitHub main 提交 `{summary['source_commit']}` 的706个文件逐一核对一致。归档 SHA-256 为 `{summary['source_zip_sha256']}`。历史模型记录日期为2026年10月19日；本次离线复算日期为2026年10月20日。本次没有重新调用模型，也没有把旧会话草案视为新实验。

| 报告代号 | 实际 Prompt 版本 | 历史批次 | 版本作用 |
| --- | --- | --- | --- |
| v1 | v1 | wp2-eval-42 | 通用基线，已有统一输出协议 |
| v2 | v2 | wp2-eval-42 | 加强逐字证据、成立条件与漏洞专属规则 |
| v3 | final-wp4-v2 | wp4-final-wp4-v2 | 纳入主体 POC 反馈，补齐可观测性、严格类型与排除证据约束 |

v3 是报告代号，源文件与输出里的版本名保持 `final-wp4-v2`。原三版中的 `final` 尚未纳入后续工作包4反馈，不直接改名为 v3。为避免只展示最优版本，补充保留原 `final`、工作包4的 `final` 基线和 `final-wp4-v1` 中间版；合计复算84份历史响应，其中主比较42份。

完整 Prompt 汇编见 [v1](prompts/v1.md)、[v2](prompts/v2.md)、[v3](prompts/v3.md)，逐包原件见 `raw_inputs/`。逐字节来源和哈希见 [输入清单](input_manifest.csv) 与 [来源核对](source_hash_audit.csv)。

## 2 实验条件与计数口径

样本为工作包1输入 v2，含14个父样本、17份输入包。逐包提取审计数据区并计算 SHA-256，六个比较组的17个数据区全部一致。SQLI-005与AUTH-001的多包只汇总为一个父样本，不重复计数。

真实标签取 `results/batches/wp4-poc-01/ground_truth.csv` 的14条 `main_condition=yes` 记录，共12个阳性、2个阴性。17条条件验证全部保留供追溯，但AUTH-001的四个配置不能算成四个独立父样本。父样本主标签为low条件下存在漏洞，不代表impossible配置也存在漏洞。

历史模型名称均记为 DeepSeek Harness subagent（deepseek-flash），每条结果在独立子代理上下文生成，多包一次性提供。具体服务端快照、温度、最大输出长度、工具权限与内部调用次数无法核验；不同版本来自历史批次，不能声称严格随机受控或完全同参。任务不要求商业API，关键限制是实际参数与过程记录缺失。

预测“存在候选”记阳性，“未检出候选”记阴性，“无法判定”记U并报告覆盖率。精确率=TP/(TP+FP)，召回率=TP/(TP+FN)，F1=2TP/(2TP+FP+FN)。分母为零记不适用，未知实测结果记待测。

证据完整率采用保守、可复算的字段口径：一份父样本响应的所有候选均具有非空位置、数据流、前置条件，且响应含有效结论状态，才计完整。两个阴性响应采用排除证据结构，没有显式 `data_flow` 与 `preconditions` 字段，计为字段不齐；这不表示其排除判断错误。字段齐全不等于数据流语义或行号正确，后者需另行核验。

## 3 整体结果

| 指标 | v1 | v2 | v3 |
| --- | --- | --- | --- |
{chr(10).join(table_rows)}

每版 TP=12、FP=0、FN=0、TN=2、U=0。TP样本为AUTH-001、CMD-001/002/003、SQLI-001/002/003/005、XSS-001/002/003/005；TN为CMD-004与XSS-004。FP/FN集合为空，不能虚构代表性误报漏报。逐条判断见 [标注表](labeled_results.csv)。

![主比较](figures/01_primary_comparison.png)

v1到v2的严格协议通过率增加21.43个百分点；v2到v3增加42.86个百分点；v1到v3增加64.29个百分点，相对增加180.00%。证据字段完整率提高7.14个百分点，相对增加9.09%。精确率、召回率与F1变化均为0个百分点。差值使用原始分数计算后四舍五入，不用显示值相减。

v1的AUTH-001有一个finding缺少 `data_flow` 字段，没有满足统一证据字段要求，因此v1阳性证据字段完整为11/12；v2与v3为12/12。阴性的字段结构差异使整体比例分别为11/14、12/14、12/14。

### 分漏洞类型结果

| 类型 | 版本 | n | TP | FP | FN | TN | F1 | 严格协议 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
{chr(10).join(type_rows)}

![分类别结果](figures/04_by_type.png)

SQL注入与权限类没有阴性样本，不能据此评估这些类型的误报率；权限类仅一个父样本，结论非常有限。总体仅两个阴性，不能把0/2外推为实际误报率为零。

## 4 中间版本与错误分析

![所有批次](figures/02_all_cohorts.png)

原三版 v1/v2/final 严格协议分别为5/14、8/14、4/14；工作包4闭环 final/final-wp4-v1/final-wp4-v2 分别为5/14、4/14、14/14。两批同名final是不同历史输出，必须分开。提示词更长并未带来单调改善，中间版本的退步也应报告。

常见失败为 `vulnerability_type` 使用带括号的子类型、`limitations` 或 `success_criteria` 类型不符合协议，以及个别行号问题。这些是输出可消费性问题，不应计作漏洞分类FP/FN。详细逐条错误见 [协议失败记录](protocol_failures.csv)。

CR-008明确类型值和字段类型后，v3在原检查器上14/14通过。但它还对CMD-004提出负例专属条数要求，透露了该样本的角色，属于同集调优或标签线索泄露。加上已有输出被用于设计修正版，v3结果不能称为独立盲测成绩，也不能把全部差值归因于某一条约束。

工作包4原有POC契约评分40/47→45/47是关键词与文本长度启发式，既不等于本报告的四项字段完整率，也不等于POC实测成功率；本报告不把该评分作为可运行性指标。

## 5 POC 可运行性与成本

主比较从原始响应按finding抽取40份POC代码：v1为14份，v2和v3各13份。AUTH-001包含多个候选，所以POC数与父样本数不同。代码及哈希见 `pocs/` 和 [执行台账](poc_execution.csv)。语言名称统一识别Python、python3、Python 3后进行编译检查，结果只能表示语法状态，未向靶场发送请求。

任务书要求的分母是生成POC总数；当前成功数未知，不能填写0%、100%或用已执行子集冒充全部分母。项目中人工适配后的17条条件运行用于建立标签，不能复制成每版模型原稿的运行结果。当前主比较POC测试覆盖率为0/40。

| 成本记录 | v1 | v2 | v3 |
| --- | --- | --- | --- |
| 父样本生成任务记录 | 14 | 14 | 14 |
| 已保留额外预试验 | 1 | 0 | 0 |
| 输入包数 | 17 | 17 | 17 |
| 平均输入字符数 | {float(costs['v1']['average_input_characters']):,.2f} | {float(costs['v2']['average_input_characters']):,.2f} | {float(costs['v3']['average_input_characters']):,.2f} |
| 平均输出字符数 | {float(costs['v1']['average_output_characters']):,.2f} | {float(costs['v2']['average_output_characters']):,.2f} | {float(costs['v3']['average_output_characters']):,.2f} |
| 时延、Token、API内部调用数 | 未记录 | 未记录 | 未记录 |

![文本成本](figures/03_text_cost.png)

v3输入文本平均比v1增加约31.61%，说明新增约束增加了上下文负担；字符数不能换算成真实Token、费用或时延。历史文件时间戳不是模型生成耗时。14是记录到的任务数，不等于底层API请求数。

## 6 结论与验收边界

在这14个公开教学父样本的既定主条件下，三版分类结论与已有实测标签一致，未观察到分类精确率、召回率或F1提升。可量化变化集中在输出协议与显式证据字段：严格协议通过率从35.71%上升到100.00%，证据字段完整率从78.57%上升到85.71%，平均输入字符数增加约31.61%。中间版本存在格式退步，最终修正版也含样本特定提示，因此不能表述为全面或泛化提升。

原稿POC尚未逐版执行，无法判断这些变化是否转化为更高的可运行率。补齐此项需在同一隔离环境对40份主比较原稿逐一检查、配置、执行和记录，区分仅环境参数配置与修改验证逻辑；后者必须归入适配稿。具体步骤见 [补测交接](poc_followup.md)。

验收逐项对应见 [要求对照](acceptance.md)。单命令复算见 [复现手册](runbook.md)。文件与数据完整性检查成功并不等于整项实验完全验收。
"""
# report.md is maintained separately after the POC follow-up; do not overwrite it
# with the historical template above. Figures are still regenerated from CSVs.
report = (OUT / "report.md").read_text(encoding="utf-8")
content=markdown.markdown(report,extensions=["tables","fenced_code"])
style="""
body{font:16px/1.8 "Microsoft YaHei","Noto Sans CJK SC",sans-serif;color:#243244;background:#eef2f6;margin:0}
main{max-width:1050px;margin:35px auto;padding:48px 60px;background:white}
h1{font-size:29px;color:#122235;line-height:1.4}h2{margin-top:38px;font-size:23px;color:#162a40}
h3{font-size:19px}table{border-collapse:collapse;width:100%;font-size:13px;margin:20px 0}
th,td{border:1px solid #d9dfe5;padding:9px 11px;text-align:left}th{background:#eaf0f5}
img{max-width:100%;height:auto}code{font:13px/1.5 Consolas,monospace;overflow-wrap:anywhere}
a{color:#246692}p{margin:15px 0}pre{padding:15px;background:#f3f6f8;overflow:auto}
@media print{body{background:white}main{margin:0;padding:0}h2{break-after:avoid}img,table{break-inside:avoid}}
"""
(OUT/"report.html").write_text(
    '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    '<title>选做1 多版本 Prompt 挖掘效果对比报告</title><style>'+style+
    "</style><main>"+content+"</main></html>",encoding="utf-8")
print("Created report.html and 4 PNG/SVG chart pairs")
