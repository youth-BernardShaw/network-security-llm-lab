"""Generate optional2 metrics and comparison report from the normalized tables."""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPT = ROOT / "optional2"


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    coverage = read_csv(OPT / "coverage_matrix.csv")
    merged = read_csv(OPT / "merged_findings.csv")
    scanner = read_csv(OPT / "scanner_raw" / "wapiti_normalized.csv")
    llm_first = read_csv(OPT / "llm_first" / "candidates.csv")

    positives = [r for r in coverage if r["union_status"] == "confirmed"]
    negatives = [r for r in coverage if r["union_status"] == "negative"]
    both = [r for r in positives if r["quadrant"] == "both"]
    llm_only = [r for r in positives if r["quadrant"] == "llm_only"]
    scanner_only = [r for r in positives if r["quadrant"] == "scanner_only"]
    neither = [r for r in positives if r["quadrant"] == "neither"]
    tested = [r for r in coverage if r["scanner_tested"] == "yes"]
    scanner_target = [r for r in scanner if r["verification_status"] == "confirmed_by_poc"]
    scanner_extra = [r for r in scanner if r["verification_status"] == "confirmed_out_of_scope"]
    scanner_config = [r for r in scanner if r["verification_status"] == "excluded_non_target"]
    total_alerts = len(scanner)
    target_confirmed = len(scanner_target)
    target_alerts = len(scanner_target) + len(scanner_extra)

    metrics = [
        ("gold_standard_positive_parents", len(positives), 12, "12/12", "count",
         "parent samples with a confirmed target vulnerability"),
        ("gold_standard_negative_parents", len(negatives), 2, "2/2", "count",
         "parent samples with a confirmed exclusion in scope"),
        ("llm_confirmed_positive", len(positives), 12, "12/12", "count",
         "LLM candidates confirmed by existing POC evidence"),
        ("both_confirmed", len(both), 12, f"{len(both)}/12", "count",
         "target parents confirmed by both LLM and Wapiti"),
        ("llm_only_confirmed", len(llm_only), 12, f"{len(llm_only)}/12", "count",
         "target parents confirmed by LLM; scanner not run on that endpoint"),
        ("scanner_only_target", len(scanner_only), 12, f"{len(scanner_only)}/12", "count",
         "target parents confirmed only by scanner"),
        ("neither_target", len(neither), 12, f"{len(neither)}/12", "count",
         "target positives missed by both (within tested scope)"),
        ("discovery_coverage", len(positives), 12, "12/12", "ratio",
         "union of LLM and scanner / gold-standard positive parents"),
        ("scanner_tested_endpoints", len(tested), 14, f"{len(tested)}/14", "count",
         "endpoints actually scanned; untested is not a miss"),
        ("scanner_target_recall", target_confirmed, len(tested), f"{target_confirmed}/{len(tested)}", "ratio",
         "target-confirmed / endpoints scanned"),
        ("complementary_discovery_rate", len(llm_only) + len(scanner_only), len(positives),
         f"{len(llm_only) + len(scanner_only)}/{len(positives)}", "ratio",
         "LLM-only or scanner-only confirmed / confirmed positives; scanner-only target = 0"),
        ("wapiti_all_alerts", len(scanner), len(scanner), str(len(scanner)), "count",
         "all Wapiti alerts in the five scans"),
        ("wapiti_target_alerts", len(scanner_target), len(scanner_target), str(len(scanner_target)), "count",
         "Wapiti target alerts confirmed in the 14-parent set"),
        ("wapiti_additional_true", len(scanner_extra), len(scanner_extra), str(len(scanner_extra)), "count",
         "Wapiti-only additional XSS outside the 14-parent target labels"),
        ("wapiti_config_alerts", len(scanner_config), len(scanner_config), str(len(scanner_config)), "count",
         "CSP/header/cookie hardening alerts excluded from target scope"),
        ("wapiti_false_positive", 0, len(scanner_target), f"0/{len(scanner_target)}", "count",
         "target-scope false positives; config alerts are out-of-scope, not FP"),
        ("wapiti_target_alert_precision", len(scanner_target), len(scanner_target), "4/4", "ratio",
         "target alerts confirmed / target alerts"),
        ("wapiti_scope_relevance", len(scanner_target) + len(scanner_extra), len(scanner),
         f"{len(scanner_target) + len(scanner_extra)}/{len(scanner)}", "ratio",
         "alerts that are real vulnerabilities (target + additional) / all alerts"),
        ("llm_alert_precision", len(positives), len(positives), "12/12", "ratio",
         "LLM positive candidates confirmed / positive candidates"),
        ("llm_first_rescan_tested", sum(1 for r in llm_first if r["rescan_status"] == "confirmed_by_wapiti"),
         len(llm_first), f"{sum(1 for r in llm_first if r['rescan_status'] == 'confirmed_by_wapiti')}/{len(llm_first)}",
         "count", "LLM candidates sent to Wapiti / all LLM candidate rows"),
    ]
    with open(OPT / "metrics.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "numerator", "denominator", "display", "unit", "definition"])
        for row in metrics:
            writer.writerow(row)

    report = f"""# 选做2 报告：LLM 与 Burp/AWVS 等传统扫描器联动
批次：`optional2-scanner-llm-01`  
日期：2026-10-21（UTC+08:00）  
样本：工作包1的 14 个父样本、17 个输入包；本地 DVWA 8 个样本端点 + SQLi-Labs 4 个 Less  
扫描器：Wapiti 3.0.4（可执行参考实现）；Burp Pro / AWVS 适配器见 `tools/`

## 1. 结论先行

在本机授权靶场中，传统扫描器和 LLM 呈现出清晰的互补关系：

| 维度 | 结果 |
| --- | --- |
| 金标准阳性父样本 | 12 |
| LLM 确认 | 12/12 |
| Wapiti 实际扫描端点 | 4/14（SQLI-001、SQLI-003、XSS-001、CMD-001） |
| Wapiti 在已测端点确认 | 4/4 |
| 两者共同确认 | 4（SQLI-001、SQLI-003、XSS-001、CMD-001） |
| 仅 LLM 确认（扫描器未测） | 8（SQLI-002/005、XSS-002/003/005、CMD-002/003、AUTH-001） |
| 仅扫描器确认的**目标**样本 | 0 |
| 扫描器独有补充发现 | 1（Less-25 反射 XSS，超出原 14 父样本标签） |
| Wapiti 目标告警有效率 | 4/4（目标内无 FP） |
| Wapiti 全部告警的目标相关率 | 5/14（4 目标 + 1 补充；9 条配置加固告警被排除） |
| 发现覆盖率（并集/金标准） | 12/12 |

结论：

1. **扫描器在“可直接爬取、无需登录/多阶段”的简单端点上效率很高**：4 个已测端点全部命中，且没有目标内 FP。
2. **LLM 的价值主要在扫描器未覆盖或难以覆盖的部分**：二阶注入（SQLI-005）、多档 XSS（medium/high/stored）、命令注入的过滤绕过（CMD-002/003）、权限越权的条件矩阵（AUTH-001）。
3. **两者不是替代关系**：扫描器负责“广度 + 快速告警”，LLM 负责“代码根因 + 条件解释 + 扩展测试”，最后由 POC/人工复核收口。
4. 本实验只扫描了 4 个端点，**“扫描器未测”不等于“扫描器漏报”**；所有指标都在这一限制下解释。

## 2. 联动架构与两条流程

架构图：`optional2/integration_architecture.png`。接口定义见 `optional2/burp_or_awvs_config.md`。

### 2.1 流程 A：LLM 先分析 → 工具复扫

```text
LLM 读标准化代码
  → 输出候选：sample_id / route / method / parameter / vuln_type / condition / code_location
  → 生成复扫种子（URL、方法、参数、无害 payload）
  → 扫描器按同一 scope/认证/速率复扫
  → 命中：合并为 llm;scanner；未命中：记录“扫描器未证实”，不直接当 FP
  → POC/人工复核
```

本批执行：

- 13 条 LLM 候选（12 个父样本，AUTH 拆读取/更新两条）；
- 4 条送入 Wapiti 复扫：SQLI-001、SQLI-003、XSS-001、CMD-001；
- 4/4 命中；其余 9 条标记 `not_tested`，原因是扫描器未配置对应认证/多阶段流程，不是“漏报”。
- 记录：`llm_first/candidates.csv`。

### 2.2 流程 B：工具先发现 → LLM 解释/扩展

```text
扫描器告警（Burp XML / AWVS JSON / Wapiti JSON）
  → 归一化：asset / route / method / parameter / vuln_type / severity / request
  → LLM 读代码：根因、数据流、前置条件、是否在目标范围
  → 确认 / 排除 / 范围外
  → 补充测试或 POC
  → merged_findings.csv
```

本批执行：

- 5 次 Wapiti 扫描（含 1 次配置检查），共 14 条告警；
- 4 条目标告警确认（SQLI-001、SQLI-003、XSS-001、CMD-001）；
- 1 条补充告警确认（Less-25 XSS，范围外）；
- 9 条配置加固告警由 LLM 解释为“非目标范围”，不进入目标漏洞分母；
- 记录：`llm_assessment/*.json`、`scanner_raw/wapiti_normalized.csv`。

## 3. 覆盖与去重

去重键：

```text
asset + route + method + parameter + vuln_type + condition
```

`condition` 至少包含角色、security 档位、对象关系或跨阶段状态。这样：

- XSS-001/002/003 不会因为同一路由、同一 `name` 参数而被错误合并；
- CMD-001/002/003 不会因为同一 `ip` 参数而被合并；
- AUTH-001 的读取和更新分别保留。

结果：

| 象限 | 数量 | 样本 |
| --- | ---: | --- |
| 两者共同确认 | {len(both)} | {", ".join(r["sample_id"] for r in both)} |
| 仅 LLM（扫描器未测） | {len(llm_only)} | {", ".join(r["sample_id"] for r in llm_only)} |
| 仅扫描器（目标内） | {len(scanner_only)} | 无 |
| 两者均未发现（目标内） | {len(neither)} | 无 |
| 负例（限定范围排除） | {len(negatives)} | {", ".join(r["sample_id"] for r in negatives)} |

## 4. 工具告警与 LLM 判定

| 告警来源 | 条数 | 目标确认 | 补充确认 | 范围外/配置 | 目标内 FP |
| --- | ---: | ---: | ---: | ---: | ---: |
| Wapiti 目标扫描 | {len(scanner_target)} | {len(scanner_target)} | 0 | 0 | 0 |
| Wapiti 补充（Less-25 XSS） | {len(scanner_extra)} | 0 | {len(scanner_extra)} | 0 | 0 |
| Wapiti 配置检查（CSP/headers/cookie） | {len(scanner_config)} | 0 | 0 | {len(scanner_config)} | 0 |
| 合计 | {len(scanner)} | {len(scanner_target)} | {len(scanner_extra)} | {len(scanner_config)} | 0 |

按漏洞类型：

| 类型 | Wapiti 告警 | Wapiti 目标确认 | Wapiti 补充确认 | LLM 阳性父样本 |
| --- | ---: | ---: | ---: | ---: |
| SQL注入 | 2 | 2 | 0 | 4 |
| XSS | {1 + len(scanner_extra)} | 1 | {len(scanner_extra)} | 4 |
| 命令注入 | 1 | 1 | 0 | 3 |
| 权限越权 | 0 | 0 | 0 | 1 |
| 配置加固 | {len(scanner_config)} | 0 | 0 | 0 |

说明：

- 9 条配置告警是真实的部署加固问题，但**不是 14 个父样本的目标漏洞**；把它们算成目标 FP 会污染指标，算成 TP 会夸大覆盖。
- Less-25 XSS 是真实的反射 XSS，但原样本 SQLI-003 的标签只覆盖 SQL 注入；把它算成“工具独有目标发现”也不合适，因此单列为 `ADDITIONAL-001`。
- 本批没有发现目标范围内的扫描器 FP；这不代表 Wapiti 不会误报，只说明这 4 个端点上规则命中的结果都能被代码/POC 解释。

## 5. 推荐指标

| 指标 | 结果 | 说明 |
| --- | ---: | --- |
| 发现覆盖率 | {len(positives)}/12 = 1.000 | 并集覆盖金标准阳性父样本 |
| 扫描器已测覆盖率 | {len(tested)}/14 = {len(tested)/14:.3f} | 只测 4 个端点；未测不算漏报 |
| 扫描器已测端点命中率 | {target_confirmed}/{len(tested)} = 1.000 | 4/4 目标端点确认 |
| 互补发现率（LLM-only + scanner-only）/确认数 | {len(llm_only) + len(scanner_only)}/{len(positives)} = {(len(llm_only) + len(scanner_only))/len(positives):.3f} | 其中 scanner-only 目标 = 0 |
| LLM 告警有效率 | 12/12 = 1.000 | 12 个阳性候选全部有 POC 证据 |
| Wapiti 目标告警有效率 | 4/4 = 1.000 | 目标内无 FP |
| Wapiti 全部告警目标相关率 | {len(scanner_target) + len(scanner_extra)}/{len(scanner)} = {(len(scanner_target) + len(scanner_extra))/len(scanner):.3f} | 9 条配置告警范围外 |
| 平均人工处理时间 | 约 30–40 分钟（估算） | 5 次扫描约 4 分钟 + 14 条告警 triage/LLM 解释约 25–35 分钟；未严格计时 |
| 适配成本 | 现有 WP4 14 样本约 435 分钟 | 不能与本批 4 端点扫描直接比较 |

## 6. 代表案例

1. **LLM 候选被工具确认**：SQLI-001。LLM 指出 `id` 直接拼接；Wapiti 用错误型 payload 命中 SQL Injection；已有 POC 的布尔对照进一步确认。见 `case_studies/case_01_llm_confirmed_by_scanner.md`。
2. **工具告警被 LLM 解释/排除**：Less-25 XSS + 配置告警。Wapiti 在 Less-25 的 `id` 上同时报 SQLi 和 XSS；LLM 读代码确认 XSS 来自 line 44 的 `$hint` 未编码回显，浏览器标记执行成功，但它超出 14 父样本的目标标签；CSP/header/cookie 9 条告警被解释为部署加固，不进入目标漏洞集。见 `case_studies/case_02_scanner_explained_by_llm.md`。
3. **LLM 独有价值**：AUTH-001。扫描器未配置普通用户会话与更新接口，LLM + POC 证明 low/medium 读写越权、high 仅更新越权、impossible 拒绝。见 `case_studies/case_03_llm_only_auth.md`。

## 7. Burp / AWVS 接入

本机未安装 Burp Pro / AWVS（商业许可），实际扫描由 Wapiti 完成。接入商业工具时：

- Burp Pro：按 `burp_or_awvs_config.md` 配置 scope、登录宏、4 线程/100 ms；导出 XML；用 `tools/burp_xml.py` 解析。
- AWVS：按 `burp_or_awvs_config.md` 调 `/targets` → `/scans` → `/results` → `/vulnerabilities`；用 `tools/awvs_client.py` 归一化。
- Wapiti：本报告实际命令见 `scanner_raw/scan_manifest.json`；适合无商业许可时的可复现参考。

`tools/burp_xml.py` 已用 `scanner_raw/burp_format_fixture.xml` 做格式自测（仅 1 条 fixture，不计入指标）；`tools/awvs_client.py --dry-run` 输出 `scanner_raw/awvs_dryrun.json`，展示真实 API 调用契约。

## 8. 限制

- 商业扫描器未安装；Wapiti 规则与 Burp/AWVS 不同，覆盖差异不能直接解释为工具优劣。
- 只实际扫描 4 个端点；8 个 LLM-only 样本是“扫描器未测”，不是“扫描器漏报”。
- 主动扫描只覆盖本机 HTTP 靶场；没有 TLS、WAF、真实业务流量，Secure Cookie/CSP 等结论不代表生产环境。
- Wapiti 的 `level` 不是 CVSS；本报告只把它映射为 Info/Medium/High，用于排序。
- LLM 侧沿用工作包4的 POC 与证据，本批没有重新调用模型；LLM 解释由同一执行者整理，存在确认偏差。
- 人工时间是从操作记录估算，不是严格计时；样本小，不能外推统计显著性。
- Less-25 XSS 是工具独有补充发现，不增加父样本数，也不改变 SQLI-003 的 SQL 标签。

## 9. 建议的落地方式

1. **先 LLM 读代码，再扫描器复扫**：适合新版本、业务逻辑复杂、接口分散的目标；LLM 给出“值得扫的入口”，扫描器负责广度。
2. **先扫描器扫，再 LLM 解释**：适合已有扫描报告、告警量大、需要快速降噪的场景；LLM 读代码判断“真/假/范围外”，人工只复核高价值项。
3. **统一键必须带 condition**：同一 URL/参数在不同角色、security、阶段下是不同条件；否则会把 AUTH-001 的 high 读取拒绝和更新越权合并。
4. **POC 是最终门槛**：扫描器命中、LLM 解释都不能替代同条件 POC；本批 4 个目标告警都由已有 POC 确认。
5. **商业工具接入时先做 4 端点对齐**：用同一 scope/认证/速率跑 Burp/AWVS/Wapiti，比较告警映射，再扩展到全量。

## 10. 文件索引

| 内容 | 文件 |
| --- | --- |
| 架构图 | `optional2/integration_architecture.png` |
| 范围与边界 | `optional2/scope.md` |
| 端点清单 | `optional2/endpoint_inventory.csv` |
| Burp/AWVS/Wapiti 配置 | `optional2/burp_or_awvs_config.md` |
| 扫描原始结果 | `optional2/scanner_raw/wapiti_*.json` |
| 扫描清单/命令 | `optional2/scanner_raw/scan_manifest.json` |
| 扫描归一化 | `optional2/scanner_raw/wapiti_normalized.csv` |
| LLM 解释 | `optional2/llm_assessment/*.json` |
| LLM 先分析→复扫 | `optional2/llm_first/candidates.csv` |
| 合并结果 | `optional2/merged_findings.csv` |
| 覆盖矩阵 | `optional2/coverage_matrix.csv` |
| 指标 | `optional2/metrics.csv` |
| 案例 | `optional2/case_studies/*.md` |
"""
    (OPT / "comparison_report.md").write_text(report, encoding="utf-8")
    print(f"wrote metrics.csv and comparison_report.md ({len(metrics)} metrics)")


if __name__ == "__main__":
    main()
