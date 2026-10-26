# 选做2：LLM 与 Burp/AWVS 等传统扫描器联动

本目录给出“LLM 代码分析”和“传统扫描器”的联动方案、可执行参考实现、真实本地扫描结果、合并/去重/指标和案例。

## 快速入口

| 内容 | 文件 |
| --- | --- |
| 架构图 | [integration_architecture.png](integration_architecture.png) |
| 范围与安全边界 | [scope.md](scope.md) |
| 端点清单 | [endpoint_inventory.csv](endpoint_inventory.csv) |
| Burp/AWVS/Wapiti 配置 | [burp_or_awvs_config.md](burp_or_awvs_config.md) |
| 比较报告 | [comparison_report.md](comparison_report.md) |
| 指标 | [metrics.csv](metrics.csv) |
| 合并结果 | [merged_findings.csv](merged_findings.csv) |
| 覆盖矩阵 | [coverage_matrix.csv](coverage_matrix.csv) |
| 扫描原始结果 | `scanner_raw/` |
| LLM 解释 | `llm_assessment/` |
| LLM 先分析→复扫 | `llm_first/` |
| 案例 | `case_studies/` |

## 两条流程

1. **LLM 先分析 → 工具复扫**：LLM 输出 route/method/parameter/condition/code_location，生成扫描种子；扫描器按同一 scope/认证/速率复扫；命中合并，未命中记 `not_tested` 或 `not_confirmed`，不直接当 FP。
2. **工具先发现 → LLM 解释/扩展**：扫描器告警归一化后，LLM 读代码判断根因、前提、范围和补充测试；确认/排除/范围外三种状态分开。

## 本批实际结果

- Wapiti 3.0.4 扫描 5 次，14 条告警；
- 4 条目标告警确认：SQLI-001、SQLI-003、XSS-001、CMD-001；
- 1 条补充确认：Less-25 XSS（超出 14 父样本标签，单列 `ADDITIONAL-001`）；
- 9 条 CSP/Header/Cookie 配置告警：LLM 解释为非目标范围，不进入目标漏洞分母；
- LLM 12/12 阳性父样本有 POC 证据；扫描器实际只测 4/14 端点，未测不算漏报；
- 发现覆盖率 12/12；扫描器目标告警有效率 4/4；互补发现率 8/12（LLM-only，scanner-only 目标为 0）。

## 工具说明

本机未安装 Burp Suite Professional 或 AWVS（商业许可）；Burp Community 不含主动 Scanner。为保证真实可执行证据，本批用 **Wapiti 3.0.4** 作为传统扫描器的参考实现，并提供：

- `tools/burp_xml.py`：Burp XML 解析；
- `tools/awvs_client.py`：AWVS REST API 客户端（dry-run/真实）；
- `burp_or_awvs_config.md`：两套商业工具的 scope、认证、速率、导出配置。

接入商业工具时替换扫描器适配层即可；归一化、去重、POC 复核和指标口径不变。扫描结果不冒充 Burp/AWVS 实测。

## 复现

```bash
# 1. 启动本地靶场
bash verification/tools/env_setup.sh

# 2. 生成 DVWA Cookie（写到 optional2/tmp，已 gitignore）
python3 optional2/tools/get_dvwa_cookie.py

# 3. 扫描（命令见 scanner_raw/scan_manifest.json）
# 4. 归一化/合并/报告
python3 optional2/tools/build_optional2.py
python3 optional2/tools/build_optional2_report.py
python3 optional2/tools/verify_optional2.py
```

`optional2/tmp/` 不提交；`scanner_raw/` 的 Wapiti JSON 不含 Cookie 值，只含参数与请求行。
