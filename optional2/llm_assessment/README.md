# LLM 对扫描告警的解释

每个 JSON 对应一条或一组扫描器告警：

| 文件 | 对应告警 | 结论 |
| --- | --- | --- |
| `WAP-SQLI-001-01.json` | Wapiti SQLI-001 | confirmed，目标内，POC 双重确认 |
| `WAP-SQLI-003-01.json` | Wapiti SQLI-003 | confirmed，目标内，`&&` 绕过黑名单 |
| `WAP-XSS-001-01.json` | Wapiti XSS-001 | confirmed，目标内，浏览器执行 |
| `WAP-CMD-001-01.json` | Wapiti CMD-001 | confirmed，目标内，`<pre>` 命令输出 |
| `WAP-XSS-003-01.json` | Wapiti Less-25 XSS | confirmed，但 `out_of_scope`（超出 14 父样本标签） |
| `WAP-CONFIG-001.json` | Wapiti CSP/headers/cookie 9 条 | `excluded_non_target`，部署加固，不进入目标漏洞分母 |

字段：

- `llm_verdict`：`confirmed` / `excluded`；
- `target_status`：`in_scope` / `out_of_scope` / `excluded_non_target`；
- `code_location`、`data_flow`、`preconditions`：代码根因；
- `evidence`：已有 POC/浏览器证据；
- `extension`：建议的补充测试；
- `residual_risk`：不能从该告警推出的结论。

重要：`confirmed` 不等于“模型已实测”，它是“LLM 结合代码与已有 POC 的判断”；最终状态仍以 `merged_findings.csv` 的 `verification_status` 和 POC 证据为准。
