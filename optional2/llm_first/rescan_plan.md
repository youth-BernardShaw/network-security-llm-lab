# 流程 A：LLM 先分析 → 工具复扫

## 1. 输入

- 工作包1 v2 标准化片段；
- 工作包4 的 LLM 候选（`final-wp4-v2` 或人工确认的 finding）；
- 工作包4 的 POC/证据，用于确认扫描器命中。

## 2. 候选转扫描种子

对每条 LLM finding 提取：

| LLM 字段 | 扫描种子 |
| --- | --- |
| `sample_id` | 关联的父样本/端点 |
| `locations.fragment_id` | 所在源码/路径 |
| 请求入口 | asset + route |
| HTTP 方法 | GET/POST |
| 参数名 | scanner parameter |
| 前置条件 | 认证、security、角色、对象 |
| `poc.expected_observation` | 无害 payload / 观察点 |

生成 `optional2/llm_first/candidates.csv`，其中 `scanner_seed` 是可直接用于 Wapiti/Burp/AWVS 的请求描述。

## 3. 复扫执行

本批选择 4 个无需复杂认证/多阶段的候选：

| sample | route | method | param | Wapiti 结果 |
| --- | --- | --- | --- | --- |
| SQLI-001 | `/Less-1/index.php` | GET | id | 命中 SQLi |
| SQLI-003 | `/Less-25/index.php` | GET | id | 命中 SQLi |
| XSS-001 | `/vulnerabilities/xss_r/` | GET | name | 命中 XSS |
| CMD-001 | `/vulnerabilities/exec/` | POST | ip | 命中命令执行 |

未送扫的 9 条（AUTH 2 条 finding + SQLI-002/005、XSS-002/003/005、CMD-002/003）原因：

- 需要 DVWA 普通用户会话 / 多阶段注册-登录-改密；
- 需要 security=medium/high 的独立会话；
- 扫描器没有配置对应登录宏/更新 API。

这些条目标记 `not_tested`，不写成 `miss`，也不进入 scanner recall 分母。

## 4. 复扫结果处理

- 扫描器命中：合并为 `llm;scanner:wapiti`，状态 `confirmed_by_both`，再由 POC 复核；
- 扫描器未命中：记录 `scanner_not_confirmed`，不直接判 FP；
- 扫描器报出范围外问题：单列 `confirmed_out_of_scope`，不增加父样本数；
- 扫描器报出配置问题：单列 `excluded_non_target`，不进入目标漏洞分母。

## 5. 复现

```bash
# 生成 DVWA Cookie（不提交）
python3 optional2/tools/get_dvwa_cookie.py

# 4 个复扫命令见 optional2/scanner_raw/scan_manifest.json
# 归一化 + 合并
python3 optional2/tools/build_optional2.py
python3 optional2/tools/build_optional2_report.py
```
