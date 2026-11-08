# 展示与报告证据索引 (Evidence Index)

本文件为实验总报告、汇报 PPT 与仓库归档材料之间的核验索引，记录报告正文引用的关键代码片段、模型原始响应、浏览器实测画面、扫描器日志及跨阶段追踪文件的相对路径与校验口径。

## 1. 主体工作包 1 至 4 核心证据

| 编号 / 引用 | 报告对应章节 | 仓库路径 | 核验说明 |
| --- | --- | --- | --- |
| 代码片段一 (SQLI-001) | 4.1.5 标准输入与行号追溯 | `workpackage1/normalized_samples/SQLI-001.php`、`workpackage1/line_maps/SQLI-001.csv` | 局部第 8、14、15、20、28 行对应 GET 读取、SQL 拼接、查询执行与输出回显 |
| 图2 (wp2-eval-42 批次汇总) | 4.2.5 三版历史评测结果 | `results/batches/wp2-eval-42/README.md`、`results/batches/wp2-eval-42/metrics.csv` | 14 个父样本乘以 v1、v2、final 三版共 42 条独立子代理评测记录 |
| 输出节选 (SQLI-001 候选) | 4.3.2 三级推理职责 | `results/batches/wp2-eval-42/raw_outputs/SQLI-001__final.json` | 静态阶段标记为存在候选与待验证，包含片段 ID、局部行号与逐字引文 |
| 图3 (XSS-005 存储型回读) | 4.4.5 代表案例与条件解释 | `verification/evidence/wp4-20261019-xss005-low/browser.png`、`browser.json` | `browser.json` 记录 `marker=WP4XSS005` 且 `executed=true` |
| 图4 (XSS-004 Token 拦截) | 4.4.5 代表案例与条件解释 | `verification/evidence/wp4-20261019-xss004-impossible/browser.png`、`response.redacted.txt` | 区分无 Token 前置拦截画面与有效 Token 下的 HTML 实体编码响应 |
| 代码片段二 (CMD-003 过滤) | 4.4.5 代表案例与条件解释 | `workpackage1/normalized_samples/CMD-003.php` | 局部第 6 至 18 行黑名单替换表仅过滤带空格管道符 `\| ` |
| 图5 (CR-008 修正与复测) | 4.5.4 两轮基于证据的优化 | `results/batches/wp4-final-wp4-v2/README.md`、`results/change_requests.csv` | 严格静态协议由 4/14 提升至 14/14，XSS-004 与 CMD-004 排除证据恢复至 6 条与 13 条 |
| 主体盲评记录 | 4.5.5 辅助盲评与清理记录 | `verification/blind_review/report.md` | 17 条条件运行脱敏证据包盲评 17/17 一致 |

## 2. 选做一至选做四扩展证据

| 编号 / 引用 | 报告对应章节 | 仓库路径 | 核验说明 |
| --- | --- | --- | --- |
| 图6 (选做1 协议与 POC 对比) | 4.6.2 分类与协议结果 | `optional1/metrics.csv`、`optional1/followup_poc_metrics.csv` | 严格协议通过率 35.71% / 57.14% / 100.00%；原稿 POC 触发率 13/14、11/13、13/13 |
| 代码片段三与图7 (SQLI-003) | 4.6.4 四十份原稿 POC 补测 | `optional1/pocs/v3/SQLI-003__1.py`、`optional1/followup/evidence/v3/SQLI-003__1.md` | 基线、恒真、恒假、单引号破坏四组对照及 `login_digest` 差分结果 |
| 图8 (Less-25 补充 XSS) | 4.7.5 代表案例与效率限制 | `optional2/case_studies/less25_xss_browser.png`、`optional2/merged_findings.csv` | Wapiti 3.0.4 实扫发现的提示区反射型 XSS，单列为 `ADDITIONAL-001` |
| 图9与代码片段四 (输出闸门) | 4.8.2 至 4.8.4 | `optional3/validators/guard.py`、`optional3/checks/guard-v2-retest-20261026.md` | `auto_execute` 固定为 `False`，v2 规则将问题实例由 79 项降至 45 项 |
| 选做4 流程模型与状态矩阵 | 4.9.1 至 4.9.2 | `optional4/workflow_model.md`、`optional4/state_matrix.xlsx`、`optional4/report.md` | 角色×对象×动作×状态矩阵、7 项业务不变量及用例执行状态 |
| 选做4 专属 Prompt 与追踪 | 4.9.2 至 4.9.7 | `optional4/special_prompts/`、`optional4/dataflow_traces/`、`optional4/poc_cases/` | OPT4-P1 二次注入与 OPT4-P2 隐性逻辑专属 Prompt 全文、四条跨阶段数据流与 POC 用例 |
| 选做4 主流程集成入口 | 4.9.7 回滚记录与完善情况 | `workflow.py`、`workpackage1/extensions/optional4-v1/`、`prompts/prepared/optional4-mainflow-v1/` | 选做4 四条链路接入五模块标准化输入、规则与批次台账的验证适配器 |
