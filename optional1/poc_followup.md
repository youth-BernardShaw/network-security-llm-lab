# 三版模型 POC 原稿补测交接

主比较共有40份POC：v1 14份、v2 13份、v3 13份。模型输出中的代码已原样抽取到`pocs/`，哈希、样本、finding与来源见`poc_execution.csv`。这些脚本不能未经检查直接批量执行。

**补测状态（2026-10-20）**：40份原稿已在 WSL2 固定靶场全部执行，成功37份（v1 13/14、v2 11/13、v3 13/13）。结果见`followup_poc_results.csv`，逐条证据见`followup/evidence/`，环境见`followup/environment.md`。本文以下步骤保留为复现说明；模板已由实际结果文件取代，不再表示未执行。

开始补测时将`followup_poc_results.template.csv`复制为`followup_poc_results.csv`。模板已填好40条身份与代码哈希，其他字段由实际执行者填写；模板里的not_run不代表执行失败。

## 环境与原稿边界

复用主体项目的隔离靶场与固定源码提交，环境重建依据`../verification/runbook.md`和`../verification/environment.md`。本任务不在公网扫描。SQLi-Labs与DVWA分别使用对应PHP版本；为每版重置专用测试对象、会话、角色、security配置与数据库状态。

先检查代码的目标、写操作、恢复行为和依赖。允许通过已有命令行参数提供本地URL、专用测试账号、会话和预先创建的测试对象；这些属于环境配置，需记录。若必须改代码才能完成请求、绕过错误、解析结果或恢复状态，原稿结果保持失败或需适配；修改版另存并报告差异，不以修改后成功提升原稿成绩。

## 每份原稿的记录步骤

1. 读取该finding的原始`preconditions`、POC参数、步骤和`success_criteria`，核对`code_sha256`。
2. 先验证正常请求、登录、Token、角色与配置，避免把环境不可用当作漏洞不存在。
3. 使用固定超时、低权限、回环目标和专用对象，执行本地原稿；保存时间、命令、退出状态、脱敏输出及独立观察。
4. SQL以真/假条件业务结果差异为证；XSS需浏览器实际执行标记；命令注入需区分命令输出与页面反射；AUTH需按路径核验对象变化并恢复。脚本退出0或HTTP 200不够。
5. 独立检查清理恢复；无法安全运行的原稿记未执行及原因，不偷偷改写。
6. 写入新文件`followup_poc_results.csv`，不要修改原始台账或被复算器覆盖的CSV。

## 补测结果字段

`cohort,sample_id,finding_id,code_sha256,environment_id,condition_key,reviewer,started_at,elapsed_seconds,execution_status,success,failure_category,command_redacted,evidence_path,restore_status,adaptation_level,notes`

`success`只在有对应证据时填true或false；未执行保持空。`failure_category`区分syntax、dependency、environment、authentication、script_logic、not_triggered、observation_insufficient。环境未达到前提时应修复后重测，同时保留失败尝试。

汇总脚本接受`execution_status=executed/not_run`；原稿填写`adaptation_level=original`，恢复状态填写`restored/not_applicable`。`evidence_path`应为项目内非空证据文件，内容需包含预期现象与实际观察，不能只有脚本退出码。脚本仅检查证据引用和元数据，实际成功结论仍由复核人负责。

每个原稿提供一条最终复核记录，重试过程写入引用的证据文件。补测后在项目根运行：

```powershell
python optional1/tools/summarize_poc_followup.py optional1/followup_poc_results.csv
```

输出`followup_poc_metrics.csv`，与历史指标分离。未全部执行时保留上下界与覆盖率，不生成虚假的完整可运行率。

## 汇总口径

- 任务书主指标：已证实成功的原稿数 / 全部生成原稿数。
- 同时报告：已测试数 / 全部生成数、未测试数、失败原因分布。
- 部分执行时主比例只能称“已确认成功占全部生成数的下界”，不得称完整可运行率；也可给出`success/generated`至`(success+untested)/generated`范围。
- “已测试子集成功率”可作为辅助值，但不能替代主分母。
- 无POC的阴性结果不进入生成POC分母；其安全回归测试另列。
