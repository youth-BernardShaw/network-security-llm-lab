# 选做4：二次注入与隐性逻辑漏洞验证（optional4/）

工作包：选做四 设计复杂漏洞专属流程（对应任务书《选做4_二次注入与隐性逻辑漏洞验证.docx》）
分支：`optional_challenge_four` · 批次 `opt4-poc-02` · 环境 `opt4-env-02`（本机重建，档案见 `environment_opt4.md`）
固定代码：与主体一致（DVWA `068d974` / sqli-labs `e96f217`），新扫描面（captcha/csrf 模块）属同一 DVWA 固定提交。

## 交付物与检验项对照

| 任务书检验项 | 本包交付物 | 状态 |
| --- | --- | --- |
| 流程模型（角色/对象/状态/不变量完整可复现） | `workflow_model.md`、`state_matrix.xlsx`（3 工作表，由 `tools/make_state_matrix.py` 可再生成） | ✅ |
| 跨阶段证据（每个二次注入候选有源/存储/读取/汇点） | `dataflow_traces/OPT4-SO-01.json`、`OPT4-SO-02.json`（含反例检验与编码时间线） | ✅ |
| 专属Prompt（多步链路/异常序列+反例+输出约束） | `special_prompts/prompt_so_second_order.md`（OPT4-P1）、`prompt_logic_invariant.md`（OPT4-P2） | ✅ |
| POC可回滚（测试账号/无害数据/重置步骤） | `poc_cases/*.md` ×4、`reset_steps.md`、`tools/run_opt4_*.py` ×4 | ✅ |
| 结果可核验（逐步请求/角色/对象/状态/现象） | `verification_log.csv`、`execution_log.txt`、`evidence/opt4-20261020-*/` | ✅ |
| 结果分析（差异统计/归因/局限） | `analysis_report.md` | ✅ |

## 验证结论一览

| 用例 | 场景 | 判定 | 回溯 |
| --- | --- | --- | --- |
| OPT4-SO-01 | Less-24 注册用户名→会话→logged-in.php 未编码渲染（二次存储型XSS） | 真漏洞·已触发 | SQLI-005 同链路新汇点 |
| OPT4-SO-02 | DVWA xss_s medium name 字段（写入端字段级差异，message 为同页反例） | 真漏洞·已触发 | XSS-005 未覆盖档位 |
| OPT4-LG-01a | captcha low 直接 step=2 改密（状态跳跃） | 真漏洞·已触发 | 新扫描面 |
| OPT4-LG-01b | captcha medium 伪造 passed_captcha（客户端状态标记） | 真漏洞·已触发 | 新扫描面 |
| OPT4-LG-02 | csrf low GET 跨站改密（单步合法、组合接管） | 真漏洞·已触发 | 新扫描面 |
| SEQ-C01/C02 | 无会话改密 / impossible 无 Token | 反例·未触发 | 主体机制复用 |
| INV-06 / INV-07 | 重复提交 / 竞态窗口 | 低危害记录 / **待验证** | `analysis_report.md` §4 |

## 执行与复现

```bash
# 1. 环境（首次，含 PHP5.6 编译约 15 分钟）
wsl -d Ubuntu -u root -- bash -lc 'bash /mnt/e/<repo>/optional4/tools/opt4_env_setup.sh'
# 2. 健康检查通过后执行（顺序无关；每个脚本自含回滚）
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/e/<repo> && for s in so01 so02 lg01 lg02; do python3 optional4/tools/run_opt4_$s.py; done'
```

脚本仅标准库；请求仅发往 127.0.0.1:9080/9081；证据中的口令与 Cookie 已脱敏；全部测试数据在脚本内定点清理（`reset_steps.md` §6 有执行后核对清单）。

## 过程透明度

两处首轮失败及原因保留在 `execution_log.txt`：SO-01 载荷超出 username varchar(20)（真实攻击面约束，已并入判定文档）；LG-01 首轮误信页面消息（本地 reCAPTCHA 密钥为空时 `captcha/index.php:38-42` 覆盖模块 `$html`，判定口径改为 DB 回查）与负对照采样时序问题。
