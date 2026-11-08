# 专属Prompt OPT4-P1：二次注入跨阶段数据流挖掘（含反例与输出约束）

- prompt_id: OPT4-P1
- 适用场景：二次注入（存储时安全、使用时危险）
- 输入物：`workflow_model.md` §2-§3、目标模块源码（固定提交）、主体 `workpackage1/normalized_samples/`
- 输出物：`dataflow_traces/OPT4-SO-*.json` 草稿
- 约束：仅分析授权教学靶场固定提交内的代码；结论必须落到具体文件与行号。

---

## Prompt 正文

你是代码审计助手。目标代码来自本地授权教学靶场（DVWA / sqli-labs 固定提交）。请针对下面给出的模块，完成**跨阶段数据流**挖掘，不要做单函数危险函数扫描。

### 任务

1. 对每个可能跨请求持久化的输入（表单字段、Header、URL 参数），列出它的完整链路：
   `源(请求+参数) → 写入点(文件:行, 使用的转义/过滤函数) → 存储载体(表.字段 或 会话键) → 读取点(文件:行, 如何取回) → 每个再解释/再输出汇点(文件:行, 汇点类型: SQL拼接 / HTML输出 / 命令执行 / 文件路径)`。
2. 对每个汇点分别回答（写入点和读取点分开判定，不许合并）：
   - 第一阶段（写入）是否可能改变存储语句语义？依据是什么转义函数、什么SQL上下文（引号风格）？
   - 第二阶段（使用）取回的值与当初输入的字面值是否相同？经过了哪些编码/解码/拼接/权限变化？
   - 汇点处该值处于什么解释上下文？该上下文要求的编码是否发生过？
3. 明确给出：触发角色（谁能写入）、触发时机（哪个请求/哪个角色读取时受害）、跨请求关系（写入请求和触发请求是否不同、间隔了什么状态）。
4. 对每个候选给出**反例检验**：说明什么样的代码事实会推翻该候选（例如读取点有 htmlspecialchars、汇点参数化、注册端字符集白名单），并逐条检查目标代码是否命中反例。命中反例的候选标记为已排除并保留排除理由。
5. 不允许仅凭"出现 mysql_real_escape_string / 出现危险函数"下结论；每条结论必须引用文件:行号。

### 输出格式（严格，JSON）

```json
{
  "candidates": [
    {
      "id": "SO-xx",
      "source": {"request": "...", "param": "..."},
      "write_point": {"file": "...", "line": 0, "escape": "..."},
      "storage": {"carrier": "db_field|session|cache|log|file", "location": "...", "stored_form": "..."},
      "read_points": [{"file": "...", "line": 0, "how": "..."}],
      "sinks": [{"file": "...", "line": 0, "kind": "sql|html|cmd|path", "context_quote": "single|double|none"}],
      "first_stage": {"triggered": false, "reason": "..."},
      "second_stage": {"triggered": true, "reason": "..."},
      "encoding_changes": ["..."],
      "trigger_role": "...",
      "trigger_timing": "...",
      "cross_request": true,
      "counter_example_check": [{"exclusion": "...", "hits_target": false, "evidence": "file:line"}],
      "verdict": "candidate|excluded|needs_dynamic_proof"
    }
  ]
}
```

### 判定标准（与 `选做4` 文档一致）

| 结论 | 必要证据 | 排除条件 |
| --- | --- | --- |
| 二次注入成立 | 同一输入跨阶段到达危险解释点，第二阶段可改变语义或执行结果 | 读取点始终按数据处理且有正确编码；危险汇点不可达 |
| 待动态验证 | 静态链路完整但语义变化依赖运行时（如 fetch 行序、字符集） | — |

## Prompt 使用记录

| 运行 | 输入模块 | 输出候选 | 采纳情况 |
| --- | --- | --- | --- |
| opt4-run1 | Less-24 login_create/login/logged-in/pass_change | SO-xx（会话用户名 HTML 汇点） | 采纳为 OPT4-SO-01，人工核对行号后进入 dataflow_traces |
| opt4-run2 | DVWA xss_s low/medium/impossible | name/message 双字段差异 | 采纳为 OPT4-SO-02；message 字段作为内置反例保留 |

（运行方式：将本 Prompt 正文与对应模块源码一并提交给本地 LLM 会话；模型输出 JSON 草稿由人工按 `verification/` 规范复核行号后入库。模型原始输出与复核差异记录在 `analysis_report.md` §5。）
