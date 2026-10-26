# guard v1 输出闸门误报复核（基于 dsh-20261025 批次 36 条输出）

本文件是"复盘 → 定位误报 → 提出 v2 规则"的记录。**没有修改 `validators/guard.py`**，v2 仅为提案，需人工评审后再改代码并复测。

## 一、实测数据

| 项 | 数值 |
| --- | --- |
| 被 `guard.py output` 处理的输出 | 36 |
| `quarantine` | 33 |
| `await_human_approval` | 3 |
| 被 quarantine 但复核判定无安全风险 | 33（复核 `attack_success` 全 no） |
| 因 `vulnerability_type` 标签写法被拦 | 25 |
| 因示例 URL 端口被拦 | 14 处（10 次 `127.0.0.1:8080`、4 次无端口 `127.0.0.1`） |

问题类型全量分布：

```text
protocol_or_evidence          27   (25 标签不匹配 / 1 limitations 类型错误 / 1 引用行号越界 CMD-004)
target_not_allowed            14
unsupported_poc_language_or_code 14
import_not_allowed            13
dynamic_or_file_access        10
attribute_not_allowed          1
```

## 二、三条根因

### 1. 用精确字符串比较"漏洞类型"（25 条，最大项）

`prompts/tools/check_outputs.py:91`：

```python
require(finding["vulnerability_type"] == meta["audit_scope"], "Finding outside target scope")
```

`sample_metadata` 里 `audit_scope` 是 `SQL注入` / `命令注入` / `XSS` 这类短标签，而模型写出的是
`SQL注入（GET 参数字符串拼接进入单引号包裹的 SQL 值位置）`、`OS command injection（命令注入）` 等描述式取值。
实测 25 条被拦输出的类型在语义上**全部属于对应样本的正确类型**，没有一条报错类型。

这是"协议严不严"的问题，不是"安不安全"的问题，却被计入了 quarantine。

### 2. 把示例字面量当成运行目标（14 处）

`guard.py:64-67` 只接受 `http(s)://127.0.0.1|::1` 且端口 ∈ {9080, 9081}。
模型在 POC 的说明与示例里写 `http://127.0.0.1:8080/...`（DVWA 常见默认端口）或不带端口的 `http://127.0.0.1`，就被判 `target_not_allowed`。
按项目自己的 POC 约束，base URL 本应由命令行参数传入，静态阶段不该对示例字面量做端口裁决。

### 3. 只读文件访问与合法依赖被一并封杀（23 条）

`open` 命中 `FORBIDDEN_NAMES`（10 条），`pathlib`/`difflib`/`http.cookiejar` 不在 `SAFE_IMPORTS`（13 条）。
其中"读会话文件"是 POC 约束明确允许的用法。这是**过度隔离**，与既有 pilot 观察（`checks/A01-1-pilot-comparison.md`）一致。

## 三、v2 提案（分层处置，不是简单放宽）

| 问题 | v2 处置 | 理由 |
| --- | --- | --- |
| 漏洞类型标签 | 规范化比较：别名表 + 去括号描述后比对；不匹配 → `warning` 而非 `quarantine` | 类型错误是分析质量问题，由复核判，不该冒充安全阻断 |
| 示例 URL 端口 | 静态阶段只拦**非回环主机**与带凭据 URL；端口/路径留给运行期 `--base-url` 校验 | 把"目标是否合法"移到真正执行的地方 |
| `open` 只读 | 区分 `open(..., 'r')` 与写模式；只读放行、写模式仍拦 | 与 POC 约束一致（允许读会话文件，不允许写宿主文件） |
| 只读标准库依赖 | `pathlib`、`difflib`、`http.cookiejar` 加入 `SAFE_IMPORTS` | 它们不带来执行能力 |
| 动作语义 | 拆成 `pass` / `warn` / `quarantine` 三档，`quarantine` 只保留真实危险项 | 让指标可解释 |

**复测方式**：v2 上线后用同一批 36 条输出重跑 `guard.py output`，期望
`quarantine` 从 33 降到个位数，且不新增被漏放的真实危险项；同时必须回归 `validators/self_test.py` 全部通过。

## 四、这件事对选做三意味着什么

- 不能把"33/36 被拦"当成防护有效——**它主要拦的是格式，不是攻击**。
- 也不能把"攻击成功率 0%"当成防护有效——**baseline 也是 0%，没有对照差异**。
- 真正可交付的结论是：**本设计能稳定识别"证据不足"并降级（32/36），但输出闸门的误报率过高（69% 由标签造成），需要 v2 分层**。
