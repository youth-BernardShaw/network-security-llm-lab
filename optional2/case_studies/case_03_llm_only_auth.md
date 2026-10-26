# 案例三：LLM 独有价值（AUTH-001 权限条件矩阵）

## 1. 为什么扫描器没有覆盖

AUTH-001 需要：

- DVWA 管理员会话与普通用户 `gordonb` 会话；
- `security` Cookie 的 low/medium/high/impossible 四档；
- 页面、读取 API、更新 API 三个独立入口；
- 专用测试对象 `wp4target` 的更新与恢复。

本批 Wapiti 只配置了 4 个简单端点，未建立普通用户会话与更新 API 的扫描序列，因此 AUTH-001 标记为 `scanner_tested=no`，**不是“扫描器漏报”**。

## 2. LLM + POC 的发现

代码事实：

- 读取接口 `AUTH-001-D:10`：high/impossible 且非 admin → `Access denied`；
- 更新接口 `AUTH-001-E:11`：仅 impossible 且非 admin → `Access denied`；
- 页面检查在 `AUTH-001-C`（medium/high/impossible），low 没有页面角色检查。

POC 结果：

| 条件 | 页面 | 读取 | 更新 | 结论 |
| --- | --- | --- | --- | --- |
| 普通用户 low | 200 | 全部 6 行 | `ok`，DB 变化 | 读+写越权 |
| 普通用户 medium | 403 | 全部行 | `ok`，DB 变化 | 页面拒绝不覆盖 API |
| 普通用户 high | 403 | `Access denied` | `ok`，DB 变化 | 仅更新越权 |
| 普通用户 impossible | 403 | `Access denied` | `fail`，无 DB 变化 | 条件内拒绝 |

证据：`verification/evidence/wp4-20261019-auth001-low/`、`...-medium/`、`...-high/`、`...-impossible/`。

## 3. 联动含义

- 扫描器擅长“参数级、可爬取”的入口；AUTH-001 的问题是**业务授权条件**，需要代码 + 多会话 + 对象状态；
- LLM 能先指出“页面检查、读取检查、更新检查不是同一段代码”，再由 POC 验证；
- 如果只让扫描器扫页面，会得到 403，误以为“已防护”；如果只让 LLM 读代码，没有运行证据也不能确认；
- 两者与人工 POC 的组合才形成完整结论。

## 4. 结论

- 这条案例体现 LLM 的独有价值：**跨入口、跨角色、跨配置的授权一致性**；
- 也体现指标口径：`scanner_tested=no` 不能算作 scanner FN，只有实际扫描且未发现才谈漏报；
- 在商业工具接入时，应为 AUTH-001 配置普通用户会话、更新 API 请求和对象 ID，再比较 scanner 与 LLM 的覆盖。
