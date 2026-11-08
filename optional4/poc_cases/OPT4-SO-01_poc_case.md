# POC 用例 OPT4-SO-01：Less-24 会话用户名二次存储型XSS

- 追踪：`dataflow_traces/OPT4-SO-01.json`；回溯样本 SQLI-005
- 目标：证明"存储时安全（转义落库）、使用时危险（会话取回后无编码渲染）"
- 无害标记：`<svg onload=__o4s=1>`（onload 内仅为全局赋值，不读 Cookie、不外传）；测试账号用后即删，不触碰预置教学用户
- 真实约束：`security.users.username` 为 varchar(20)，注册端存在长度约束但无字符集约束——载荷恰好 20 字符，超长载荷（如 37 字符的 `<img src=x onerror=...>`）会在 INSERT 时被拒绝（"Data too long"），该事实已记入追踪文件

## 前置条件

sqli-labs-wsl 服务在线（127.0.0.1:9081）；`security` schema 可由 root 经 unix socket 访问。

## 步骤（SEQ-A01）

| 步 | 角色 | 操作 | 输入 | 预期 |
| --- | --- | --- | --- | --- |
| 1 | R2 | POST /Less-24/login_create.php | username=`<svg onload=__o4s=1>`（整体作用户名，20字符），password=re_password=`<专用一次性口令>` | 注册成功页（Less-24-user-created） |
| 2 | — | DB 回查 | `SELECT username FROM security.users WHERE username LIKE '%svg%' OR username LIKE '%__o4s%'` | 字面值落库（含 `<`、`>` 原字符） |
| 3 | R3 | POST /Less-24/login.php | login_user=同载荷用户名，login_password=专用口令 | 302 → logged-in.php，Auth Cookie |
| 4 | R3 | GET /Less-24/logged-in.php | — | 响应 HTML 中 `<svg onload=__o4s=1>` 以**未编码元素**出现（汇点命中） |
| 5 | R3 | 对照组：注册普通用户名 opt4ctl 后同样登录访问 | 无载荷 | 响应无标记 |
| 6 | — | 清理 | DELETE 两个测试用户（含 LIKE '%__o4s%'） | 行数恢复 |

## 判定

- 成立：步骤 4 的载荷在 HTML 元素位置原样出现（未被 `&lt;` 转义），且步骤 2 证明写入端转义未改变字面值。
- 排除示例（不命中）：若 logged-in.php 使用 htmlspecialchars（本代码没有），或注册端拒绝 `<`/`>`（本代码没有）。
- 浏览器执行层：主体 XSS-005 已用无头浏览器证明同一渲染机制可执行脚本（window.__wp4xss 置位）；本用例以"响应含可执行元素构造且未被编码"为充分证据。

## 回滚

见 `reset_steps.md` §1（按用户名定点 DELETE，无需重置整库）。
