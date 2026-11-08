# POC 用例 OPT4-LG-02：DVWA csrf 模块 GET 改密跨站请求伪造（单步合法、组合后接管）

- 追踪：`dataflow_traces/OPT4-LG-02.json`；新扫描面 vulnerabilities/csrf（同一固定提交）
- 目标：证明受害者浏览器被诱导发出的单个 GET 即可改密（无 Token/无 Origin/无当前口令）
- 实验室内模拟：请求携带**受害者会话 Cookie + 攻击者 Referer**，等价于 `<img src=...>` 自动发起的跨站加载；不部署公网攻击页
- 测试对象：gordonb（口令经 DB 恢复）

## 步骤（SEQ-A05）

| 步 | 角色 | 操作 | 输入 | 预期 |
| --- | --- | --- | --- | --- |
| 1 | R3 | 登录 gordonb（security=low） | — | 会话建立；记录旧 md5 |
| 2 | R5(模拟) | GET /vulnerabilities/csrf/ | password_new=password_conf=opt4csrf, Change=Change；**Referer: http://attacker.invalid/opt4.html**；**无 user_token** | HTTP 200 且响应含 `Password Changed.` |
| 3 | — | DB 回查 | users.password | = md5(opt4csrf) → 跨站改密成立 |
| 4 | — | DB 恢复 | UPDATE 回 md5(abc123) | 恢复 |
| 5 | R3(反例) | 登录后 GET csrf（security=impossible） | 同参数、无 Token | 302 拒绝（checkToken） |
| 6 | — | 攻击页形态记录 | evidence 附模拟攻击者页面 HTML（仅含无害 `<img>` 指向上述 URL） | 证明"访问即触发、无需点击" |

## 判定

- 成立：步骤 2-3 证明跨源上下文（攻击者 Referer）下、无任何主体绑定凭证的请求完成了状态变更。
- 排除条件检验：impossible 档 Token+当前口令（反例）；若动作为 POST+Token 则排除（本代码为 GET 无 Token）。
- 附带观察：GET 改密使新口令进入浏览器历史/服务端访问日志（低危记录，不单列漏洞）。

## 回滚

见 `reset_steps.md` §3。
