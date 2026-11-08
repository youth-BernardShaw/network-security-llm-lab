# POC 用例 OPT4-LG-01：DVWA captcha 改密状态机绕过（状态跳跃 / 客户端状态标记）

- 追踪：`dataflow_traces/OPT4-LG-01.json`；新扫描面 vulnerabilities/captcha（同一固定提交）
- 目标：在**不知道当前口令、未通过 CAPTCHA** 的前提下完成口令变更（low：跳过 step=1；medium：伪造 passed_captcha）
- 测试对象：gordonb（口令本地一次性变更后经 DB 恢复为 md5(abc123)）

## 前置条件

dvwa-wsl 服务在线；DVWA reCAPTCHA 密钥未配置（recaptcha_check_answer 恒假 → 合法路径在本地不可达，属环境事实，不影响异常路径）；密钥为空时 captcha/index.php:38-42 会覆盖模块 $html，页面消息显示为密钥缺失横幅——**判定一律以 DB 哈希回查为准**。

## 步骤（SEQ-A03 / SEQ-A04）

| 步 | 档位 | 操作 | 输入 | 预期 |
| --- | --- | --- | --- | --- |
| 1 | low | 登录 gordonb（security=low） | — | 会话建立；记录旧 md5 |
| 2 | low | POST /vulnerabilities/captcha/ | step=2, password_new=password_conf=opt4lg1new, Change=Change（**无 g-recaptcha-response、无当前口令**） | UPDATE 执行，DB 哈希变化（页面消息被横幅覆盖） |
| 3 | — | DB 回查 | users.password | = md5(opt4lg1new) → 状态跳跃成立 |
| 4 | — | DB 恢复 | UPDATE 回 md5(abc123) | 恢复 |
| 5 | medium | 登录 gordonb（security=medium） | — | 会话建立 |
| 6 | medium | 负对照：POST step=2 **不带** passed_captcha | 同上 | 请求被拦截，DB 哈希不变（证明该标记是被检条件） |
| 7 | medium | POST step=2 + passed_captcha=true | 同上 | UPDATE 执行；DB = md5(新值) |
| 8 | — | DB 恢复 | — | 恢复 |
| 9 | impossible | 登录后无 Token POST | step=2... | 302 拒绝（checkToken；反例） |

## 判定

- low 成立：step=2 分支无任何服务端迁移凭证校验（`low.php:52-86`），单请求改密成功。
- medium 成立：唯一被检查的 `passed_captcha` 来自客户端隐藏域（`medium.php:64-69`），可伪造；步骤 6/7 的差异证明其充分性。
- 排除条件检验：impossible 档 Token+当前口令+PDO 三重校验（反例）；若 step=2 校验会话内服务端标志则排除（本代码没有）。

## 回滚

见 `reset_steps.md` §3（DB 定点恢复口令哈希；不重置整库）。
