# 选做4 验证报告：二次注入与隐性逻辑漏洞

分支 `optional_challenge_four` · 批次 `opt4-poc-02` · 固定提交与主体一致（DVWA `068d974` / sqli-labs `e96f217`）
环境为本机 WSL 重建（与主体差异：PHP 8.3 / MariaDB 10.11，PHP5.6 自编译；仅 127.0.0.1:9080/9081，详见 `execution_log.txt`）
四条链全部真实触发，反例与回滚全部成立。

## 结论一览

| 用例 | 漏洞 | 判定 | 关键证据 |
| --- | --- | --- | --- |
| SO-01 | Less-24 用户名→会话→logged-in.php 未编码渲染（二次存储型XSS） | 触发 | 载荷 `<svg onload=__o4s=1>` 字面值落库→登录→响应含未编码元素；对照用户名无标记 |
| SO-02 | DVWA 留言 medium 档 name 字段二次XSS（message 同页反例） | 触发 | name 字面值落库并渲染为元素；message 元素被 strip_tags 剥除；low 双字段均危险；impossible 302 |
| LG-01 | captcha 改密状态机：low 直接 step=2 跳过；medium 伪造 passed_captcha | 触发 | 无验证码、无原口令单请求改密成功；medium 负对照被拦截；impossible 302 |
| LG-02 | csrf GET 改密：无 Token/Origin/原口令，跨站单请求接管 | 触发 | 受害者 Cookie + 攻击者 Referer 的 GET 后 DB=md5(攻击者口令)；impossible 302 |

竞态窗口：范围内无可竞争的共享计数/余额对象，标记**待验证**；重复提交为幂等覆盖，低危记录（见 `verification_log.csv`）。

## 最小复现序列

1. **SO-01**：注册用户名 `<svg onload=__o4s=1>`（≤20 字符，受列宽约束）→ 登录 → GET logged-in.php。修复：用户名白名单 + 输出编码。
2. **SO-02**：security=medium 下 POST txtName=`<img src=x onerror=…>`（mtxMessage 同值对照）→ GET 留言页。修复：双字段统一 htmlspecialchars + PDO。
3. **LG-01**：登录后单请求 POST `step=2&password_new=…&Change=Change`（medium 加 `passed_captcha=true`）。修复：步骤凭证放 $_SESSION + 校验当前口令。
4. **LG-02**：受害者会话下 GET `csrf/?password_new=…&password_conf=…&Change=Change`（跨站 img 自动携带 Cookie）。修复：POST + Token + 当前口令 + Origin 校验。

## 为什么单片扫描看不见

SO-01/02：写入点有转义/过滤（单片视角"安全"），危害在读取端编码缺失——须按"源→存储→读取→汇点"分段判定；LG-01/02：UPDATE 参数化完好，漏洞在状态迁移凭证来源与跨源请求组合——须建角色×对象×动作×状态矩阵与合法/异常序列对照。完整分段链路见 `dataflow_traces/*.json`。

专属 Prompt（OPT4-P1 二次注入 / OPT4-P2 隐性逻辑）要求模型输出跨请求的源/存储/读取/汇点/触发角色/时机与最小异常序列，内置反例检验与严格 JSON 输出约束（完整文本在本地历史提交 5c12a4b，需要可恢复）。

## 复现

```bash
wsl -d Ubuntu -u root -- bash -lc 'bash /mnt/e/<repo>/optional4/tools/opt4_env_setup.sh'
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/e/<repo> && python3 optional4/tools/run_opt4_so01.py'  # so02/lg01/lg02 同
```

执行后核对：`security.users`=13、guestbook 回基线、gordonb=md5(abc123)（已核，见 `execution_log.txt`）。

## 交付物索引

- `state_matrix.xlsx`：角色×对象×动作×状态矩阵 + 7 条业务不变量（`tools/make_state_matrix.py` 再生成）
- `dataflow_traces/`：四条链的 源→存储→读取→汇点、编码时间线、反例检验（JSON ×4）
- `verification_log.csv`：逐用例判定、脚本哈希、时间戳、回滚记录（含反例行与待验证行）
- `evidence/opt4-20261020-*/`：脱敏请求/响应/观察/回滚结果 ×4 组
- `tools/`：环境脚本 + 4 个仅标准库 POC 脚本（各自内含回滚）

## 过程备注

两处首轮失败保留在 `execution_log.txt`：SO-01 载荷超 `username varchar(20)` 被拒（长度约束已并入判定）；LG-01 本地 reCAPTCHA 密钥为空时 `captcha/index.php:38-42` 覆盖模块 `$html` 致页面消息不可见，判定改以 DB 哈希回查为准。
