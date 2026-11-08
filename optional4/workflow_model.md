# 选做4 跨请求业务流程与数据流模型（workflow_model.md）

工作包：选做4 设计复杂漏洞专属流程（二次注入与隐性逻辑漏洞验证）
批次：`opt4-poc-02`（环境标识 `opt4-env-02`，见 `optional4/environment_opt4.md`）
固定代码：DVWA `068d974487a297c155c48722f9fcf7180a83adc4`；sqli-labs `e96f21776372c8613a7e565106e62bc01a59355e`（与主体 `workpackage1/samples.csv` 完全一致）

本模型是选做4挖掘方案的第一步产出：先列出角色、对象、状态、请求序列和业务不变量，再由 `state_matrix.xlsx`、`dataflow_traces/`、`special_prompts/`、`poc_cases/` 逐层细化。所有结论可回溯到主体部分的样本ID与证据（`verification/validation_log/wp4-20261019-*.json`）。

---

## 1. 角色模型

| 角色ID | 角色 | sqli-labs 对应 | DVWA 对应 | 说明 |
| --- | --- | --- | --- | --- |
| R1 | 匿名访客 | 未登录，无 `Auth` Cookie/会话 | 未登录，无 PHPSESSID | 只能访问登录页、注册页 |
| R2 | 注册新用户入口 | `new_user.php` 提交者（写入载体第一阶段的控制点） | 无对应（DVWA 无公开注册） | R1 通过注册升级为 R3 的前置 |
| R3 | 已登录普通用户 | `users` 表任一行，`$_SESSION["username"]` + `Auth` Cookie | `gordonb` 等 5 个预置账号 | 主要攻击起点 |
| R4 | 管理员 | 无角色区分（教学靶场） | `admin`，菜单与 `/api/v1/user` 写接口授权主体 | 垂直越权目标 |
| R5 | 受害者浏览器上下文 | — | 持有有效会话的浏览器，被诱导访问攻击者页面 | CSRF 类漏洞的"执行环境"，不是人 |
| R6 | 攻击者控制的第三方页面 | — | 与靶场不同源的任意 HTML 页面 | 仅用于 CSRF/组合请求分析，不部署公网 |

sqli-labs 无角色分级（所有登录用户等权），垂直越权仅在 DVWA 侧建模；这与主体 AUTH-001 的结论一致（`verification/validation_log/wp4-20261019-auth001-*.json`）。

## 2. 对象模型

| 对象ID | 对象 | 存储位置 | 关键属性 | 跨阶段载体类型 |
| --- | --- | --- | --- | --- |
| O1 | `security.users` 行 | MariaDB `security` schema | `id, username, password` | 数据库字段（二次注入载体） |
| O1S | `$_SESSION["username"]` | PHP 会话（文件 `/srv/wp4/sessions`） | 登录时从 O1 读回 | 会话/缓存（二次注入中转载体） |
| O2 | `dvwa.guestbook` 行 | MariaDB `dvwa` schema | `comment_id, comment, name` | 数据库字段（二次注入载体） |
| O3 | `dvwa.users.password` | MariaDB `dvwa` schema | md5 口令 | 状态机保护对象 |
| O4 | DVWA CSRF token | `$_SESSION['session_token']` | impossible 档生成 | 状态凭证 |
| O5 | DVWA security 档位 | `cookies[security]` | low/medium/high/impossible | 客户端可控条件变量（主体已记录为条件而非漏洞） |
| O6 | 改密流程状态 | `$_POST['step']`、`$_POST['passed_captcha']` | captcha 模块两步状态 | **客户端提交的"状态"**（隐性逻辑核心对象） |

## 3. 状态模型

### 3.1 账号生命周期（sqli-labs Less-24 全链）

```text
[未注册] --register(转义后INSERT)--> [已注册] --login(SELECT按原文匹配)--> [已登录(会话保存原文用户名)]
   [已登录] --pass_change(UPDATE拼接会话用户名)--> [口令已变] --logout--> [未登录]
```

- 注册→存储：`login_create.php:25` `mysql_escape_string` 后拼入 INSERT（48 行），特殊字符以**字面值**落库，第一阶段不触发（主体 `workpackage3/edge_cases/SQLI-001.md` 同源结论：转义只保证存储安全）。
- 登录→会话：`login.php` SELECT 按转义后的精确串匹配，`$row[1]`（数据库原文）写入 `$_SESSION["username"]`——主体 SQLI-005 已验证"落库原文原样回到会话"。
- 会话→再解释：`pass_change.php:31` 直接取 `$_SESSION["username"]` **不经任何转义**拼入 UPDATE（38 行）→ 主体 SQLI-005 已以 `wp4s' OR id=<victim_id>#` 验证（`wp4-20261019-sqli005-low.json`）。
- **会话→HTML输出**：`logged-in.php:26` `echo $_SESSION["username"]` **无输出编码** → 本工作包新增汇点 OPT4-SO-01。

### 3.2 留言生命周期（DVWA xss_s）

```text
[输入] --write(档位相关过滤+DB转义)--> [落库字面值] --read(index.php渲染)--> [HTML输出]
```

- low：`message` 仅 `stripslashes+mysqli_real_escape_string`，`name` 仅 DB 转义（`low.php:11-20`）→ 主体 XSS-005 已在 low 验证渲染执行（`wp4-20261019-xss005-low.json`）。
- medium：`message` 先 `strip_tags`（整个 `<img>` 元素被剥除，可执行构造从未持久化）再转义+预编码；**`name` 仅 `str_replace('<script>','')` + DB 转义**（`medium.php:21-24`）→ 本工作包 OPT4-SO-02。
- impossible：Token + 双字段 `htmlspecialchars` + PDO 参数化 → 反例基线。

### 3.3 改密流程状态机（DVWA captcha 模块）

```text
合法：[填写新口令] --step=1+CAPTCHA通过--> [确认页] --step=2--> [UPDATE]
异常：[直接 POST step=2] -------------------------------> [UPDATE]   ← low 档无服务端状态校验
异常：[直接 POST step=2 + passed_captcha=true] ---------> [UPDATE]   ← medium 档校验的是客户端参数
```

- low：`captcha/source/low.php` step=2 分支（52-86 行）不验证 step=1 是否发生过、无当前口令校验 → OPT4-LG-01（状态跳跃）。
- medium：仅校验 `$_POST['passed_captcha']`（客户端可伪造的隐藏域）→ 同一漏洞的第二形态（信任客户端状态标记）。
- impossible：Anti-CSRF Token + 当前口令 PDO 校验 → 反例基线。

### 3.4 跨站改密组合流（DVWA csrf 模块）

```text
合法：[登录用户在站内表单] --GET Change+双口令一致--> [UPDATE]
异常：[受害者浏览器访问攻击者页面] --<img src=靶场/csrf/?password_new=...&Change=Change>--> [UPDATE]  ← 无Token/无Origin/无当前口令
```

- `csrf/source/low.php:3-24`：GET 改密、无 Token、无 `password_current`、无 Origin/Referer 校验 → OPT4-LG-02（单步合法、组合后接管账号）。
- impossible：Token + 当前口令 + PDO → 反例基线。

## 4. 请求序列（正常流 vs 异常流）

| 序列ID | 角色 | 步骤 | 序列 | 对应用例 |
| --- | --- | --- | --- | --- |
| SEQ-N01 | R3 | 4 | 注册(专用账号)→登录→改密(带正确当前口令)→登出 | 主体 SQLI-005 正常流；OPT4-SO-01 对照组 |
| SEQ-A01 | R2/R3 | 3 | 注册(用户名=HTML标记载荷)→登录→GET logged-in.php | **OPT4-SO-01**：第三步在 HTML 汇点渲染原始载荷 |
| SEQ-N02 | R3 | 3 | 留言(name+message 正常)→再访问→渲染 | 主体 XSS-005 正常流 |
| SEQ-A02 | R3 | 3 | 留言(name=`<img src=x onerror=标记>` , message=同载荷)→再访问→渲染 | **OPT4-SO-02**：medium 档 name 危险/message 安全同页对照 |
| SEQ-A03 | R3 | 1 | 直接 POST `step=2&password_new&password_conf&Change`（low） | **OPT4-LG-01a**：跳过 CAPTCHA+无当前口令改密 |
| SEQ-A04 | R3 | 1 | 直接 POST `step=2&passed_captcha=true&...`（medium） | **OPT4-LG-01b**：伪造客户端状态标记 |
| SEQ-A05 | R5+R6 | 2 | 攻击者页面构造跨站 GET 改密 URL → 受害者会话发出请求 | **OPT4-LG-02**：CSRF 组合（模拟：受害者 Cookie+攻击者 Referer+无 Token） |
| SEQ-C01 | R1 | 1 | 无会话直接 POST pass_change / captcha step=2 | 反例：服务端重定向，状态前置 enforced |
| SEQ-C02 | R3 | 1 | csrf impossible 档无 Token 请求 | 反例：`checkToken` 302（主体 CMD-004/XSS-004 同机制已验证） |

## 5. 业务不变量

| 不变量ID | 不变量表述 | 映射对象/流程 | 检查结果 |
| --- | --- | --- | --- |
| INV-01 | 口令变更必须验证当前口令或等效强度的服务端凭证 | 3.1/3.3/3.4 改密流 | Less-24 部分成立（UPDATE 带口令条件但可被注入绕过）；captcha low/medium **违反**；csrf low **违反** |
| INV-02 | 多步流程的步骤迁移只能由服务端状态判定，客户端提交的 `step/标记` 不可信 | 3.3 captcha | low **违反**（不校验）；medium **违反**（校验的是 POST 参数）；impossible 成立 |
| INV-03 | 状态变更动作必须绑定会话主体，且不可由其他源页面代替主体发起 | 3.4 csrf、主体 AUTH-001 | csrf low **违反**（无 Token/Origin）；api 侧主体已验证（AUTH-001 impossible 成立） |
| INV-04 | 落库数据读回渲染时必须按输出上下文编码，"写入时已转义"不构成输出安全 | 3.1 logged-in / 3.2 xss_s | logged-in.php **违反**；xss_s medium 的 name **违反**、message 成立；impossible 成立 |
| INV-05 | 落库数据再进入 SQL 解释时必须参数化，不因"存储时转义过"而豁免 | 3.1 pass_change | **违反**（主体 SQLI-005 已验证 UPDATE 汇点）；注册写入端成立（反例） |
| INV-06 | 重复提交同一状态变更不产生放大危害（幂等或防重放） | 3.3/3.4 | captcha step=2 重复提交=重复覆盖口令（无防重放，但无放大，低危记录）；见 `verification_log.csv` |
| INV-07 | 并发窗口内不变量不被打破（竞态） | 全部 | 作用域内无可竞争的共享计数/余额类对象；PHP 内置服务器单请求原子性不足以构造判定窗口 → **待验证**（分析报告 §4 说明） |

## 6. 与主体部分的回溯关系

| 选做4用例 | 回溯样本 | 主体证据 | 新增点 |
| --- | --- | --- | --- |
| OPT4-SO-01 | SQLI-005 | `wp4-20261019-sqli005-low.json`（会话回显仅被当作"落库原文回到会话"的检查点） | 同一数据流的**第二个汇点**：会话→HTML 无编码输出（二次存储型XSS） |
| OPT4-SO-02 | XSS-005 | `wp4-20261019-xss005-low.json`（仅 low 档） | medium 档**同页双字段**写入端差异：name 无输出编码路径 vs message 预编码 |
| OPT4-LG-01 | （新扫描面）DVWA `vulnerabilities/captcha` | 无（主体样本集未含 captcha） | 状态跳跃：服务端不校验步骤迁移 |
| OPT4-LG-02 | （新扫描面）DVWA `vulnerabilities/csrf` | 无（主体样本集未含 csrf） | 跨站组合：单步合法、组合后接管 |
| 反例基线 | XSS-004 / CMD-004 / AUTH-001-impossible | 对应 validation_log | Token+参数化+输出编码的排除条件已在主体验证，本包复用结论 |

新扫描面说明：captcha/csrf 模块不在主体 `samples.csv` 的 15 个固定样本内，但属于同一固定提交（DVWA `068d974`）同一授权环境的一部分；选做4的挖掘方案以"业务流程模型驱动"扩展扫描面，这正是"跨阶段流程分析相对单片分析的新增发现"的直接证据（见 `analysis_report.md` §2）。
