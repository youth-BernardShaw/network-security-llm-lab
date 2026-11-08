# 选做4 结果分析报告（analysis_report.md）

批次 `opt4-poc-02` · 环境 `opt4-env-02` · 判定明细见 `verification_log.csv`，原始证据见 `evidence/`。

## 1. 结论汇总

| 用例 | 类别 | 触发前置条件 | 判定 | 新增性 |
| --- | --- | --- | --- | --- |
| OPT4-SO-01 | 二次注入（DB字段→会话→HTML） | 攻击者可注册含HTML构造的用户名并登录 | 真漏洞 | 主体 SQLI-005 同链路的新汇点 |
| OPT4-SO-02 | 二次注入（DB字段→HTML） | 登录用户可留言；medium 档 name 字段 | 真漏洞 | 主体 XSS-005 未覆盖的档位与字段级差异 |
| OPT4-LG-01a/b | 隐性逻辑（状态跳跃/客户端标记） | 已登录会话；low/medium 档 | 真漏洞 | 新扫描面 captcha |
| OPT4-LG-02 | 隐性逻辑（跨站组合越权） | 受害者已登录；攻击者页面被访问；low 档 | 真漏洞 | 新扫描面 csrf |
| SEQ-C01/C02 | 反例（状态前置/Token） | — | 未触发，符合排除条件 | 复用主体机制结论 |
| INV-06 重复提交 | 幂等/防重放 | — | 低危害记录（幂等覆盖） | — |
| INV-07 竞态窗口 | 并发 | — | **待验证**（见 §4） | — |

## 2. 单片分析 vs 跨阶段流程分析的差异

主体工作包3 的单片推理（`workpackage3/reasoning_framework.md`）以"单函数 + 危险函数 + 输入点"为单位：它对本次四个用例的可见性如下——

| 用例 | 单片分析能看到什么 | 单片分析为什么看不到 | 跨阶段流程分析补上的环节 |
| --- | --- | --- | --- |
| SO-01 | `logged-in.php` 里的 `echo`（若被单独审计）只是一个输出语句 | 危险性不在该语句本身，而在"echo 的值来自另一请求写入数据库、经登录取回的链路"；且注册端 `mysql_escape_string` 让写入点在单片视角下"看起来安全" | 注册→存储→登录→会话→渲染的 5 段链路与两处编码检查（写端SQL转义 / 读端HTML编码分别判定） |
| SO-02 | medium.php 写入端：两字段都有"过滤代码" | 单片只能判断"有过滤"，无法判断 name 的黑名单与 message 的剥除在**读取端**造成的不同结果；主体只测了 low 档整体 | 写入端逐字段编码矩阵 × 读取端渲染对照（同页双字段互为反例） |
| LG-01 | captcha low.php 的 step=2 分支只是一个普通 UPDATE | UPDATE 参数化/转义完好，无注入；漏洞是"step=2 分支不校验 step=1 是否发生过"这一**状态机性质** | 角色×对象×动作×状态矩阵 + 迁移凭证来源审计（服务端会话 vs 客户端参数） |
| LG-02 | csrf low.php 是一个"参数化正确的 UPDATE" | 漏洞不在函数内而在请求层：谁能代表主体发起请求 | 合法/异常请求序列对比 + 跨源组合建模（R5/R6 角色） |

**新增发现的来源归因**：SO-01 的新增来自"同一数据流的第二个汇点"（主体已证明数据到达会话，但没有把会话值当作 HTML 汇点审计）；SO-02 的新增来自"写入端字段级差异 + 读取端结果"这一段；LG-01/02 的新增来自"业务状态机的迁移凭证"与"跨源请求组合"——两者都不在任何单函数的危险函数列表里，正是选做4要求设计的跨请求、跨角色、跨状态挖掘方案所覆盖的盲区。

## 3. 每个确认漏洞的要素与修复建议

### OPT4-SO-01（Less-24 会话用户名二次存储型XSS）
- **触发前置条件**：目标开放注册；用户名列允许存储 HTML 元素字符（本例 varchar(20)，无字符集白名单）；攻击者随后登录一次。
- **最小复现序列**：① 注册用户名 `<svg onload=__o4s=1>`；② 用该用户名登录；③ GET /Less-24/logged-in.php（登录重定向即触发）。
- **影响对象**：登录该账号的用户本人；结合 Less-24 已知的 UPDATE 二次注入（主体 SQLI-005），会话名同时是 SQL 载荷载体，形成复合危害。
- **修复建议**：注册端对用户名做字符集白名单（`^[A-Za-z0-9_]{3,20}$`）；`logged-in.php` 输出前 `htmlspecialchars`；改密处参数化（呼应主体结论）。

### OPT4-SO-02（DVWA xss_s medium name 字段）
- **触发前置条件**：security=medium；登录用户可提交留言；后续任何人（含 admin）访问留言页。
- **最小复现序列**：① POST txtName=`<img src=x onerror=…>`（mtxMessage 同值作对照）；② 任意用户 GET 留言页。
- **影响对象**：所有浏览留言者（含管理员会话）。
- **修复建议**：按 impossible 档对两字段统一 `htmlspecialchars` + PDO；黑名单式 `str_replace('<script>')` 应替换为输出编码——写入端"有过滤"不等于读取端安全。

### OPT4-LG-01a/b（DVWA captcha 状态机绕过）
- **触发前置条件**：已登录会话；low 档（无需任何凭证）或 medium 档（可附 `passed_captcha=true`）。
- **最小复现序列**：单请求 POST `step=2&password_new=&password_conf=&Change=Change`（medium 再加 `passed_captcha=true`）。
- **影响对象**：当前会话用户口令（配合会话固定/CSRF 可扩大到他人）。
- **修复建议**：步骤迁移凭证放入 `$_SESSION`（服务端状态）；改密必须校验当前口令；impossible 档的 Token+当前口令+PDO 即正确基线。

### OPT4-LG-02（DVWA csrf GET 改密）
- **触发前置条件**：受害者已登录且 security=low；攻击者页面被受害者浏览器加载（实验内以受害者 Cookie+攻击者 Referer+无 Token 等价模拟）。
- **最小复现序列**：① 受害者登录；② 攻击者页面含 `<img src="…/csrf/?password_new=opt4csrf&password_conf=opt4csrf&Change=Change">`；③ 页面加载即完成改密。
- **影响对象**：任何已登录用户的账号（攻击者随后用已知新口令登录）。
- **修复建议**：改密改 POST + Anti-CSRF Token + 当前口令校验 + Origin/Referer 检查（impossible 档基线）；GET 不应承载状态变更。

## 4. 待验证项与检查过但不成立的项

- **竞态窗口（INV-07）→ 待验证**：审计范围内（DVWA captcha/csrf/api、sqli-labs Less-24）不存在共享可变计数器、余额或库存类对象；改密/留言均为幂等覆盖，交错请求无法构造"不变量被打破"的可断言窗口。PHP 内置服务器（PHP_CLI_SERVER_WORKERS=4）可发并发请求，但缺少可竞争对象使判定无从下手。引入带计数器的业务流（如积分、限量领取）后应复检。
- **重复提交（INV-06）→ 已记录低危害**：step=2 与 GET 改密均可重复提交并反复覆盖口令，无防重放/幂等键；因结果幂等、无放大效应，记录不单列漏洞。
- **外部系统回调**：reCAPTCHA 为唯一外部依赖，本地密钥为空时 `recaptcha_check_answer` 恒假（合法路径不可达的环境事实），`index.php:38-42` 还会覆盖模块 `$html`——该行为导致页面消息不可见，POC 判定改以 DB 回查为准（已记入 LG-01 追踪与 execution_log）。
- **真实业务规则缺口**：sqli-labs 无角色分级，垂直越权仅在 DVWA 侧可检（主体 AUTH-001 已覆盖 four 档），本包未新增垂直越权用例，属范围如实声明而非遗漏。

## 5. 专属Prompt使用记录与人工复核差异

- OPT4-P1（二次注入）两次运行、OPT4-P2（隐性逻辑）三次运行的使用记录见 `special_prompts/*.md`。复核修正了模型草稿的三类问题：
  1. **行号与文件名偏差**：草稿引用 logged-in.php 的 echo 为"第24行"（实际 26-28 行），逐条按固定提交核对后入库；
  2. **载体表述合并错误**：草稿把"数据库字段"与"会话"并作一个载体，实际是两段中转（存储载体 + 会话载体），已拆分（OPT4-SO-01 flow 分段）；
  3. **反例误判**：草稿最初认为 xss_s medium 的 message 是"预编码保留"，静态复核 `strip_tags` 语义后更正为"整个元素被剥除、落库为空串"——该修正使同页反例的表述更准确（详见 dataflow_traces/OPT4-SO-02.json 修订说明）。
- 模型局限（与文档要求对应）：动态行为（fetch 行序、运行时覆盖 `$html` 一类页面装配效应）需要执行证据兜底；并发竞态如 §4 所述在当前范围不可判；外部回调（reCAPTCHA）与真实业务规则需人工补充。

## 6. 回溯与证据索引

- 回溯主体：`verification/validation_log/wp4-20261019-{sqli005,xss005,auth001}-*.json`；样本定义 `workpackage1/samples.csv`；单片基线 `workpackage3/`。
- 本包证据：`evidence/opt4-20261020-{so01,so02,lg01,lg02}/`（request.redacted.json / response.redacted.txt / observation.json / restore_result.json / 页面与DB快照）。
- 完整性核对：见 `execution_log.txt` 末段与 `reset_steps.md` §6。
