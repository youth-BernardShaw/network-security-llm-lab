# POC 用例 OPT4-SO-02：DVWA xss_s medium 档 name 字段二次存储型XSS（message 同页反例）

- 追踪：`dataflow_traces/OPT4-SO-02.json`；回溯样本 XSS-005（主体仅验 low 档）
- 目标：同一请求、同一档位内证明 name（危险）与 message（安全）的写入端差异在读取端的结果
- 无害标记：`window.__opt4nm=1` / `window.__opt4ms=1`

## 前置条件

dvwa-wsl 服务在线（127.0.0.1:9080）；测试账号 gordonb（口令本地一次性替换后恢复）；security=medium Cookie。

## 步骤（SEQ-A02）

| 步 | 角色 | 操作 | 输入 | 预期 |
| --- | --- | --- | --- | --- |
| 1 | R3 | 登录 gordonb，设 security=medium | — | 会话建立 |
| 2 | R3 | POST /vulnerabilities/xss_s/ | txtName=`<img src=x onerror=window.__opt4nm=1>`；mtxMessage=`<img src=x onerror=window.__opt4ms=1>` | 留言提交成功 |
| 3 | — | DB 回查 guestbook | 按 name LIKE 定位 | name=字面值；comment 中 `<img` 元素已被 strip_tags 剥除（无可执行构造） |
| 4 | R3 | GET /vulnerabilities/xss_s/ | — | 响应中 name 载荷为未编码 `<img ...`；message 无可执行元素 |
| 5 | — | 对照A（low 档）：同输入 security=low 提交+读取 | — | 两字段均字面值渲染（与主体 XSS-005 结论一致） |
| 6 | — | 对照B（impossible 档）：无 Token 提交 | — | 302 拒绝（checkToken；主体 XSS-004 同机制已验） |
| 7 | — | 清理 | DELETE 两条测试留言 | guestbook 行数恢复 |

## 判定

- 成立：步骤 4 同一页面同一请求的两字段中，name 的可执行元素原样进入页面而 message 的元素在写入端即被剥除，且步骤 3 证明该差异由写入端处理不同造成。
- 排除条件检验：message 字段即"读取点始终按数据处理且有正确编码"的内置反例；impossible 档即"危险汇点不可达"反例。

## 回滚

见 `reset_steps.md` §2（按 name 定点 DELETE 留言）。
