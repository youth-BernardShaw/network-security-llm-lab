# 案例二：工具告警被 LLM 解释/排除（Less-25 XSS 与配置告警）

## 1. 工具告警：Less-25 反射 XSS

Wapiti 扫描 `http://127.0.0.1:9081/Less-25/index.php?id=1` 时同时报出：

- SQL Injection（对应 SQLI-003，目标内）；
- Cross Site Scripting（`WAP-XSS-003-01`，目标外补充）。

LLM 读代码确认 XSS 根因：

```php
$id = blacklist($_GET['id']);
$hint = $id;
...
echo "Hint: Your Input is Filtered with following result: ".$hint;
```

`$hint` 在 line 44 直接拼接进 HTML，没有 `htmlspecialchars`；blacklist 只处理 SQL 关键字，不处理 HTML 上下文。

## 2. 浏览器确认

用无害 `<svg onload="window.__wp4xss='WAP_LESS25_XSS'">` 访问同一 URL，Chrome 中 `window.__wp4xss` 被置位，页面无脚本错误：

- 证据：`optional2/case_studies/less25_xss_browser.json`
- 截图：`optional2/case_studies/less25_xss_browser.png`
- 结果：`executed=true`，`marker_in_raw_html=true`

## 3. LLM 判定：确认但范围外

- 这是一个**真实的反射 XSS**，不是误报；
- 但它不在工作包1的 14 个父样本目标标签内：SQLI-003 的标签只覆盖 **SQL 注入**；
- 因此合并表中使用 `sample_id=ADDITIONAL-001`、`target_status=out_of_scope`、`verification_status=confirmed_out_of_scope`；
- 不增加父样本数（仍为 14），也不改变 SQLI-003 的 SQL 标签。

这体现“工具发现 → LLM 解释”的价值：**既不能把范围外的真问题丢掉，也不能把它混进目标指标。**

## 4. 工具告警：配置加固（排除）

Wapiti 对 `login.php` 的配置检查报出 9 条：

- CSP 未设置（1）；
- HTTP Secure Headers（X-Frame-Options、X-Content-Type-Options、HSTS 等，4）；
- `PHPSESSID` / `security` Cookie 的 HttpOnly、Secure 标志（4）。

LLM 判定：

- 这些是真实的部署加固问题，但**不是 14 个父样本的目标漏洞**；
- 本地实验使用 HTTP，`Secure` Cookie 在无 TLS 的本机环境中不适用；
- 不把它们算成目标 TP，也不把它们算成目标 FP；
- 合并表状态：`excluded_non_target`，单独保留，便于部署加固跟踪。

## 5. 结论

- 工具告警需要 LLM 做**范围解释**：真实问题 ≠ 目标漏洞，范围外 ≠ 误报；
- 本批 14 条 Wapiti 告警中，5 条是真实漏洞（4 目标 + 1 补充），9 条是配置加固；
- 目标范围内没有 FP；这一点只适用于已测的 4 个端点，不能外推。
