# 选做1 原稿 POC 补测（2026-10-20）

40 份三版 Prompt 原稿已在固定 WSL2 靶场全部实际执行。**40/40 执行，37 成功**：v1 13/14（92.86%）、v2 11/13（84.62%）、v3 13/13（100.00%）。

## 结果入口

- [followup_poc_results.csv](../followup_poc_results.csv)：逐条命令、耗时、成功/失败、失败类别、恢复状态。
- [followup_poc_metrics.csv](../followup_poc_metrics.csv)：按版本汇总（由 `tools/summarize_poc_followup.py` 生成）。
- `evidence/<cohort>/<stem>.md`：每份原稿的 stdout/stderr、独立观察、浏览器证据与判定；共 40 份。
- [environment.md](environment.md)：组件版本、安装与网络修复、执行边界。
- [cleanup.md](cleanup.md)：补测后的数据库与专用对象清理。
- `raw/`：原始运行 JSON（命令中的 Cookie 已脱敏）与 XSS 浏览器 JSON。

## 成功判据

不以脚本退出码或 HTTP 200 为准：

- SQL 注入：真/假条件的业务结果差异（行命中/登录行），而非仅报错；
- 命令注入：marker 出现在 `<pre>` 命令输出区，且控制请求无同一 marker；
- AUTH：普通用户越权读取或写入，并有独立回读与恢复；
- XSS：headless Chrome 实际执行，捕获 `alert` 或 `console` 标记。

## 三例失败

| 原稿 | 类别 | 原因 |
| --- | --- | --- |
| v1 SQLI-003 | script_logic | false 分支 `1'||'1'='2` 中 `id='1'` 先为真，仍命中同一行，无差分 |
| v2 SQLI-003 | script_logic | UNION 先返回 `id=1` 行且 `LIMIT 0,1` 截断，marker 未渲染；只检查静态文案 |
| v2 XSS-005 | script_logic | 函数 `http()` 覆盖 `http` 包，`http.cookiejar` 抛 AttributeError，请求未发出 |

CMD-002 的 v2/v3 原稿自身返回失败，但独立对照确认 pipe 命令执行成功；详见报告第 5 节。若只按“脚本自报成功”统计，v2 为 10/13、v3 为 12/13。

## 复现

```powershell
python optional1\followup\tools\run_batch.py
python optional1\followup\tools\browser_batch.py
python optional1\followup\tools\build_followup_results.py
python optional1\tools\summarize_poc_followup.py optional1\followup_poc_results.csv
```

`run_batch.py` 会重新登录 DVWA 并在 `sessions/` 生成临时 Cookie（未纳入交付），同时重置专用账号与留言；XSS 浏览器证据由 `browser_batch.py` 单独生成。

## 边界

- POC 源码未修改；只通过既有 CLI 参数提供本地 URL、端口、会话、账号名与部署路径。
- 结果仅适用于本机固定靶场（DVWA `068d974`、SQLi-Labs `e96f217`、MariaDB 10.6、PHP 8.1/5.6）。
- 历史模型时延、Token、采样参数仍无法补造；人工独立复核仍需课程成员完成。
