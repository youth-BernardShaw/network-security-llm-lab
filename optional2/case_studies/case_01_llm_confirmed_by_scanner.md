# 案例一：LLM 候选被扫描器确认（SQLI-001）

## 1. 候选

| 项目 | 内容 |
| --- | --- |
| LLM finding | `LLM-SQLI-001-F1` |
| 样本 | SQLI-001（SQLi-Labs Less-1） |
| 入口 | `GET /Less-1/index.php?id=` |
| 代码位置 | `SQLI-001:14-15` |
| LLM 判断 | 存在候选；`id` 未过滤直接拼接，`mysql_query` 执行 |
| 条件 | `env=sqli-labs|role=anonymous` |

代码事实：

```php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result=mysql_query($sql);
```

## 2. 工具复扫

Wapiti 3.0.4 对同一 URL 的 `id` 参数报 **SQL Injection (DBMS: MariaDB)**：

```text
GET /Less-1/index.php?id=1%C2%BF%27%22%28 HTTP/1.1
Host: 127.0.0.1:9081
```

- 工具告警：`WAP-SQLI-001-01`
- 来源：`optional2/scanner_raw/wapiti_sqli001.json`
- 归一化：`optional2/scanner_raw/wapiti_normalized.csv`
- 状态：`confirmed_by_both`

## 3. 独立 POC 复核

已有工作包4 POC 在同一路径完成：

- 正常 `id=1` → `Your Login name:Dumb`；
- 真条件 `1' AND '1'='1` → 同一行；
- 假条件 `1' AND '1'='2` → 无行；
- 仅改变 `id`，请求/响应与布尔语义对应。

证据：`verification/evidence/wp4-20261019-sqli001-low/observation.json`。

## 4. 结论

- 扫描器与 LLM 都命中，且 POC 独立确认 → 合并为 `llm;scanner:wapiti`，状态 `confirmed_by_both`。
- 扫描器的优势是**快速发现参数级注入**；LLM 的优势是**给出代码根因、成立条件和可解释的成功标准**。
- 这条案例满足“至少一个 LLM 发现被工具或 POC 确认”的要求。

## 5. 可复用命令

```bash
wapiti -u 'http://127.0.0.1:9081/Less-1/index.php?id=1' \
  --scope page -m 'sql,xss,exec' -S polite \
  --max-scan-time 60 --max-attack-time 60 \
  -f json -o optional2/scanner_raw/wapiti_sqli001.json --flush-session
```
