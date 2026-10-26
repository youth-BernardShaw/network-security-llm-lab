# Burp / AWVS 扫描配置与导出说明

本文件给出两套商业扫描器的可复现配置，以及本实验实际使用的 Wapiti 参考配置。商业软件未安装时，配置模板仍可作为接入说明；不要把 Wapiti 结果写成 Burp/AWVS 成绩。

## 1. 工具适用范围

| 工具 | 版本/形态 | 适用范围 | 扫描强度 | 认证 | 速率 | 导出 |
| --- | --- | --- | --- | --- | --- | --- |
| Burp Suite Professional | 商业许可 | Crawl + Audit、被动/主动扫描、Repeater 复核 | Light / Thorough | 登录宏、Session Handling、Cookie | 4 线程、100 ms 延迟 | Burp XML（`<issues>`） |
| Burp Suite Community | 免费 | Proxy、Repeater、Logger；**无主动 Scanner** | 不适用 | 手工 Cookie | 单用户 | HTTP history（非漏洞报告） |
| Acunetix / Invicti (AWVS) | 商业许可，on-prem | 全站爬取 + 主动扫描、登录序列 | Full Scan / High Risk | 登录序列、Cookie、Headers | 4 线程、Normal | REST API JSON |
| Wapiti | 3.0.4，开源 | 本实验参考扫描器：SQLi/XSS/CMD/配置检查 | `-S polite`，单进程 | JSON Cookie 文件 | 串行、限时 | JSON |

官方参考：

- Burp 命令行与版本要求：[Launching Burp Suite from the command line](https://portswigger.net/burp/documentation/desktop/troubleshooting/launch-from-command-line)
- Burp 安装与版本：[Download and install](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)
- Burp XML 报告结构：Burp `issues` DTD（`serialNumber/type/name/host/path/location/severity/confidence/requestresponse`）
- AWVS API 示例：[Managing scans using Bash and the Invicti API](https://www.acunetix.com/blog/docs/managing-scans-bash-api/)
- Wapiti 官方站点：[Wapiti](https://wapiti.sourceforge.io/)（本机 3.0.4）

## 2. Burp Suite Professional

### 2.1 范围

只加入：

```text
http://127.0.0.1:9080/vulnerabilities/*
http://127.0.0.1:9080/login.php
http://127.0.0.1:9081/Less-1/*
http://127.0.0.1:9081/Less-11/*
http://127.0.0.1:9081/Less-24/*
http://127.0.0.1:9081/Less-25/*
```

排除：

```text
http://127.0.0.1:9080/setup.php
http://127.0.0.1:9080/logout.php
http://127.0.0.1:9080/dvwa/css/*
http://127.0.0.1:9080/dvwa/images/*
http://127.0.0.1:9081/images/*
```

### 2.2 认证

- 用 Burp 内置浏览器登录 DVWA `admin`，确认 `security=low`。
- 在 **Project options → Sessions → Session handling rules** 增加登录宏：GET `login.php` → 提取 `user_token` → POST `login.php`；或直接固定测试会话 Cookie（仅本地）。
- 对 AUTH-001 另建普通用户 `gordonb` 会话，避免把 admin 结果当成普通用户结果。
- 不把 Cookie 写入报告或仓库；导出前用 Burp 的 “redact” 或后处理脚本移除。

### 2.3 扫描配置

- Dashboard → New scan → URL 填 `http://127.0.0.1:9080/`。
- Scan configuration：Crawl + Audit；Light（先跑）或 Thorough（复跑）。
- Resource pool：4 线程，100 ms 延迟；单目标最大请求数按时间设置。
- 关闭 “Follow redirects” 之外的无关选项；保留 `security` Cookie。
- 不对 `setup.php`、`logout.php` 做主动扫描。

### 2.4 导出

- Target → Site map → 右键 → **Report issues** → HTML/XML。
- 选择 XML；导出文件放到 `optional2/scanner_raw/burp_*.xml`。
- 用 `optional2/tools/burp_xml.py` 转成统一字段：

```bash
python optional2/tools/burp_xml.py \
  --input optional2/scanner_raw/burp_report.xml \
  --output optional2/scanner_raw/burp_normalized.csv
```

Burp XML 关键字段：

| Burp 字段 | 归一化字段 |
| --- | --- |
| `name` | `title` / `scanner_rule` |
| `host` + `path` | `asset` + `route` |
| `location` | `parameter`（解析 `[param]`） |
| `severity` | `severity` |
| `confidence` | `confidence` |
| `request method` | `method` |
| `requestresponse/request` | `request_sample`（base64 解码） |
| `issueDetail` | `evidence_summary` |

## 3. Acunetix / Invicti (AWVS)

### 3.1 API 基本参数

```text
Base URL: https://127.0.0.1:3443/api/v1
Header:   X-Auth: <API_KEY>
          Content-Type: application/json
```

API Key 只放环境变量 `AWVS_API_KEY`，不写入脚本或仓库。

### 3.2 创建目标

```http
POST /api/v1/targets
{
  "address": "http://127.0.0.1:9080/",
  "description": "DVWA local lab - optional2",
  "type": "default",
  "criticality": 10
}
```

响应中取 `target_id`。

### 3.3 启动扫描

```http
POST /api/v1/scans
{
  "profile_id": "11111111-1111-1111-1111-111111111111",
  "incremental": false,
  "schedule": {"disable": false, "start_date": null, "time_sensitive": false},
  "user_authorized_to_scan": "yes",
  "target_id": "<target_id>"
}
```

扫描 ID 在响应头 `Location` 中，不在响应体。

### 3.4 轮询与取结果

```http
GET /api/v1/scans/{scan_id}
GET /api/v1/scans/{scan_id}/results
GET /api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities
```

- 轮询 `current_session.status`，直到 `completed`。
- 取 `current_session.scan_session_id`、`results[].result_id`。
- 漏洞列表分页；按 `pagination` 继续取。

### 3.5 认证、速率与导出

- 登录序列：在 Target 设置中录制 DVWA 登录（`admin` / `password`，`security=low`）；AUTH-001 另录普通用户。
- 扫描速度：Normal；并发 4；不要对本地 PHP 内置服务器开高并发。
- 导出 JSON 到 `optional2/scanner_raw/awvs_*.json`，用 `tools/awvs_client.py` 归一化。
- 只保留 `vt_name/affects_url/affects_detail/severity/status/request/evidence` 等字段，Cookie 与 Token 脱敏。

## 4. Wapiti 参考实现（本实验实际执行）

### 4.1 版本与模块

```text
Wapiti 3.0.4
modules: sql, xss, permanentxss, exec, cookieflags, http_headers, csp
scope: page
rate: -S polite
limits: --max-scan-time 45–60, --max-attack-time 45–60
```

### 4.2 实际命令

```bash
# SQLI-001
wapiti -u 'http://127.0.0.1:9081/Less-1/index.php?id=1' \
  --scope page -m 'sql,xss,exec' -S polite \
  --max-scan-time 60 --max-attack-time 60 \
  -f json -o optional2/scanner_raw/wapiti_sqli001.json --flush-session

# SQLI-003
wapiti -u 'http://127.0.0.1:9081/Less-25/index.php?id=1' \
  --scope page -m 'sql,xss,exec' -S polite \
  --max-scan-time 45 --max-attack-time 45 \
  -f json -o optional2/scanner_raw/wapiti_sqli003.json --flush-session

# XSS-001（需要 DVWA 会话）
wapiti -u 'http://127.0.0.1:9080/vulnerabilities/xss_r/?name=test' \
  --scope page -m 'sql,xss,permanentxss,exec' \
  -c optional2/tmp/dvwa_cookies.json -S polite \
  --max-scan-time 60 --max-attack-time 60 \
  -f json -o optional2/scanner_raw/wapiti_xss001.json --flush-session

# CMD-001（需要 DVWA 会话）
wapiti -u 'http://127.0.0.1:9080/vulnerabilities/exec/' \
  --scope page -m 'sql,xss,exec' \
  -c optional2/tmp/dvwa_cookies.json -S polite \
  --max-scan-time 45 --max-attack-time 45 \
  -f json -o optional2/scanner_raw/wapiti_cmd001.json --flush-session

# 配置类告警（登录页头部/Cookie）
wapiti -u 'http://127.0.0.1:9080/login.php' \
  --scope page -m 'cookieflags,http_headers,csp' -S polite \
  --max-scan-time 20 --max-attack-time 20 \
  -f json -o optional2/scanner_raw/wapiti_headers_login.json --flush-session
```

`optional2/tools/get_dvwa_cookie.py` 生成 `optional2/tmp/dvwa_cookies.json`；该文件已 gitignore，不提交。

## 5. 统一导出字段

所有适配器输出以下字段，供 `merged_findings.csv` 使用：

```text
source, scanner_rule, asset, route, http_method, parameter,
vulnerability_type, severity, title, evidence_summary,
request_sample, code_location, condition, verification_status
```

## 6. 限制

- Burp Pro/AWVS 未安装，商业工具配置为模板；实际扫描由 Wapiti 完成，报告必须明确区分。
- Burp Community 没有主动 Scanner，不能把 Community 的 Proxy 记录当作扫描结果。
- Wapiti 的检测规则与 Burp/AWVS 不同；覆盖率差异主要反映工具能力，不是绝对“谁更强”。
- 商业工具接入后，建议先用同一 4 个端点做一次对齐，再扩展到全量样本。
