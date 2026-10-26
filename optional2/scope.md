# 选做2 范围与安全运行边界

批次：`optional2-scanner-llm-01`  
日期：2026-10-21（UTC+08:00）  
目标：`127.0.0.1:9080`（DVWA）、`127.0.0.1:9081`（SQLi-Labs）

## 1. 授权范围

本任务只对本机 WSL2 中的两个固定教学靶场执行扫描和验证：

| 资产 | 地址 | 固定提交 | 说明 |
| --- | --- | --- | --- |
| DVWA | `http://127.0.0.1:9080` | `068d974487a297c155c48722f9fcf7180a83adc4` | PHP 8.1 + MariaDB |
| SQLi-Labs | `http://127.0.0.1:9081` | `e96f21776372c8613a7e565106e62bc01a59355e` | PHP 5.6 + ext/mysql |

不访问公网目标，不扫描非计划端口，不使用外部回连，不把扫描器指向未知域名。主机白名单在脚本和配置中固定为 `127.0.0.1`；`localhost` 仅作为等价本地回环。

## 2. 主动扫描前的准备

1. 用 `verification/tools/env_setup.sh` 重置靶场数据库并启动服务；该脚本会重新运行 DVWA setup 与 SQLi-Labs setup-db。
2. 记录扫描时间、版本、范围、模块、认证与速率；详见 `scanner_raw/scan_manifest.json`。
3. 只使用无害验证输入：
   - SQL：布尔/报错对照，不枚举、不导出数据；
   - XSS：无害 DOM 标记，不读取 Cookie、不外传；
   - 命令注入：固定 `printf`/`env` 标记，不读取敏感文件、不建立连接；
   - 越权：只使用专用对象，读优先，写操作有原值、回查和恢复。
4. 扫描前不手工修改审计源码；如必须改配置，另开部署变体并记录。
5. 扫描后按 `verification/cleanup_checklist.md` 删除专用账号/留言并停止服务。

## 3. 速率与并发

| 工具 | 扫描强度 | 并发/速率 | 说明 |
| --- | --- | --- | --- |
| Wapiti 3.0.4 | `-S polite`；单 URL/page scope；`--max-scan-time 45–60`、`--max-attack-time 45–60` | 单进程，串行 | 本机参考实现 |
| Burp Suite Professional | Crawl + Audit，light/thorough 按需 | 建议 4 线程、100 ms 延迟 | 需商业许可 |
| Burp Suite Community | 只作 Proxy/Repeater，不提供 Scanner | 单用户 | 不能冒充主动扫描 |
| AWVS | Full Scan profile | 建议 4 线程、正常速率 | 需商业许可 |

禁止把并发调高到影响本机服务的程度；出现 5xx、连接拒绝或页面超时，先降低速率并检查靶场，不把环境错误当作“无漏洞”。

## 4. 认证与凭据

- DVWA 使用 `admin` 预置账号建立会话；Cookie 仅写入 `optional2/tmp/dvwa_cookies.json`（已 gitignore），不进入证据或仓库。
- SQLi-Labs 无需登录。
- Wapiti 通过 `-c` 读取 JSON Cookie 文件；Burp 通过 session handling/宏；AWVS 通过登录序列。
- 报告中的请求样例可能包含 payload，但不包含真实 Cookie/Token；提交前检查 `PHPSESSID`、`security`、`Auth` 等字段。

## 5. 结果与数据边界

- `scanner_raw/` 保存工具原始输出（Wapiti JSON；Burp/AWVS 适配器格式样例）。
- `llm_assessment/` 保存 LLM 对扫描告警的解释、代码位置、确认/排除状态。
- `merged_findings.csv` 只保存归一化后的字段与证据摘要，不保存原始响应正文中的敏感数据。
- 同一告警的不同角色/配置/阶段不合并；去重键包含 `condition`。
- 负例、未测、环境失败分别记录，不自动算作“安全”。

## 6. 工具可用性说明

本机未安装 Burp Suite Professional 或 AWVS（均需商业许可）；Burp Community 不包含主动 Scanner。为保证联动方案有真实可执行证据，本任务使用 **Wapiti 3.0.4** 作为“传统扫描器”的参考实现，并同时提供：

- `tools/burp_xml.py`：解析 Burp Professional XML 报告；
- `tools/awvs_client.py`：AWVS REST API 客户端（dry-run/真实扫描）；
- `burp_or_awvs_config.md`：两套商业工具的扫描范围、认证、速率、导出配置。

因此本报告中的扫描数据来自 Wapiti，不冒充 Burp/AWVS 实测；商业工具接入时只需替换扫描器适配层，归一化、去重、复核和指标口径不变。
