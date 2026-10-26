# 扫描原始结果

| 文件 | 内容 | 备注 |
| --- | --- | --- |
| `wapiti_sqli001.json` | Wapiti 对 Less-1 的原始 JSON | 1 条 SQLi |
| `wapiti_sqli003.json` | Wapiti 对 Less-25 的原始 JSON | 1 条 SQLi + 1 条 XSS |
| `wapiti_xss001.json` | Wapiti 对 DVWA xss_r low 的原始 JSON | 1 条 XSS |
| `wapiti_cmd001.json` | Wapiti 对 DVWA exec low 的原始 JSON | 1 条命令执行 |
| `wapiti_headers_login.json` | 登录页 CSP/Header/Cookie 检查 | 9 条配置告警 |
| `wapiti_normalized.csv` | 统一字段的 14 条告警 | 供合并/去重 |
| `scan_manifest.json` | 版本、URL、模块、认证、速率、命令、计数 | 复现清单 |
| `burp_format_fixture.xml` | Burp XML 格式自测样例 | **不是**真实 Burp 扫描 |
| `burp_format_fixture_normalized.csv` | `burp_xml.py` 的解析结果 | 仅格式自测 |
| `awvs_dryrun.json` | AWVS API 调用计划 | 无 API Key，未实际扫描 |

Wapiti JSON 只包含请求行与参数，不包含 Cookie 值；`wapiti_headers_login.json` 只出现 Cookie 名称。
