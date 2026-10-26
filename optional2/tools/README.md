# 选做2 工具

| 工具 | 用途 |
| --- | --- |
| `get_dvwa_cookie.py` | 登录本地 DVWA，生成 `optional2/tmp/dvwa_cookies.json`（不提交） |
| `build_optional2.py` | 解析 Wapiti JSON，生成归一化、合并、覆盖矩阵、LLM assessment、扫描清单 |
| `build_optional2_report.py` | 生成 `metrics.csv` 与 `comparison_report.md` |
| `build_architecture.py` | 生成 `integration_architecture.png` |
| `verify_less25_xss.js` | 用 Chrome headless 确认 Less-25 反射 XSS（工具独有补充发现） |
| `burp_xml.py` | 解析 Burp Professional XML 报告，输出统一字段 |
| `awvs_client.py` | AWVS REST API 客户端；`--dry-run` 输出扫描计划，真实运行需 `AWVS_API_KEY` |

## 运行顺序

```bash
# 1. 启动靶场（如果尚未启动）
bash verification/tools/env_setup.sh

# 2. 生成 DVWA cookie（只写 optional2/tmp）
python3 optional2/tools/get_dvwa_cookie.py

# 3. 扫描（命令见 scanner_raw/scan_manifest.json）

# 4. 归一化/合并/指标
python3 optional2/tools/build_optional2.py
python3 optional2/tools/build_optional2_report.py

# 5. 架构图（Pillow）
python3 optional2/tools/build_architecture.py
```

## Burp / AWVS

```bash
# Burp XML -> 统一 CSV（fixture 自测）
python3 optional2/tools/burp_xml.py \
  --input optional2/scanner_raw/burp_format_fixture.xml \
  --output optional2/scanner_raw/burp_format_fixture_normalized.csv

# AWVS 计划（无 API Key 也能跑）
python3 optional2/tools/awvs_client.py \
  --target http://127.0.0.1:9080/ --dry-run \
  --plan optional2/scanner_raw/awvs_dryrun.json
```

不要把 `optional2/tmp/dvwa_cookies.json`、`AWVS_API_KEY` 或未脱敏的扫描报告提交到仓库。
