# 选做4 本地环境档案（opt4-env-02）

记录日期：2026-10-20（UTC+08:00）
部署标识：`dvwa-wsl-02`、`sqli-labs-wsl-02`

本档案与主体 `verification/environment.md`（wp4-poc-01 / 队友机器 `yanyu`）同构：同一套 bootstrap 逻辑（`verification/tools/env_setup.sh` → 本包适配版 `optional4/tools/opt4_env_setup.sh`），仅因宿主机不同存在下列差异。源码固定提交与主体完全一致。

## 1. 主机与运行时

| 项目 | 本机（opt4-env-02） | 主体（wp4-poc-01） | 差异说明 |
| --- | --- | --- | --- |
| 宿主机 | Windows 11 专业版 Build 26200 | 同 | — |
| WSL 发行版 | `Ubuntu` 24.04.2 LTS | `yanyu` Ubuntu 22.04.5 | 发行版/版本不同 |
| MariaDB | 10.11.14-MariaDB（24.04 自带） | 10.6.23 | 大版本差异，均本机回环 |
| DVWA PHP | PHP 8.3.6（24.04 自带，`/usr/bin/php8.3`） | PHP 8.1.2 | 大版本差异 |
| sqli-labs PHP | PHP 5.6.40（源码编译，`/opt/php56`） | 同 | 一致；本机用 gcc-12 编译（22.04 时为默认 gcc） |
| Python | WSL python3 3.12（仅标准库） | 3.10 | 一致策略：POC 仅标准库 |
| 端口 | DVWA 127.0.0.1:9080；sqli-labs 127.0.0.1:9081 | 同 | 一致 |
| 网络边界 | 仅本机回环；出网经本机代理 127.0.0.1:7890（仅用于安装依赖） | 仅本机回环 | 一致原则：靶场不对外 |

## 2. 源码一致性

- `/srv/source_projects/{DVWA,sqli-labs}` 由本地 `source_projects/`（含 .git，固定提交）复制后在 WSL ext4 内 `git reset --hard` 恢复完整工作树（规避 Windows 大小写不敏感文件系统对 Less-24/40 的影响）。
- `git rev-parse HEAD`：DVWA `068d974487a297c155c48722f9fcf7180a83adc4`；sqli-labs `e96f21776372c8613a7e565106e62bc01a59355e`（与 `workpackage1/samples.csv` 一致）。
- 部署副本 `/srv/web/` 由 `opt4_env_setup.sh` 从 source_projects 打包复制（排除 .git），无任何过滤/SQL/角色/Token 代码改动。

## 3. 部署差异清单（相对审计源码）

与主体 environment.md §4 相同的四处：DVWA `config/config.inc.php`（本地一次性口令，不入仓库）、PHP5.6 php.ini（socket/session 路径）、内置服务器启动参数、数据库账号与 schema。另加本机编译器差异（gcc-12 构建 PHP 5.6）与 PHP/MariaDB 大版本差异（见上表）。

## 4. 账号与测试对象

| 用途 | 账号/对象 | 处置 |
| --- | --- | --- |
| DVWA 登录（LG-01/LG-02 受害者） | `gordonb`（预置，abc123） | 口令经 DB 定点恢复 md5(abc123)；与主体 AUTH-001 用法一致 |
| sqli-labs SO-01 载荷/对照用户 | 载荷用户名=`<img src=x onerror=window.__opt4so=1>`、对照=`opt4ctl` | 执行后 DELETE |
| xss_s SO-02 留言 | name 含 `__opt4nm` 标记 | 执行后按标记 DELETE |
| 预置账号 admin/1337/pablo/smithy | 未登录未触碰 | — |

口令仅本地一次性使用；证据请求体对口令/Cookie 字段脱敏（脚本内 redact，规则沿用 `verification/tools/wp4lib.py`）。

## 5. 环境健康检查（漏洞判断之前）

| 检查 | 结果 |
| --- | --- |
| `GET :9080/login.php` | 200 |
| SQLI-001 正常 `id=1` | `Your Login name:Dumb` |
| DVWA admin 登录（302 + index 横幅） | `logged in as 'admin'` |
| `security.users` 行数 | 13 |
| `dvwa.users` 行数 | 5 |
| bootstrap 输出 | `OPT4_ENV_SETUP_OK` |

任何一项失败时先修环境再执行漏洞判断（同主体原则）。

## 6. 可复现入口

```bash
# 环境重建（首次约 15 分钟，含 PHP5.6 编译）
wsl -d Ubuntu -u root -- bash -lc 'bash /mnt/e/<repo>/optional4/tools/opt4_env_setup.sh'
# POC 执行（WSL python3，仅标准库）
wsl -d Ubuntu -u root -- bash -lc 'cd /mnt/e/<repo> && python3 optional4/tools/run_opt4_so01.py && ...'
```
