# 补测环境实录（2026-10-20）

本文件记录 40 份 POC 原稿实际执行时的环境，不把历史分析环境当成补测环境。

## 1. 宿主机与 WSL

| 项目 | 实际值 |
| --- | --- |
| WSL 发行版 | Ubuntu 22.04.5 LTS，WSL2 |
| 内核 | 6.18.54.1-microsoft-standard-WSL2 x86_64 |
| 权限 | `root`（`wsl -d Ubuntu-22.04 -u root`） |
| 磁盘 | ext4 根分区约 952 GB 可用 |
| 网络 | 仅本机回环；Windows 侧访问 `127.0.0.1:9080/9081` |

## 2. 组件与固定提交

| 组件 | 实际值 |
| --- | --- |
| MariaDB | 10.6.23-MariaDB-0ubuntu0.22.04.1 |
| PHP 8.1 | 8.1.2-1ubuntu2.27（DVWA） |
| PHP 5.6 | 5.6.40，源码编译到 `/opt/php56`（SQLi-Labs 的 ext/mysql） |
| DVWA | 提交 `068d974487a297c155c48722f9fcf7180a83adc4` |
| SQLi-Labs | 提交 `e96f21776372c8613a7e565106e62bc01a59355e` |
| Python（POC/工具） | Windows Python 3.12.14 |
| Chrome | 155.0.8059.85，headless，CDP 驱动 |
| Node.js | v24.19.0 |

靶场部署：`/srv/web/dvwa`、`/srv/web/sqli-labs`；运行时目录 `/srv/wp4`；源码工作树 `/srv/source_projects`。

## 3. 安装过程与网络修复

上次交接记录的 `install_prereqs.sh` 失败原因是 apt 连接 `archive.ubuntu.com:80` 超时/IPv6 不可达（退出 100）。本次先验证：

```bash
curl -4 -sS -o /dev/null -w '%{http_code}\n' --max-time 15 \
  http://archive.ubuntu.com/ubuntu/dists/jammy/Release
```

返回 200。随后强制 IPv4 并加超时/重试：

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true -o Acquire::http::Timeout=30 \
  -o Acquire::Retries=5 update
apt-get -o Acquire::ForceIPv4=true -o Acquire::http::Timeout=30 \
  -o Acquire::Retries=5 install -y mariadb-server php8.1-cli php8.1-mysql \
  php8.1-mbstring php8.1-gd php8.1-xml php8.1-curl php8.1-zip \
  build-essential libxml2-dev libssl-dev pkg-config unzip ca-certificates
```

结果：退出 0，安装成功。日志保留在 WSL `/srv/install_prereqs_retry.log`；本次结论是原失败属于 IPv6/网络路径问题，而非权限或审批拦截。

PHP 5.6：

```bash
curl -4 -sSL -o /tmp/php-5.6.40.tar.gz https://museum.php.net/php5/php-5.6.40.tar.gz
cd /srv && tar xzf /tmp/php-5.6.40.tar.gz && cd php-5.6.40
./configure --prefix=/opt/php56 --with-config-file-path=/opt/php56/etc \
  --with-mysql=mysqlnd --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd \
  --enable-mbstring --without-openssl --without-pear --disable-cgi \
  CFLAGS='-O2 -fcommon'
make -j20 && make install
```

`php -m` 确认 `mysql`、`mysqli`、`mysqlnd`、`pdo_mysql`、`mbstring`、`session` 存在。

## 4. 部署与健康检查

部署脚本 `verification/tools/env_setup.sh` 复制到 `/srv/env_setup.sh` 并去除 CRLF 后执行，输出：

```text
DVWA rows: 5
SQLi-Labs users: 13
ENV_SETUP_OK
```

健康检查：

- `GET http://127.0.0.1:9081/Less-1/?id=1` 返回 `Your Login name:Dumb`；
- `GET http://127.0.0.1:9080/login.php` 返回 200；
- `dvwa.users=5`、`security.users=13`。

## 5. 执行边界

- 40 份 POC **源码未修改**。只通过既有 CLI 参数提供本地 URL、端口、会话 Cookie、专用账号名与路径。
- 会话：`admin`（DVWA 预置）与 `gordonb`（普通用户），按安全档位写 `PHPSESSID` + `security` Cookie 文件。
- 专用对象：`wp4target`（user_id=6）、SQLI-005 的 `v`、`v_ctl`、`sqli005_victim` 等；执行后清理或恢复。
- XSS 执行证据：headless Chrome + CDP，捕获 `Page.javascriptDialogOpening` 与 `Runtime.consoleAPICalled`，不使用“响应中出现 payload”代替执行。
- 所有结果与证据见 `optional1/followup_poc_results.csv`、`optional1/followup/evidence/`。

## 6. 复现入口

```powershell
python optional1/followup/tools/run_batch.py
python optional1/followup/tools/browser_batch.py
python optional1/followup/tools/build_followup_results.py
python optional1/tools/summarize_poc_followup.py optional1/followup_poc_results.csv
```

注意：`run_batch.py` 会重置专用测试账号与留言；`browser_batch.py` 必须在 XSS 原稿写入后运行。
