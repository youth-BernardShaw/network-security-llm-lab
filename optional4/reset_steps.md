# 选做4 重置与回滚步骤（reset_steps.md）

原则：每条 POC 用例在断言完成后立即回滚；全部通过专用测试数据定点清理，不使用 btnClear/TRUNCATE、不重置整库、不触碰预置教学账号（gordonb 口令经 DB 哈希定点恢复）。

## 0. 通用入口

```bash
wsl -d Ubuntu -u root -- bash -lc 'mariadb -e "<SQL>"'   # 数据库定点操作
wsl -d Ubuntu -u root -- bash -lc 'bash /mnt/e/<repo>/optional4/tools/opt4_env_setup.sh'  # 环境/服务重建
```

## 1. OPT4-SO-01（sqli-labs 测试用户清理）

```sql
-- 按标记定点删除（载荷用户名与对照用户名均含 opt4 前缀标记）
DELETE FROM security.users WHERE username LIKE '%__opt4so%' OR username = 'opt4ctl';
SELECT COUNT(*) FROM security.users;  -- 预期回到 13（初始教学用户数）
```

回滚后健康检查：`SELECT * FROM security.users WHERE username LIKE '%opt4%'` 应为空。

## 2. OPT4-SO-02（DVWA 测试留言清理）

```sql
DELETE FROM dvwa.guestbook WHERE name LIKE '%__opt4nm%' OR comment LIKE '%__opt4nm%' OR name LIKE '%__opt4ms%';
SELECT COUNT(*) FROM dvwa.guestbook;  -- 预期回到 setup 后基线
```

## 3. OPT4-LG-01 / OPT4-LG-02（gordonb 口令恢复）

```sql
UPDATE dvwa.users SET password = MD5('abc123') WHERE user = 'gordonb';
SELECT user, password FROM dvwa.users WHERE user = 'gordonb';  -- 预期 md5(abc123)
```

登录面验证：gordonb/abc123 可登录 DVWA；opt4lg1new/opt4csrf 登录失败。

## 4. 会话与文件

- 测试产生的 PHP 会话文件位于 `/srv/wp4/sessions`，为一次性本地目录，不入仓库；如需清空：`rm -f /srv/wp4/sessions/sess_*`。
- 证据中 Cookie/口令字段已脱敏（脚本内 redact）。

## 5. 整库级重置（仅在定点恢复失效时使用）

- DVWA：重新访问 `http://127.0.0.1:9080/setup.php` 点击 Create / Reset Database（脚本化步骤见 `verification/tools/env_setup.sh` 第6步）。
- sqli-labs：`curl http://127.0.0.1:9081/sql-connections/setup-db.php`（重建 `security` 全部 13 个教学用户）。
- 两者都会清掉测试数据，执行后需重新跑健康检查（见 `environment_opt4.md` §5）。

## 6. 执行后核对清单

| 项 | 核对 |
| --- | --- |
| security.users 行数 | 13，无 opt4 标记行 |
| dvwa.guestbook | 无 opt4 标记行 |
| gordonb 口令 | md5(abc123)，登录验证通过 |
| admin/1337/pablo/smithy | 未触碰（全程未登录） |
| 服务进程 | 仍监听 9080/9081（或按需停止：`kill $(cat /srv/wp4/pids/*.pid)`） |
