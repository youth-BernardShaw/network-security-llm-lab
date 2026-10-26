# 补测后的清理与现场状态

## 1. 清理动作

```sql
DELETE FROM dvwa.guestbook WHERE name IN ('LLM_LAB','wp4x5');
DELETE FROM security.users
 WHERE username IN ('v','v_ctl','v''#','wp4v',
                    'x'' OR username=''v''#',
                    'sqli005_victim','sqli005_victim''#',
                    'sqli005_control','sqli005_victim_ctl');
```

`wp4target`（user_id=6）由 AUTH POC 自行恢复为 `Wp4` / `Target`，保留作为下一次复现的专用对象。

## 2. 清理后核对

| 检查 | 实际值 |
| --- | --- |
| `SELECT COUNT(*) FROM dvwa.users` | 6（5 个预置 + 专用 wp4target） |
| `SELECT COUNT(*) FROM security.users` | 13（预置教学用户） |
| `SELECT comment_id,name FROM dvwa.guestbook` | 仅 `1 test`（默认留言） |
| `wp4target` 姓名 | `Wp4` / `Target` |

SQLI-005 的三个临时账号已删除；AUTH 专用对象已恢复；XSS 专用留言已删除。

## 3. 仍在运行的服务

补测结束时保留现场供复核：

- MariaDB 10.6（WSL 内 `service mariadb`）；
- DVWA：PHP 8.1 内置服务器 `127.0.0.1:9080`；
- SQLi-Labs：PHP 5.6 内置服务器 `127.0.0.1:9081`。

PID 与日志位于 `/srv/wp4/pids/`、`/srv/wp4/logs/`。如需停止：

```bash
kill $(cat /srv/wp4/pids/dvwa.pid) $(cat /srv/wp4/pids/sqli.pid) 2>/dev/null || true
fuser -k 9080/tcp 9081/tcp 2>/dev/null || true
service mariadb stop
```
