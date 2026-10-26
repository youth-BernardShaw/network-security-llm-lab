#!/usr/bin/env bash
# Work package 4 local lab bootstrap (WSL2 Ubuntu 22.04).
# Deploys the fixed upstream commits already present in /srv/source_projects,
# creates an isolated MariaDB schema, and starts the two PHP built-in servers.
# This script changes /srv only; it does not write into the Git work tree.
set -euo pipefail

SRC=/srv/source_projects
WEB=/srv/web
RUN=/srv/wp4
DVWA_DB_PASS='wp4_local_dvwa_2026'
DVWA_PORT=9080
SQLI_PORT=9081

mkdir -p "$WEB" "$RUN/logs" "$RUN/pids" "$RUN/sessions"
chmod 700 "$RUN/sessions"

echo "[1/7] Deploying working copies from fixed commits"
rm -rf "$WEB/dvwa" "$WEB/sqli-labs"
mkdir -p "$WEB/dvwa" "$WEB/sqli-labs"
tar -C "$SRC/DVWA" --exclude=.git -cf - . | tar -C "$WEB/dvwa" -xf -
tar -C "$SRC/sqli-labs" --exclude=.git -cf - . | tar -C "$WEB/sqli-labs" -xf -

echo "[2/7] Writing DVWA local config (credentials stay outside the repository)"
cat > "$WEB/dvwa/config/config.inc.php" <<'PHP'
<?php
$DBMS = 'MySQL';

$_DVWA = array();
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'wp4_local_dvwa_2026';
$_DVWA[ 'db_port' ]     = '3306';

$_DVWA[ 'recaptcha_public_key' ]  = '';
$_DVWA[ 'recaptcha_private_key' ] = '';
$_DVWA[ 'default_security_level' ] = 'low';
$_DVWA[ 'default_locale' ] = 'en';
$_DVWA[ 'disable_authentication' ] = false;

define ('MYSQL', 'mysql');
define ('SQLITE', 'sqlite');
$_DVWA['SQLI_DB'] = MYSQL;
?>
PHP
chmod 640 "$WEB/dvwa/config/config.inc.php"

echo "[3/7] Writing PHP 5.6 runtime config"
mkdir -p /opt/php56/etc
cat > /opt/php56/etc/php.ini <<'INI'
[PHP]
date.timezone = Asia/Shanghai
default_charset = "UTF-8"
display_errors = On
display_startup_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_STRICT
log_errors = On
error_log = /srv/wp4/logs/php56-error.log
mysql.default_socket = /run/mysqld/mysqld.sock
mysqli.default_socket = /run/mysqld/mysqld.sock
pdo_mysql.default_socket = /run/mysqld/mysqld.sock
session.save_path = "/srv/wp4/sessions"
session.gc_maxlifetime = 7200
output_buffering = 4096
allow_url_fopen = On
INI

echo "[4/7] Preparing MariaDB schemas and least-privilege accounts"
service mariadb start >/dev/null 2>&1 || true
for i in $(seq 1 30); do mariadb -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
mariadb <<SQL
CREATE DATABASE IF NOT EXISTS dvwa CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY '${DVWA_DB_PASS}';
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY '${DVWA_DB_PASS}';
ALTER USER 'dvwa'@'127.0.0.1' IDENTIFIED BY '${DVWA_DB_PASS}';
ALTER USER 'dvwa'@'localhost' IDENTIFIED BY '${DVWA_DB_PASS}';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'127.0.0.1';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
GRANT CREATE ON *.* TO 'dvwa'@'127.0.0.1';
GRANT CREATE ON *.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "[5/7] Starting PHP servers"
if [ -f "$RUN/pids/dvwa.pid" ]; then kill "$(cat "$RUN/pids/dvwa.pid")" 2>/dev/null || true; fi
if [ -f "$RUN/pids/sqli.pid" ]; then kill "$(cat "$RUN/pids/sqli.pid")" 2>/dev/null || true; fi
fuser -k "${DVWA_PORT}/tcp" 2>/dev/null || true
fuser -k "${SQLI_PORT}/tcp" 2>/dev/null || true
sleep 1

cd "$WEB/dvwa"
PHP_CLI_SERVER_WORKERS=4 nohup /usr/bin/php8.3 \
  -d display_errors=On -d error_reporting=E_ALL \
  -d session.save_path=/srv/wp4/sessions -d date.timezone=Asia/Shanghai \
  -S "127.0.0.1:${DVWA_PORT}" -t "$WEB/dvwa" \
  >"$RUN/logs/dvwa-server.log" 2>&1 &
echo $! > "$RUN/pids/dvwa.pid"

cd "$WEB/sqli-labs"
nohup /opt/php56/bin/php -c /opt/php56/etc/php.ini \
  -S "127.0.0.1:${SQLI_PORT}" -t "$WEB/sqli-labs" \
  >"$RUN/logs/sqli-server.log" 2>&1 &
echo $! > "$RUN/pids/sqli.pid"

for i in $(seq 1 30); do
  curl -s -o /dev/null "http://127.0.0.1:${DVWA_PORT}/login.php" && break
  sleep 1
done
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://127.0.0.1:${SQLI_PORT}/" && break
  sleep 1
done

echo "[6/7] Running DVWA database setup"
JAR=$(mktemp)
TOKEN=$(curl -s -c "$JAR" "http://127.0.0.1:${DVWA_PORT}/setup.php" | grep -oP "value='\K[0-9a-f]+" | head -1)
if [ -z "${TOKEN:-}" ]; then echo "DVWA setup token not found"; exit 1; fi
curl -s -b "$JAR" -c "$JAR" -o "$RUN/logs/dvwa-setup-response.html" \
  --data-urlencode 'create_db=Create / Reset Database' \
  --data-urlencode "user_token=${TOKEN}" \
  "http://127.0.0.1:${DVWA_PORT}/setup.php"
rm -f "$JAR"
DVWA_ROWS=$(mariadb -N -e 'SELECT COUNT(*) FROM dvwa.users' 2>/dev/null || echo 0)
if [ "${DVWA_ROWS:-0}" -lt 1 ]; then
  echo "DVWA setup did not seed dvwa.users; see $RUN/logs/dvwa-setup-response.html"; exit 1
fi

echo "[7/7] Running SQLi-Labs database setup"
curl -s -o "$RUN/logs/sqli-setup-response.html" "http://127.0.0.1:${SQLI_PORT}/sql-connections/setup-db.php"
grep -q "Creating New database" "$RUN/logs/sqli-setup-response.html" || {
  echo "SQLi-Labs setup did not report success; see $RUN/logs/sqli-setup-response.html"; exit 1; }

echo "DVWA rows: $(mariadb -N -e 'SELECT COUNT(*) FROM dvwa.users')"
echo "SQLi-Labs users: $(mariadb -N -e 'SELECT COUNT(*) FROM security.users')"
echo "OPT4_ENV_SETUP_OK"
