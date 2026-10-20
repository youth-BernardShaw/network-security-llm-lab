set +e
printf 'PROCESS\n'; ps -eo pid,comm,args | grep -E '[a]pt-get|[g]it fetch|[m]ake|[p]hp.*-S 127.0.0.1' || :
printf 'PKGS\n'; dpkg-query -W -f='${Package} ${Status} ${Version}\n' mariadb-server php8.1-cli php8.1-mysql php8.1-mbstring php8.1-gd php8.1-xml php8.1-curl php8.1-zip libxml2-dev libssl-dev pkg-config 2>&1
printf 'SRC\n'; git -C /srv/source_projects/DVWA rev-parse HEAD; git -C /srv/source_projects/sqli-labs rev-parse HEAD
printf 'RUNTIME\n'; test -x /opt/php56/bin/php && echo php56_present || echo php56_absent; ss -ltn | grep -E ':9080|:9081' || :