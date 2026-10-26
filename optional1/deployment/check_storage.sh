printf 'SOURCE_SIZE\n'; du -sh /srv/source_projects/DVWA /srv/source_projects/sqli-labs 2>/dev/null
printf 'APT_CACHE\n'; du -sh /var/cache/apt/archives /var/lib/apt/lists 2>/dev/null
printf 'APT_ARCHIVES_FILES='; find /var/cache/apt/archives -maxdepth 1 -name '*.deb' | wc -l
printf 'APT_LOCK_PROCESSES\n'; ps -eo pid,comm,args | grep -E '[a]pt-get|[d]pkg|[g]it fetch' || :