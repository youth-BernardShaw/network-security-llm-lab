set -e
printf 'UID='; id -u
printf 'DISK='; df -h / | sed -n '2p'
printf 'LISTEN_9080_9081='; ss -ltn | grep -E ':9080|:9081' || :
for p in /srv/source_projects /srv/web /srv/wp4 /opt/php56; do if test -e "$p"; then printf 'exists %s\n' "$p"; else printf 'absent %s\n' "$p"; fi; done
