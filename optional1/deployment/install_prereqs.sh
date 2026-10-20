#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  mariadb-server php8.1-cli php8.1-mysql php8.1-mbstring \
  php8.1-gd php8.1-xml php8.1-curl php8.1-zip \
  build-essential libxml2-dev libssl-dev pkg-config \
  unzip ca-certificates

printf 'PHP8='; php8.1 -v | head -n 1
printf 'MARIADB='; mariadb --version
printf 'BUILD='; gcc --version | head -n 1
