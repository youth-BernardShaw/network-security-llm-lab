#!/usr/bin/env bash
set -euo pipefail

base=/srv/source_projects
mkdir -p "$base"

fetch_fixed() {
  local name="$1" url="$2" commit="$3" dir actual
  dir="$base/$name"
  if [ ! -e "$dir" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "$url"
  elif [ ! -d "$dir/.git" ]; then
    printf 'Refusing non-Git existing path: %s\n' "$dir" >&2
    return 1
  fi
  git -C "$dir" fetch -q --depth 1 origin "$commit"
  git -C "$dir" checkout -q --detach FETCH_HEAD
  actual="$(git -C "$dir" rev-parse HEAD)"
  [ "$actual" = "$commit" ] || { printf 'Wrong commit for %s: %s\n' "$name" "$actual" >&2; return 1; }
  printf '%s=%s\n' "$name" "$actual"
}

fetch_fixed DVWA https://github.com/digininja/DVWA.git \
  068d974487a297c155c48722f9fcf7180a83adc4
fetch_fixed sqli-labs https://github.com/Audi-1/sqli-labs.git \
  e96f21776372c8613a7e565106e62bc01a59355e
