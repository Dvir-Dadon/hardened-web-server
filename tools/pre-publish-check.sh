#!/usr/bin/env bash
# pre-publish-check.sh - run ON THE VM inside the repo folder, right before "git push".
# Fails if anything personal or secret is found in tracked text files.
set -Eeuo pipefail
cd "${1:-.}"
load_env() {  # read KEY="value" lines as DATA - never execute the file (no "source")
  local line re='^(HOME_IP_PREFIX|HOME_NET|ADMIN_USER|SERVER_IP|FAMILY_DOMAIN)="?([A-Za-z0-9./:_-]*)"?[[:space:]]*(#.*)?$'
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ $re ]] && printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
  done < "$1"
}
[[ -r local.env ]] && load_env ./local.env || { echo "run inside the repo folder (local.env not found)"; exit 1; }
q() { printf '%s' "$1" | sed 's/[.[\*^$|()]/\\&/g'; }
PAT="TODO\(dvir\)|$(q "$HOME_IP_PREFIX")|$(q "${HOME_IP_PREFIX//./-}")|$(q "$FAMILY_DOMAIN")|/home/$(q "$ADMIN_USER")\b|\b$(q "$ADMIN_USER")@|AllowUsers[[ :]]+$(q "$ADMIN_USER")\b"
PAT+="|SHA256:[A-Za-z0-9+/]{20,}|BEGIN [A-Z ]*PRIVATE KEY|AAAAC3NzaC1lZDI1NTE5|[A-Za-z0-9._%+-]+@(gmail|walla|outlook|hotmail|yahoo)\."
if [[ -d .git ]]; then FILES="$(git ls-files)"; else FILES="$(find . -type f ! -path './.git/*' ! -name local.env ! -name '*.png')"; fi
FILES="$(printf '%s\n' "$FILES" | grep -v 'pre-publish-check\.sh$' || true)"  # this file contains the patterns themselves
[[ -n "$FILES" ]] || { echo "no files to check"; exit 1; }
if git check-ignore -q local.env 2>/dev/null || ! [[ -d .git ]]; then :; else echo "STOP - local.env is not ignored by git"; exit 1; fi
if hits="$(printf '%s\n' "$FILES" | xargs -d '\n' grep -nIE "$PAT" -- 2>/dev/null)"; then
  echo "STOP - possible personal data or unfinished TODO:"; echo "$hits" | sed 's/^/  /'; exit 1
fi
# secrets written as key=value / key: value (DuckDNS token, API keys, passwords)
SECRET='((token|api[_-]?key|secret)[[:space:]]*[=:]|passw(or)?d[[:space:]]*=)[[:space:]]*[^[:space:]<]{6,}'
if hits="$(printf '%s\n' "$FILES" | xargs -d '\n' grep -nIiE "$SECRET" -- 2>/dev/null)"; then
  echo "STOP - looks like a secret (token / key / password):"; echo "$hits" | sed 's/^/  /'; exit 1
fi
echo "OK - no home IP, user name, keys, family-site domain, personal e-mail or TODO(dvir) in tracked text files."
echo "Images are not scanned here: run tools/prep-screens.sh on them first."
