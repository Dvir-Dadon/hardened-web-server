#!/usr/bin/env bash
# lab-redact - pipe terminal output through this before taking a screenshot.
#   sudo fail2ban-client status sshd | lab-redact
# Masks: your home IP (fully, as HOME-IP), your admin user, SSH key fingerprints and public keys,
# e-mail addresses, the server hostname and the family-site domain.
# Personal values come from /etc/lab-private.env (server) or ../local.env (package).
set -euo pipefail
load_env() {  # read KEY="value" lines as DATA - never execute the file (no "source")
  local line re='^(HOME_IP_PREFIX|HOME_NET|ADMIN_USER|SERVER_IP|FAMILY_DOMAIN)="?([A-Za-z0-9./:_-]*)"?[[:space:]]*(#.*)?$'
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ $re ]] && printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
  done < "$1"
}
for f in /etc/lab-private.env "$(dirname "$(readlink -f "$0")")/../local.env"; do
  [[ -r "$f" ]] && { load_env "$f"; break; }
done
esc() { printf '%s' "$1" | sed 's/[.[\*^$/]/\\&/g'; }
args=(
  -e 's#SHA256:[A-Za-z0-9+/]{16,}=*#SHA256:<redacted>#g'
  -e 's#(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp[0-9]+) AAAA[A-Za-z0-9+/=]+#\1 <redacted-key>#g'
  -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<email>/g'
)
if [[ -n "${HOME_IP_PREFIX:-}" ]]; then
  # (^|[^0-9.]) instead of \b: in "8.<prefix>3" the prefix is part of someone else's address
  args+=(-e "s/(^|[^0-9.])$(esc "$HOME_IP_PREFIX")[0-9]{1,3}(\\.[0-9]{1,3})?\\b/\\1HOME-IP/g")
  dashed="${HOME_IP_PREFIX//./-}"            # a.b. -> a-b- (reverse-DNS host names)
  args+=(-e "s/(^|[^0-9-])$(esc "$dashed")[0-9]{1,3}(-[0-9]{1,3})?[A-Za-z0-9.-]*/\\1HOME-IP/g")
fi
[[ -n "${ADMIN_USER:-}" ]] && args+=(-e "s/\\b$(esc "$ADMIN_USER")\\b/admin/g")
[[ -n "${FAMILY_DOMAIN:-}" ]] && args+=(-e "s/$(esc "$FAMILY_DOMAIN")/family-site.example/g")
host="$(hostname 2>/dev/null || true)"
if [[ -n "$host" && "$host" != localhost && "$host" =~ ^[A-Za-z0-9.-]+$ ]]; then
  args+=(-e "s/\\b$(esc "$host")\\b/web01/g")
fi
exec sed -E "${args[@]}"
