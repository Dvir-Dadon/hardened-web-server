#!/usr/bin/env bash
# install.sh - deploy the lab page + the stats pipeline (every 20 minutes) on the web server.
#
#   sudo ./install.sh --check                     # read-only preflight, changes nothing
#   sudo ./install.sh                             # install / update (backs up first)
#   sudo ./install.sh --uninstall                 # remove cron + stats script (keeps the site and backups)
#
# Optional: --repo-url URL   (default https://github.com/Dvir-Dadon/hardened-web-server)
#           --domain NAME    (default dvir-lab.duckdns.org)
set -Eeuo pipefail
umask 022

R="${LAB_TEST_ROOT:-}"            # test harness only; empty on the real server
DOMAIN="dvir-lab.duckdns.org"
REPO_URL="https://github.com/Dvir-Dadon/hardened-web-server"
MODE=""
WEBROOT="$R/var/www/lab"
BIN="$R/usr/local/sbin/lab-stats"
REDACT_BIN="$R/usr/local/bin/lab-redact"
CONF="$R/etc/lab-stats.conf"
CRON="$R/etc/cron.d/lab-stats"
STATE_DIR="$R/var/lib/lab-stats"
BACKUP_DIR="$R/var/backups/lab-site"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIV="$R/etc/lab-private.env"

ok()   { printf '  \e[32m[ OK ]\e[0m %s\n' "$*"; }
warn() { printf '  \e[33m[WARN]\e[0m %s\n' "$*"; WARNS=$((WARNS+1)); }
bad()  { printf '  \e[31m[FAIL]\e[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
hdr()  { printf '\n\e[1m== %s ==\e[0m\n' "$*"; }
die()  { printf '\e[31mERROR:\e[0m %s\n' "$*" >&2; exit 1; }
WARNS=0; FAILS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE=check ;;
    --uninstall) MODE=uninstall ;;
    --email) die "--email is no longer used: the page shows LinkedIn and GitHub only (no e-mail address is published)" ;;
    --repo-url) REPO_URL="${2:-}"; shift ;;
    --domain) DOMAIN="${2:-}"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done
[[ -z "$MODE" ]] && MODE=install
[[ -r "$HERE/local.env" ]] || die "local.env missing next to install.sh (copy local.env.example and fill it in)"
load_env() {  # read KEY="value" lines as DATA - never execute the file (no "source")
  local line re='^(HOME_IP_PREFIX|HOME_NET|ADMIN_USER|SERVER_IP|FAMILY_DOMAIN)="?([A-Za-z0-9./:_-]*)"?[[:space:]]*(#.*)?$'
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ $re ]] && printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
  done < "$1"
}
load_env "$HERE/local.env"
for v in HOME_IP_PREFIX HOME_NET ADMIN_USER SERVER_IP FAMILY_DOMAIN; do [[ -n "${!v:-}" ]] || die "$v is empty in local.env"; done
python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False); ipaddress.ip_address(sys.argv[2])' "$HOME_NET" "$SERVER_IP" 2>/dev/null || die "HOME_NET / SERVER_IP in local.env are not valid"
id "$ADMIN_USER" >/dev/null 2>&1 || die "ADMIN_USER=$ADMIN_USER in local.env is not a user on this machine"
[[ -z "$R" && $EUID -ne 0 ]] && die "run with sudo"

# ---------------------------------------------------------------- uninstall
if [[ $MODE == uninstall ]]; then
  hdr "Uninstall"
  rm -f "$CRON" "$BIN" "$REDACT_BIN" "$PRIV" && ok "removed cron job, lab-stats and lab-redact"
  echo "  Kept: $WEBROOT, $CONF, $STATE_DIR and backups in $BACKUP_DIR"
  echo "  To restore an old site: sudo tar -xzf $BACKUP_DIR/<file>.tar.gz -C /var/www"
  exit 0
fi

# ---------------------------------------------------------------- input validation
[[ "$REPO_URL" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "repo URL must look like https://github.com/user/repo"
[[ "$DOMAIN" =~ ^[a-z0-9.-]+$ ]] || die "bad domain"

# ---------------------------------------------------------------- preflight (read-only)
hdr "Package"
for f in site/index.html site/assets/app.js site/assets/style.css bin/lab-stats.py conf/lab-stats.conf conf/lab-stats.cron tools/redact.sh; do
  [[ -f "$HERE/$f" ]] || die "missing $f - run from the extracted package directory"
done
ok "all package files present"

hdr "System"
if grep -q 'VERSION_ID="24.04"' "$R/etc/os-release" 2>/dev/null; then ok "Ubuntu 24.04"; else warn "not Ubuntu 24.04 - tested only there"; fi
command -v python3 >/dev/null && ok "python3 $(python3 -c 'import sys;print(sys.version.split()[0])')" || bad "python3 missing"
python3 -c 'import zoneinfo; zoneinfo.ZoneInfo("Asia/Jerusalem")' 2>/dev/null && ok "time zone data" || warn "tzdata missing - daily buckets fall back to UTC"
command -v curl >/dev/null && ok "curl" || warn "curl missing - post-install HTTP checks skipped"

hdr "Nginx"
if nginx -t >/dev/null 2>&1; then ok "nginx -t passes"; else bad "nginx -t fails - fix nginx before installing"; fi
NGX="$(nginx -T 2>/dev/null || true)"
if grep -qE "server_name[^;]*\b${DOMAIN//./\\.}\b" <<<"$NGX"; then ok "server block for $DOMAIN found"; else bad "no server_name $DOMAIN in nginx -T"; fi
if grep -qE "root[[:space:]]+/var/www/lab/?;" <<<"$NGX"; then ok "root /var/www/lab found"; else bad "no 'root /var/www/lab;' in nginx -T"; fi
CSP_CONF="$(grep -iE 'add_header[[:space:]]+Content-Security-Policy' <<<"$NGX" | head -1 || true)"
if [[ -z "$CSP_CONF" ]]; then
  warn "no Content-Security-Policy add_header found in nginx -T"
elif grep -qiE "connect-src[^;]*'self'" <<<"$CSP_CONF"; then
  ok "CSP allows fetch() to the same origin (connect-src 'self')"
elif grep -qiE "connect-src" <<<"$CSP_CONF"; then
  bad "CSP has connect-src without 'self' - the dashboard cannot load data/stats.json"
elif grep -qiE "default-src[^;]*'self'" <<<"$CSP_CONF"; then
  ok "CSP: connect-src falls back to default-src 'self'"
else
  bad "CSP blocks fetch(): add connect-src 'self' (or default-src 'self')"
fi
if grep -qiE "img-src[^;]*'self'|default-src[^;]*'self'" <<<"$CSP_CONF"; then ok "CSP allows same-origin images"; else warn "check that CSP allows img-src 'self' (screenshots)"; fi

hdr "Log sources (read-only test run)"
TMPCONF="$(mktemp)"; TMPHTML="$(mktemp)"; trap 'rm -f "$TMPCONF" "$TMPHTML"' EXIT
if [[ -f "$CONF" ]]; then cp "$CONF" "$TMPCONF"; ok "using existing $CONF"; else
  sed -e "s|__HOME_NET__|$HOME_NET|" -e "s|__SERVER_IP__|$SERVER_IP|" "$HERE/conf/lab-stats.conf" > "$TMPCONF"; fi
CHECK_OUT="$(python3 -I "$HERE/bin/lab-stats.py" --config "$TMPCONF" --check ${LAB_TEST_ARGS:-} 2>&1)" || { bad "lab-stats --check crashed"; echo "$CHECK_OUT" | tail -5; }
sed -n '/== sources ==/,/== JSON/p' <<<"$CHECK_OUT" | grep -vE '^== ' | sed 's/^/  /' || true
grep -qE 'ssh journal lines read +[1-9]' <<<"$CHECK_OUT" && ok "sshd events found in the journal" || warn "0 sshd lines in the journal (last 25h) - check: journalctl -u ssh --since -1h"
grep -qE 'nginx lines read +[1-9]' <<<"$CHECK_OUT" && ok "nginx access log readable" || bad "nginx access log empty or missing"
grep -qE 'web attack events \(24h\) +[1-9]' <<<"$CHECK_OUT" || warn "0 web attack events parsed - is access_log in the default 'combined' format?"
if [[ -d "$R/var/log/journal" ]]; then ok "journal is persistent (survives the 02:00 reboot)"; else warn "journal is volatile: SSH events are lost on reboot (the dashboard keeps its own hourly counts)"; fi
if command -v fail2ban-client >/dev/null && fail2ban-client ping >/dev/null 2>&1; then ok "fail2ban running"; else warn "fail2ban-client not answering"; fi
if grep -qF "$HOME_IP_PREFIX" <<<"$(sed -n '/== JSON/,$p' <<<"$CHECK_OUT")" || grep -qE 'SHA256:' <<<"$(sed -n '/== JSON/,$p' <<<"$CHECK_OUT")"; then bad "home IP / key fingerprint found in output - do not install"; else ok "leak check: no home IP or key fingerprint in the JSON"; fi
if grep -qE '\b[0-9]{1,3}\.[0-9]{1,3}\.(x|[0-9]{1,3})\.(x|[0-9]{1,3})\b' <<<"$(sed -n '/== JSON/,$p' <<<"$CHECK_OUT")"; then bad "an IP address (or part of one) is in the JSON - must not be published"; else ok "leak check: no IP address, not even partly"; fi

hdr "Gaps worth knowing about (informational)"
if command -v ufw >/dev/null; then
  UFW="$(ufw status 2>/dev/null | head -1 || true)"
  [[ "$UFW" == *"active"* && "$UFW" != *"inactive"* ]] && ok "ufw: $UFW" || warn "ufw is not active - consider a host firewall (allow 22,80,443) or confirm a Kamatera firewall"
fi
if command -v ss >/dev/null; then
  EXTRA="$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\]|::1)' | grep -vE ':(22|80|443)$' || true)"
  [[ -z "$EXTRA" ]] && ok "only 22/80/443 listen on public addresses" || warn "other public listeners: $(tr '\n' ' ' <<<"$EXTRA")"
fi

if [[ $FAILS -gt 0 ]]; then
  printf '\n\e[31m%d check(s) failed, %d warning(s). Nothing was changed.\e[0m\n' "$FAILS" "$WARNS"; exit 2
fi
if [[ $MODE == check ]]; then
  printf '\n\e[32mPreflight passed\e[0m (%d warning(s)). Nothing was changed.\n' "$WARNS"; exit 0
fi

# ---------------------------------------------------------------- install
hdr "Backup"
mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
if [[ -d "$WEBROOT" ]]; then
  tar -czf "$BACKUP_DIR/lab-$TS.tar.gz" -C "$(dirname "$WEBROOT")" "$(basename "$WEBROOT")"
  ok "web root saved to $BACKUP_DIR/lab-$TS.tar.gz"
fi
for f in "$CONF" "$CRON" "$BIN"; do [[ -f "$f" ]] && cp -p "$f" "$BACKUP_DIR/$(basename "$f").$TS"; done

hdr "Site"
install -d -m 755 "$WEBROOT" "$WEBROOT/assets" "$WEBROOT/img" "$WEBROOT/data"
install -m 644 "$HERE/site/assets/app.js" "$HERE/site/assets/style.css" "$HERE/site/assets/favicon.svg" "$WEBROOT/assets/"
sed -e "s|__REPO_URL__|$REPO_URL|g" "$HERE/site/index.html" > "$TMPHTML"
grep -q '__[A-Z_]*__' "$TMPHTML" && die "unreplaced placeholder left in index.html"
install -m 644 "$TMPHTML" "$WEBROOT/index.html"
for img in "$HERE"/site/img/*.png; do [[ -f "$img" ]] && install -m 644 "$img" "$WEBROOT/img/"; done
[[ -z "$R" ]] && chown -R root:root "$WEBROOT"
ok "index.html, assets/ installed (img/ contents kept)"
OTHER="$(cd "$WEBROOT" && find . -maxdepth 1 -mindepth 1 ! -name index.html ! -name assets ! -name img ! -name data -printf '%f ' || true)"
[[ -n "$OTHER" ]] && warn "old files still in $WEBROOT: $OTHER(remove them if they belonged to the temporary page)"

hdr "Stats pipeline"
install -D -m 755 "$HERE/bin/lab-stats.py" "$BIN"
install -D -m 755 "$HERE/tools/redact.sh" "$REDACT_BIN"
if [[ -f "$CONF" ]]; then ok "kept existing $CONF"; else install -D -m 644 "$TMPCONF" "$CONF"; ok "created $CONF (home network $HOME_NET excluded)"; fi
install -D -m 640 "$HERE/local.env" "$PRIV"
[[ -z "$R" ]] && chown "root:$(id -gn "$ADMIN_USER")" "$PRIV"
ok "personal values for lab-redact in $PRIV (root and $ADMIN_USER only)"
install -d -m 750 "$STATE_DIR"
install -D -m 644 "$HERE/conf/lab-stats.cron" "$CRON"
ok "cron: every 20 minutes ($CRON)"
if [[ -z "$R" ]]; then "$BIN"; else python3 -I "$BIN" --config "$CONF" ${LAB_TEST_ARGS:-}; fi
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["schema"]==3' "$WEBROOT/data/stats.json" \
  && ok "first stats.json written and valid" || die "stats.json invalid"

hdr "Live checks"
if [[ -z "$R" ]] && command -v curl >/dev/null; then
  code="$(curl -s -o /dev/null -w '%{http_code}' "https://$DOMAIN/" || true)"
  [[ "$code" == 200 ]] && ok "https://$DOMAIN/ -> 200" || warn "https://$DOMAIN/ -> $code"
  hdrs="$(curl -sD - -o /dev/null "https://$DOMAIN/data/stats.json" || true)"
  grep -qE '^HTTP/[0-9.]+ 200' <<<"$hdrs" && ok "data/stats.json -> 200" || warn "data/stats.json not served (blocked by a snippet?)"
  grep -qi '^content-type: application/json' <<<"$hdrs" && ok "served as application/json" || warn "stats.json content-type is not application/json"
  for h in strict-transport-security content-security-policy x-content-type-options referrer-policy; do
    grep -qi "^$h:" <<<"$hdrs" && ok "header $h present" || warn "header $h missing on $DOMAIN (a location-level add_header can hide the http-level ones)"
  done
fi

printf '\n\e[32mDone.\e[0m %d warning(s). Open https://%s/ and press Ctrl+F5.\n' "$WARNS" "$DOMAIN"
echo "Rollback: sudo tar -xzf $BACKUP_DIR/lab-$TS.tar.gz -C /var/www && sudo ./install.sh --uninstall"
