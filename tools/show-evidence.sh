#!/usr/bin/env bash
# show-evidence.sh - run ON THE SERVER with sudo. Read-only: changes nothing.
# Shows the evidence for screenshots 04, 08, 09, 10 and 12, one clean screen at a time.
# (11 = your own security-check.sh: run it the way you always do, piped through lab-redact.)
# Take a screenshot of each screen, then press Enter for the next one.
#   sudo ./tools/show-evidence.sh
# Everything passes through lab-redact (home IP, admin user, keys, e-mails, family domain, host name)
# and then every other IPv4 address is replaced with x.x.x.x: attackers' addresses are not published either.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
U="${SUDO_USER:?run with sudo from your normal user}"; UHOME="$(getent passwd "$U" | cut -d: -f6)"
REDACT="$(command -v lab-redact || echo "$(dirname "$(readlink -f "$0")")/redact.sh")"

clean() { "$REDACT" | sed -E 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/x.x.x.x/g'; }
screen() { # screen <file name> <title>
  clear 2>/dev/null || printf "\n\n"
  printf '\e[1m%s\e[0m   \e[2m(%s)\e[0m\n\n' "$2" "$1.png"
}
next() { printf '\n\e[2m--- screenshot this, then press Enter ---\e[0m'; read -r _; }

screen 04-ufw "Firewall: only 22, 80 and 443 are allowed in"
echo "\$ sudo ufw status verbose"
ufw status verbose | clean
next

screen 08-fail2ban "Fail2ban: jails and how many addresses they blocked"
echo "\$ sudo fail2ban-client status"
fail2ban-client status | clean
for j in sshd nginx-botsearch; do
  echo; echo "\$ sudo fail2ban-client status $j   (address list hidden)"
  fail2ban-client status "$j" 2>/dev/null | grep -v "Banned IP list" | clean || echo "  (jail $j not found)"
done
next

screen 09-incident1 "Incident 1: the loose rule vs. the anchored rule (last 30 days)"
J="$(journalctl -q --no-pager -u ssh --since -30d 2>/dev/null || true)"
echo "Loose rule:    grep \"Accepted\"                               -> $(grep -c "Accepted" <<<"$J" || true) lines"
echo "Anchored rule: grep -E \"Accepted (publickey|password) for \"  -> $(grep -cE "Accepted (publickey|password) for " <<<"$J" || true) lines"
echo
echo "Lines the loose rule caught that are NOT logins (a bot offering an old ssh-rsa key):"
grep "PubkeyAcceptedAlgorithms" <<<"$J" | tail -3 | cut -c1-160 | clean \
  || echo "  (none in the last 30 days)"
next

screen 10-incident2 "Incident 2: mtime in the future, ctime tells the real story"
F=/var/www/html/assets/chocolate-sushi-top.jpg
echo "\$ stat $F"
if [[ -e $F ]]; then stat "$F" | grep -E "File:|Modify:|Change:|Birth:" | clean; else echo "  (file not found)"; fi
next

screen 12-lynis "Lynis hardening index: before and after"
for f in lynis-before.txt lynis-after.txt; do
  if [[ -f "$UHOME/$f" ]]; then
    printf '%-18s ' "$f"; sed 's/\x1b\[[0-9;]*m//g' "$UHOME/$f" | grep -m1 "Hardening index" | sed 's/^[[:space:]]*//'
  else echo "$f: not found"; fi
done
next
clear 2>/dev/null || true; echo "Done. Nothing was changed on the server."
