#!/usr/bin/env bash
# export-configs.sh - run ON THE SERVER with sudo. Read-only: changes nothing on the server.
# Collects the hardening configs into ~/hardening-configs.tar.gz (your home, not /tmp), redacted,
# so you can pull them to the VM, review them and add them to the GitHub repo.
# For directories that also hold distro files (sysctl.d, modprobe.d ...) only the files
# YOU added are taken: anything owned by an Ubuntu package (dpkg -S) is skipped.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
REDACT="$(command -v lab-redact || echo "$(dirname "$(readlink -f "$0")")/redact.sh")"
U="${SUDO_USER:?run with sudo from your normal user}"; UHOME="$(getent passwd "$U" | cut -d: -f6)"
WORK="$(mktemp -d)"; OUT="$WORK/configs"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"/{nginx/conf.d,nginx/snippets,nginx/sites,ssh,firewall,fail2ban,kernel,audit,updates,scripts,lynis}

copy() { # copy <src> <dst-dir>, redacted
  [[ -f "$1" ]] || return 0
  "$REDACT" < "$1" > "$2/$(basename "$1")"
  echo "  + $1"
}
mine() { # true if no Ubuntu package owns the file (= you created it)
  ! dpkg -S "$(readlink -f "$1")" >/dev/null 2>&1
}
capture() { # capture <dst-file> <description> <command...>
  local dst="$1" what="$2"; shift 2
  if "$@" 2>/dev/null | "$REDACT" > "$dst" && [[ -s "$dst" ]]; then echo "  + $what"; else rm -f "$dst"; fi
}

echo "Collecting:"
copy /etc/nginx/nginx.conf "$OUT/nginx"
for f in /etc/nginx/conf.d/*.conf;   do copy "$f" "$OUT/nginx/conf.d"; done
for f in /etc/nginx/snippets/*.conf; do case "$f" in *fastcgi*|*snakeoil*) ;; *) copy "$f" "$OUT/nginx/snippets";; esac; done
for f in /etc/nginx/sites-enabled/*; do [[ -e "$f" ]] && copy "$(readlink -f "$f")" "$OUT/nginx/sites"; done

for f in /etc/ssh/sshd_config.d/*.conf; do [[ -e "$f" ]] && copy "$f" "$OUT/ssh"; done
capture "$OUT/ssh/sshd-effective.txt" "sshd -T (security keys only)" \
  bash -c "sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|maxauthtries|logingracetime|loglevel|x11forwarding|allowagentforwarding|allowtcpforwarding|banner|permitemptypasswords) '"

capture "$OUT/firewall/ufw-status.txt" "ufw status verbose" ufw status verbose

copy /etc/fail2ban/jail.local "$OUT/fail2ban"
for f in /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/*.conf; do [[ -e "$f" ]] && mine "$f" && copy "$f" "$OUT/fail2ban"; done

for f in /etc/sysctl.d/*.conf;    do [[ -e "$f" ]] && mine "$f" && copy "$f" "$OUT/kernel"; done
for f in /etc/modprobe.d/*.conf;  do [[ -e "$f" ]] && mine "$f" && copy "$f" "$OUT/kernel"; done
for f in /etc/security/limits.d/*.conf /etc/systemd/coredump.conf.d/*.conf; do [[ -e "$f" ]] && mine "$f" && copy "$f" "$OUT/kernel"; done
for f in /etc/audit/rules.d/*.rules; do [[ -e "$f" ]] && mine "$f" && copy "$f" "$OUT/audit"; done

copy /etc/apt/apt.conf.d/20auto-upgrades "$OUT/updates"
# 50unattended-upgrades is a long distro file: keep only the lines that are switched on.
capture "$OUT/updates/50unattended-upgrades.active" "50unattended-upgrades (active lines)" \
  bash -c "grep -vE '^[[:space:]]*(//|$)' /etc/apt/apt.conf.d/50unattended-upgrades"

copy "$UHOME/security-check.sh" "$OUT/scripts"

for f in "$UHOME/lynis-before.txt" "$UHOME/lynis-after.txt"; do
  [[ -f "$f" ]] || continue
  capture "$OUT/lynis/$(basename "$f" .txt)-summary.txt" "$(basename "$f") (summary only)" \
    bash -c 'sed "s/\x1b\[[0-9;]*m//g" "$1" | grep -E "Hardening index|Tests performed|Warnings \(|Suggestions \("' _ "$f"
done

echo; echo "Review these before publishing (IPs, domains, e-mails that are left):"
grep -rnEo '([0-9]{1,3}\.){3}[0-9]{1,3}|[A-Za-z0-9.-]+\.duckdns\.org|<email>' "$OUT" \
  | grep -vE ':(127\.0\.0\.1|0\.0\.0\.0)$' | sort -u | sed 's/^/  /' || true

# Built inside the private temp dir, then installed into your home. Never a fixed name in /tmp:
# root writing to a predictable /tmp path can be tricked into following a planted symlink.
DEST="$UHOME/hardening-configs.tar.gz"
tar -czf "$WORK/out.tar.gz" -C "$WORK" configs
rm -f "$DEST"
install -m 600 -o "$U" -g "$(id -gn "$U")" "$WORK/out.tar.gz" "$DEST"
echo; echo "Created $DEST"
SERVER_IP="$( . /etc/lab-private.env 2>/dev/null; echo "${SERVER_IP:-<server-ip>}")"
echo "Pull it from the VM:  scp ${U}@${SERVER_IP}:~/hardening-configs.tar.gz ."
