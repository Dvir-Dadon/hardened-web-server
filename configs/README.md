# Configuration from the live server (redacted)

Exported with `sudo tools/export-configs.sh` and reviewed by hand before publishing.
Home IP, admin user name, key material and the family-site domain are masked.

| Folder | What |
|---|---|
| `nginx/` | `nginx.conf`, `conf.d/` (headers, CSP, TLS), `snippets/` (blocked files), `sites/` (vhosts + catch-all) |
| `ssh/` | `sshd_config.d` drop-in and the effective security settings (`sshd -T`) |
| `firewall/` | `ufw status verbose` |
| `fail2ban/` | jails (`sshd`, `nginx-botsearch`) |
| `kernel/` | sysctl, blocked modules, core dumps |
| `updates/` | unattended-upgrades settings |
| `scripts/` | `security-check.sh` |
| `lynis/` | hardening index before and after |
