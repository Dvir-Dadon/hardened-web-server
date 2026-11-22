# Screenshots

Scanner grades were captured in the browser (results hidden from the scanners' public lists).
Terminal screens come from `tools/show-evidence.sh` on the server, which passes every line through
`tools/redact.sh` (home IP, user name, key fingerprints, e-mail) and replaces every other IP address with `x.x.x.x`.
Every image then went through `tools/prep-screens.sh` (metadata stripped, OCR leak scan).
No port scans were run: the hosting provider's acceptable-use policy requires written approval first.

| File | Shows |
|---|---|
| 00-lab-page.png | The live attack dashboard |
| 01-securityheaders.png | Security Headers grade (A+) |
| 02-ssllabs.png | SSL Labs grade (A+) |
| 03-observatory.png | Mozilla Observatory score (A+, 115/100) |
| 04-ufw.png | `ufw status verbose`: only 22, 80, 443 allowed in |
| 08-fail2ban.png | Fail2ban jails and ban counts (address list hidden) |
| 09-incident1.png | Incident 1: loose vs. anchored search, and the bot lines the loose one caught |
| 10-incident2.png | Incident 2: `stat` - mtime in 2027, birth time and ctime in 2026 |
| 12-lynis.png | Lynis hardening index, before and after |
