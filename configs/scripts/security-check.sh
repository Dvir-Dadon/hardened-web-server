#!/bin/bash
# בדיקת אבטחה. הרצה: sudo ~/security-check.sh   (ברירת מחדל: 7 ימים אחרונים)
SINCE="${1:-7 days ago}"
journalctl -u ssh --since "$SINCE" --no-pager > /tmp/ssh-check.log
IPRE='([0-9]{1,3}\.){3}[0-9]{1,3}'
echo "===== 1. כניסות מוצלחות ב-SSH ====="
grep -E "Accepted (publickey|password)" /tmp/ssh-check.log | awk '{print $1,$2,$3,"user="$9,"ip="$11,$NF}'
echo; echo "===== 2. ניסיונות כושלים ב-SSH ====="
grep -E "Invalid user|authenticating user|Failed" /tmp/ssh-check.log > /tmp/ssh-fail.log
echo "שורות כישלון: $(wc -l < /tmp/ssh-fail.log)"
echo "כתובות שונות: $(grep -oE "$IPRE" /tmp/ssh-fail.log | sort -u | wc -l)"
echo "ניסיונות על root: $(grep -c 'authenticating user root' /tmp/ssh-fail.log)"
echo "--- 10 הכתובות הכי פעילות:"
grep -oE "$IPRE" /tmp/ssh-fail.log | sort | uniq -c | sort -rn | head -10
echo "--- 15 שמות המשתמש הכי מנוסים:"
grep -oE "Invalid user [^ ]+" /tmp/ssh-fail.log | awk '{print $3}' | sort | uniq -c | sort -rn | head -15
echo; echo "===== 3. Fail2ban ====="
fail2ban-client status sshd | grep -E "Currently|Total"
fail2ban-client status nginx-botsearch | grep -E "Currently|Total"
echo; echo "===== 4. האתר ====="
zcat -f /var/log/nginx/access.log* > /tmp/web-check.log
echo "--- קודי תשובה:"
awk '{print $9}' /tmp/web-check.log | sort | uniq -c | sort -rn | head -8
echo "--- 15 נתיבים שלא קיימים (404):"
awk '$9==404 {print $7}' /tmp/web-check.log | sort | uniq -c | sort -rn | head -15
echo "--- 10 הכתובות הכי פעילות:"
awk '{print $1}' /tmp/web-check.log | sort | uniq -c | sort -rn | head -10
echo "--- נתיבים רגישים שקיבלו 200 (אמור להיות ריק):"
grep -iE '\.env|\.git|wp-|\.php|admin|\.bak|\.sql' /tmp/web-check.log | awk '$9==200 && index($7,"?")==0 {print $1,$7}' | head -10
echo; echo "===== 5. חיפוש דלת אחורית ====="
echo "--- UID 0 (אמור להיות רק root):"
awk -F: '$3==0 {print $1}' /etc/passwd
echo "--- משתמשים עם shell:"
grep -vE 'nologin|/false|/sync' /etc/passwd | cut -d: -f1,3,7
echo "--- קבוצת sudo:"
getent group sudo
echo "--- מפתחות SSH מורשים:"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && { echo "$f:"; ssh-keygen -lf "$f"; }
done
echo "--- cron של root:"; crontab -l -u root 2>/dev/null | grep -v '^#'
echo "--- cron של admin:"; crontab -l -u admin 2>/dev/null | grep -v '^#'
ls /etc/cron.d
echo "--- שירותים חדשים (30 יום):"
find /etc/systemd/system -type f -newermt "-30 days"
echo "--- פורטים פתוחים:"
ss -tulpn | awk 'NR>1 {print $1,$5,$7}'
echo "--- חיבורים פעילים:"
ss -tnp state established | awk 'NR>1 {print $3,$4,$5}'
echo "--- קבצים באתר ששונו (7 ימים):"
find /var/www/html -type f -newermt "-7 days"
echo "--- קבצי הרצה בתיקיות זמניות (אמור להיות ריק):"
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
echo "--- תהליכים שצורכים הכי הרבה מעבד:"
ps aux --sort=-%cpu | awk 'NR<=6 {print $1,$3,$11}'
echo; echo "===== 6. עדכונים ====="
grep -h "Packages that will be upgraded" /var/log/unattended-upgrades/unattended-upgrades.log | tail -3
[ -f /var/run/reboot-required ] && echo "צריך ריבוט" || echo "לא צריך ריבוט"
rm -f /tmp/ssh-check.log /tmp/ssh-fail.log /tmp/web-check.log
