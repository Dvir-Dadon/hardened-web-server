#!/usr/bin/python3 -I
"""
lab-stats - turn raw server logs into a small, PUBLIC summary of attack attempts.

Publishes ONLY:
  * how many attack attempts happened (per hour, per day, last 24 h)
  * what was tried: SSH usernames, web paths, type of web attack

Never published and never stored: IP addresses (not even partly), normal visitors,
successful logins, the admin's own traffic, real account names (UID >= 1000).

Usernames and paths are attacker-chosen text, so they are character-filtered, IPs
inside them are masked, and one is shown only when MIN_SOURCES different IPs sent it
(the IPs are used for that check in memory and then thrown away).

Sources (read-only): journalctl -u ssh (same rule as ~/security-check.sh),
nginx access.log (+ .1), fail2ban.log (+ .1).
Runs every 20 minutes from /etc/cron.d/lab-stats as root. Standard library only.
"""
import argparse
import collections
import datetime as dt
import fcntl
import gzip
import ipaddress
import json
import os
import pwd
import re
import subprocess  # nosec B404 - used once, for journalctl with a fixed argument list (see ssh_lines)
import sys
import tempfile
import time
import urllib.parse

DEFAULTS = {
    "OUTPUT": "/var/www/lab/data/stats.json",
    "STATE": "/var/lib/lab-stats/history.json",
    "ACCESS_LOGS": "/var/log/nginx/access.log.1 /var/log/nginx/access.log",
    "F2B_LOGS": "/var/log/fail2ban.log.1 /var/log/fail2ban.log",
    "SSH_UNIT": "ssh",
    "EXCLUDE_NETS": "127.0.0.0/8 ::1/128",
    "TZ": "Asia/Jerusalem",
    "HISTORY_DAYS": "30",
    # A username or path is published only if at least this many DIFFERENT IPs sent it.
    # One attacker cannot write a word of his choice onto the public page.
    "MIN_SOURCES": "3",
}

MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}
COUNTERS = ("ssh", "web", "bans")

# ---------------------------------------------------------------- helpers


def load_config(path):
    """KEY=VALUE lines, read as data (never executed)."""
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                cfg[key.strip()] = val.strip().strip('"').strip("'")
    return cfg


class Excluder:
    """True for the admin's own traffic (home range, the server itself, localhost)."""

    def __init__(self, nets):
        self.nets = [ipaddress.ip_network(n, strict=False) for n in nets.split()]

    def __call__(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in n for n in self.nets)


def real_accounts():
    return {p.pw_name for p in pwd.getpwall() if 1000 <= p.pw_uid < 65534}


IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SAFE_USER = re.compile(r"^[A-Za-z0-9._@-]{1,32}$")
SAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9/._~\-=&?%+:,]")


def hide_ips(text):
    """Attackers often put IP addresses into usernames or paths. Never publish them."""
    return IPV4.sub("x.x.x.x", text)


def user_label(u):
    if u == "":
        return "(empty)"
    if IPV4.fullmatch(u):
        return "(an IP address)"   # bots often try the server's own IP as a username
    return hide_ips(u) if SAFE_USER.match(u) else "(other)"


def safe_path(path):
    """Display form of a path. The query string is never shown (attackers could write text there):
    "/?a=..." becomes "/?…" so it is clear the attack was in the parameters, not the page itself."""
    base, has_query = path.split("?", 1)[0], "?" in path
    base = SAFE_PATH_CHARS.sub("_", hide_ips(base[:200]))
    if len(base) > 48:
        return base[:48] + "…"
    return base + ("?…" if has_query else "")


def hour_floor(ts):
    return int(ts) // 3600 * 3600


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_lines(paths, counter):
    """Yield lines from several files one at a time (a huge log never sits in memory)."""
    for p in paths.split():
        try:
            opener = gzip.open if p.endswith(".gz") else open
            with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    counter[0] += 1
                    yield line
        except (FileNotFoundError, OSError):
            continue

# ---------------------------------------------------------------- SSH


# Same detection rule as ~/security-check.sh section 2, so the numbers match.
SSH_FAIL = re.compile(r"Invalid user|authenticating user|Failed")
# sshd always ends the message with "<ip> port <n>". The username comes earlier and is
# chosen by the attacker, so take the LAST match: a username like "8.8.8.8 port 1" cannot
# spoof the source.
SRC_IP = re.compile(r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}) port \d{1,5}")
USER_PATTERNS = [
    re.compile(r"Invalid user (\S*) from "),
    re.compile(r"authenticating user (\S{1,64}) "),
    re.compile(r"^Failed \S+ for (?:invalid user )?(\S{1,64}) from "),
]
JOURNAL_LINE = re.compile(r"^(\d{9,11})(?:\.\d+)? \S+ (?:sshd|sshd-session)\[\d+\]: (.*)$")


def ssh_lines(cfg, since_ts, ssh_file=None):
    if ssh_file:
        with open(ssh_file, encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    # Fixed argument list, no shell: nothing from a log can ever become a command.
    cmd = ["journalctl", "-q", "--no-pager", "-o", "short-unix", "-u", cfg["SSH_UNIT"],
           "--since", "@%d" % since_ts]
    # Bandit B603 reviewed: fixed argv, no shell; the only variables are an integer and SSH_UNIT from root-owned config
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace",  # nosec B603
                          timeout=120, check=True).stdout.splitlines()


def parse_ssh(lines, since_ts, excluded):
    """-> list of (ts, ip or None, username or None). IPs stay in memory only."""
    events = []
    for raw in lines:
        m = JOURNAL_LINE.match(raw.rstrip("\n"))
        if not m:
            continue
        ts, msg = int(m.group(1)), m.group(2)
        # Real logins are never attack events. Anchored at the start of the message:
        # a bare grep "Accepted" also hits "...not in PubkeyAcceptedAlgorithms" (incident 1).
        if ts < since_ts or msg.startswith("Accepted ") or not SSH_FAIL.search(msg):
            continue
        found = SRC_IP.findall(msg) or IPV4.findall(msg)
        ip = found[-1] if found else None
        if ip and excluded(ip):
            continue
        user = None
        for pat in USER_PATTERNS:
            um = pat.search(msg)
            if um:
                user = um.group(1)
                break
        events.append((ts, ip, user))
    return events

# ---------------------------------------------------------------- nginx


ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<t>[^\]]+)\] "(?P<req>[^"]*)" (?P<st>\d{3}) ')
TIME_RE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
REQ_RE = re.compile(r"^([A-Z]{3,10}) (\S+) HTTP/[0-9.]+$")
ATTACK_STATUS = {400, 404, 405, 444}
HARMLESS_404 = re.compile(r"^/(favicon\.ico|robots\.txt|apple-touch-icon[^/]*\.png|\.well-known/)")

CATEGORIES = [  # first match wins
    ("secrets", re.compile(
        r"(^|/)\.(env|git|aws|ssh|svn|hg|docker|npmrc|htpasswd|ds_store|vscode)|credentials|"
        r"id_rsa|id_ed25519|wp-config|(^|/)config\.(json|php|ya?ml|js)|\.(sql|bak|old|backup|"
        r"tar|tgz|gz|zip|7z|swp)$|phpinfo|server-status")),
    ("traversal_rce", re.compile(
        r"\.\./|/etc/passwd|/bin/(ba)?sh|cmd=|\$\{jndi|eval\(|base64_decode|"
        r"/shell|invokefunction|/cgi-bin/")),
    ("wordpress", re.compile(r"wp-|xmlrpc|/wordpress")),
    ("admin_panels", re.compile(
        r"phpmyadmin|/pma|/admin|/manager|/console|actuator|/solr|/owa|autodiscover|"
        r"/hnap1|/boaform|/vendor/|phpunit|/remote/|/geoserver|/\+cscoe\+|\.php$|\.aspx?$|\.jsp$")),
]
NAMED = {"secrets", "traversal_rce", "wordpress", "admin_panels"}  # only these list a path


def parse_nginx_time(s):
    m = TIME_RE.match(s)
    if not m:
        return None
    d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
    off = (int(oh) * 3600 + int(om) * 60) * (1 if sign == "+" else -1)
    try:
        base = dt.datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss),
                           tzinfo=dt.timezone.utc)
    except (KeyError, ValueError):
        return None
    return int(base.timestamp()) - off


def classify(req, status):
    """-> (category, path) for attack events, or None for a normal visitor."""
    rm = REQ_RE.match(req)
    if not rm:
        return ("malformed", None) if status in ATTACK_STATUS or req else None
    method, path = rm.groups()
    low = urllib.parse.unquote(path).lower()
    for name, pat in CATEGORIES:
        if pat.search(low):
            return name, path
    if status == 405 or method in ("TRACE", "TRACK", "CONNECT", "PROPFIND"):
        return "method_probe", path
    if status == 444:
        return "unknown_host", path
    if status in (400, 404) and not HARMLESS_404.match(low):
        return "not_found", path
    return None


def parse_web(lines, since_ts, excluded):
    """-> list of (ts, category, path, ip). Normal visitors are dropped right here."""
    ev = []
    for raw in lines:
        m = ACCESS_RE.match(raw)
        if not m:
            continue
        ts = parse_nginx_time(m.group("t"))
        if ts is None or ts < since_ts or excluded(m.group("ip")):
            continue
        c = classify(m.group("req"), int(m.group("st")))
        if c is None:
            continue  # a normal visitor: never counted, never stored
        ev.append((ts, c[0], c[1], m.group("ip")))
    return ev

# ---------------------------------------------------------------- fail2ban


F2B_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),\d+ fail2ban\.actions\s+\[\d+\]:\s+"
    r"NOTICE\s+\[(?P<jail>[^\]]+)\] Ban (?P<ip>\S+)")


def parse_f2b(lines, since_ts, excluded):
    """-> list of ban times. 'Restore Ban' after a restart does not match."""
    ev = []
    for raw in lines:
        m = F2B_RE.match(raw)
        if not m or excluded(m.group("ip")):
            continue
        y, mo, d, hh, mm, ss = (int(x) for x in m.groups()[:6])
        # fail2ban writes the server's local time: a naive datetime is read the same way
        ts = int(dt.datetime(y, mo, d, hh, mm, ss).timestamp())
        if ts >= since_ts:
            ev.append(ts)
    return ev

# ---------------------------------------------------------------- main


def new_bucket():
    return {k: 0 for k in COUNTERS}


def popular(pairs, min_src):
    """pairs of (label, ip) -> Counter of labels sent by >= min_src different IPs.
    The IPs are only counted here, in memory; they never leave this function."""
    count, ips = collections.Counter(), collections.defaultdict(set)
    for label, ip in pairs:
        count[label] += 1
        ips[label].add(ip)
    return collections.Counter({k: v for k, v in count.items() if len(ips[k]) >= min_src})


def build(cfg, now, ssh_file=None, report=None):
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(cfg["TZ"])
    except Exception:  # noqa: BLE001 - no tzdata: fall back to UTC
        tz = dt.timezone.utc
    excluded = Excluder(cfg["EXCLUDE_NETS"])
    errors = []
    cur_hour = hour_floor(now)
    read_from = cur_hour - 25 * 3600   # hours from here on are fully covered by the logs
    hidden = real_accounts()

    try:
        raw_ssh = ssh_lines(cfg, read_from, ssh_file)
        ssh_ok = True
    except Exception:  # noqa: BLE001
        raw_ssh, ssh_ok = [], False
        errors.append("ssh source unavailable")
    ssh = parse_ssh(raw_ssh, read_from, excluded)

    web_lines, f2b_lines = [0], [0]
    web = parse_web(read_lines(cfg["ACCESS_LOGS"], web_lines), read_from, excluded)
    if not web_lines[0]:
        errors.append("web logs unavailable")
    bans = parse_f2b(read_lines(cfg["F2B_LOGS"], f2b_lines), read_from, excluded)

    # ---- hourly counters for the window the logs fully cover (numbers only, no IPs)
    fresh = {h: new_bucket() for h in range(read_from, cur_hour + 1, 3600)}
    for ts, _ip, _u in ssh:
        fresh.setdefault(hour_floor(ts), new_bucket())["ssh"] += 1
    for ts, _c, _p, _ip in web:
        fresh.setdefault(hour_floor(ts), new_bucket())["web"] += 1
    for ts in bans:
        fresh.setdefault(hour_floor(ts), new_bucket())["bans"] += 1

    # ---- merge into the private history with max(): a reboot, log rotation or a
    # bad run can only ADD information, never erase hours already counted.
    state = {"since": now, "hours": {}}
    try:
        with open(cfg["STATE"], encoding="utf-8") as fh:
            state = json.load(fh)
    except (FileNotFoundError, ValueError):
        pass
    hours = state.setdefault("hours", {})
    for h, b in fresh.items():
        old = hours.get(str(h), {})
        merged = {k: max(old.get(k, 0), b[k]) for k in COUNTERS}
        if not ssh_ok:
            merged["ssh"] = old.get("ssh", 0)
        hours[str(h)] = merged
    keep_from = cur_hour - int(cfg["HISTORY_DAYS"]) * 86400
    for k in [k for k in hours if int(k) < keep_from]:
        del hours[k]
    state["since"] = min(int(state.get("since", now)), min((int(k) for k in hours), default=now))

    def bucket(h):
        return hours.get(str(h), new_bucket())

    last24 = [cur_hour - i * 3600 for i in range(23, -1, -1)]

    # ---- what was tried: the same 24 hourly buckets as the totals above,
    # so the lists always add up to the headline numbers
    min_src = int(cfg["MIN_SOURCES"])
    win_start = last24[0]
    ssh24 = [e for e in ssh if e[0] >= win_start]
    web24 = [e for e in web if e[0] >= win_start]
    users = popular(((user_label(u), ip) for _t, ip, u in ssh24
                     if u is not None and u not in hidden), min_src)
    # a path with an IP address inside is left out of the list entirely (it is still counted)
    paths = popular(((safe_path(p), ip) for _t, c, p, ip in web24
                     if p and c in NAMED and not IPV4.search(urllib.parse.unquote(p))), min_src)
    types = collections.Counter(c for _t, c, _p, _ip in web24)

    daily = collections.OrderedDict()
    for k in sorted(hours, key=int):
        day = dt.datetime.fromtimestamp(int(k), tz).date().isoformat()
        d = daily.setdefault(day, {"date": day, "ssh": 0, "web": 0, "bans": 0, "hours": 0})
        for f in COUNTERS:
            d[f] += hours[k].get(f, 0)
        d["hours"] += 1

    def top(counter, n):
        return [[k, v] for k, v in counter.most_common(n)]

    out = {
        "schema": 3,
        "generated_utc": iso(now),
        "refresh_minutes": 20,
        "tracking_since_utc": iso(state["since"]),
        "last24": {
            "ssh_attempts": sum(bucket(h)["ssh"] for h in last24),
            "web_attacks": sum(bucket(h)["web"] for h in last24),
            "bans": sum(bucket(h)["bans"] for h in last24),
        },
        "hourly": {
            "start_utc": iso(last24[0]),
            "ssh_attempts": [bucket(h)["ssh"] for h in last24],
            "web_attacks": [bucket(h)["web"] for h in last24],
        },
        "daily": list(daily.values())[-int(cfg["HISTORY_DAYS"]):],
        "tried": {
            "ssh_usernames": top(users, 8),
            "web_paths": top(paths, 8),
            "web_attack_types": top(types, 8),
        },
        "errors": errors,
    }
    if report is not None:
        report.update({
            "ssh journal lines read": len(raw_ssh),
            "ssh failed attempts (24h)": out["last24"]["ssh_attempts"],
            "nginx lines read": web_lines[0],
            "web attack events (24h)": out["last24"]["web_attacks"],
            "fail2ban lines read": f2b_lines[0],
            "fail2ban bans (24h)": out["last24"]["bans"],
            "real accounts hidden": len(hidden),
            "errors": errors,
        })
    return out, state


def atomic_write(path, data, mode):
    """Write to a temp file in the same folder, then rename: readers never see half a file."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"), ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="/etc/lab-stats.conf")
    ap.add_argument("--check", action="store_true",
                    help="read the sources, print a report and the JSON, write nothing")
    ap.add_argument("--stdout", action="store_true", help="print JSON, write nothing")
    ap.add_argument("--ssh-file", help=argparse.SUPPRESS)       # tests only
    ap.add_argument("--now", type=int, help=argparse.SUPPRESS)  # tests only
    args = ap.parse_args()

    cfg = load_config(args.config)
    now = args.now or int(time.time())
    report = {} if args.check else None
    dry = args.check or args.stdout

    if not dry:
        lock_dir = os.path.dirname(cfg["STATE"])
        os.makedirs(lock_dir, mode=0o750, exist_ok=True)
        lock = open(os.path.join(lock_dir, ".lock"), "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("lab-stats: another run is in progress", file=sys.stderr)
            return 0

    out, state = build(cfg, now, args.ssh_file, report)

    if args.check:
        print("== sources ==")
        for k, v in report.items():
            print(f"  {k:36} {v}")
        print("== JSON that would be published (this is EVERYTHING that goes public) ==")
    if dry:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    atomic_write(cfg["STATE"], state, 0o640)
    atomic_write(cfg["OUTPUT"], out, 0o644)
    return 0


if __name__ == "__main__":
    sys.exit(main())
