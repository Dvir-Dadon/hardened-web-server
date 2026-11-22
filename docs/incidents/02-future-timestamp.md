# Incident 2 - File with a modification time in the future (suspected timestomping)

| | |
|---|---|
| **Date** | November 2026 (found by my weekly check) |
| **Severity (initial)** | Medium - possible anti-forensics |
| **Verdict** | Benign - expected `wget` behaviour |
| **MITRE ATT&CK (suspected)** | T1070.006 Indicator Removal: Timestomp |

## Detection
My weekly check lists files changed in the last 7 days. It flagged an image on the static site,
`/var/www/html/assets/chocolate-sushi-top.jpg`, because its modification date was in the future:
```
Modify: 2027-02-06 04:25:12 +0000
Change: 2026-09-15 09:50:30 +0000
 Birth: 2026-09-14 11:46:09 +0000
```

## Why it mattered
Attackers change file timestamps (timestomping) so that dropped tools blend in with system files
or fall outside an investigator's time window.

## Investigation
1. `stat <file>` to see all timestamps:
   - **mtime** (Modify) - content change time. Any program can set it (`touch -d`, `wget`, `tar`).
   - **ctime** (Change) - inode change time. Set by the kernel and updated by any change, including a `touch`.
     A normal user cannot set it to an arbitrary value.
2. The kernel-set times told the real story: **Birth** 14 Sep 2026 (the day I added the image) and **ctime** 15 Sep 2026
   (a metadata change the next day, e.g. permissions). Both were in the past; only the mtime pointed to 2027.
3. The file had been downloaded with `wget`, which by default sets the local mtime to the server's
   `Last-Modified` header. The remote server's header carried that (future) date.

## Verdict
Benign. The future mtime came from the remote server, not from tampering on this host.

## Lessons
- Know which timestamps can be forged easily (mtime, atime) and which cannot (ctime; birth time where supported).
- Look for the benign explanation before escalating, and record why it was ruled out.
- `wget --no-use-server-timestamps` keeps the local download time if that is wanted.
