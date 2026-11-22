# Incident 1 - "Successful SSH logins" every hour (false positive)

| | |
|---|---|
| **Date** | November 2026 |
| **Severity (initial)** | High - a successful login by an unknown party would mean compromise |
| **Verdict** | False positive - detection rule too broad |
| **MITRE ATT&CK (suspected)** | T1078 Valid Accounts, T1110 Brute Force |

## Detection
My log check counted successful SSH logins with a search for the word `Accepted` in the SSH log.
It started reporting a "successful login" roughly every hour, at times when I was not connected.

## Investigation
1. Pulled the raw lines that matched instead of trusting the count.
2. They were not login events. They were sshd rejecting a client:
   ```
   sshd[…]: userauth_pubkey: signature algorithm ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]
   ```
   A bot offered an old `ssh-rsa` (SHA-1) key signature, sshd refused it, and the word
   `PubkeyAcceptedAlgorithms` contains `Accepted`.
3. Checked the real login events (`Accepted publickey for …`): only my own logins, from my own network,
   at times I was connected.

## Root cause
The rule matched a substring anywhere in the line instead of the specific login message.

## Fix
Anchored the rule to the real event:
```
# before (too broad)
grep "Accepted" /var/log/auth.log
# after
grep -E "sshd\[[0-9]+\]: Accepted (publickey|password) for " /var/log/auth.log
```
The same lesson is built into `bin/lab-stats.py`, which skips logins with `msg.startswith("Accepted ")`.

## Lessons
- Validate a detection rule against raw events before relying on it.
- False positives are not harmless: they train you to ignore the alert that matters.
- The rejected `ssh-rsa` signature is itself useful information: OpenSSH disables SHA-1 RSA signatures by default,
  so the server refused an outdated client.
