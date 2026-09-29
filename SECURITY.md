# Security Policy

## Reporting a vulnerability

Report security issues privately — do not open a public GitHub issue.

- **Email:** ultimate-sys-hardening@protonmail.com
- **GitHub:** [Private vulnerability reporting](https://github.com/Kal1010101/ultimate-sys-hardening/security/advisories/new)

Include the script and version, your OS and distro, what you ran, and what happened.
Expect an acknowledgement within 72 hours and a fix or plan within 14 days for
confirmed issues.

## Scope

This project is a root-privileged system modification tool. The following are
in scope and taken seriously:

- Command injection through arguments, config files, or policy files
- Privilege escalation beyond the root the script already requires
- A hardening module that leaves the system **less** secure than before
- Backup or revert failing silently, leaving a system unrecoverable
- Secrets (SMTP passwords, SSH keys) leaking into logs or reports

Out of scope: the script requiring root (that is by design), and hardening
choices you disagree with — open a normal issue for those.

## What this tool does to your system

It is designed to be auditable before you run it. Concretely:

| Behaviour | Guarantee |
|-----------|-----------|
| Network calls | None, except your own package manager. No telemetry, no license check, no phone-home. |
| Backups | Every modified file is copied to `/root/hardening_backup_<timestamp>/` before the first write. |
| Revert | `--revert` restores SSH, sysctl, and permissions. `--revert-suid` restores SUID/SGID bits from a recorded inventory. |
| Preview | `--dry-run` prints every intended change and exits without writing. |
| PAM | Not touched. The script never modifies `/etc/pam.d`. Want SSH MFA anyway? See [docs/mfa.md](docs/mfa.md) — a manual guide, deliberately not automated. |
| SSH lockout protection | `sshd -t` validates the config before restart; on failure the backup is restored automatically. |

## Known risks

These are inherent to what the tool does. Read before running in production.

**SUID/SGID removal** is the highest-risk module. It strips SUID from binaries
outside an explicit safe list. If a binary your workload depends on is not on
that list, it will lose its SUID bit. `--revert-suid` restores it from the
inventory taken at the start of the run.

**Disabling services** stops and disables services from a fixed list, and
records exactly which ones it actually stopped (most hosts don't have most of
this list running to begin with). Selecting this module again from the menu
while it shows enabled re-enables and starts exactly those — nothing from the
list this run didn't touch. This is behind the same confirmation tier as
SUID/GRUB (typing "yes"), on purpose: re-enabling a service that was disabled
for a reason should still be a conscious act, just no longer a manual one if
you choose to confirm it. Prefer to do it by hand instead, or the inventory is
missing (a host hardened before this existed)? Re-enable manually with
`systemctl enable --now <service>`.

**Firewall configuration** resets existing rules before applying its own. If you
have a hand-built ruleset, back it up separately — the script's backup covers
config files, not live kernel state.

**Encrypted home directories.** An earlier version modified PAM and locked a test
machine out of its login screen on an eCryptfs system. PAM modification was
removed entirely as a result. If you are on eCryptfs or LUKS-per-home, this is
why that module no longer exists.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes |
| < 2.0   | No |

## Verifying before you run

```bash
git clone https://github.com/Kal1010101/ultimate-sys-hardening.git
cd ultimate-sys-hardening

# Read it
less src/free/ultimate_hardening.sh

# Lint it yourself
shellcheck src/free/ultimate_hardening.sh
bash -n  src/free/ultimate_hardening.sh

# See what it would do, without doing it
sudo ./src/free/ultimate_hardening.sh --auto-mode --dry-run
```
