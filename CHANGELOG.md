# Changelog

All notable changes to Ultimate Hardening (free tier) are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com),
and the project follows [Semantic Versioning](https://semver.org).

## [Unreleased]

### Added
- Per-module revert: selecting an already-applied module from the
  interactive menu now reverts it instead of re-applying. 18 of 22
  modules covered; the rest explain why they can't be automated instead
  of failing silently. Verified end-to-end on real guests across all
  three tiers.
- Backup retention: per-run backup directories now prune after
  `UH_BACKUP_RETENTION_DAYS` (default 90). Genesis backups are never
  pruned.

### Fixed
- SSH hardening was rolled back on RHEL-family and Alpine hosts where sshd
  had never started: `sshd -t` failed for want of host keys, not the
  config. Validation now uses a throwaway key there; no real keys are made.
- The update check now refuses a `UH_UPDATE_REPO` that is not `owner/repo`
  before building the API URL. Its test had passed only where curl was
  missing.
- A host without `find` (e.g. the rockylinux:8 image) listed no restore
  points instead of erroring. The tool now refuses to start when `find`,
  `awk`, `sed`, `grep` or `sort` is missing, and names it.
- Multi-distro CI never got past package install on 8 of 11 images and ran
  every case in one shared container. It now runs `tests/run.sh` per
  distro, one fresh container per case. EOL Debian 11 dropped.
- `backup_file()` never created a per-run copy on a file's first-ever
  backup, only the permanent genesis copy — de-duplication was checking
  the wrong order.
- SSH module's `sshd -t` safety check could false-reject on a host where
  sshd has never started (missing `/run/sshd`), skipping SSH hardening
  unnecessarily.
- AIDE's daily integrity check was broken on every RHEL-family host — the
  baseline database was never promoted to its final filename.
- The `boot` module's new revert was unreachable on hosts with no GRUB
  (Alpine) — its compliance tag could never show as applied.
- Reverting the firewall module could lock out the live SSH session by
  reloading a stale zone into a running daemon.
- `firewalld` never actually set its own default zone — `--set-default-
  zone` can't be combined with `--permanent`, which failed silently on
  every run.
- Per-module revert could silently no-op, or delete a real file it never
  touched, for tool-generated files and modules that were never actually
  applied.
- Repeated runs against an unchanged host duplicated every backed-up file
  every time; now skipped when byte-identical to the last capture.
- Several `enable_service` callers (firewalld, nftables, audit, apparmor)
  could log success for a service that never started.

### Testing
- Fixed two bugs in the lab's own attacker-simulation script (SSH key
  handling, console-unban privilege detection) that produced false
  "unreachable" and false "control engaged" readings.
- Ran the containerized test suite on real Docker for the first time;
  fixed the bugs it found (see Fixed above) plus two stale test
  assertions. Full suite now passes clean.
- Added Arch, openSUSE, and real RHEL 7/8 (via CentOS) as lab guests;
  ran the full module suite on each. Void Linux and Gentoo have no
  cloud-init image and can't be added without a manual OS install.
- Regenerated stale screenshots in `docs/images/`.

## [2.4.0] — 2026-09-21

A reliability and safety release: a hardening run should never leave a machine
worse off than it found it — not half-configured, not unable to boot, and never
reporting success when it failed. Found and fixed against real Debian, Rocky,
and Alpine VMs.

### Fixed
- **Unattended updates could leave a machine unbootable.** After a kernel
  upgrade, module 1 now verifies the kernel that will boot next has a matching
  boot image, rebuilds it if it is stale, and — if it cannot — refuses to
  report success and warns not to reboot. Previously a kernel upgrade on Alpine
  left the initramfs behind and the machine failed its next boot.
- **A single failing module aborted the entire run.** Modules now run through a
  wrapper that records the failure and continues, then reports what did and did
  not complete, instead of stopping silently and leaving the system
  half-hardened.
- **The firewall module aborted the run on RHEL.** Module 3 assumed `ufw`; a
  RHEL host without it stopped the run at module 3.
- A `SIGPIPE`-under-`pipefail` bug that could corrupt the CIS score.
- A second `SIGPIPE` bug that made ModSecurity read as "not installed".
- The interactive menu no longer drops you out of the session when one module
  fails — menu actions use the same no-abort path as automated runs.

### Added
- **Preflight dependency resolution.** Before anything is changed, each
  module's packages are resolved for the platform, what can be installed is
  installed, and anything the enabled repositories cannot supply is named (for
  example, packages that live in EPEL on RHEL). Runs automatically before an
  apply, and standalone with `--preflight` — a "will this work here?" check
  that changes nothing.
- `--safe-only` — with `--auto-mode`, skip the two High-risk modules (9, 16).
- **Choose which backup to revert to.** `--revert` now offers an interactive
  picker of restore points (each labelled with its tier, version, and date);
  `--revert-to <date|timestamp|genesis|latest>` selects one non-interactively;
  and `--list-backups` prints them. The default is unchanged — restore to the
  true original (genesis) state. The menu's revert entries are consolidated
  under one **R) Revert options** submenu (full revert, SUID/SGID-only, or
  revert to a specific dated backup).

### Changed
- **The firewall module is platform-aware.** Module 3 selects the firewall the
  system actually ships — firewalld on RHEL/SUSE, ufw on Debian, nftables
  elsewhere — and writes nftables rules that persist across a reboot.

### Security
Because the tool runs as root, this release closes gaps in its own footprint:
- `PATH` is pinned to the system directories, so a binary planted earlier in
  `PATH` cannot be what root executes.
- The run log (which lists every file touched and the SUID inventory) is now
  created `0600`, and the backup directory `0700` — no longer world-readable.
- The remote-syslog destination and the update-check repository are validated
  before use, closing two injection paths.
- A warning is printed if the shared library was loaded from a directory
  writable by someone other than root or the invoking user.

### Testing
- A KVM lab provisions real Debian, Rocky, and Alpine guests, applies
  hardening, and **reboots each guest** to prove the machine survives — which
  is how the boot-chain bug above was found.

---

Compatibility unchanged: 22 hardening modules across 26 platforms (8 Linux
families, macOS, and the BSDs). No telemetry, no licence check, no account — the
only outbound request is the optional, explicitly-invoked `--check-update`. MIT
licensed.

[2.4.0]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.0
