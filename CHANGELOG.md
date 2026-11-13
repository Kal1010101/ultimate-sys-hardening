# Changelog

All notable changes to Ultimate Hardening (free tier) are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com),
and the project follows [Semantic Versioning](https://semver.org).

## [Unreleased]

## [2.5.2] — 2026-11-12

### Fixed
- A revert left auditd running where it was installed but stopped before
  hardening (Arch), and still reported it as put back: auditd's systemd unit
  refuses `systemctl stop`. The revert now stops it the way auditd documents,
  and warns if a service it should have stopped is still running.
- A full revert left firewalld on the drop zone. It now puts back the default
  zone, the drop zone's SSH setting and whether firewalld was running, as
  reverting module 3 on its own already did.
- Reverting module 2 (SSH) on its own, or a full revert, left the
  `/etc/issue.net` banner behind on hosts that ship no such file (Alpine,
  Arch). It is now removed when it still holds only the module's banner; an
  admin's own banner is restored as before.
- A full revert restored nothing when the backup folder's path held `[`, `*`
  or `?` (for example `UH_BACKUP_ROOT=/mnt/backups[1]`), reporting every file
  as "could not restore".

## [2.5.1] — 2026-11-11

### Security
- The SUID/SGID revert (`--revert-suid`, and the SUID step of a full revert)
  could be made, on versions up to 2.5.0, to set the SUID bit on files the
  hardening never touched. On a host where untrusted users have local accounts,
  that is a path to root. Update to 2.5.1. The revert now puts back only a SUID
  bit module 9 removed, on a root-owned file whose path only root can change.
- Module 9 writes its SUID inventory in a new format, one entry per file. Files
  whose name contains a line break are not recorded or stripped, and are
  reported instead.
- An inventory written by 2.5.0 or earlier is never restored unattended
  (`--auto-mode`). Interactively, the files are listed and restored only after
  typing "yes". Re-running module 9 writes an inventory in the new format.

### Changed
- Module 9 no longer strips SUID from files on a path someone other than root
  could change: a symlink, a file not owned by root, or a directory owned by
  another account or writable by its group or everyone. It lists each one as
  "not stripped, path is not under root's sole control (review by hand)". The
  menu's module 9 state (`UH_SUID_SCAN=1`) ignores those files too.

## [2.5.0] — 2026-11-08

### Changed
- Module 3 (Firewall) opens only SSH inbound. It used to open ports 80 and 443
  too, on every host, desktops included. A host that serves the web now opens
  them itself (`ufw allow 80,443/tcp`, or `firewall-cmd --permanent
  --add-service=http --add-service=https && firewall-cmd --reload`). Re-running
  module 3 closes them on nftables hosts hardened earlier. On ufw (see Fixed
  below) and firewalld it does not; close them with `ufw delete allow 80/tcp &&
  ufw delete allow 443/tcp`, or `firewall-cmd --permanent
  --remove-service=http --remove-service=https && firewall-cmd --reload`.

### Fixed
- Module 3 on ufw no longer runs `ufw reset` first, which deleted every rule the
  host already had, including ones made in a distro's firewall GUI. It backs up
  ufw's rule and settings files and adds its policies and the SSH allow on top.
  Because nothing is reset, ufw hosts hardened earlier keep 80/443 open after a
  re-run; close them with `ufw delete allow 80/tcp && ufw delete allow 443/tcp`.
- Reverting module 3 on ufw restores those files and turns ufw back on or off
  as it was, instead of resetting and disabling it, which left distros that ship
  ufw enabled with no firewall. A full revert does the same. Hosts hardened by
  an earlier release have no such backup and still get the old reset, also
  after a 2.5.0 run: their rules (22, 80 and 443 open) are not saved as the
  state before hardening.
- Reverting module 3 on firewalld puts back the default zone the host had (for
  example FedoraWorkstation), the drop zone's SSH setting, and firewalld running
  or not, all recorded before the first run. It used to switch to the public
  zone and stop firewalld on every host. While sshd is running (or over SSH),
  it will not switch back to a zone that does not allow SSH; it says so and
  gives the command to run from a console. This is judged by sshd, not only by
  `$SSH_CONNECTION`, which `sudo` usually clears. Hosts hardened by an earlier
  release have no record and still get the old revert.
- Module 3 on nftables checks that the SSH accept rule loaded before saving
  anything. If it did not, the table is removed again and nothing is saved or
  enabled at boot, so a default-drop ruleset without SSH can never be loaded at
  the next boot.
- Module 3 on nftables no longer overwrites the host's own nftables config. Its
  table goes in `/etc/nftables-uh_filter.nft`, included by one line appended to
  the config, and nftables is enabled at boot without being started (starting
  it loads the config, which may flush every table, Docker's included). Where
  nftables was not enabled at boot before, the host's config was never loaded,
  so it is kept aside (restored on revert) and the boot file loads the module's
  table alone: loading Alpine's dormant default as well drops SSH. Its
  revert found nothing on hosts with the current table and reported "nothing
  reverted"; it now removes the table, the file and the include line, puts the
  config back as it was, and never stops nftables (stopping it flushes every
  table). On hosts hardened by an earlier release, revert restores the
  backed-up config instead of deleting it. A full revert also puts nftables'
  start-at-boot setting back; it used to leave it enabled, and on Alpine the
  restored default config then dropped SSH at the next boot. With
  `--skip-backup`, a config nftables does not load at boot is left alone (it
  could not be restored), and nftables is not enabled at boot; the rules last
  until reboot, and the run says so.
- Reverting module 3 deleted any nftables `ip filter` table, taking it for the
  one releases before 2.5.0 made. ufw and Docker make one through
  iptables-nft, so on a ufw host with `nft` installed the revert wiped ufw's
  and Docker's live IPv4 rules, deleted `/etc/nftables.conf` and stopped
  nftables. Only the table with this tool's combined 22/80/443 accept is
  removed now.
- Reverting module 3 on nftables keeps edits made to the host's nftables config
  after hardening. It takes out only the include line it added; it used to copy
  the backup over the config. Where the module had replaced a config nftables
  did not load at boot and the file was edited since, the edited file stays and
  the config from before hardening is saved next to it as
  `<config>.before-hardening`.
- Hosts hardened by a release from before the firewalld default-zone fix had
  ssh, http and https in the zone that was the default then, usually public.
  Module 3 recorded that zone as the state before hardening, so reverting it
  switched back to that zone and opened 80/443 again. Such a host is now
  recognised (an earlier run of this tool, and all three services in the
  default zone), nothing is recorded, and revert removes http and https from
  that zone. A web server's own public zone, on a host the tool never ran on
  before, is recorded and restored as before.
- Choosing module 3 in the menu ended the program when its revert found nothing
  of the module's to undo (for example, nftables running with only the host's
  own rules).
- Module 17 (Docker) merges its settings into an existing `daemon.json` instead
  of replacing it, so storage location, registry mirrors and the like are kept,
  and a log driver the admin chose is left alone. `userns-remap` is only turned
  on where Docker holds no containers, images or volumes yet: it made existing
  ones disappear from view. Docker is not restarted while that would stop
  running containers, when applying the module or when reverting it.
- Module 13 (AppArmor) switches only the profiles in complain mode to enforce,
  instead of running `aa-enforce` on everything in `/etc/apparmor.d`, and records
  each first. Reverting it, which had no automated way back, now puts exactly
  those profiles back in complain mode, and so does a full revert.
- Module 4 (Fail2Ban) writes its SSH jail to
  `/etc/fail2ban/jail.d/99-ultimate-hardening.local` instead of overwriting
  `jail.local`, which switched off every jail an admin had there. Its jail no
  longer sets `[DEFAULT]` values for other jails.
- Reverting modules 4, 7 and 13, and a full revert, stop and disable fail2ban,
  auditd and AppArmor again if they were not running or not started at boot
  before hardening.
- Reverting module 6 puts the live kernel settings back to their values before
  hardening. Removing the drop-in alone left them hardened until a reboot.
- Module 7 (auditd) loaded no rules on Alpine although it reported "configured
  with 17 audit rules": Alpine's `augenrules --load` calls `/sbin/auditctl`,
  which lives in `/usr/sbin` there. The merged rules are now loaded with
  `auditctl -R`, and success is reported only when `auditctl -l` lists them.
  Reverting the module restores the merged `/etc/audit/audit.rules` (or removes
  it where hardening created it) and reloads the kernel's rules from it: Alpine
  loads that file at every start and never rebuilds it, so the rules came back
  at boot after a revert.
- Checks that piped a command into `grep -q` could fail at random under
  `pipefail` (grep exits early, the command gets SIGPIPE): module 3 reported
  that nothing was applied when it had been. They now capture the output first,
  and a test keeps new ones out.

## [2.4.9] — 2026-11-06

### Fixed
- The `scp` command printed after an AIDE fingerprint is recorded did not work
  from another machine. It named the host by its hostname, which other machines
  may not resolve, and on systems with a 027 umask (module 1 sets one) the
  fingerprint folder was closed to the ordinary account scp logs in as. It now
  names the account that ran sudo and the machine's address (from `hostname -I`,
  or `ip` where hostname has no -I, as on Arch and Alpine), and the folder can
  be entered (not listed) by other accounts.

### Security
- The website sets a Content-Security-Policy: only its own script by hash, no
  third-party loads, no forms or base changes. A new test checks every page in
  `docs/` for this and for contact addresses other than the project's.
- The pre-push hook also refuses commits that carry payment account details.
- Release packages come with a `SHA256SUMS` file, and CI pins every GitHub
  Action to a commit and runs with a read-only token.
- gitleaks scans the full history on every push, and the pre-commit hook scans
  staged changes when gitleaks is installed.

### Documentation
- `docs/installation.md` clones the released tag instead of `main`, and the
  version test now covers it.
- CONTRIBUTING.md's conduct contact is the project address, not a placeholder.
- README and site list a yearly Enterprise price: $490/year for up to 10 hosts.

## [2.4.8] — 2026-11-03

### Added
- AIDE baseline fingerprint: each accepted baseline's SHA-256 is printed, saved
  in `/var/lib/ultimate-hardening/aide-fingerprint`, sent to syslog, and
  optionally copied to a drive folder that is remembered for later runs. A copy
  is always a new file and never written over an existing one, and unattended
  runs never copy to the machine's own disk.
- `--aide-verify <hash|file>` checks the live AIDE database against a
  fingerprint kept elsewhere (exit 0 match, 1 changed, 2 could not check).
- `--aide-fingerprint` records the fingerprint of a baseline accepted by hand.

### Fixed
- Backups on systems without `cmp` (minimal RHEL-family and Arch installs have no
  diffutils): every run copied every unchanged file again and printed
  `cmp: command not found`. Files are now compared by checksum there.

### Documentation
- README and site: the quick-start example uses `--safe-only`, because `--auto-mode`
  on its own also strips SUID bits without asking; the FAQ says which High-risk
  modules prompt and when.
- `--dry-run` is described as it behaves: with `--auto-mode` it prints the changes
  and exits, on its own it previews from the menu.
- README: "SSH can't lock you out" replaced with what the `sshd -t` check does and
  does not catch.
- Site: the PAM card said password policy goes to `pwquality.conf`; it is set in
  `/etc/login.defs` only and PAM is never modified.
- Site: the supported-distributions FAQ lists all eight Linux families and the
  Unix/BSD systems; the firewall line names firewalld.
- "Coming soon" kept only where a reader lands on it on its own; the README's
  standards table states it once above the table.

## [2.4.7] — 2026-11-02

### Added
- `--aide-refresh` replaces the AIDE baseline safely: it refuses while AIDE runs,
  tests the new database and its hash, asks for approval, and keeps a backup.
- `.deb`, `.rpm`, `.apk` and Arch packages, install-tested in CI and attached to
  each release.

### Fixed
- `--aide-refresh` reads the AIDE 0.16 config format used on RHEL 8 and openSUSE
  Leap 15, and a plain 0.16 database is no longer mistaken for a corrupt one.
- The library trust warning no longer fires on a symlinked `lib/` because of the
  link's own mode.
- AIDE on Arch: the module and preflight say the package is in the AUR, and an
  AIDE already installed from there is used instead of being skipped.
- Running the AIDE module again keeps a good baseline instead of accepting every
  change unread.
- AIDE setup no longer reports success after a failed or stopped init: an empty
  or corrupt database is not moved into place, and the menu no longer shows an
  empty database as active.

## [2.4.6] — 2026-10-30

### Fixed
- Restore and revert put back the SELinux label of every file they copy into
  place, so a confined sshd can read a restored `sshd_config` again.
- SSH hardening checks that a running sshd came back after the restart; if it
  did not, the previous config is restored and the module fails.
- The sshd drop-in also sets `X11Forwarding no` and `AllowTcpForwarding no`,
  so a vendor drop-in such as Fedora's `50-redhat.conf` no longer overrides them.
- Config edits change only the first commented default, so commented example
  blocks (sshd_config's `Match` stanza) stay commented.
- SSH hardening leaves settings inside active `Match` blocks alone, and adds a
  missing setting above the first `Match` line instead of inside the last block.
- Full revert removes the sshd drop-in.
- Full revert also removes the Fail2Ban `jail.local` and Docker `daemon.json`
  the tool wrote, and the uncommon-filesystem blacklist when one module is
  reverted.
- Reverting Fail2Ban or Docker hardening no longer deletes a `jail.local` or
  `daemon.json` that was there before the first run; it is restored, or left
  alone when it was never changed.
- A relative or root `UH_BACKUP_ROOT` falls back to `/root`, so pruning old
  backups stays out of the wrong directory.
- The first-run backup tree is created private (mode 700) at every level.
- Wildcards in `--revert-to` no longer widen the backup search.
- Remote syslog over TLS refuses a CA path containing quotes, backslashes or
  control characters, which would otherwise break the generated `rsyslog.conf`.
- Config edits refuse a key that is not a plain identifier.
- `--check-update` strips unsafe characters from the release tag it reads.

### Documentation
- README: an "About this project" section, the exact CI distro list, and a
  Changelog link.

## [2.4.5] — 2026-10-22

### Fixed
- SSH hardening: the login banner no longer writes through a symlinked
  `/etc/issue.net` into the distribution's own file (Fedora links it to
  `/usr/lib/issue.net`). The link is replaced by a regular file, the original
  `/etc/issue.net` is backed up, and revert restores it as a link or a file.
  On a Fedora host hardened by an earlier version,
  `dnf reinstall fedora-release-common` puts the vendor file back.

### Documentation
- The paid-tier lists on the site and in the README include the compromise
  indicator scan.
- The Pro tier covers up to 10 hosts (your own or your clients'), and Pro and
  Enterprise are marked as coming soon.

## [2.4.4] — 2026-10-17

### Fixed
- CIS checks: the uncommon protocol and filesystem checks no longer report
  blacklisted kernel modules as loadable on hosts with a large module
  configuration.
- Firewall (firewalld): applying module 3 no longer lifts the bans fail2ban
  has in place; its jails are restarted after the firewall reload so every
  active ban is applied again.
- Alpine: a kernel upgrade that removes the running kernel's modules is now
  detected (the old module directory can survive with a stray file in it),
  so unattended runs exit with status 10 and say a reboot is required.
- Alpine 3.22: Fail2Ban recognises failed SSH logins again; OpenSSH 10 logs
  them as `sshd-session`, which the filter did not match.

### Changed
- Alpine: when a kernel update is pending, applying all modules sets up the
  firewall and Fail2Ban before system updates, and runs Fail2Ban's ban action
  once against a documentation address, so the firewall and new bans keep
  working until the reboot.

### Documentation
- The website's version badge shows the current release.
- The paid-tier lists on the site and in the README name every paid feature.
- The README and SECURITY.md mention the optional update check.
- The README and the site list the distros CI actually tests.

## [2.4.3] — 2026-10-15

### Fixed
- Alpine: a kernel update pending before module 1 is reported up front, and
  an upgrade that removes the running kernel's modules is flagged. Interactive
  runs offer to reboot at the end; unattended runs never reboot, say a reboot
  is required, and exit with status 10.

### Documentation
- Install commands in the README, SECURITY.md and the site check out the
  latest release tag instead of `main`; the README says how to upgrade.
- The site's install commands now run from the repository root.
- SECURITY.md lists 2.4.x as the supported version.

## [2.4.2] — 2026-10-15

### Fixed
- Firewall (nftables): no longer reports success when the rules could not be
  loaded, and no longer saves an empty ruleset for the next boot.
- Fail2Ban on Alpine: the SSH jail now matches Alpine's `sshd.pam` log lines,
  so repeated failed logins are banned.
- Boot security (module 15) shows N/A, not "disable", on hosts without GRUB
  when `UH_USB_STORAGE_BLACKLIST=false` leaves it nothing to apply.
- Service hints in warnings name the right command on OpenRC and other
  non-systemd hosts.
- Dry run: a package lookup that times out is reported as "not checked"
  instead of stalling the run.

## [2.4.1] — 2026-10-14

### Added
- `examples/.env.example` lists every setting with its default; the
  README's Usage section points to it.

### Changed
- Pre-commit hook clean-up.
- README screenshots sized down and kept to a consistent width.

### Security
- Git hooks refuse real env files (`.env`, `.env.local`, `*.env`, `.envrc`)
  in commits and pushes, and refuse a `.env.example`-style template that
  has a value filled in for a password, token, secret or key.

### CI
- Workflows pin the Ubuntu runner to 24.04 and actions to a major tag,
  with the upgrade policy documented (trial 26.04 on a branch first).

## [2.4.0] — 2026-10-11

A reliability and safety release: a hardening run should never leave a machine
worse off than it found it — not half-configured, not unable to boot, and never
reporting success when it failed. Found and fixed against real Debian, Rocky,
and Alpine VMs.

### Added
- Per-module revert: selecting an already-applied module from the
  interactive menu now reverts it instead of re-applying. 18 of 22
  modules covered; the rest explain why they can't be automated instead
  of failing silently. Verified end-to-end on real guests across all
  three tiers.
- Backup retention: per-run backup directories now prune after
  `UH_BACKUP_RETENTION_DAYS` (default 90). Genesis backups are never
  pruned.
- `UH_USB_STORAGE_BLACKLIST=false` skips module 15's USB storage
  blacklist, for hosts that need USB disks. Default unchanged.
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
- The PAM guard test checked nothing on images without `find`, and now
  excuses a changed PAM file only when the package manager confirms it is
  byte-identical to its package (a vendor upgrade), never a tool edit.
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

### Documentation
- README, site and script header describe exactly what the free tier
  includes.
- Removed `docs/free-tier.md`, an unlinked page with outdated counts,
  support claims and statistics.
- Bug report template lists the distributions CI tests.
- README screenshots are rendered from the same generated output as the
  site's terminal windows (`docs/build-readme-shots.sh`).

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
- A KVM lab provisions real Debian, Rocky, and Alpine guests, applies
  hardening, and **reboots each guest** to prove the machine survives — which
  is how the boot-chain bug above was found.

---

Compatibility unchanged: 22 hardening modules across 26 platforms (8 Linux
families, macOS, and the BSDs). No telemetry, no licence check, no account — the
only outbound request is the optional, explicitly-invoked `--check-update`. MIT
licensed.

[Unreleased]: https://github.com/Kal1010101/ultimate-sys-hardening/compare/v2.5.2...HEAD
[2.5.2]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.5.2
[2.5.1]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.5.1
[2.5.0]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.5.0
[2.4.9]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.9
[2.4.8]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.8
[2.4.7]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.7
[2.4.6]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.6
[2.4.5]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.5
[2.4.4]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.4
[2.4.3]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.3
[2.4.2]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.2
[2.4.1]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.1
[2.4.0]: https://github.com/Kal1010101/ultimate-sys-hardening/releases/tag/v2.4.0
