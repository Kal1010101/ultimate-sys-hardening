# Changelog

All notable changes to Ultimate Hardening (free tier) are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com),
and the project follows [Semantic Versioning](https://semver.org).

## [Unreleased]

### Added
- **Per-module revert.** Selecting an already-applied module from the
  interactive menu now reverts just that module instead of re-applying
  it — the `[enable ]`/`[disable]` tags become a real toggle, matching
  what `lib/menu.sh`'s own header comment had promised all along ("revert
  it and the tag flips back") but never actually did. 18 of 22 modules get
  a real revert: ssh, fail2ban, kernel, audit, password, grubpw, docker,
  protocols, syslog, umask, perms, boot, apparmor's SELinux branch, and
  firewall (across all three backends — ufw, firewalld, nftables) are
  file/state-backed; suid, compiler, services, and aide use their own
  inventory- or generated-content-based revert; modsec is a real revert on
  Debian only (see below). The remaining modules (updates, rkhunter,
  etckeeper, and modsec on RHEL) have no tool-owned action to undo — each
  confirmed on a real guest rather than assumed — and explain why instead
  of guessing or silently doing nothing. Wired
  into all three tiers' menus (the numbered dispatch turned out to be
  duplicated per tier, not shared). Verified end-to-end on a real guest
  with an actual SSH password login: blocked while hardened, working
  immediately after reverting module 2 from the menu, blocked again
  immediately after re-applying it — through both the free and Enterprise
  entrypoints. Firewall's revert was verified on all three real backends
  without locking out the live SSH session on any of them (see Fixed,
  below, for the lockout this caught along the way).
  **Services (module 12) is a deliberate exception, not an oversight**:
  `SECURITY.md` explicitly documented re-enabling a disabled service as a
  permanently manual, conscious act. Asked before automating it, since
  that meant changing stated security policy rather than filling a gap —
  confirmed the user wanted to override it. `apply_disable_services()` now
  records exactly which services it actually stopped (most of its list is
  inactive by default and untouched on a normal host), and the revert
  re-enables exactly those, gated behind the same strongest confirmation
  tier as SUID/GRUB (typing "yes"). `SECURITY.md` was rewritten to
  describe this real behavior rather than the old, no-longer-true
  "deliberately manual" claim. Verified on a real guest: installed and
  started `avahi-daemon`, applied the module (confirmed genuinely
  `inactive` after), reverted from the menu (confirmed genuinely `active`
  and `enabled` again, not just a log message), then re-applied. Extended
  to a two-service case to confirm the scoping is exact — reverting
  brought back only the two services this run had actually disabled,
  leaving everything else on the list untouched.
  **AIDE (module 10)** follows the same "package stays installed, only
  generated content is removed" precedent: its own compliance check only
  looks at whether a baseline database exists, not the daily cron check,
  so revert removes `/var/lib/aide/aide.db[.gz]` and `/etc/cron.daily/
  aide-check` — exactly what the check reads — and leaves `aide` itself
  installed. Verified on a real guest: reverted an already-applied AIDE
  module, confirmed the database and cron script were genuinely gone from
  disk (not just the log saying so), then re-applied, which genuinely
  rebuilt the baseline from scratch and flipped the tag back correctly.
  **perms (module 5) and boot (module 15)** get a new mode-inventory
  revert (`perm_original_modes.txt` / `boot_original_perms.txt`, same
  shape as compiler's own inventory): each file's original mode is
  recorded only when it was actually looser than the hardened target, and
  restored on revert; boot's revert also removes the USB-storage modprobe
  blacklist it creates. Verified on a real guest with a full loosen →
  apply → revert round trip: exact original modes restored, `[enable ]`/
  `[disable]` tags flipping correctly at every step, `/etc/security/
  limits.conf`'s appended line cleanly removed via a new `remove_line()`
  helper (append_once's inverse, `lib/core.sh`).
  **modsec (module 18)** gets a real revert on Debian: `a2dismod
  security2` cleanly undoes the module's own `a2enmod` call, package
  stays installed. Verified on a real guest (apache2 installed
  specifically for this test, purged afterward): `security2_module`
  present after apply, gone after revert, tag flips accordingly. RHEL
  stays unautomated — confirmed via `rpm -ql mod_security` on a real
  guest that its `LoadModule` directive ships unconditionally inside the
  package's own config, never touched by this tool, so there is nothing
  of the tool's own to revert there.
  **rkhunter and etckeeper stay unautomated, now for a confirmed reason
  instead of a placeholder**: `dpkg -L` on a real guest showed both
  modules' on/off signals (`/etc/cron.daily/rkhunter`, `/etc/apt/apt.conf.
  d/05etckeeper`) ship as part of the package itself, not anything either
  apply function writes — rkhunter's tag can't flip without uninstalling
  the package, and etckeeper's apt hook would silently reinitialise
  `/etc/.git` on the next `apt` run even if it were deleted, while
  deleting it destroys real accumulated commit history for nothing.
- **Backup retention.** Per-run backup directories (`/root/hardening_
  backup_*`) had no retention at all, the same "grows unbounded" shape as
  the Enterprise state DB fixed earlier this session. `prune_old_backups()`
  now runs automatically on every hardening run, deleting directories
  older than `UH_BACKUP_RETENTION_DAYS` (default 90). The genesis
  directory — the one true pre-hardening original of every file — is never
  pruned. Verified: aged two real backup directories to 200 days old,
  confirmed a normal run removed exactly those two.

### Fixed
- **AIDE's daily integrity check has been silently broken on every
  RHEL-family host this tool has ever hardened.** `apply_aide()` only
  promoted the uncompressed `aide.db.new` to `aide.db` — the path
  Debian's `aideinit` wrapper produces. RHEL-family hosts have no
  `aideinit`, and `aide.conf`'s own default `database_out` there is
  compressed (`aide.db.new.gz`), so that promotion never matched: `aide.db.gz`
  never existed, meaning the daily cron check (which reads it) has been
  failing since the module first shipped, and the compliance tag could
  never show `[enable ]` either. Found by testing the module for real on a
  Rocky guest. Fixed to handle both variants; reverified with a real
  apply → revert round trip.
- **The new `boot` module revert (this release) was unreachable on any
  host with no GRUB at all.** `module_probe_state()`'s `boot` check was
  purely `grub.cfg mode == 600`, which can never be satisfied when
  `grub.cfg` doesn't exist (Alpine's extlinux bootloader) — so even after
  `apply_boot_secure()` genuinely created the USB-storage blacklist, the
  tag stayed `[disable]` forever and the revert this release added could
  never be selected from the menu. Fixed with a fallback to the blacklist
  file's own presence when no grub.cfg exists anywhere; reverified
  round-trip on a real Alpine guest.
- **Reverting the firewall module could lock out the live SSH session.**
  The first version of the new firewalld revert path called `--reload`
  right before stopping the service. `--permanent` firewalld edits don't
  take effect until reload — but a real host had `ssh`/`http`/`https`
  sitting in the wrong zone (see the separate bug below), so reloading
  that now-ssh-less zone into a still-actively-enforcing firewalld cut the
  live connection immediately. Recovered over the serial console. Fixed by
  never reloading a more-restrictive config into a still-running daemon —
  the edits are still written (correct if firewalld starts again later),
  but the service is stopped directly instead, which is safe regardless of
  what the pending edits would have done. Reverified on all three real
  firewall backends (ufw, firewalld, nftables) afterward without a single
  lockout.
- **`_fw_firewalld()` can silently configure the wrong zone.**
  `--set-default-zone=drop` can fail to take effect when called
  immediately after firewalld is installed and started in the same run (a
  timing race between the daemon starting and the next D-Bus call) —
  found while building the firewall revert above, not fixed here. The
  practical effect: `ssh`/`http`/`https` can end up allowed in the
  "public" zone instead of the intended "drop" zone, and the live security
  posture ends up weaker than the log's own "default zone drop" message
  claims.
- **Per-module revert could silently do nothing, or worse, delete a real
  system file it never touched.** Found testing the feature above against
  every covered module, not just the one already proven:
  - Any file a module fully regenerates rather than edits in place
    (kernel's sysctl file, audit rules, disabled-protocols config, Docker's
    `daemon.json`) could "revert" to an already-hardened snapshot instead
    of the true original, the same root cause as the SSH fix above but not
    limited to SSH: `backup_file()` can never see the file absent for these,
    because the module's own apply function only ever calls it once the
    file already exists. Fixed by extending the known-tool-created-path
    list (already used for the SSH drop-in) to cover all of them — always
    deleted on revert, no backup lookup involved at all.
  - Worse: reverting a module that had never actually been applied — the
    host was already compliant by default (Rocky ships SELinux enforcing
    out of the box, so the AppArmor/SELinux module's revert had nothing to
    revert) — deleted the real, in-use `/etc/selinux/config` outright,
    because "no backup found anywhere" was being treated as proof a file
    was tool-created. It isn't proof of that; it's equally consistent with
    "this module never ran here." Fixed: only an explicit tool-created-path
    match deletes on revert now. Anything else with no backup is left
    completely untouched, with an honest "nothing to revert" message.
  Verified on a real, freshly-created guest specifically because a
  long-lived one's own history makes this exact class of bug invisible:
  password and umask correctly restore login.defs to genuine distro
  defaults, kernel/audit/protocols correctly delete their files, and
  `/etc/selinux/config` is now confirmed byte-identical (via md5sum)
  before and after selecting a module that was never actually applied.
- **Repeated hardening runs against an already-hardened, unchanged host
  left a full duplicate of every untouched file in a new backup directory,
  every single time** — "too many copies of the same file with different
  dates." `backup_file()` now skips the copy when the file is
  byte-identical to whatever was captured most recently. Verified: running
  SSH hardening twice back-to-back with nothing changed in between no
  longer duplicates `sshd_config` the second time, while a file that
  genuinely had changed since the last capture still gets backed up
  correctly.
- **Several `enable_service` callers could log success for a service that
  never actually started.** `enable_service()` itself (`lib/platform.sh`)
  discards `systemctl start`'s exit code entirely and always logs
  "Service enabled" — `apply_fail2ban()` already guarded against this by
  checking `is_service_active` afterward, but four other callers didn't:
  `_fw_firewalld()`, `_fw_nftables()`, `apply_audit_config()` (module 7),
  and `apply_apparmor()`'s AppArmor branch (module 13; the SELinux branch
  doesn't call `enable_service` and was unaffected). All four now verify
  before claiming success and counting the fix. `_fw_nftables()` is worded
  carefully rather than copy-pasted: its rules are already live in the
  kernel by the time `enable_service` runs, so an inactive service there
  means "won't survive a reboot," not "not enforcing right now." Verified
  on real guests: `systemctl is-active firewalld auditd` on Rocky,
  `systemctl is-active apparmor` on Debian, `rc-service nftables status`
  on Alpine — all confirmed genuinely active, matching what the script
  logged.

### Testing
- **`tests/vm/uh-attacker-sim.sh` (the real attacker-simulation tool, not the
  product) had two bugs of its own, found by re-running it after an
  unrelated cleanup round and getting suspicious results on all three lab
  guests.** Phase 4a (the config audit over the lab's management SSH key)
  reported "could not reach the guest" on `uh-debian12`, `uh-rocky9`, *and*
  `uh-alpine` — including the two fully-hardened guests, which have nothing
  that would block a legitimate connection. Root cause: `SSHOPTS` checked
  that the management key existed but never actually passed `-i` to `ssh`,
  so phase 4a only ever worked by relying on the operator's own default key
  being authorized on the guest. Fixed by adding `-i "$KEY" -o
  IdentitiesOnly=yes` to `SSHOPTS`. Separately, on `uh-alpine`, phase 3's
  out-of-band console unban reported success but a real connection still
  failed — the console had landed on a **root** shell (not `uh`, as in
  earlier sessions), and Alpine's root has no sudoers entry, so the unban's
  hardcoded `sudo fail2ban-client ...` failed silently. Fixed to try the
  bare command first and fall back to `sudo`, working regardless of which
  user the console lands on. Neither bug was in any hardening module — both
  were in the test tool's own SSH plumbing. Re-verified against all three
  real lab guests after both fixes.
- **`uh-attacker-sim.sh` phase 4b couldn't tell "a control engaged" apart
  from "the guest was unreachable"** — a refused connection looked
  identical either way, and it had already produced a false "control
  engaging" reading once this session before phase 4a's own fix above.
  Added one independent, timeout-bounded baseline connection right before
  the real probe; a failure there now reports "target unreachable —
  skipping 4b" instead of a possibly-false finding. Verified both branches
  on real guests, including an unplanned live demonstration: a guest went
  genuinely unreachable mid-verification (traced to `ufw limit ssh`
  legitimately rate-limiting this session's own cumulative test traffic,
  not a bug), and the new check correctly reported it rather than
  inventing a result.
- **`uh-alpine` now has SSH hardening (module 2) applied**, matching
  Firewall and Fail2Ban (modules 3/4), which were already on from earlier
  work despite being listed as part of an "unhardened baseline." Verified
  with a real attacker-sim run: BLOCKED/BLOCKED/WARN, the same pattern
  Debian and Rocky already show.
- Regenerated the three stale screenshots in `docs/images/` (they showed
  `v2.3.0` and a pre-consolidation revert menu) from the exact same real,
  drift-checked content `docs/build-terminals.sh --check` already
  verifies for `docs/index.html`, rather than hand-transcribing or
  screenshotting a live run.

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
