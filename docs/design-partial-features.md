# Design note: finishing the partly covered features

Status: approved 2026-11-18 (item 6 as new free module 23). Citations checked
against ComplianceAsCode's CIS Ubuntu 22.04, CIS RHEL 9 and RHEL 9 STIG control files. Nine items, built in this order, one at a time.
After each: `tests/run.sh --case <x>` (Docker, debian:12, plus fedora:40 where the
item is distro-sensitive), shellcheck as CI runs it, diff read, one-line report.

Ground rules: entries only where CIS or DISA STIG backs them (cited in a comment
next to each one); free gets the hardening, Pro/Enterprise get it through the
shared `lib/` symlink; no PAM edits; no offensive tools; kernel lockdown is out.

| # | Item | Lives in | Risk | Revert | Tests |
|---|------|----------|------|--------|-------|
| 1 | SSH crypto allowlist | free `lib/modules.sh` module 2 | Medium | in `sshd_config` + the existing `00-ultimate-hardening.conf` drop-in, both already reverted | extend `test_ssh.sh`; new `test_ssh_crypto.sh` |
| 2 | sysctl additions | free module 6 | Safe (IPv6 RA: guarded) | existing drop-in removal + `sysctl_before.txt` | extend `test_sysctl.sh` |
| 3 | auditd CIS 4.1.3.x rules | free module 7 | Safe (`-e 2` opt-in) | existing rules-file removal; `-e 2` needs a reboot, said so | extend `test_audit_rules_load.sh` |
| 4 | module blacklist additions | free module 19 | Safe (opt-ins off) | existing tool-created files | extend `test_kmod_blacklist.sh` |
| 5 | Fail2ban progressive bans | free module 4 | Safe | existing jail file removal | new `test_fail2ban_jails.sh` |
| 6 | /dev/shm, time sync, sudo | see decision below | Medium / Safe / Safe | fstab backup + remount; service state record; drop-in removal | new cases per piece |
| 7 | `--verify` health check | free `lib/` + entry points | read-only | n/a (changes nothing) | new `test_verify.sh` |
| 8–9 | paid-tier items | the private commercial repository | read-only / writes only an output dir | n/a | commercial CI |

## 1. SSH crypto allowlist

- Read `ssh -Q cipher|kex|mac|key` (the installed client and server come from
  the same OpenSSH build) and intersect with the allowlist, so an old OpenSSH is
  never handed a name it rejects. Allowlist, best first:
  - Ciphers: chacha20-poly1305, aes256-gcm, aes128-gcm (each @openssh.com),
    aes256-ctr, aes192-ctr, aes128-ctr
  - KexAlgorithms: mlkem768x25519-sha256, sntrup761x25519-sha512(@openssh.com),
    curve25519-sha256(@libssh.org), diffie-hellman-group16/18-sha512
  - MACs: hmac-sha2-512-etm, hmac-sha2-256-etm, umac-128-etm (@openssh.com)
  - HostKeyAlgorithms: ssh-ed25519(-cert), rsa-sha2-512/256(-cert), ecdsa-sha2-nistp256/384/521
- RHEL/Fedora run system-wide crypto policies (`/etc/crypto-policies`): there the
  allowlist is skipped with a message pointing at `update-crypto-policies`,
  because overriding the policy per daemon is what Red Hat tells admins not to do.
- Written to both the main file and the drop-in (first-value-wins, as now).
  `sshd -t` already gates the restart; a failure restores the backup.
- `UH_SKIP_SETTINGS=Ciphers` etc. leaves any of the four alone.
- Sources: Ciphers CIS Ubuntu 22.04 5.1.6 / RHEL 9 5.1.4, STIG RHEL-09-255064/65;
  KexAlgorithms CIS Ubuntu 5.1.12 / RHEL 9 5.1.5; MACs CIS Ubuntu 5.1.15 /
  RHEL 9 5.1.6, STIG RHEL-09-255070/75. HostKeyAlgorithms has no CIS/STIG
  control; it stays because the task names it, and is flagged as such.
- README count goes 13 → 17.

## 2. sysctl additions (27 → about 36)

Already present: kptr_restrict, dmesg_restrict, unprivileged_bpf_disabled,
perf_event_paranoid, yama.ptrace_scope, suid_dumpable, protected_hard/symlinks.
Proposed additions, each to be checked against CIS Ubuntu 24.04 / RHEL 9 and the
RHEL 9 / Ubuntu 22.04 STIGs before it lands (a subagent does the check):
`net.core.bpf_jit_harden=2`, `kernel.kexec_load_disabled=1`,
`net.ipv4.conf.{all,default}.secure_redirects=0`, `net.ipv4.conf.default.send_redirects=0`,
`net.ipv6.conf.default.accept_redirects=0`, `net.ipv6.conf.default.accept_source_route=0`,
`net.ipv6.conf.{all,default}.accept_ra=0`, `net.ipv6.conf.all.forwarding=0`.
Checked: fs.protected_fifos/regular and dev.tty.ldisc_autoload have no CIS/STIG
control and are dropped. The existing kptr_restrict=2 and perf_event_paranoid=3
are stricter than STIG's 1 and 2 and stay. Anything without a citation is dropped. `accept_ra=0` breaks hosts whose IPv6
address comes from router adverts (SLAAC, most cloud IPv6), so it is written only
when no interface holds a dynamic global IPv6 address, and the log says why.

## 3. auditd

Rules generated, not a fixed heredoc: for each `-S` syscall line, b64 always and
b32 only where the arch has a 32-bit ABI; each syscall name is kept only if
`ausyscall <arch> <name>` knows it (aarch64 has no `open`, `chmod`, `rename`…), so
`auditctl -R` never stops on an unknown name. Added CIS 4.1.3.x groups: user
emulation, sudo log file, time change, system locale/network config,
privileged commands (setuid/setgid binaries found with `find -xdev`),
unsuccessful access (EACCES/EPERM), DAC permission changes, session (utmp/wtmp/
btmp), logins (faillock dir), deletions, MAC policy, chcon/setfacl/chacl/usermod,
full kernel-module syscalls. `-e 2` only with `UH_AUDIT_IMMUTABLE=true`; revert
then says the old rules stay loaded until reboot. Log line counts the real rules.

## 4. Module blacklist

Default additions (STIG RHEL 9 backed): `atm`, `can` (protocols), `firewire-core`
(new file `disable-unused-hardware.conf`). Opt-ins: `UH_BLACKLIST_BLUETOOTH=true`
(STIG RHEL-09-291035). Thunderbolt has no CIS/STIG control: dropped. Loaded and
in-use modules are blacklisted for next boot and reported, as now. The snapd /
squashfs guard stays. usb-storage stays in module 15.

## 5. Fail2ban

In our own jail file only (the admin's jail.local and [DEFAULT] stay theirs):
`bantime.increment = true`, `bantime.maxtime = 1w` per jail when fail2ban ≥ 0.11;
a `recidive` jail reading wherever `fail2ban-client get logtarget` says it logs
(file or journal); `nginx-http-auth`, `apache-auth`, `postfix` jails only when the
service is installed and its log source exists. The config is checked with
`fail2ban-client -t`; if the extra jails fail it, the module falls back to the
SSH jail alone rather than leaving fail2ban dead.

## 6. /dev/shm, time sync, sudo — decision needed

- /dev/shm `nodev,nosuid,noexec` (CIS 1.1.2.2.x): fstab line, checked with
  `findmnt --verify`, then `mount -o remount`. Revert restores fstab and remounts.
  Medium: noexec breaks a few apps that exec from shm.
- Time sync (CIS 2.3.x): keep whichever of chrony/timesyncd is running; if none,
  enable timesyncd, else install chrony. Revert restores the recorded service state.
- sudo `Defaults use_pty, logfile=/var/log/sudo.log` (CIS 5.2.2/5.2.3) in
  `/etc/sudoers.d/50-ultimate-hardening`, mode 0440, only installed after
  `visudo -cf` passes and only when sudoers has an includedir. Revert removes it.
- Recommendation: all three in free as one new module 23 "Base system" (keeps
  each existing module's meaning; count 22 → 23 everywhere). Alternative: fold
  them into modules 5/7 to keep "22 modules".
- ClamAV / Lynis: Pro options only (optional install, weekly scan, Lynis score as
  a second opinion in the report). Proposed as a later item, not in this round
  unless asked.

## 7. `--verify`

Every apply run saves a pre-run snapshot (failed systemd units, sshd port) in the
state dir. `--verify` (alone, or after an apply in the same run) checks: sshd
active and listening on its configured port; no failed unit that was not failed
before; firewall loaded when module 3 has run (ufw active, firewalld running, or
`inet uh_filter` present). Prints each check; exits with a new
`UH_EXIT_VERIFY_FAILED` code and the reason. Read-only.

## Not verified here

Docker containers cannot run sshd restarts, auditd in the kernel, or real
remounts the way a VM does; each item's report says which parts were exercised
only in containers.

## Outcome (2026-11-18)

All nine items are built, except ClamAV/Lynis, which this note deferred.

- 1: 17 SSH settings where OpenSSH supports the full allowlist; left to
  crypto-policies on RHEL/Fedora.
- 2: 36 sysctl parameters. kexec_load_disabled and core_pattern were left out:
  both are STIG-backed, but neither reverts without a reboot.
- 3: rules generated per arch; `UH_AUDIT_IMMUTABLE` for `-e 2`.
- 4: atm, can, firewire-core by default; `UH_BLACKLIST_BLUETOOTH`.
- 5: bantime.increment (0.11+), recidive, service jails, `fail2ban-client -t`
  gate.
- 6: module 23 "Base system". The menu's apply-all entries moved to 24/25, and
  the paid tiers' own numbering moved up by one.
- 7: `--verify`, exit 20; baseline in `$UH_STATE_DIR/health-snapshot`.
- 8–9: paid-tier; their notes live in the commercial repository.
