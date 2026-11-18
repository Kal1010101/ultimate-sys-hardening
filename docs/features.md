# Free-tier features

## Modules

The menu lists these 23 modules in order. Each one can be selected separately.

1. **System updates** installs package updates through the system package manager.
2. **SSH hardening** applies and validates the SSH server settings before restarting the service.
3. **Firewall** configures nftables, UFW, or firewalld, depending on the distribution.
4. **Fail2Ban** configures an SSH jail to handle repeated failed login attempts.
5. **File permissions** checks permissions on system files and shared temporary directories.
6. **Kernel & network** applies kernel and network settings through sysctl.
7. **Audit daemon** installs audit rules for system changes.
8. **Password policy** applies account defaults in `login.defs`. PAM stays untouched.
9. **SUID/SGID hardening** records original permissions before removing elevated bits outside the allowlist.
10. **AIDE file integrity** creates a file-integrity baseline and schedules checks.
11. **Rootkit scanner** sets up rkhunter and a scheduled scan.
12. **Disable unused services** disables services on the module's list when they are present.
13. **AppArmor / SELinux** applies the enforcement settings for the host's security framework.
14. **/etc version control** sets up etckeeper to track changes in `/etc`.
15. **Boot security** hardens boot configuration and manages the optional USB storage blacklist.
16. **GRUB password** sets a bootloader password in interactive mode.
17. **Docker security** applies Docker daemon defaults when Docker is installed.
18. **ModSecurity WAF** configures the web application firewall when Apache is installed.
19. **Disable unused kernel modules** blacklists selected network protocols and uncommon filesystems.
20. **Compiler access restriction** restricts compiler access and records the original permissions.
21. **Remote syslog** configures log forwarding to a collector.
22. **UMASK hardening** sets the default umask to 027.
23. **Base system** mounts `/dev/shm` without devices, setuid or executables, turns on time sync, and sets sudo to use a pty and a log file.

## What full revert does

- Restores original configuration files captured before hardening. If no original backup exists, it falls back to the most recent per-run backup when available.
- Removes files the tool created and restores recorded permissions and symlinks where applicable.
- Restores the network tunables, firewall state, audit rules, and security profile state that it recorded.
- Restarts SSH and, when running, the audit service after restoring their configuration.
- Leaves services that the tool disabled for you to re-enable where needed.
- Reports missing backups before trying to restore files. Dry-run previews the selected restore without applying it.
