The script performs all 28 hardening actions:

Updates system packages

Hardens SSH (disables root, password auth, sets MaxAuthTries)

Configures nftables firewall

Installs and configures Fail2Ban

Secures file permissions

Applies kernel sysctl hardening

Configures auditd monitoring

Sets password policies

Hardens SUID binaries with backup

Installs AIDE and rkhunter

Disables unnecessary services

Configures AppArmor/SELinux

Sets up etckeeper

Secures boot loader

Optional: GRUB password, Docker security, ModSecurity, MFA, USB blocking, compiler restriction, remote syslog

#########################################################################################

What the Full Revert Does:

Restores SSH configuration from backup and restarts SSH service

Restores kernel sysctl settings

Restores auditd rules

Restores PAM password policies

Restores SUID/SGID permissions

Disables nftables firewall (if it wasn't originally present)

Re-enables previously disabled services (avahi-daemon, cups, nfs-server, etc.)

Re-enables USB storage

Re-enables unused protocols


Restores compiler permissions for regular users

##########################################################################################

Safety Features:

Confirmation prompt before any revert (unless "--auto-mode" is used)

Requires "yes" typed explicitly for full revert confirmation

Checks for backup existence before attempting restore

Graceful error handling if backups are missing
