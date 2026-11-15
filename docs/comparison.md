# How Ultimate Hardening compares

Several good open-source tools harden or audit Linux. They do different jobs,
and some work well together. This page says what each one does, where
Ultimate Hardening fits, and when you should pick something else.

Facts about other projects were checked against their own repositories and
documentation on **2026-11-15** (sources at the end). If something here is
out of date, please [open an issue](https://github.com/Kal1010101/ultimate-sys-hardening/issues).

## At a glance

| | Ultimate Hardening | Lynis | OpenSCAP + ComplianceAsCode | ansible-lockdown (e.g. UBUNTU24-CIS) | dev-sec `os_hardening` |
|---|---|---|---|---|---|
| **What it is** | Bash tool: audits, fixes, undoes | Security audit tool | SCAP scanner + policy content | Ansible role per OS release | Ansible collection |
| **Changes the system** | Yes, 22 modules | No: reports findings and tips | Yes, with `--remediate` or generated Bash/Ansible fixes | Yes | Yes |
| **Preview before changing** | `--dry-run` prints every change | Not needed (read-only) | Generate the fix scripts and read them first | Ansible check mode: "not supported" per its README | Ansible check mode (support not stated) |
| **Undo** | `--revert`, or per module from the menu, from backups taken before the first write | Not needed | None documented | None documented | None documented |
| **Standard** | CIS-*aligned* checks (25 in the free tier); not certified | Own tests; helps with HIPAA, ISO 27001, PCI DSS | SCAP profiles: CIS, DISA STIG, ANSSI, PCI-DSS and more, where the distro's content ships them | The CIS Benchmark for that one OS release | DevSec Linux Baseline (not CIS) |
| **Checks its own work** | Built-in compliance score before and after | It *is* the check | Re-evaluates each rule after fixing it | Optional goss audit (separate repo, off by default) | Use the DevSec InSpec baseline |
| **Platforms** | 8 Linux families; macOS and the BSDs detected and adapted (thinner) | Linux, macOS, BSD, other UNIX | Wherever SCAP content exists (strongest on RHEL family) | One role per release (RHEL 9, Ubuntu 24, …) | EL, Ubuntu, Debian, Amazon, Fedora, Arch, openSUSE, SmartOS |
| **Needs** | Bash, root | Shell; no install needed | `oscap` and the content package | Ansible 2.16+ and a controller | Ansible and a controller |
| **Licence** | MIT | GPL-3.0 | LGPL-2.1 (scanner), BSD-3-Clause (content) | MIT | Apache-2.0 |

## What makes Ultimate Hardening different

**It is built for hosts you cannot rebuild.** ansible-lockdown's README says
its roles were developed against a clean install and should be reviewed before
use on an existing system. That is sound advice, and it is the gap this tool
fills: servers that have been running for years, with configuration nobody
fully remembers.

**Every change has a way back.** Before its first write, it copies each file it
touches. It also keeps the very first copy of every file, so a revert returns
the host to how it was before *any* hardening, not just before the last run.
SSH config is checked with `sshd -t` and rolled back if it fails. None of the
other tools above documents a rollback.

**You see the changes first.** `--dry-run --auto-mode` lists every change it
would make and writes nothing.

**One tool for a mixed fleet.** It detects the distro and adapts, so Debian,
Rocky, Alpine and Arch hosts run the same command. Each push runs its test
suite in fresh containers on 10 distro images, applying real hardening and
checking the result.

**No controller and no agent.** Plain Bash and root. There is an
[Ansible role](../ansible/) if you do use Ansible.

## When to pick something else

Be honest with yourself about what you need. Use:

- **OpenSCAP with ComplianceAsCode content, or CIS-CAT**, when an auditor wants
  evidence against an official profile: CIS, DISA STIG, PCI-DSS. Ultimate
  Hardening's checks are CIS-aligned, not a certified CIS implementation, and
  the free tier runs 25 of them, far fewer than a full benchmark. (The
  Enterprise tier wraps `oscap` for exactly this.)
- **ansible-lockdown**, when you build fresh images with Ansible on one OS
  release and want that release's CIS Benchmark control by control.
- **dev-sec**, when you already run Ansible and want broad, well-tested
  defaults, including hardening for SSH, nginx and MySQL.
- **Lynis**, when you want a broad read-only audit. It is also a good second
  opinion after Ultimate Hardening: run Lynis before and after to see what
  changed and what is left.

## Using them together

These tools are not mutually exclusive. A reasonable path for an existing
server:

1. `lynis audit system`: a baseline from an independent tool.
2. `ultimate-harden --auto-mode --safe-only --dry-run`: read what would change.
3. `ultimate-harden --auto-mode --safe-only`: apply it, with a backup.
4. `lynis audit system` again, and `ultimate-harden --cis-only` for the score.
5. Where an audit needs an official profile, scan with OpenSCAP.

If anything breaks, `ultimate-harden --revert` puts it back.

## Sources

Checked 2026-11-15.

- Lynis: [README](https://github.com/CISOfy/lynis) (GPL-3.0, release 3.1.7)
- OpenSCAP: [repository](https://github.com/OpenSCAP/openscap) (LGPL-2.1, release 1.4.6) and [user manual](https://static.open-scap.org/openscap-1.3/oscap_user_manual.html) (remediation, review mode)
- ComplianceAsCode: [repository](https://github.com/ComplianceAsCode/content) (BSD-3-Clause)
- ansible-lockdown: [UBUNTU24-CIS README](https://github.com/ansible-lockdown/UBUNTU24-CIS) (MIT, release 1.8.0) and [RHEL9-CIS](https://github.com/ansible-lockdown/RHEL9-CIS)
- dev-sec: [os_hardening README](https://github.com/dev-sec/ansible-collection-hardening/tree/master/roles/os_hardening) (Apache-2.0, release 11.0.0)
- CIS-CAT: [CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro) (CIS SecureSuite members) and [CIS-CAT Lite](https://learn.cisecurity.org/cis-cat-lite) (free, limited benchmarks)
