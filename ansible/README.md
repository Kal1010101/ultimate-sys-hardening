# Ansible role: ultimate_hardening

Runs Ultimate Hardening on your hosts from Ansible. It installs the release
package (checked against the release's `SHA256SUMS`), then previews, applies or
just scores the hardening, and can save each host's compliance results as JSON.

The default is a dry run: nothing changes until you set `uh_mode: apply`.

## Use it

Copy `roles/ultimate_hardening` into your roles path (or point
`ANSIBLE_ROLES_PATH` at this folder), then:

```yaml
# playbook.yml
- hosts: servers
  become: true
  roles:
    - role: ultimate_hardening
      vars:
        uh_mode: apply
        uh_settings:
          UH_SKIP_SETTINGS: "AllowTcpForwarding"   # this fleet needs SSH tunnels
        uh_report_dir: ./compliance
```

```bash
ansible-playbook -i inventory playbook.yml --check   # dry run on every host
ansible-playbook -i inventory playbook.yml           # apply
```

`--check` always runs the tool's own dry run, so it shows the real changes a
run would make on each host.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `uh_mode` | `dry-run` | `dry-run`, `apply`, or `cis` (read-only compliance checks) |
| `uh_safe_only` | `true` | With `apply`, leave out the two High-risk modules (9, 16) |
| `uh_install_method` | `package` | `package`, `git` (checkout of the release tag in `uh_git_dest`), or `none` (use the tool already at `uh_command`) |
| `uh_version` | the release this role came with | Release to install |
| `uh_package_sha256` | `""` | With `package`: the SHA-256 of this host's package file, checked instead of the release's `SHA256SUMS` |
| `uh_git_commit` | `""` | With `git`: the full commit the release tag must point at |
| `uh_settings` | `{}` | Tool settings (`UH_*` keys only), passed as environment variables (see `examples/.env.example`) |
| `uh_report_dir` | `""` | Folder on the controller for one `<host>.json` compliance file per host (mode 0600) |
| `uh_reboot_when_required` | `false` | Reboot when a run upgraded the kernel (the tool never reboots by itself) |

The role sets `uh_cis` (the compliance results) and `uh_reboot_required` as
facts for later tasks.

## Pinning what gets installed

By default the package is checked against the `SHA256SUMS` file published with
the same release. That catches a corrupted download, but not a release whose
package and `SHA256SUMS` were both replaced. To be sure you install the exact
file you reviewed, pin its hash in your own playbook or group vars:

```yaml
uh_version: "2.6.1"
uh_package_sha256: "<sha256 of ultimate-hardening_2.6.1_all.deb>"   # per OS family
```

The hash is per package file, so a mixed fleet sets it per OS family (for
example in `group_vars/debian.yml` and `group_vars/rhel.yml`). With
`uh_install_method: git`, `uh_git_commit` does the same for the checkout:
the role stops if the release tag does not point at that commit.

Release packages are not GPG-signed, which is why the role installs them with
`--allow-untrusted` (Alpine), `--allow-unsigned-rpm` (SUSE) and
`disable_gpg_check` (RHEL); the hash check above is what vouches for them.

## Settings

`uh_settings` becomes the environment of the tool, which runs as root, so only
keys starting with `UH_` are accepted. A variable such as `BASH_ENV` or
`LD_PRELOAD` there would run code as root, and the role refuses it.

## What "changed" means

A run reports *changed* when any compliance check's result differs before and
after it. Every run rewrites the same files, so a second run on a hardened
host reports no change. Modules the checks do not cover (AIDE, rkhunter,
etckeeper) do not count toward it.

## Platforms

Release packages exist for the Debian, RHEL, SUSE, Alpine and Arch families.
Elsewhere, use `uh_install_method: git`.

## Tests

`tests/ansible/run.sh` runs the role in throwaway containers: every mode,
`--check`, `uh_settings`, the saved report and a repeat run on Debian, and the
package install on Debian and Rocky Linux. It needs Docker and network access.
CI runs it on every push and pull request, and weekly
(`.github/workflows/ansible.yml`).
