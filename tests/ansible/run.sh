#!/bin/bash
# =============================================================================
#  tests/ansible/run.sh — run the Ansible role in throwaway containers
#
#  Each container installs ansible-core from PyPI and runs the role against
#  itself (connection: local):
#
#    debian:12   every uh_mode, --check, uh_settings, the saved report, and a
#                second apply that must report no change. Uses this working
#                tree's script (uh_install_method: none).
#    debian:12, rockylinux:9
#                the package install: download, SHA256SUMS check, install,
#                for the published release named by UH_ANSIBLE_PKG_VERSION.
#
#  Needs docker and network access to PyPI and GitHub.
#  Usage: ./tests/ansible/run.sh        Exit code: number of failed parts.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_VERSION="${UH_ANSIBLE_PKG_VERSION:-2.7.0}"
# The commit tag v$PKG_VERSION points at on GitHub, for the uh_git_commit test.
# Looked up rather than written here: a release commit cannot contain its own
# hash. An annotated tag lists its commit as "<tag>^{}"; a lightweight one
# points at the commit directly.
GIT_REPO="https://github.com/Kal1010101/ultimate-sys-hardening.git"
tag_commit() {
    local refs
    refs=$(git ls-remote "$GIT_REPO" "refs/tags/v$1" "refs/tags/v$1^{}" 2>/dev/null) || return 1
    awk '$2 ~ /\^\{\}$/ { peeled = $1 } { any = $1 } END { print (peeled != "" ? peeled : any) }' <<<"$refs"
}
PKG_GIT_COMMIT="${UH_ANSIBLE_PKG_GIT_COMMIT:-$(tag_commit "$PKG_VERSION")}"
[[ "$PKG_GIT_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Could not find the commit for tag v$PKG_VERSION on GitHub (no network, or not released yet)." >&2
    echo "Set UH_ANSIBLE_PKG_GIT_COMMIT, or UH_ANSIBLE_PKG_VERSION to a released version." >&2
    exit 1
}
FAILED=0

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }

# $1 = image, $2 = setup commands, $3 = test commands (run with /repo mounted).
in_container() {
    docker run --rm -v "$REPO_ROOT:/repo:ro" "$1" /bin/bash -c "set -e
        $2
        python3 -m venv /opt/ansible >/dev/null
        /opt/ansible/bin/pip install -q ansible-core >/dev/null
        export PATH=/opt/ansible/bin:\$PATH ANSIBLE_ROLES_PATH=/repo/ansible/roles
        export ANSIBLE_NOCOLOR=1 ANSIBLE_STDOUT_CALLBACK=default
        printf '%s\n' '- hosts: localhost' '  connection: local' '  gather_facts: true' \
            '  roles: [ultimate_hardening]' > /tmp/play.yml
        $3"
}

part() {  # $1 = name, rest = command
    local name="$1"; shift
    printf '  %-34s ' "$name"
    local out
    if out=$("$@" 2>&1); then
        echo "PASS"
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
        echo "$out" | grep -vE '^debconf|^$' | tail -15 | cut -c1-400 | sed 's/^/      /'
    fi
}

DEBIAN_SETUP='apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        python3 python3-venv openssh-server procps ca-certificates >/dev/null'

modes_test() {
    in_container debian:12 "$DEBIAN_SETUP" '
        ok() { echo "OK: $*"; }
        bad() { echo "ASSERT: $*"; exit 1; }
        play() { ansible-playbook -i localhost, /tmp/play.yml \
            -e uh_install_method=none -e uh_command=/repo/src/free/ultimate_hardening.sh "$@"; }
        # The tool writes its log next to itself unless told otherwise.
        export LOG_FILE=/tmp/uh.log
        before=$(sha256sum /etc/ssh/sshd_config)

        out=$(play) || bad "dry-run play failed: $out"
        grep -q "changed=0" <<<"$out" || bad "dry run reported a change"
        grep -q "CIS score" <<<"$out" || bad "no score shown"
        [ "$(sha256sum /etc/ssh/sshd_config)" = "$before" ] || bad "dry run changed sshd_config"
        ok "dry run changes nothing and shows the score"

        out=$(play --check -e uh_mode=apply) || bad "check-mode play failed: $out"
        [ "$(sha256sum /etc/ssh/sshd_config)" = "$before" ] || bad "--check applied hardening"
        ok "--check runs a dry run even with uh_mode=apply"

        mkdir -p /tmp/reports
        out=$(play -e uh_mode=cis -e uh_report_dir=/tmp/reports) || bad "cis play failed: $out"
        python3 -c "import json; d=json.load(open(\"/tmp/reports/localhost.json\")); assert d[\"total\"] == len(d[\"checks\"])" \
            || bad "saved report is not the compliance JSON"
        [ "$(stat -c %a /tmp/reports/localhost.json)" = 600 ] \
            || bad "saved report is mode $(stat -c %a /tmp/reports/localhost.json), not 600"
        ok "uh_mode=cis saves the results as JSON on the controller, readable by its owner only"

        out=$(play -e uh_mode=apply -e "{\"uh_settings\": {\"UH_SKIP_SETTINGS\": \"X11Forwarding\"}}") \
            || bad "apply play failed: $out"
        grep -q "changed=1" <<<"$out" || bad "first apply did not report a change"
        grep -qE "^PermitEmptyPasswords[[:space:]]+no" /etc/ssh/sshd_config || bad "apply did not harden sshd_config"
        grep -qE "^X11Forwarding[[:space:]]+no" /etc/ssh/sshd_config && bad "uh_settings did not reach the tool"
        ok "apply hardens, reports changed, and passes uh_settings through"

        out=$(play -e uh_mode=apply -e "{\"uh_settings\": {\"UH_SKIP_SETTINGS\": \"X11Forwarding\"}}") \
            || bad "second apply failed: $out"
        grep -q "changed=0" <<<"$out" || bad "a second apply reported a change"
        ok "a second apply reports no change"

        out=$(play -e uh_mode=bogus 2>&1) && bad "a bad uh_mode was accepted"
        grep -q "uh_mode must be" <<<"$out" || bad "bad uh_mode not explained"
        ok "a bad uh_mode is refused with the reason"

        # uh_settings becomes the environment of a root process: BASH_ENV or
        # LD_PRELOAD there would run code as root, so only UH_* keys pass.
        out=$(play -e "{\"uh_settings\": {\"BASH_ENV\": \"/tmp/x.sh\"}}" 2>&1) && bad "uh_settings accepted BASH_ENV"
        grep -q "BASH_ENV" <<<"$out" || bad "the refused uh_settings key is not named"
        ok "uh_settings refuses keys that are not UH_ settings"

        out=$(play -e uh_package_sha256=nothex 2>&1) && bad "a malformed uh_package_sha256 was accepted"
        grep -q "uh_package_sha256" <<<"$out" || bad "malformed uh_package_sha256 not explained"
        out=$(play -e uh_git_commit=v2.6.0 2>&1) && bad "a tag was accepted as uh_git_commit"
        grep -q "uh_git_commit" <<<"$out" || bad "malformed uh_git_commit not explained"
        ok "malformed pins are refused with the reason"
    '
}

# A hash pinned in the playbook replaces the release's own SHA256SUMS, so a
# release whose package and SHA256SUMS were both replaced is still caught.
pinned_package_test() {
    in_container debian:12 "$DEBIAN_SETUP" "
        ok() { echo \"OK: \$*\"; }
        bad() { echo \"ASSERT: \$*\"; exit 1; }
        install() { ansible-playbook -i localhost, /dev/stdin -e uh_version=$PKG_VERSION \"\$@\" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: true
  tasks:
    - ansible.builtin.include_role:
        name: ultimate_hardening
        tasks_from: install_package
PLAY
        }
        zeros=\$(printf '0%.0s' \$(seq 64))
        out=\$(install -e uh_package_sha256=\$zeros 2>&1) && bad 'a wrong pinned hash was accepted'
        command -v ultimate-harden >/dev/null && bad 'the package was installed despite the wrong hash'
        ok 'a wrong uh_package_sha256 stops the install'

        sums=\$(python3 -c 'import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1]).read().decode())' \
            https://github.com/Kal1010101/ultimate-sys-hardening/releases/download/v$PKG_VERSION/SHA256SUMS)
        right=\$(awk '\$2 ~ /_all\\.deb\$/ { print \$1 }' <<<\"\$sums\")
        [ \${#right} -eq 64 ] || bad 'could not read the .deb hash from SHA256SUMS'
        rm -f /var/cache/ultimate-hardening/*
        out=\$(install -e uh_package_sha256=\$right 2>&1) || bad \"the right pinned hash was refused: \$out\"
        ultimate-harden --version | grep -q 'Ultimate Hardening $PKG_VERSION' || bad 'wrong version installed'
        ok 'the right uh_package_sha256 installs the package'
    "
}

# uh_git_commit checks the commit the release tag points at, since a tag can
# be moved and a commit cannot.
pinned_git_test() {
    in_container debian:12 "$DEBIAN_SETUP
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git >/dev/null" "
        ok() { echo \"OK: \$*\"; }
        bad() { echo \"ASSERT: \$*\"; exit 1; }
        install() { ansible-playbook -i localhost, /dev/stdin -e uh_version=$PKG_VERSION \"\$@\" <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: true
  tasks:
    - ansible.builtin.include_role:
        name: ultimate_hardening
        tasks_from: install_git
PLAY
        }
        zeros=\$(printf '0%.0s' \$(seq 40))
        out=\$(install -e uh_git_commit=\$zeros 2>&1) && bad 'a wrong pinned commit was accepted'
        grep -q 'uh_git_commit' <<<\"\$out\" || bad 'the commit mismatch is not explained'
        ok 'a wrong uh_git_commit stops the git install'

        out=\$(install -e uh_git_commit=$PKG_GIT_COMMIT 2>&1) || bad \"the right pinned commit was refused: \$out\"
        [ -x /opt/ultimate-hardening/src/free/ultimate_hardening.sh ] || bad 'no checkout after the right pin'
        ok 'the right uh_git_commit passes'
    "
}

package_test() {  # $1 = image, $2 = setup
    in_container "$1" "$2" "
        ansible-playbook -i localhost, /dev/stdin -e uh_version=$PKG_VERSION <<'PLAY'
- hosts: localhost
  connection: local
  gather_facts: true
  tasks:
    - ansible.builtin.include_role:
        name: ultimate_hardening
        tasks_from: install_package
PLAY
        ultimate-harden --version | grep -q 'Ultimate Hardening $PKG_VERSION' || { echo 'ASSERT: wrong version installed'; exit 1; }
        echo 'OK: package installed and runs'
    "
}

echo "Ansible role tests"
part "modes on debian:12"            modes_test
part "package install on debian:12"  package_test debian:12 "$DEBIAN_SETUP"
part "package install on rockylinux:9" package_test rockylinux:9 'dnf install -y -q python3 python3-pip >/dev/null'
part "pinned package hash on debian:12" pinned_package_test
part "pinned git commit on debian:12"  pinned_git_test
echo "  failed: $FAILED"
exit "$FAILED"
