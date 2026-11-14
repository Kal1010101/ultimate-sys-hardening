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
PKG_VERSION="${UH_ANSIBLE_PKG_VERSION:-2.5.3}"
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
        ok "uh_mode=cis saves the results as JSON on the controller"

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
    '
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
echo "  failed: $FAILED"
exit "$FAILED"
