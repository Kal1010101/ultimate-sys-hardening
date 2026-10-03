#!/bin/bash
# Preflight must resolve the dependency list without being truncated by set -e,
# and must agree with the module that will actually do the installing.
#
# Dependency resolution used to live inside each module, at apply time, which
# is how a Rocky 9 guest ended up hardened through SSH and untouched from the
# firewall onward. This pass runs before anything is mutated.
#
# Needs no root: this is list resolution and package queries, not installation.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

export LOG_FILE="${TMPDIR:-/tmp}/uh_preflight_$$.log"

_lib='source "'"$REPO"'/lib/core.sh"
      source "'"$REPO"'/lib/platform.sh"
      source "'"$REPO"'/lib/modules.sh"'

# --- the list is well formed -------------------------------------------------
out=$(bash -c "set -euo pipefail; $_lib; DISTRO_TYPE=debian module_dependencies" 2>&1) || true
assert_output_contains "$out" '^fail2ban:fail2ban$'   "debian: fail2ban resolves to its package"
assert_output_contains "$out" '^audit:auditd$'        "debian: audit resolves to auditd, not audit"
assert_output_contains "$out" '^apparmor:apparmor-utils$' "debian: apparmor-utils is listed"

bad=$(printf '%s\n' "$out" | grep -vE '^[a-z0-9]+:[A-Za-z0-9._+-]+$' || true)
if [[ -z "$bad" ]]; then
    pass_msg "every line is a well-formed key:package pair"
else
    fail "malformed dependency line(s): $(printf '%s' "$bad" | tr '\n' ' ')"
fi

# --- and is complete on a non-debian platform --------------------------------
# The apparmor entry is conditional, so everything listed after it depends on
# the list surviving a false condition. It does today — a failing `[[ ]]` mid
# function is exempt from errexit, checked directly rather than assumed — but
# the same line placed last in the function makes it return 1 and, under the
# set -e every tier sets, kills the caller. That is the `[[ cond ]] && var=x`
# entry in the project's bug table. This asserts the tail of the list is
# actually produced, whatever form the conditional takes.
rhel=$(bash -c "set -euo pipefail; $_lib; DISTRO_TYPE=rhel module_dependencies" 2>&1) || true
assert_output_contains "$rhel" '^audit:audit$'        "rhel: audit resolves to audit, not auditd"
assert_output_contains "$rhel" '^etckeeper:etckeeper$' \
    "rhel: the list continues past the debian-only apparmor entry"
if ! grep -q 'apparmor' <<< "$rhel"; then
    pass_msg "rhel: apparmor-utils is correctly absent"
else
    fail "rhel: apparmor-utils listed on a platform that does not ship it"
fi

# --- preflight and the firewall module must name the same package ------------
for d in debian rhel suse alpine arch; do
    want=$(bash -c "$_lib; firewall_package_for $d" 2>/dev/null)
    got=$(bash -c "set -euo pipefail; $_lib; DISTRO_TYPE=$d module_dependencies" 2>&1 \
          | sed -n 's/^firewall://p')
    # The firewall entry only appears when no firewall is installed on THIS
    # host, so an empty result is a legitimate skip, not a mismatch.
    if [[ -z "$got" ]]; then
        echo "  ⏭️  SKIP: $d firewall entry — this host already has a firewall installed"
        continue
    fi
    if [[ "$got" == "$want" ]]; then
        pass_msg "$d: preflight and apply_firewall agree on '$want'"
    else
        fail "$d: preflight would install '$got' but apply_firewall installs '$want'"
    fi
done

# --- an unknown package manager must report "cannot tell", not "missing" -----
rc=$(bash -c "$_lib; get_package_manager() { echo nosuchpm; }; package_available foo; echo \$?" 2>/dev/null)
assert_exit_code 2 "$rc" "package_available reports 2 (unknown) on an unrecognised package manager"

# --- dry run must not install, and must not touch the network ----------------
# refresh_package_index reaches distro mirrors. A dry run is a promise that
# nothing happens, and "nothing" includes outbound traffic.
dry=$(bash -c "set -euo pipefail; $_lib
    DISTRO_TYPE=debian; DRY_RUN=true
    package_installed() { return 1; }
    package_available() { return 0; }
    install_package()   { echo 'INSTALL-CALLED'; return 0; }
    preflight_dependencies" 2>&1) || true
assert_output_contains "$dry" 'Would install' "dry run says what it would install"
if ! grep -q 'INSTALL-CALLED' <<< "$dry"; then
    pass_msg "dry run installs nothing"
else
    fail "dry run called install_package"
fi
if ! grep -q 'package index refreshed' <<< "$dry"; then
    pass_msg "dry run does not refresh the package index"
else
    fail "dry run hit the network to refresh the package index"
fi

# A refresh that fails must degrade to a warning, not take the run with it.
norefresh=$(bash -c "set -euo pipefail; $_lib
    DISTRO_TYPE=debian; DRY_RUN=false
    refresh_package_index() { return 1; }
    package_installed() { return 0; }
    preflight_dependencies
    echo 'REACHED-END'" 2>&1) || true
assert_output_contains "$norefresh" 'could not refresh the package index' \
    "a failed index refresh is reported"
assert_output_contains "$norefresh" 'REACHED-END' \
    "a failed index refresh does not abort the caller"

# --- an unavailable package is reported, and does not abort the run ----------
miss=$(bash -c "set -euo pipefail; $_lib
    DISTRO_TYPE=debian; DRY_RUN=false
    package_installed() { return 1; }
    package_available() { return 1; }
    install_package()   { echo 'INSTALL-CALLED'; return 0; }
    preflight_dependencies
    echo 'REACHED-END'" 2>&1) || true
assert_output_contains "$miss" 'not available from the configured repositories' \
    "unavailable packages are named"
assert_output_contains "$miss" 'REACHED-END' \
    "an unavailable package does not abort the caller"
if ! grep -q 'INSTALL-CALLED' <<< "$miss"; then
    pass_msg "nothing unavailable is handed to install_package"
else
    fail "tried to install a package it had just reported as unavailable"
fi

rm -f "$LOG_FILE"
finish
