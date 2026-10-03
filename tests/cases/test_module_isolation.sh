#!/bin/bash
# One module failing must not silently truncate the run.
#
# This exists because it did. apply_firewall returned 1 on Rocky 9 (no ufw in
# its repos, and the module hardcoded ufw), the tier scripts run under
# `set -euo pipefail`, and the aggregate called each module bare on its own
# line — so the run died at [3/22] and modules 4-22 never executed. The host
# was left hardened through SSH and untouched from the firewall onward, and
# nothing in the output said so. Six of the seven test failures that run
# reported were collateral from modules that never ran.
#
# Needs no root: this is the wrapper's logic, not a hardening run.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

export LOG_FILE="${TMPDIR:-/tmp}/uh_module_isolation_$$.log"

out=$(bash -c '
    set -euo pipefail
    source "'"$REPO"'/lib/core.sh"
    source "'"$REPO"'/lib/platform.sh"
    source "'"$REPO"'/lib/modules.sh"
    source "'"$REPO"'/lib/cis.sh"
    source "'"$REPO"'/lib/menu.sh"

    broken_module() { return 1; }
    later_module()  { echo "LATER-MODULE-RAN"; return 0; }

    UH_MODULE_FAILED=()
    FIXES_APPLIED=0

    run_module firewall broken_module
    echo "WRAPPER-RETURNED=$?"
    run_module umask later_module
    echo "RECORDED=${UH_MODULE_FAILED[*]}"
    report_module_results "test scope"
    echo "REACHED-END"
' 2>&1) || true

assert_output_contains "$out" 'WRAPPER-RETURNED=0' \
    "run_module returns 0 when the module it wrapped failed"
assert_output_contains "$out" 'LATER-MODULE-RAN' \
    "a module after the failing one still runs"
assert_output_contains "$out" 'REACHED-END' \
    "the sequence reaches its end instead of dying at the failure"
assert_output_contains "$out" 'RECORDED=Firewall' \
    "the failure is recorded under the module's menu label, not its function name"
assert_output_contains "$out" '1 module\(s\) did not complete' \
    "the run summary states how many modules did not complete"
assert_output_contains "$out" 'did not complete: Firewall' \
    "the run summary names which module failed"

# Without lib/menu.sh sourced there is no MOD_LABEL to look the name up in.
# The wrapper must still name the module rather than failing on an unbound
# array under `set -u` — test_lib_loading sources less than a tier does.
nomenu=$(bash -c '
    set -euo pipefail
    source "'"$REPO"'/lib/core.sh"
    source "'"$REPO"'/lib/platform.sh"
    source "'"$REPO"'/lib/modules.sh"

    broken_module() { return 1; }
    UH_MODULE_FAILED=()
    FIXES_APPLIED=0
    run_module firewall broken_module
    report_module_results "test scope"
' 2>&1) || true

assert_output_contains "$nomenu" 'did not complete: firewall' \
    "falls back to the module key when lib/menu.sh is not sourced"

# The wrapper is only worth anything if the aggregates actually go through it.
# Reverting them to bare calls must fail this case, not pass it quietly.
for fn in apply_all_modules apply_safe_modules; do
    body=$(sed -n "/^${fn}() {/,/^}/p" "$REPO/lib/modules.sh")
    bare=$(printf '%s\n' "$body" | grep -cE '^[[:space:]]+apply_[a-z_]+$' || true)
    if [[ "$bare" -eq 0 ]]; then
        pass_msg "$fn calls every module through run_module"
    else
        fail "$fn still calls $bare module(s) directly — a failure there truncates the run"
    fi
done

# Same for the per-module menu entries. A module failing from the menu used to
# drop the operator out of an interactive session with no message at all, since
# the tier scripts run under `set -euo pipefail` and the case arm called the
# module bare. Pro and Enterprise live in a separate private repo, so a missing
# tier is skipped visibly rather than passing silently.
for tier in "src/free/ultimate_hardening.sh" \
            "src/pro/ultimate-hardening-pro.sh" \
            "src/enterprise/ultimate-hardening-enterprise.sh"; do
    if [[ ! -f "$REPO/$tier" ]]; then
        echo "  ⏭️  SKIP: $(basename "$tier") not in this checkout (free-tier repo)"
        continue
    fi
    bare=$(grep -cE '^[[:space:]]*[0-9]+\)[[:space:]]+apply_' "$REPO/$tier" || true)
    if [[ "$bare" -eq 0 ]]; then
        pass_msg "$(basename "$tier") dispatches every module through run_module"
    else
        fail "$(basename "$tier") has $bare menu entry(s) calling a module directly — one failure exits the session"
    fi
done

rm -f "$LOG_FILE"
finish
