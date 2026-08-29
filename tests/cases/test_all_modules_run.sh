#!/bin/bash
# The full run must reach every one of the 22 modules.
# This is the regression test for the set -e early-exit class of bug.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

out=$(run_hardening --auto-mode --dry-run)

for n in $(seq 1 22); do
    assert_output_contains "$out" "\[$n/22\]" "module $n/22 executed"
done

# Modules 16-22 were dropped by the lib/ refactor and restored in v2.3.0.
# The loop above only proves the header line printed; assert on each one's
# dry-run text too, so a module reduced to a bare log_message stub would
# still fail here rather than silently pass.
assert_output_contains "$out" "GRUB"        "module 16 previews GRUB password work"
assert_output_contains "$out" "[Dd]ocker"   "module 17 previews Docker work"
assert_output_contains "$out" "ModSecurity" "module 18 previews ModSecurity work"
assert_output_contains "$out" "DCCP"        "module 19 previews protocol blacklisting"
assert_output_contains "$out" "compiler|gcc" "module 20 previews compiler restriction"
assert_output_contains "$out" "syslog"      "module 21 previews remote syslog"
assert_output_contains "$out" "umask"       "module 22 previews umask hardening"

finish
