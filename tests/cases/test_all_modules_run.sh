#!/bin/bash
# The full run must reach every one of the 23 modules.
# This is the regression test for the set -e early-exit class of bug.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
require_root

out=$(run_hardening --auto-mode --dry-run)

for n in $(seq 1 23); do
    assert_output_contains "$out" "\[$n/23\]" "module $n/23 executed"
done

# Modules 16-22 were dropped by the lib/ refactor and restored in v2.3.0.
# The loop above only proves the header line printed; assert on each one's
# dry-run text too, so a module reduced to a bare log_message stub would
# still fail here rather than silently pass.
assert_output_contains "$out" "GRUB"        "module 16 previews GRUB password work"
assert_output_contains "$out" "[Dd]ocker"   "module 17 previews Docker work"
assert_output_contains "$out" "ModSecurity" "module 18 previews ModSecurity work"
assert_output_contains "$out" "dccp"        "module 19 previews protocol blacklisting"
assert_output_contains "$out" "cramfs"      "module 19 previews filesystem blacklisting (CIS 1.1.1.x)"
assert_output_contains "$out" "compiler|gcc" "module 20 previews compiler restriction"
assert_output_contains "$out" "syslog"      "module 21 previews remote syslog"
assert_output_contains "$out" "umask"       "module 22 previews umask hardening"
assert_output_contains "$out" "/dev/shm|Base System" "module 23 previews the base system work"

finish
