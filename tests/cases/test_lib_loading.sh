#!/bin/bash
# The tier scripts must locate and source lib/ correctly, and every module
# function the menu references must actually be defined.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"

out=$(bash "$FREE_SCRIPT" --version 2>&1)
assert_output_contains "$out" "Ultimate Hardening" "--version works (lib loaded)"

out=$(bash "$FREE_SCRIPT" --help 2>&1)
assert_output_contains "$out" "auto-mode" "--help works"

# Pro and Enterprise source the same lib/ from one directory deeper (src/pro,
# src/enterprise) — their own LIB_DIR discovery must resolve it too, and a
# real --auto-fix --dry-run must walk all 22 modules rather than dying partway
# through (the class of bug this test exists to catch).
#
# They live in a separate private repository, so a clone of the public
# free-tier repo will not have them. Absent is not a failure here; the private
# repo runs this same case with them present. What WOULD be a failure is these
# checks silently passing because the loop body never ran, so each tier is
# reported either way.
for tier_script in "$PRO_SCRIPT" "$ENTERPRISE_SCRIPT"; do
    if [[ ! -f "$tier_script" ]]; then
        echo "  ⏭️  SKIP: $(basename "$tier_script") not in this checkout (free-tier repo)"
        continue
    fi
    tier_out=$(bash "$tier_script" --version 2>&1)
    assert_output_contains "$tier_out" "Ultimate Hardening" "$(basename "$tier_script") --version works (lib loaded)"

    tier_out=$(bash "$tier_script" --help 2>&1)
    assert_output_contains "$tier_out" "auto-mode" "$(basename "$tier_script") --help works"

    if [[ $EUID -eq 0 ]]; then
        tier_out=$(bash "$tier_script" --auto-mode --auto-fix --dry-run 2>&1)
        assert_output_contains "$tier_out" "\[22/22\]" "$(basename "$tier_script") --auto-fix --dry-run reaches the final module"
    else
        # Not using skip() here: it exits the whole script, and the checks
        # below (function definitions, unknown-flag handling) don't need root.
        echo "  ⏭️  SKIP: $(basename "$tier_script") --auto-fix --dry-run (requires root)"
    fi
done

# Every apply_ function referenced must exist after sourcing the libs
missing=0
for fn in apply_system_updates apply_ssh_hardening apply_firewall apply_fail2ban \
          apply_permission_hardening apply_kernel_hardening apply_audit_config \
          apply_password_policies apply_suid_hardening apply_aide apply_rkhunter \
          apply_disable_services apply_apparmor apply_etckeeper apply_boot_secure \
          apply_grub_password apply_docker_security apply_modsecurity \
          apply_unused_protocols apply_compiler_restriction apply_remote_syslog \
          apply_umask_hardening \
          apply_all_modules apply_safe_modules run_cis_checks full_system_revert undo_suid_hardening; do
    if ! bash -c "source ${REPO_ROOT:-/repo}/lib/core.sh
                  source ${REPO_ROOT:-/repo}/lib/platform.sh
                  source ${REPO_ROOT:-/repo}/lib/modules.sh
                  source ${REPO_ROOT:-/repo}/lib/cis.sh
                  declare -F $fn >/dev/null" 2>/dev/null; then
        fail "function not defined: $fn"
        missing=$((missing+1))
    fi
done
[[ $missing -eq 0 ]] && pass_msg "all 19 library functions defined"

# Unknown flags must be rejected, not silently ignored
bash "$FREE_SCRIPT" --nonsense-flag >/dev/null 2>&1
assert_exit_code 1 $? "unknown flag exits 1"
finish
