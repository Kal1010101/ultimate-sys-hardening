#!/bin/bash
# Proves the test suite catches the exact bugs hit during development.
# Each mutation reintroduces a real historical bug; the named test must FAIL.
#
# REPO_ROOT defaults to this script's own repo (tests/../) rather than a
# hardcoded build path, so it runs against whatever checkout it lives in —
# override by exporting REPO_ROOT before calling if you need a different one
# (e.g. a throwaway clone, since mutations are applied to real files on disk).
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT" || exit 1

export UH_TEST=1
export REPO_ROOT

pass=0
fail=0

mutate_and_check() {
    local label="$1" file="$2" test_name="$3" pyscript="$4"

    cp "$file" /tmp/mutate.bak
    python3 -c "$pyscript" || { echo "  mutation failed to apply"; cp /tmp/mutate.bak "$file"; return; }

    bash "tests/cases/test_${test_name}.sh" > /tmp/mut_out.txt 2>&1
    local rc=$?

    cp /tmp/mutate.bak "$file"

    printf '  %-42s ' "$label"
    if [ "$rc" -eq 0 ]; then
        echo "NOT CAUGHT  <-- test gap"
        fail=$((fail + 1))
    else
        echo "caught by test_${test_name}"
        pass=$((pass + 1))
    fi
}

echo "=============================================================="
echo "  Regression proof: do the tests catch historical bugs?"
echo "=============================================================="
echo ""

# Bug 1: `return 0` placed before the CIS summary made it unreachable.
mutate_and_check \
  "unreachable CIS summary (return 0 early)" \
  lib/cis.sh cis_score \
'
import os
p=os.environ["REPO_ROOT"]+"/lib/cis.sh"
s=open(p).read()
old="    local total=$((CHECKS_PASSED + CHECKS_FAILED))\n    CIS_SCORE="
new="    return 0\n    local total=$((CHECKS_PASSED + CHECKS_FAILED))\n    CIS_SCORE="
assert old in s
open(p,"w").write(s.replace(old,new,1))
'

# Bug 2: bare ((var++)) exits non-zero from 0 and kills the run under set -e.
mutate_and_check \
  "bare ((var++)) kills run under set -e" \
  lib/core.sh all_modules_run \
'
import os
p=os.environ["REPO_ROOT"]+"/lib/core.sh"
s=open(p).read()
old="bump()  { local __n=\"$1\"; eval \"$__n=\\$(( \\${$__n:-0} + 1 ))\"; return 0; }"
new="bump()  { local __n=\"$1\"; eval \"(( $__n++ ))\"; }"
assert old in s
open(p,"w").write(s.replace(old,new,1))
'

# Bug 3: score suppressed by a conditional guard, so the summary never prints.
# (The original mutation here clamped the score at >=200, which never fires and
#  therefore changed nothing — an invalid mutation, not a test gap. It was
#  replaced with a >=50 guard, which has the *same* problem: on any reasonably
#  hardened test system CIS_SCORE legitimately exceeds 50, so the guard still
#  never suppresses anything and "NOT CAUGHT" reports a phantom gap. CIS_SCORE
#  is a 0-100 percentage by construction (lib/cis.sh's `total > 0 ? ... : 0`),
#  so >=101 can never be true on any system — this guarantees the echo is
#  always suppressed, making the mutation valid and deterministic everywhere.)
mutate_and_check \
  "score line suppressed by conditional guard" \
  lib/cis.sh cis_score \
'
import os
p=os.environ["REPO_ROOT"]+"/lib/cis.sh"
s=open(p).read()
old="    echo -e \"${WHITE}  CIS Score: ${CIS_SCORE}%  (${CHECKS_PASSED}/${total} checks passed)${NC}\""
new="    [[ $CIS_SCORE -ge 101 ]] \u0026\u0026 echo -e \"${WHITE}  CIS Score: ${CIS_SCORE}%  (${CHECKS_PASSED}/${total} checks passed)${NC}\""
assert old in s
open(p,"w").write(s.replace(old,new,1))
'

# Bug 4: dry-run that actually writes.
mutate_and_check \
  "dry-run writes to disk anyway" \
  lib/modules.sh dryrun \
'
import os
p=os.environ["REPO_ROOT"]+"/lib/modules.sh"
s=open(p).read()
old="    if [[ \"$DRY_RUN\" == true ]]; then\n        log_dry \"Would write 27 sysctl parameters to /etc/sysctl.d/99-hardening.conf\"\n        return 0\n    fi"
new="    if [[ \"$DRY_RUN\" == true ]]; then\n        log_dry \"Would write 27 sysctl parameters\"\n    fi"
assert old in s
open(p,"w").write(s.replace(old,new,1))
'

# Bug 5: PAM modification returning (the eCryptfs lockout).
mutate_and_check \
  "PAM modification reintroduced" \
  lib/modules.sh pam_untouched \
'
import os
p=os.environ["REPO_ROOT"]+"/lib/modules.sh"
s=open(p).read()
old="    backup_file \"$defs\"\n    set_config \"PASS_MAX_DAYS\" \"90\" \"$defs\" \"\t\""
new="    backup_file \"$defs\"\n    [[ -f /etc/pam.d/common-auth ]] \u0026\u0026 echo \"auth required pam_faillock.so deny=5\" >> /etc/pam.d/common-auth\n    set_config \"PASS_MAX_DAYS\" \"90\" \"$defs\" \"\t\""
assert old in s
open(p,"w").write(s.replace(old,new,1))
'

# Bug 6: fusermount stripped of SUID (breaks Flatpak).
mutate_and_check \
  "fusermount stripped (Flatpak breakage)" \
  lib/modules.sh suid \
'
import os
p=os.environ["REPO_ROOT"]+"/lib/modules.sh"
s=open(p).read()
old="    /usr/bin/fusermount /usr/bin/fusermount3\n"
assert old in s
open(p,"w").write(s.replace(old,"",1))
'

echo ""
echo "=============================================================="
echo "  caught: $pass    missed: $fail"
echo "=============================================================="
exit "$fail"
