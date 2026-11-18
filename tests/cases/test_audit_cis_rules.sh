#!/bin/bash
# Module 7's generated rules: the CIS groups are there, every -S syscall is
# one this arch knows (auditctl stops loading a file at the first unknown
# name), watches never sit under a missing directory, -e 2 only on request,
# and in a container where auditd can run, auditctl accepts every line.
# Needs no root for the generation checks.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

gen() {   # $1 = extra shell before generating
    bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
             LOG_FILE=/dev/null; $1
             _audit_rules_content" 2>&1
}

rules=$(gen '')
for key in identity sudoers time-change system-locale user_emulation access perm_mod \
           mounts delete modules session logins privesc; do
    grep -qE -- "-k ${key}\$" <<< "$rules" && pass_msg "rules carry the $key group" \
        || fail "no rule with key $key"
done
grep -qx -- '-e 2' <<< "$rules" && fail "-e 2 written without UH_AUDIT_IMMUTABLE" \
    || pass_msg "rules stay changeable by default"
[[ "$(head -1 <<< "$rules")" == "-D" ]] && pass_msg "first line clears old rules" || fail "first line is not -D"

locked=$(gen 'UH_AUDIT_IMMUTABLE=true')
[[ "$(tail -1 <<< "$locked")" == "-e 2" ]] && pass_msg "UH_AUDIT_IMMUTABLE=true makes -e 2 the last line" \
    || fail "UH_AUDIT_IMMUTABLE=true did not end the rules with -e 2"
bad=$(gen 'UH_AUDIT_IMMUTABLE=yes')
grep -qx -- '-e 2' <<< "$bad" && fail "an invalid UH_AUDIT_IMMUTABLE locked the rules" \
    || pass_msg "an invalid UH_AUDIT_IMMUTABLE value is refused"

# Every watch sits on an existing path or under an existing directory.
while read -r _ path _; do
    [[ -e "$path" || -d "$(dirname "$path")" ]] || fail "watch under a missing directory: $path"
done < <(grep -- '^-w ' <<< "$rules")
pass_msg "watches checked against the filesystem"

# On a 64-bit ABI without the legacy calls, none of them may appear (stubbed
# arch, no ausyscall to ask).
arm=$(gen 'uname() { echo aarch64; }; ausyscall() { return 127; }; command() { [[ "$2" == ausyscall ]] && return 1; builtin command "$@"; }')
if grep -E -- '-F arch=b64' <<< "$arm" | grep -qE -- '-S (open|creat|chmod|chown|rename|unlink) '; then
    fail "aarch64 b64 rules name syscalls that arch does not have"
else
    pass_msg "aarch64 b64 rules leave out the legacy syscalls"
fi

# auditctl itself, where the container may load rules (needs CAP_AUDIT_CONTROL).
if command -v auditctl >/dev/null 2>&1 && auditctl -s >/dev/null 2>&1; then
    f=$(mktemp); printf '%s\n' "$rules" > "$f"
    if auditctl -R "$f" >/dev/null 2>&1; then pass_msg "auditctl -R loads every rule"
    else fail "auditctl -R rejected the generated rules: $(auditctl -R "$f" 2>&1 | head -3)"; fi
    auditctl -D >/dev/null 2>&1
    rm -f "$f"
fi
finish
