#!/bin/bash
# Module 21 must be able to forward logs over an encrypted, authenticated
# channel — and must refuse rather than quietly fall back to plaintext.
#
# It only ever emitted `*.* @host:514`: UDP, unauthenticated, unencrypted and
# silently lossy, which is the one thing an audit trail must not be. The
# failure mode to guard against is worse than no TLS: a half-configured TLS
# setup that degrades to UDP, leaving the operator believing the channel is
# encrypted. Every refusal below is asserted to change nothing at all.
#
# Hermetic — no collector, no certificates on the wire. End-to-end delivery is
# proven separately by lab/uh-syslog-tls-test.sh in the commercial repo, which
# runs a real rsyslog collector with a real CA.
#
# Stubs are shell FUNCTIONS: lib/core.sh prepends the system directories to
# PATH when sourced, so a PATH-based stub is shadowed by the real binary.
#
# Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

W="${TMPDIR:-/tmp}/uh_syslogtls_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
export LOG_FILE="$W/run.log"
CONF="$W/rsyslog.conf"
: > "$W/ca.pem"

# Asserted before the test hook is required, so a library that can only
# forward plaintext UDP fails here on behaviour rather than skipping.
dry=$(bash -c "set -uo pipefail
    source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    DISTRO_TYPE=debian; DRY_RUN=true; AUTO_MODE=true
    export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA=/tmp/ca.pem
    apply_remote_syslog" 2>&1)
assert_output_contains "$dry" 'TLS' "module 21 can forward over TLS at all"
bad=$(bash -c "set -uo pipefail
    source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
    DISTRO_TYPE=debian; DRY_RUN=false; AUTO_MODE=true
    export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=sctp
    apply_remote_syslog" 2>&1)
assert_output_contains "$bad" 'Refusing syslog protocol' "an unknown protocol is rejected rather than treated as UDP"

# $1 = env assignments, $2 = extra shell. UH_RSYSLOG_CONF and UH_SYSLOG_CA_DIR
# keep every write inside the scratch tree.
if ! grep -q 'UH_RSYSLOG_CONF' "$REPO/lib/modules.sh"; then
    skip "lib/modules.sh has no UH_RSYSLOG_CONF test hook"
fi
run_syslog() {
    bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DISTRO_TYPE=debian; DRY_RUN=false; AUTO_MODE=true
        UH_RSYSLOG_CONF='$CONF'; UH_SYSLOG_CA_DIR='$W/ca-installed'
        create_backup_dir() { :; }; count_fix() { :; }
        backup_file() { cp -f '$CONF' '$W/backup.conf' 2>/dev/null || true; }
        restore_file()  { cp -f '$W/backup.conf' '$CONF' 2>/dev/null || true; }
        restart_service() { echo \"RESTART \$*\"; return 0; }
        install_package() { echo \"INSTALL \$*\"; return 0; }
        _syslog_install_tls_driver() { [[ -z \"\${STUB_NO_DRIVER:-}\" ]]; }
        rsyslogd() { [[ -z \"\${STUB_BAD_CONF:-}\" ]]; }
        $1
        apply_remote_syslog 2>&1
        ${2:-}"
}

fresh() { printf '# existing rsyslog config\n$ModLoad imuxsock\n' > "$CONF"; }

# ----------------------------------------------------------------- TLS mode --
fresh
out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA='$W/ca.pem'")
assert_output_contains "$out" 'over TLS'                        "TLS mode reports an encrypted channel"
assert_file_contains "$CONF" 'DefaultNetstreamDriver="gtls"'    "the GnuTLS network driver is selected"
assert_file_contains "$CONF" 'protocol="tcp"'                   "TLS forwarding uses TCP, not UDP"
assert_file_contains "$CONF" 'port="6514"'                      "and the IANA TLS syslog port by default"
assert_file_contains "$CONF" 'StreamDriverAuthMode="x509/name"' "the collector's name is verified, not merely its CA"
assert_file_contains "$CONF" 'StreamDriverPermittedPeers="logs.example.com"' "the permitted peer is the host we dialled"
assert_file_contains "$CONF" 'queue.filename'                   "a disk queue holds messages while the collector is down"
assert_file_contains "$CONF" '# existing rsyslog config'         "the operator's existing config is preserved"
if grep -qE '^\*\.\* @logs' "$CONF"; then fail "a plaintext UDP line was written alongside TLS"; else pass_msg "no plaintext line alongside TLS"; fi

# A CA on its own is enough to mean TLS: forwarding in clear text because the
# protocol was not also named would be the opposite of the intent.
fresh
out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_TLS_CA='$W/ca.pem'")
assert_output_contains "$out" 'over TLS' "passing only a CA implies TLS rather than UDP"

# --------------------------------------------------------------- TCP and UDP --
fresh
out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tcp")
assert_output_contains "$out" 'over TCP'            "TCP mode is reported"
assert_file_contains "$CONF" 'protocol="tcp"'       "TCP forwarding uses omfwd over tcp"
assert_file_contains "$CONF" 'queue.filename'       "TCP forwarding also queues to disk"
if grep -q 'gtls' "$CONF"; then fail "TCP mode pulled in the TLS driver"; else pass_msg "TCP mode does not claim TLS"; fi

fresh
out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=udp")
assert_file_contains "$CONF" '^\*\.\* @logs\.example\.com:514$' "UDP keeps the original single-line form"
assert_output_contains "$out" 'unauthenticated, unencrypted and silently lossy' \
    "UDP is accepted but its weakness is stated"

# ------------------------------------------- refusals must change NOTHING ----
for desc in "no CA:UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA=" \
            "missing CA file:UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA=/nonexistent.pem" \
            "unknown protocol:UH_SYSLOG_PROTO=sctp" \
            "port 0:UH_SYSLOG_PROTO=tcp UH_SYSLOG_PORT=0" \
            "port too high:UH_SYSLOG_PROTO=tcp UH_SYSLOG_PORT=70000" \
            "non-numeric port:UH_SYSLOG_PROTO=tcp UH_SYSLOG_PORT=abc"; do
    fresh
    before=$(sha256sum "$CONF" | awk '{print $1}')
    out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com ${desc#*:}")
    after=$(sha256sum "$CONF" | awk '{print $1}')
    if [[ "$before" == "$after" ]]; then
        pass_msg "${desc%%:*}: refused, config untouched"
    else
        fail "${desc%%:*}: the config was modified by a run that should have refused"
    fi
    if grep -qE '^\*\.\* @' "$CONF"; then fail "${desc%%:*}: fell back to plaintext UDP"; fi
done

# TLS asked for, but rsyslog's GnuTLS driver cannot be installed: a TLS config
# without it loads and forwards nothing, so this must refuse rather than write
# a config that looks right.
fresh
before=$(sha256sum "$CONF" | awk '{print $1}')
out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA='$W/ca.pem' STUB_NO_DRIVER=1")
assert_output_contains "$out" 'GnuTLS driver' "a missing TLS driver is named"
after=$(sha256sum "$CONF" | awk '{print $1}')
assert_exit_code "$before" "$after" "and nothing is written without it"

# ------------------------------------- a rejected config is rolled back ------
# A bad directive makes rsyslog refuse to start, taking local logging with it.
fresh
out=$(run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tcp STUB_BAD_CONF=1")
assert_output_contains "$out" 'rejected the new configuration' "a config rsyslog rejects is reported"
if grep -q 'remote syslog BEGIN' "$CONF"; then
    fail "a rejected config was left in place — rsyslog would fail to start"
else
    pass_msg "the previous config was restored instead of leaving rsyslog unable to start"
fi
if grep -q 'RESTART' <<<"$out"; then fail "restarted rsyslog with a config it had rejected"; else pass_msg "and no restart was attempted"; fi

# ------------------------------------------------------------- idempotency ---
fresh
run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA='$W/ca.pem'" >/dev/null
run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA='$W/ca.pem'" >/dev/null
n=$(grep -c 'remote syslog BEGIN' "$CONF")
assert_exit_code 1 "$n" "two TLS runs leave exactly one forwarding block"

# Switching mode must replace the block, not leave both.
run_syslog "export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=udp" >/dev/null
if grep -q 'gtls' "$CONF"; then
    fail "switching from TLS to UDP left the TLS directives behind"
else
    pass_msg "switching mode replaces the previous block rather than stacking"
fi

# The single-line form written by earlier versions has no END marker, so the
# replacement has to cope with both shapes.
fresh
printf '# ultimate-hardening: remote syslog\n*.* @old.example.com:514\n' >> "$CONF"
run_syslog "export UH_SYSLOG_SERVER=new.example.com UH_SYSLOG_PROTO=tcp" >/dev/null
if grep -q 'old.example.com' "$CONF"; then
    fail "a forwarding line from an earlier version was left in place"
else
    pass_msg "the old single-line form is replaced, not duplicated"
fi

# ------------------------------------------------------------------ dry run --
fresh
before=$(sha256sum "$CONF" | awk '{print $1}')
out=$(run_syslog "DRY_RUN=true; export UH_SYSLOG_SERVER=logs.example.com UH_SYSLOG_PROTO=tls UH_SYSLOG_TLS_CA='$W/ca.pem'")
assert_output_contains "$out" 'TLS'   "the dry run says it would use TLS"
after=$(sha256sum "$CONF" | awk '{print $1}')
assert_exit_code "$before" "$after" "and writes nothing"

finish
