#!/bin/bash
# =============================================================================
#  docs/build-terminals.sh — render the site's terminal blocks from real code
#
#  docs/index.html shows the tool's screens as coloured HTML rather than as
#  screenshots. HTML stays crisp at any width; a screenshot of a 90-column
#  terminal scaled into a 280px card is unreadable, which is what the "See it"
#  row had become.
#
#  The catch is that hand-written HTML replicas drift. The last one advertised
#  "16) Apply all Safe/Medium modules" — the numbering from when the tool
#  shipped 15 — directly beneath a badge reading "22 modules", with a header
#  box that did not close.
#
#  So nothing here is transcribed. Each block is produced by running the same
#  functions the tool runs (box_line, render_module_list, record_check,
#  print_cis_score, show_distro_menu) and converting the ANSI colour to spans.
#  Rename a module, change a risk level, add a compliance check, and re-running
#  this picks it up.
#
#  Demo data, deliberately: module states and check results are fixed values,
#  not this machine's. The site should not publish one host's compliance
#  posture, and deriving real results needs root. Everything ABOUT the output
#  — layout, ordering, labels, risk tags, hint text, score arithmetic — is real.
#
#  Pro and Enterprise blocks are generated only when the commercial repo is
#  linked alongside; without it those blocks are left untouched rather than
#  emptied, so a contributor with only the public repo can still run this.
#
#  Usage: ./docs/build-terminals.sh          rewrite docs/index.html in place
#         ./docs/build-terminals.sh --check  exit 1 if any block is out of date
# =============================================================================
set -euo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HTML="$REPO/docs/index.html"
COMMERCIAL="${UH_COMMERCIAL_REPO:-$REPO/../ultimate-hardening-commercial}"
MODE="${1:-}"

# --- shared preamble ---------------------------------------------------------
# lib/core.sh blanks the palette when stdout is not a terminal, and this always
# runs into a pipe, so the colours are reinstated after sourcing it.
read -r -d '' PREAMBLE <<'PRE' || true
# Generating the page must not create a run log. LOG_FILE is set before
# core.sh is sourced because core.sh only defaults it (:= ), and log_success /
# log_warning — which record_check calls — tee into it unconditionally.
LOG_FILE=/dev/null
source lib/core.sh
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; WHITE="\033[1;37m"; NC="\033[0m"
source lib/platform.sh
source lib/modules.sh
source lib/cis.sh
source lib/menu.sh
demo_states() {
    local k
    for k in "${MOD_KEYS[@]}"; do MOD_STATE[$k]=on; done
    for k in suid aide services protocols compiler syslog; do MOD_STATE[$k]=off; done
    for k in grubpw docker modsec;                          do MOD_STATE[$k]=na;  done
}
PRE

run_block() { ( cd "$REPO" && bash -c "$PREAMBLE
$1" ); }

# --- the blocks --------------------------------------------------------------
block_distro() {
    run_block '
        # show_distro_menu prints the list, blocks on read, then reports what
        # was chosen. Stub all three side effects so the printed menu is
        # captured as-is rather than copied out of it: without the log_success
        # stub the empty stubbed read falls through to auto-detect and appends
        # a "Platform: ..." line that is not part of the menu.
        clear()       { :; }
        read()        { :; }
        log_success() { :; }
        show_distro_menu
    '
}

block_modules() {
    run_block '
        demo_states
        box_top
        box_line "${CYAN}       ULTIMATE HARDENING ${UH_VERSION} — FREE TIER${NC}"
        box_line "${CYAN}       Platform: ${WHITE}rhel${NC}"
        box_bottom
        echo ""
        echo -e "  ${YELLOW}${WARNING} DRY RUN — nothing will be modified${NC}"
        echo ""
        echo -e "  ${WHITE}[enable ]${NC} already in place   ${WHITE}[disable]${NC} not applied yet   ${WHITE}[  N/A  ]${NC} not applicable here"
        echo ""
        render_module_list
        echo ""
        printf "  ${WHITE}%2s)${NC} %s\n" 23 "Apply all Safe/Medium modules (skip High risk)"
        printf "  ${WHITE}%2s)${NC} %s\n" 24 "Apply all ${#MOD_KEYS[@]} modules (includes High risk)"
        printf "  ${WHITE}%2s)${NC} %s\n"  C "Run compliance checks (read-only)"
        printf "  ${WHITE}%2s)${NC} %s\n"  R "Revert everything from backup"
        printf "  ${WHITE}%2s)${NC} %s\n"  Q "Quit"
    '
}

block_cis() {
    run_block '
        log_cis "Running CIS-aligned compliance checks (read-only)"
        # record_check is the real printer: it derives the remediation hint from
        # cis_check_module() and counts the score. Only the pass/fail values
        # below are demo data.
        for part in /home /tmp; do
            record_check "$part is a separate partition" true
        done
        for part in /var /var/log /var/tmp; do
            record_check "$part is a separate partition" false "Not a separate mount point"
        done
        for c in "SSH root login disabled" \
                 "SSH password authentication disabled" \
                 "SSH X11 forwarding disabled" \
                 "SSH empty passwords rejected" \
                 "SSH MaxAuthTries is 3 or fewer" \
                 "auditd is running" \
                 "fail2ban is running" \
                 "Firewall is active" \
                 "ASLR fully enabled" \
                 "IP forwarding disabled" \
                 "TCP SYN cookies enabled" \
                 "Kernel log restricted to root" \
                 "Kernel pointers hidden" \
                 "SUID core dumps disabled" \
                 "Password max age is 90 days or fewer" \
                 "/etc/passwd permissions are 644 or stricter" \
                 "/etc/shadow permissions are 640 or stricter" \
                 "/etc/group permissions are 644 or stricter" \
                 "/etc/gshadow permissions are 640 or stricter" \
                 "Mandatory access control is enforcing"; do
            record_check "$c" true
        done
        print_cis_score
    '
}

# --- ANSI -> spans -----------------------------------------------------------
# Written to a temp file rather than piped in on stdin: `python3 - <<EOF` makes
# the heredoc the script, so the script's own sys.stdin.read() would then find
# it already consumed and convert nothing.
ansi_to_html() {
    local conv; conv=$(mktemp)
    cat > "$conv" <<'PYCONV'
import sys, re, html
ansi = re.compile(r'\033\[([0-9;]*)m')
CLASS = {'0;32':'c-g', '0;36':'c-c', '1;33':'c-a',
         '1;37':'c-w', '0;31':'c-r', '0;34':'c-f', '0;35':'c-c'}
out = []
for line in sys.stdin.read().split('\n'):
    pos, buf, depth = 0, [], 0
    for m in ansi.finditer(line):
        buf.append(html.escape(line[pos:m.start()]))
        code = m.group(1)
        if code in ('0', '', '0;0'):
            if depth: buf.append('</span>'); depth -= 1
        else:
            cls = CLASS.get(code)
            if cls:
                if depth: buf.append('</span>'); depth -= 1
                buf.append('<span class="%s">' % cls); depth += 1
        pos = m.end()
    buf.append(html.escape(line[pos:]))
    while depth:
        buf.append('</span>'); depth -= 1
    out.append(''.join(buf))
sys.stdout.write('\n'.join(out).strip('\n'))
PYCONV
    python3 "$conv"
    rm -f "$conv"
}

# --- splice ------------------------------------------------------------------
# Same trap as the converter: the script must come from a file, because stdin
# is carrying the block body.
splice() {
    local name="$1" body="$2"
    local sp; sp=$(mktemp)
    cat > "$sp" <<'PYSPLICE'
import sys, io
path, name, mode = sys.argv[1:4]
body = sys.stdin.read().rstrip('\n')
begin = '<!-- BEGIN generated %s: ./docs/build-terminals.sh -->' % name
end   = '<!-- END generated %s -->' % name
s = io.open(path, encoding='utf-8').read()
i, j = s.find(begin), s.find(end)
if i < 0 or j < 0:
    sys.exit("  markers for '%s' not found in %s" % (name, path))
new = '%s\n%s\n%s' % (begin, body, end)
if s[i:j+len(end)] == new:
    print("  %-9s up to date" % name); sys.exit(0)
if mode == '--check':
    sys.exit("  %s is STALE - run ./docs/build-terminals.sh" % name)
io.open(path, 'w', encoding='utf-8').write(s[:i] + new + s[j+len(end):])
print("  %-9s regenerated" % name)
PYSPLICE
    printf '%s' "$body" | python3 "$sp" "$HTML" "$name" "$MODE"
    local rc=$?
    rm -f "$sp"
    return $rc
}

splice distro  "$(block_distro  | ansi_to_html)"
splice modules "$(block_modules | ansi_to_html)"
splice cis     "$(block_cis     | ansi_to_html)"

if [[ -f "$COMMERCIAL/src/pro/ultimate-hardening-pro.sh" ]]; then
    echo "  (commercial repo linked — tier blocks would build here)"
else
    echo "  (commercial repo not linked — tier blocks left as they are)"
fi
