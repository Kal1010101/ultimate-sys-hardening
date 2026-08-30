#!/bin/bash
# =============================================================================
#  docs/build-hero.sh — regenerate the hero terminal block in docs/index.html
#
#  The hero used to be a hand-written HTML replica of the menu, and it drifted:
#  it advertised "16) Apply all Safe/Medium modules" (the numbering from when
#  the tool shipped 15) directly under a badge reading "22 modules", with a box
#  border that did not close and two shield emoji the real header no longer
#  prints. A hand-written replica is a second copy of the UI that nothing keeps
#  in sync.
#
#  So the block is still hand-written HTML — it reads far better than a scaled
#  screenshot — but it is no longer written by hand. This script renders it
#  through the SAME functions the tool uses (box_line, render_module_list,
#  MOD_KEYS/MOD_LABEL/MOD_RISK) and converts the ANSI colour to spans. Add a
#  module, rename one, change a risk level or touch the header, and re-running
#  this picks it up. Nothing here is transcribed.
#
#  Module states are demo values, deliberately: the site should not display one
#  machine's compliance posture, and deriving real ones needs root.
#
#  Usage: ./docs/build-hero.sh            rewrite docs/index.html in place
#         ./docs/build-hero.sh --check    exit 1 if the file is out of date
# =============================================================================
set -euo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HTML="$REPO/docs/index.html"
BEGIN='<!-- BEGIN generated hero: ./docs/build-hero.sh -->'
END='<!-- END generated hero -->'

# Force colour on: lib/core.sh strips it when stdout is not a terminal, and
# this always runs into a pipe.
render_ansi() {
    cd "$REPO"
    bash -c '
        exec 3>&1
        source lib/core.sh
        RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
        CYAN="\033[0;36m"; WHITE="\033[1;37m"; NC="\033[0m"
        source lib/platform.sh
        source lib/modules.sh
        source lib/cis.sh
        source lib/menu.sh

        # A representative spread, not this machine.
        for k in "${MOD_KEYS[@]}"; do MOD_STATE[$k]=on; done
        for k in suid aide services protocols compiler syslog; do MOD_STATE[$k]=off; done
        for k in grubpw docker modsec;                          do MOD_STATE[$k]=na;  done

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
        printf "  ${WHITE}%2s)${NC} %s\n"  Q "Quit"
    '
}

# ANSI -> spans. The converter is written to a temp file rather than piped in
# on stdin: `python3 - <<EOF` makes the heredoc the *script*, so the script's
# own sys.stdin.read() then finds it already consumed and converts nothing.
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
sys.stdout.write('\n'.join(out).rstrip('\n'))
PYCONV
    python3 "$conv"
    rm -f "$conv"
}

block=$(render_ansi | ansi_to_html)

new=$(printf '%s\n%s\n%s' "$BEGIN" "$block" "$END")

python3 - "$HTML" "$BEGIN" "$END" "$new" "${1:-}" <<'PY'
import sys, io
path, begin, end, new, mode = sys.argv[1:6]
s = io.open(path, encoding='utf-8').read()
i, j = s.find(begin), s.find(end)
if i < 0 or j < 0:
    sys.exit("markers not found in %s — add %s / %s around the hero block" % (path, begin, end))
cur = s[i:j+len(end)]
if cur == new:
    print("hero block is up to date"); sys.exit(0)
if mode == '--check':
    sys.exit("hero block is STALE — run ./docs/build-hero.sh")
io.open(path, 'w', encoding='utf-8').write(s[:i] + new + s[j+len(end):])
print("hero block regenerated")
PY
