#!/bin/bash
# =============================================================================
#  docs/capture-demo.sh — record every menu path for the site's replay demo
#
#  docs/demo.html lets a visitor click through the real menu and see what each
#  choice prints. Nothing on that page is written by hand: this script drives
#  the tool through a real terminal (util-linux `script`), once per menu
#  choice, in --dry-run mode, and saves exactly what the terminal showed.
#  docs/build-demo.sh then turns those recordings into the page.
#
#  RUN IT ONLY ON A THROWAWAY MACHINE, as root: a fresh VM from a snapshot,
#  restored afterwards. --dry-run modifies nothing, but the recordings publish
#  that host's state (package set, module states, hostname), and a lab guest is
#  the only host whose state is fine to publish. A container is the wrong
#  place: without systemd, half the services read as "not running" and the
#  demo would misreport what the tool finds on a real server.
#
#  Usage: sudo ./docs/capture-demo.sh <output-dir> [choice...]
#         With choices (e.g. 12 R S), re-records only those into an existing
#         recordings directory, for when one menu path changed.
#  Then, on your own machine: ./docs/build-demo.sh <output-dir>
# =============================================================================
set -euo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
UH="$REPO/src/free/ultimate_hardening.sh"
OUT="${1:?usage: sudo $0 <output-dir> [choice...]}"
shift

# Every choice the main menu offers, unless the caller named some. The two
# apply-all entries (24/25) are included because in --dry-run they only print
# what they would do.
CHOICES=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 C U R S)
(( $# )) && CHOICES=("$@")

# Seconds to wait for the menu to draw, and for one choice to finish. A choice
# that is still running when its time is up gets a truncated recording, which
# build-demo.sh rejects (no "Press Enter" line), so err on the generous side.
MENU_WAIT=4
CHOICE_WAIT=30

# The terminal the recordings are made at. 100x50 fits the 66-column boxes and
# the 22-row module table without wrapping, the same size the site renders.
COLS=100
ROWS=50

[[ $EUID -eq 0 ]] || { echo "Run as root on a disposable machine (see the header)." >&2; exit 1; }
command -v script >/dev/null || { echo "util-linux 'script' is required." >&2; exit 1; }
mkdir -p "$OUT"

# Feed one menu path to the tool through a pty, a line at a time with pauses,
# so the terminal echo of each answer lands where a person typing it would see
# it. The run opens on the profile screen, answered with the cis profile (the
# demo records cis only; the page explains that modern differs in modules 8,
# 20 and 22). "Press Enter to return to the menu" takes any line, and an
# invalid menu choice also ends at it. One answer sequence after the choice
# ends on the profile screen and quits for both shapes a choice can take:
#   choice asks to confirm:  "yes" confirms (also satisfies type-'yes' prompts),
#                            "" dismisses "Press Enter", "P" goes back to the
#                            profile screen, "Q" quits; the rest find no tool.
#   choice does not confirm: "yes" dismisses "Press Enter", "" is an invalid
#                            choice, "P" dismisses its "Press Enter", "Q" is
#                            invalid too (Q quits only from the profile
#                            screen), "P" dismisses that, "P" goes back,
#                            "Q" quits.
# The extra menus drawn on the way are identical, which build-demo.sh checks.
# Writes after the tool has quit fail with a broken pipe; the feeder's stderr
# is dropped for them. timeout is the backstop.
DEMO_PROFILE_KEY=2   # the profile screen's key for cis
record_choice() {
    local choice="$1" file="$2" answer
    {
        sleep "$MENU_WAIT";   printf '%s\n' "$DEMO_PROFILE_KEY"   # profile screen: cis
        sleep "$MENU_WAIT";   printf '0\n'          # distro menu: auto-detect
        sleep "$MENU_WAIT";   printf '%s\n' "$choice"
        sleep "$CHOICE_WAIT"; printf 'yes\n'
        for answer in '' P Q P P Q; do
            sleep "$MENU_WAIT"; printf '%s\n' "$answer"
        done
        sleep "$MENU_WAIT"
    } 2>/dev/null | TERM=xterm-256color timeout $((CHOICE_WAIT * 3)) \
        script -qfec "stty cols $COLS rows $ROWS; cd '$REPO' && '$UH' --dry-run" /dev/null \
        > "$file" 2>&1 || true
}

for choice in "${CHOICES[@]}"; do
    printf '  recording choice %-3s ... ' "$choice"
    record_choice "$choice" "$OUT/choice-$choice.raw"
    echo "$(wc -c < "$OUT/choice-$choice.raw") bytes"
done

# Where the recording was made, for the page's caption. Version comes from the
# tool itself so the caption cannot drift from what was actually run.
{
    echo "version=$("$UH" --version | awk '{print $3}')"
    echo "profile=cis"
    . /etc/os-release && echo "os=$PRETTY_NAME"
    echo "date=$(date -u +%Y-%m-%d)"
} > "$OUT/meta.txt"
echo "  done: $OUT"
