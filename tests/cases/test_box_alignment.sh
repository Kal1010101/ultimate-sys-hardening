#!/bin/bash
# The banner boxes must close, on every tier, for every input.
#
# This exists because none of them did. Three separate headers were padded by
# hand and all three were wrong:
#
#   * the free tier's "Platform:" line had no closing edge at all;
#   * the Pro and Enterprise headers had the same missing edge, on a line that
#     interpolates $(hostname) — unbounded input against fixed padding;
#   * every title line was padded assuming the shield emoji occupies two
#     terminal columns. Many fonts render it as one, which is what shipped in
#     the published screenshots: a header box two columns short of its corners.
#
# The last one is the reason emoji are banned inside a box rather than merely
# re-counted. Terminals genuinely disagree about that glyph's width, so a
# hand-padded box containing one cannot be correct everywhere at once.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"

REPO="${REPO_ROOT:-/repo}"

# wc -L reports display width, which is the property under test; byte length
# would pass on an em-dash that breaks the alignment.
if [[ "$(printf 'ab\n' | wc -L 2>/dev/null)" != "2" ]]; then
    skip "wc -L (display width) unavailable in this image"
fi

box_env() {
    printf '%s\n' "source '$REPO/lib/core.sh'
                   source '$REPO/lib/platform.sh'
                   source '$REPO/lib/modules.sh'
                   source '$REPO/lib/cis.sh'
                   source '$REPO/lib/menu.sh'"
}

# Every line a box emits must be the same width, whatever is inside it.
check_box() {
    local label="$1" width="$2" body="$3"
    local out widths distinct
    out=$(bash -c "$(box_env)
                   UH_BOX_WIDTH=$width
                   box_top
                   $body
                   box_bottom" 2>/dev/null)
    [[ -n "$out" ]] || { fail "$label: box produced no output"; return; }
    widths=$(printf '%s\n' "$out" | while IFS= read -r l; do printf '%s\n' "$l" | wc -L; done)
    distinct=$(printf '%s\n' "$widths" | sort -u | wc -l)
    assert_exit_code 1 "$distinct" "$label: all box lines share one width"
    assert_exit_code "$((width + 2))" "$(printf '%s\n' "$widths" | sort -u | head -1)" \
        "$label: box is $width wide plus both edges"
}

# --- the free tier header, across platform names of different lengths --------
for distro in x rhel opensuse-leap-15.6; do
    check_box "free header (platform=$distro)" 66 \
        "DISTRO_TYPE=$distro
         box_line \"\${CYAN}       ULTIMATE HARDENING \${UH_VERSION} — FREE TIER\${NC}\"
         box_line \"\${CYAN}       Platform: \${WHITE}\${DISTRO_TYPE}\${NC}\""
done

# --- unbounded input must be truncated, not allowed to run off the edge ------
long="a-very-long-hostname-that-runs-well-past-any-fixed-padding.example.internal"
check_box "pro header (long hostname)" 70 \
    "box_line \"\${CYAN}       Platform: \${WHITE}debian\${CYAN}  |  Host: \${WHITE}$long\${NC}\""

# --- degenerate content ------------------------------------------------------
check_box "empty line"      20 'box_line ""'
check_box "exact fit"       20 'box_line "12345678901234567890"'
check_box "one over"        20 'box_line "123456789012345678901"'
check_box "colour only"     20 'box_line "${CYAN}${WHITE}${NC}"'

# --- colour codes must not be counted as width -------------------------------
plain=$(bash -c "$(box_env); UH_BOX_WIDTH=30; box_line 'hello'" | wc -L)
coloured=$(bash -c "$(box_env); UH_BOX_WIDTH=30; box_line \"\${CYAN}hello\${NC}\"" | wc -L)
assert_exit_code "$plain" "$coloured" "colour codes occupy no columns"

# --- no tier may go back to hand-padding a box -------------------------------
# A literal box edge inside an echo is how all three headers were written, and
# how they were all wrong. The box helpers are the only sanctioned way.
for f in "$REPO/src/free/ultimate_hardening.sh" \
         "$REPO/src/pro/ultimate-hardening-pro.sh" \
         "$REPO/src/enterprise/ultimate-hardening-enterprise.sh" \
         "$REPO/lib/platform.sh" \
         "$REPO/lib/cis.sh" \
         "$REPO/lib/modules.sh"; do
    [[ -f "$f" ]] || continue
    hand=$(grep -c 'echo .*║' "$f" || true)
    assert_exit_code 0 "$hand" "$(basename "$f"): no hand-padded box lines"
done

# --- and no emoji may re-enter a box -----------------------------------------
emoji_in_box=$(grep -n 'box_line' "$REPO"/src/*/*.sh 2>/dev/null \
               | grep -cE '\$\{(SHIELD|LOCK|GEAR|FIRE|ROCKET|DB_ICON|NET_ICON|CIS_ICON|CHECK_MARK|CROSS_MARK|WARNING|INFO|UNDO)\}' || true)
assert_exit_code 0 "$emoji_in_box" "no emoji passed to box_line"

finish
