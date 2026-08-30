#!/bin/bash
# The module count must agree everywhere: the menu table, the dispatch, the
# aggregates, and the public docs.
#
# This exists because it once did not. The lib/ refactor silently reduced a
# 24-module tool to 15, the docs were then "corrected" downward to match, and
# nothing failed — the regression was only caught by a user comparing the
# shipped menu against the published screenshots months later. A drifting
# count is the cheapest possible signal that modules went missing, so it is
# now a test rather than a thing anyone has to notice.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"

REPO="${REPO_ROOT:-/repo}"
EXPECTED=22

# --- lib/menu.sh is the source of truth for the table -----------------------
count=$(bash -c "source '$REPO/lib/core.sh'
                 source '$REPO/lib/platform.sh'
                 source '$REPO/lib/modules.sh'
                 source '$REPO/lib/cis.sh'
                 source '$REPO/lib/menu.sh'
                 echo \${#MOD_KEYS[@]}" 2>/dev/null)
assert_exit_code "$EXPECTED" "$count" "MOD_KEYS holds $EXPECTED modules"

# Every key must map to a label and a risk. (There is no MOD_FN map — the
# tiers dispatch modules directly from their own case statements, which the
# per-tier check further down verifies.)
for arr in MOD_LABEL MOD_RISK; do
    n=$(bash -c "source '$REPO/lib/core.sh'
                 source '$REPO/lib/platform.sh'
                 source '$REPO/lib/modules.sh'
                 source '$REPO/lib/cis.sh'
                 source '$REPO/lib/menu.sh'
                 echo \${#${arr}[@]}" 2>/dev/null)
    assert_exit_code "$EXPECTED" "$n" "$arr covers all $EXPECTED modules"
done

# Every module key must have a risk level the renderer understands, or its
# risk tag renders blank and the table silently loses a column.
badrisk=$(bash -c "source '$REPO/lib/core.sh'
                   source '$REPO/lib/platform.sh'
                   source '$REPO/lib/modules.sh'
                   source '$REPO/lib/cis.sh'
                   source '$REPO/lib/menu.sh'
                   for k in \"\${MOD_KEYS[@]}\"; do
                       case \"\${MOD_RISK[\$k]:-}\" in
                           safe|medium|high) ;;
                           *) echo \"\$k\" ;;
                       esac
                   done" 2>/dev/null)
if [[ -n "$badrisk" ]]; then
    fail "module(s) with a missing or unknown risk level: $(echo "$badrisk" | tr '\n' ' ')"
else
    pass_msg "every module has a valid risk level"
fi

# --- module headers in lib/modules.sh ---------------------------------------
headers=$(grep -coE '\[[0-9]+/'"$EXPECTED"'\]' "$REPO/lib/modules.sh" 2>/dev/null || echo 0)
assert_exit_code "$EXPECTED" "$headers" "lib/modules.sh has $EXPECTED [n/$EXPECTED] module headers"

# No module may still be numbered against an older total.
if grep -qE '\[[0-9]+/(15|24|25)\]' "$REPO/lib/modules.sh" 2>/dev/null; then
    fail "lib/modules.sh still has module headers numbered against an old total"
else
    pass_msg "no stale module numbering in lib/modules.sh"
fi

# --- each tier dispatches every module --------------------------------------
# Pro/Enterprise live in a separate private repo and are absent from a clone
# of the public free-tier repo, so a missing tier is skipped rather than
# failed — but it is reported, so "all tiers pass" can never mean "no tier
# was actually checked".
for tier in "src/free/ultimate_hardening.sh" \
            "src/pro/ultimate-hardening-pro.sh" \
            "src/enterprise/ultimate-hardening-enterprise.sh"; do
    if [[ ! -f "$REPO/$tier" ]]; then
        echo "  ⏭️  SKIP: $(basename "$tier") not in this checkout (free-tier repo)"
        continue
    fi
    missing=""
    for n in $(seq 1 "$EXPECTED"); do
        grep -qE "^[[:space:]]*$n\)[[:space:]]+apply_" "$REPO/$tier" || missing="$missing $n"
    done
    if [[ -n "$missing" ]]; then
        fail "$(basename "$tier") has no menu case for module(s):$missing"
    else
        pass_msg "$(basename "$tier") dispatches all $EXPECTED modules"
    fi
done

# --- public docs must not advertise a different number ----------------------
for doc in README.md PRICING.md docs/index.html; do
    [[ -f "$REPO/$doc" ]] || continue
    if grep -qE '\b(15|24|25|30) (hardening |security )?modules\b' "$REPO/$doc" 2>/dev/null; then
        fail "$doc advertises a module count that is not $EXPECTED"
    else
        pass_msg "$doc does not advertise a stale module count"
    fi
done

# --- and must not advertise it in a table cell either ------------------------
# The check above only sees "<n> modules" as adjacent words. A comparison table
# puts the label in one cell and the number in the next, which is precisely how
# docs/index.html came to advertise 15 hardening modules in its pricing table
# while its own feature list two sections earlier said 22. Seven modules the
# project actually ships, priced as if they did not exist.
html="$REPO/docs/index.html"
if [[ -f "$html" ]]; then
    row=$(grep -i 'hardening modules' "$html" | grep '<td' || true)
    if [[ -n "$row" ]]; then
        nums=$(printf '%s' "$row" | grep -oE '>[0-9]{1,3}<' | tr -d '><' | sort -u)
        bad=0
        for n in $nums; do
            if [[ "$n" != "$EXPECTED" ]]; then
                fail "docs/index.html comparison table lists $n hardening modules, not $EXPECTED"
                bad=1
            fi
        done
        [[ -n "$nums" && $bad -eq 0 ]] && \
            pass_msg "comparison table lists $EXPECTED modules in every tier column"
    fi
fi

# --- the site's hero must match the menu it claims to show --------------------
# docs/index.html renders the menu as HTML in its hero, which reads far better
# than a scaled screenshot. The last time it did that by hand it drifted: it
# offered "16) Apply all Safe/Medium modules", the numbering from when the tool
# shipped 15, sitting directly beneath a badge reading "22 modules", with a box
# border that did not close.
#
# It is generated from the tool's own menu code now, so this asserts it is not
# stale rather than banning the replica outright — banning it would have thrown
# away the thing that reads best.
gen="$REPO/docs/build-hero.sh"
if [[ -x "$gen" ]]; then
    if "$gen" --check >/dev/null 2>&1; then
        pass_msg "docs/index.html hero matches the current menu"
    else
        fail "docs/index.html hero is stale — run ./docs/build-hero.sh"
    fi
fi

finish
