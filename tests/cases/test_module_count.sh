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
# Counted on the log_message lines that ARE the headers, not on every line
# containing the pattern: a comment that quotes a module number (explaining a
# past failure at [3/22], say) is not a 23rd module, and counting it as one
# made this assertion fail for a documentation change.
headers=$(grep -cE 'log_message .*\[[0-9]+/'"$EXPECTED"'\]' "$REPO/lib/modules.sh" 2>/dev/null || echo 0)
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
        # Any of three forms counts as dispatched: the module called
        # directly, through run_module, or through dispatch_module_choice
        # (the per-module-revert toggle every tier's menu now routes
        # through — see test_module_isolation.sh, which enforces the
        # wrapper, and lib/menu.sh's dispatch_module_choice()).
        grep -qE "^[[:space:]]*$n\)[[:space:]]+((run_module|dispatch_module_choice)[[:space:]]+[a-z0-9]+[[:space:]]+)?apply_" \
            "$REPO/$tier" || missing="$missing $n"
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
    # Match only the total-count row, not "Paid-only hardening modules" —
    # that row's own number (extra paid-only modules) is legitimately
    # different from EXPECTED and isn't a staleness signal.
    row=$(grep -iE '(^|>)hardening modules' "$html" | grep -v -i 'paid-only' | grep '<td' || true)
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
gen="$REPO/docs/build-terminals.sh"
if [[ -x "$gen" ]] && ! command -v python3 >/dev/null 2>&1; then
    echo "  ⏭️  SKIP: build-terminals.sh check — python3 not available in this image"
elif [[ -x "$gen" ]]; then
    if "$gen" --check >/dev/null 2>&1; then
        pass_msg "docs/index.html terminals match the current code"
    else
        fail "docs/index.html terminal blocks are stale — run ./docs/build-terminals.sh"
    fi
fi


# --- the feature lists must agree too, whatever words they use ---------------
# Every check above recognises "<n> modules". The plain-text feature lists say
# "<n> hardening actions" instead, and that phrasing was never checked:
# features.txt, docs/features.md and docs/free-tier.md all said 28 while the
# tool had 22 — and the public repo's copy said 28 for code that had 24. One
# pattern for every phrasing, every doc that states a count.
for doc in README.md features.txt docs/features.md docs/free-tier.md \
           docs/index.html docs/installation.md SECURITY.md CONTRIBUTING.md; do
    [[ -f "$REPO/$doc" ]] || continue
    nums=$(grep -oE '\b[0-9]{1,3} (hardening|security) (actions|modules|features)\b' "$REPO/$doc" \
           | grep -oE '^[0-9]+' | sort -u)
    [[ -n "$nums" ]] || continue
    bad=""
    for n in $nums; do [[ "$n" == "$EXPECTED" ]] || bad="$bad $n"; done
    if [[ -n "$bad" ]]; then
        fail "$doc states$bad hardening actions/modules, not $EXPECTED"
    else
        pass_msg "$doc states $EXPECTED hardening actions/modules"
    fi
done

# --- and must not send a reader to a menu option that does not exist ---------
# docs/free-tier.md told readers to revert via "menu option #28" — the old
# monolith's numbering. The refactored menu stops well short of 28, so that
# instruction pressed a key that does nothing. The upper bound is read from the
# free tier's own dispatch, so adding a menu entry never needs this test edited.
free="$REPO/src/free/ultimate_hardening.sh"
if [[ -f "$free" ]]; then
    maxopt=$(grep -oE '^[[:space:]]+[0-9]{1,2}\)' "$free" | tr -dc '0-9\n' | sort -n | tail -1)
    stale=""
    for doc in README.md features.txt docs/features.md docs/free-tier.md \
               docs/index.html docs/installation.md docs/mfa.md SECURITY.md CONTRIBUTING.md; do
        [[ -f "$REPO/$doc" ]] || continue
        for n in $(grep -oiE '\boption #?[0-9]{1,2}\b' "$REPO/$doc" | grep -oE '[0-9]+$'); do
            (( n > maxopt )) && stale="$stale $doc:$n"
        done
    done
    stale=$(tr ' ' '\n' <<< "$stale" | sort -u | tr '\n' ' ')
    if [[ -n "${stale// /}" ]]; then
        fail "docs point at menu option(s) the menu does not have (max $maxopt): $stale"
    else
        pass_msg "no doc points at a menu option beyond $maxopt"
    fi
fi


# --- every label must fit the menu's label column ----------------------------
# render_main_menu pads the label with printf "%-Ns". A longer label is not
# truncated — it pushes that row's risk and status columns sideways, so one
# module sits visibly out of line in the menu and in the site's generated copy.
# Module 19's label was lengthened to 38 characters against a 32-character
# field, and nothing caught it; the box-alignment test checks borders, not
# labels. The width is read from the renderer so changing it needs no edit here.
width=$(grep -oE 'printf "%2s\) %-[0-9]+s' "$REPO/lib/menu.sh" | grep -oE '%-[0-9]+' | tr -dc '0-9' | head -c 3)
if [[ -n "$width" ]]; then
    long=$(bash -c "source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'
                    source '$REPO/lib/modules.sh'; source '$REPO/lib/cis.sh'
                    source '$REPO/lib/menu.sh'
                    for k in \"\${MOD_KEYS[@]}\"; do
                        l=\"\${MOD_LABEL[\$k]}\"
                        (( \${#l} > $width )) && echo \"\$k (\${#l} chars: \$l)\"
                    done" 2>/dev/null)
    if [[ -n "$long" ]]; then
        fail "menu label(s) wider than the ${width}-column field: $(tr '\n' ';' <<< "$long")"
    else
        pass_msg "every module label fits the ${width}-column menu field"
    fi
else
    fail "could not find the label width in lib/menu.sh's row printf — this check no longer applies"
fi

finish
