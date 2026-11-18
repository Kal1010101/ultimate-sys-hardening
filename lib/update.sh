#!/bin/bash
# =============================================================================
#  lib/update.sh — check GitHub for a newer release
#
#  Best-effort only: no network, a rate-limited API, or a malformed response
#  must never fail or slow down a hardening run. Every failure path here
#  logs at most a warning and returns 0.
# =============================================================================

: "${UH_UPDATE_REPO:=Kal1010101/ultimate-sys-hardening}"

# Compares two "MAJOR.MINOR.PATCH" strings. Echoes "newer", "same", or
# "older" describing how $1 relates to $2. Falls back to string inequality
# if either side doesn't parse as three dot-separated integers.
_uh_version_cmp() {
    local a="$1" b="$2"
    if [[ "$a" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$b" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local -a av bv
        IFS='.' read -r -a av <<< "$a"
        IFS='.' read -r -a bv <<< "$b"
        local i
        for i in 0 1 2; do
            if (( av[i] > bv[i] )); then echo "newer"; return 0; fi
            if (( av[i] < bv[i] )); then echo "older"; return 0; fi
        done
        echo "same"
        return 0
    fi
    [[ "$a" == "$b" ]] && echo "same" || echo "older"
}

# GitHub owner (alnum + hyphen, max 39) / repo (alnum . _ -). The value is
# interpolated into the API URL, so anything else could steer the request.
_uh_valid_repo() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]] || return 1
    [[ "${1#*/}" != "." && "${1#*/}" != ".." ]]
}

# Is version $1 inside a GitHub advisory range such as ">= 2.3.0, <= 2.6.1",
# "< 2.6.3" or "2.6.0"? Every comma-separated bound must hold. Returns 0 if
# inside, 1 if outside, 2 if either side does not parse, so the caller can say
# it could not tell rather than stay silent about an advisory.
_uh_version_in_range() {
    local ver="$1" bound op cmp
    local re='^(>=|<=|>|<|=)?v?([0-9]+\.[0-9]+\.[0-9]+)$'
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && -n "${2//[[:space:],]/}" ]] || return 2
    local -a bounds
    IFS=',' read -r -a bounds <<<"$2"
    for bound in "${bounds[@]}"; do
        bound="${bound//[[:space:]]/}"
        [[ "$bound" =~ $re ]] || return 2
        op="${BASH_REMATCH[1]:-=}"
        cmp=$(_uh_version_cmp "$ver" "${BASH_REMATCH[2]}")
        case "$op $cmp" in
            ">= newer"|">= same"|"> newer"|"<= older"|"<= same"|"< older"|"= same") ;;
            *) return 1 ;;
        esac
    done
    return 0
}

# First string value of "key" in one advisory's JSON, still escaped. Inside a
# JSON string every quote is escaped, so the pattern cannot match text in a
# description. sed -n 1p rather than head: no early-exit pipe under pipefail.
_uh_json_str() {
    grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"([^\"\\\\]|\\\\.)*\"" <<<"$2" \
        | sed -n 1p | sed -E 's/^"[^"]*"[[:space:]]*:[[:space:]]*"//; s/"$//'
    return 0
}

# Advisory text arrives over the network and is printed to a terminal: decode
# the common escapes, drop \uXXXX and anything that is not printable.
_uh_json_text() {
    local s="$1"
    s="${s//\\\"/\"}"; s="${s//\\n/ }"; s="${s//\\t/ }"
    s=$(sed -E 's/\\u[0-9A-Fa-f]{4}//g; s/\\\\/\\/g' <<<"$s")
    printf '%s' "${s//[^[:print:]]/}"
}

# Warns about every published advisory of UH_UPDATE_REPO whose affected range
# includes the running version. Part of the update check, so it runs only when
# the user asks for that. Returns 0 always.
_uh_check_advisories() {
    local api="https://api.github.com/repos/${UH_UPDATE_REPO}/security-advisories?state=published&per_page=100"
    local response
    response=$(curl -fsSL --max-time 4 "$api" 2>/dev/null) || {
        log_info "Security advisory check skipped (GitHub unreachable or rate-limited)"
        return 0
    }
    # One advisory per line: ghsa_id is the first key of every advisory, and
    # the key cannot occur unescaped anywhere else.
    response="${response//[$'\r\n']/ }"
    response="${response//\"ghsa_id\":/$'\n'\"ghsa_id\":}"

    local chunk ghsa severity summary patched ranges range rc found=0 unsure=0 affected
    local ghsa_re='^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$'
    while IFS= read -r chunk; do
        [[ "$chunk" == '"ghsa_id":'* ]] || continue
        ghsa=$(_uh_json_str ghsa_id "$chunk")
        [[ "$ghsa" =~ $ghsa_re ]] || continue
        [[ -z "$(_uh_json_str withdrawn_at "$chunk")" ]] || continue
        ranges=$(grep -oE '"vulnerable_version_range"[[:space:]]*:[[:space:]]*"[^"]*"' <<<"$chunk" \
                 | sed -E 's/.*:[[:space:]]*"//; s/"$//') || true
        affected=1
        while IFS= read -r range; do
            [[ -n "$range" ]] || continue
            rc=0; _uh_version_in_range "$UH_VERSION" "$range" || rc=$?
            if (( rc == 0 )); then affected=0; break; fi
            (( rc == 2 )) && affected=2
        done <<<"$ranges"
        (( affected == 1 )) && continue

        severity=$(_uh_json_str severity "$chunk")
        [[ "$severity" =~ ^(low|medium|high|critical)$ ]] || severity="unknown severity"
        summary=$(_uh_json_text "$(_uh_json_str summary "$chunk")")
        patched=$(_uh_json_str patched_versions "$chunk")
        patched="${patched//[^0-9A-Za-z.,<>= _-]/}"
        if (( affected == 2 )); then
            unsure=$((unsure + 1))
            printf '%b %s%b\n' "${YELLOW}${WARNING}" \
                "Could not tell whether v${UH_VERSION} is affected by ${ghsa} (${severity}): ${summary}" "${NC}"
        else
            found=$((found + 1))
            printf '%b %s%b\n' "${RED}${WARNING}" \
                "Security: v${UH_VERSION} is affected by ${ghsa} (${severity}): ${summary}" "${NC}"
        fi
        printf '%b   %s%b\n' "${CYAN}" \
            "Fixed in ${patched:-no release yet}: https://github.com/${UH_UPDATE_REPO}/security/advisories/${ghsa}" "${NC}"
    done <<<"$response"

    (( found + unsure == 0 )) && log_info "No published security advisory affects v${UH_VERSION}"
    return 0
}

# Explicitly-invoked only (menu option U, or --check-update) — never
# called automatically at startup. "No telemetry, no network calls" is a
# documented trust claim on the project site; the only outbound requests
# this tool ever makes are these two to GitHub (the latest release, then
# the published security advisories), and only when the user asks for it.
#
# Prints a human-readable result and returns 0 always.
check_for_updates() {
    if ! _uh_valid_repo "$UH_UPDATE_REPO"; then
        log_warning "UH_UPDATE_REPO $(printf '%q' "$UH_UPDATE_REPO") is not a valid owner/repo — skipping update check"
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        log_info "curl not found — skipping update check"
        return 0
    fi

    local api="https://api.github.com/repos/${UH_UPDATE_REPO}/releases/latest"
    local response
    response=$(curl -fsSL --max-time 4 "$api" 2>/dev/null) || {
        log_info "Update check skipped (no network or GitHub unreachable)"
        return 0
    }

    local latest_tag
    latest_tag=$(grep -m1 '"tag_name"' <<<"$response" | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([^"]+)".*/\1/')
    [[ -n "$latest_tag" ]] || { log_info "Update check: couldn't parse GitHub's response"; return 0; }

    latest_tag="${latest_tag//[^0-9A-Za-z._-]/}"
    [[ -n "$latest_tag" ]] || { log_info "Update check: tag contained only unsafe characters"; return 0; }

    local cmp
    cmp=$(_uh_version_cmp "$latest_tag" "$UH_VERSION")
    case "$cmp" in
        newer)
            echo -e "${YELLOW}${WARNING} A newer release is available: v${latest_tag} (you have v${UH_VERSION})${NC}"
            echo -e "${CYAN}   https://github.com/${UH_UPDATE_REPO}/releases/latest${NC}"
            ;;
        same)
            log_info "Up to date (v${UH_VERSION})" ;;
        older)
            log_info "Running v${UH_VERSION}, ahead of the latest tagged release (v${latest_tag})" ;;
    esac
    _uh_check_advisories
    return 0
}
