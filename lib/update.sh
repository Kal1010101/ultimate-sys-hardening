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

# Explicitly-invoked only (menu option U, or --check-update) — never
# called automatically at startup. "No telemetry, no network calls" is a
# documented trust claim on the project site; the only outbound request
# this tool ever makes is this one, and only when the user asks for it.
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
    latest_tag=$(echo "$response" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([^"]+)".*/\1/')
    [[ -n "$latest_tag" ]] || { log_info "Update check: couldn't parse GitHub's response"; return 0; }

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
    return 0
}
