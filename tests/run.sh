#!/bin/bash
# =============================================================================
#  tests/run.sh — integration test runner
#
#  Runs each test case inside a throwaway container, applies real hardening,
#  and asserts the system state actually changed. This is the difference
#  between "the script parses" and "the script works".
#
#  Usage:
#    ./tests/run.sh                      All cases on debian:12
#    ./tests/run.sh --distro fedora:40   All cases on a different image
#    ./tests/run.sh --case ssh           One case
#    ./tests/run.sh --all-distros        Full matrix
#    ./tests/run.sh --local              Run on THIS machine (destructive!)
#
#  Exit code is the number of failed cases, so CI can gate on it.
# =============================================================================

set -uo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CASE_DIR="$REPO_ROOT/tests/cases"

DISTRO="debian:12"
SINGLE_CASE=""
ALL_DISTROS=false
LOCAL_MODE=false

DISTRO_MATRIX=( "debian:12" "ubuntu:24.04" "fedora:40" "alpine:3.20" "archlinux:latest" )

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; WHITE=''; NC=''; }

PASSED=0; FAILED=0; SKIPPED=0
declare -a FAILED_CASES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro)      DISTRO="$2"; shift ;;
        --case)        SINGLE_CASE="$2"; shift ;;
        --all-distros) ALL_DISTROS=true ;;
        --local)       LOCAL_MODE=true ;;
        --help|-h)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# --------------------------------------------------------------- prerequisites
if [[ "$LOCAL_MODE" == false ]] && ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}docker not found.${NC} Install Docker, or use --local to run" >&2
    echo "tests directly on this machine (destructive — use a VM)." >&2
    exit 1
fi

list_cases() {
    if [[ -n "$SINGLE_CASE" ]]; then
        local f="$CASE_DIR/test_${SINGLE_CASE}.sh"
        [[ -f "$f" ]] || { echo -e "${RED}No such case: $SINGLE_CASE${NC}" >&2; exit 1; }
        echo "$f"
    else
        find "$CASE_DIR" -name 'test_*.sh' -type f | sort
    fi
}

# Bootstrap a container with bash + the tools the script expects to find.
bootstrap_cmd() {
    cat << 'BOOTSTRAP'
set -e
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y --no-install-recommends bash procps iproute2 openssh-server >/dev/null 2>&1
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False bash procps-ng iproute openssh-server findutils >/dev/null 2>&1
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache bash procps iproute2 openssh >/dev/null 2>&1
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm bash procps-ng iproute2 openssh >/dev/null 2>&1
fi
BOOTSTRAP
}

run_case_in_docker() {
    local case_file="$1" image="$2"
    local case_name; case_name=$(basename "$case_file" .sh | sed 's/^test_//')

    printf "  %-22s %-18s " "$case_name" "$image"

    local output
    output=$(docker run --rm \
        -v "$REPO_ROOT:/repo:ro" \
        -e "UH_TEST=1" \
        "$image" \
        /bin/sh -c "$(bootstrap_cmd); exec bash /repo/tests/cases/$(basename "$case_file")" 2>&1)
    local rc=$?

    case $rc in
        0)  echo -e "${GREEN}PASS${NC}"; PASSED=$((PASSED+1)) ;;
        77) echo -e "${YELLOW}SKIP${NC}"; SKIPPED=$((SKIPPED+1))
            echo "$output" | grep -E '^SKIP:' | sed 's/^/      /' ;;
        *)  echo -e "${RED}FAIL${NC}"; FAILED=$((FAILED+1))
            FAILED_CASES+=("$case_name @ $image")
            echo "$output" | grep -E '^(ASSERT|FAIL|ERROR):' | sed 's/^/      /' | head -8
            [[ -n "${VERBOSE:-}" ]] && echo "$output" | tail -30 | sed 's/^/      | /'
            ;;
    esac
}

run_case_local() {
    local case_file="$1"
    local case_name; case_name=$(basename "$case_file" .sh | sed 's/^test_//')
    printf "  %-22s %-18s " "$case_name" "local"

    local output; output=$(UH_TEST=1 REPO_ROOT="$REPO_ROOT" bash "$case_file" 2>&1)
    local rc=$?
    case $rc in
        0)  echo -e "${GREEN}PASS${NC}"; PASSED=$((PASSED+1)) ;;
        77) echo -e "${YELLOW}SKIP${NC}"; SKIPPED=$((SKIPPED+1)) ;;
        *)  echo -e "${RED}FAIL${NC}"; FAILED=$((FAILED+1))
            FAILED_CASES+=("$case_name @ local")
            echo "$output" | grep -E '^(ASSERT|FAIL|ERROR):' | sed 's/^/      /' | head -8 ;;
    esac
}

# ---------------------------------------------------------------------- main --
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${WHITE}  Ultimate Hardening — integration tests${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [[ "$LOCAL_MODE" == true ]]; then
    echo -e "${YELLOW}  WARNING: --local modifies THIS machine. Use a VM.${NC}"
    read -r -p "  Type 'yes' to continue: " ok
    [[ "$ok" == "yes" ]] || exit 1
    echo ""
    while IFS= read -r c; do run_case_local "$c"; done < <(list_cases)
else
    targets=("$DISTRO")
    [[ "$ALL_DISTROS" == true ]] && targets=("${DISTRO_MATRIX[@]}")

    for image in "${targets[@]}"; do
        echo ""
        echo -e "${WHITE}  ${image}${NC}"
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo -n "  pulling... "
            # A pull failure must count as a real failure, not a silent skip:
            # otherwise a registry hiccup makes this exit 0 with 0 cases run,
            # which would report as CI SUCCESS despite nothing being tested.
            docker pull -q "$image" >/dev/null 2>&1 && echo "done" || {
                echo -e "${RED}failed${NC}"
                FAILED=$((FAILED+1))
                FAILED_CASES+=("(could not pull image) @ $image")
                continue
            }
        fi
        while IFS= read -r c; do run_case_in_docker "$c" "$image"; done < <(list_cases)
    done
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}passed ${PASSED}${NC}   ${RED}failed ${FAILED}${NC}   ${YELLOW}skipped ${SKIPPED}${NC}"
if [[ ${#FAILED_CASES[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Failures:${NC}"
    printf '    %s\n' "${FAILED_CASES[@]}"
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

exit "$FAILED"
