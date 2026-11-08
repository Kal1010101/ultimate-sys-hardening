#!/bin/bash
# Module 17 must merge into an existing /etc/docker/daemon.json, not replace it;
# must not turn on userns-remap where Docker already holds data (it would hide
# every existing container, image and volume); and must not restart Docker
# while that would stop running containers.
#
# docker is a stub; the service manager is trapped so the host's real one is
# never reached. Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
command -v python3 >/dev/null 2>&1 || skip "python3 is needed to merge daemon.json"

W="${TMPDIR:-/tmp}/uh_dockmerge_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

run() {   # $1 = docker stub mode: empty | data | running | running-lr | down
    : > "$W/calls"
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        DRY_RUN=false; SKIP_BACKUP=false; LOG_FILE='$W/run.log'; UH_DOCKER_CONF='$W/daemon.json'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'; BACKUP_DIR='$W/backups/hardening_backup_1'
        count_fix() { :; }; confirm() { return 0; }
        restart_service() { echo \"RESTART \$1\" >> '$W/calls'; }
        systemctl() { echo FORBIDDEN >> '$W/calls'; return 1; }
        MODE='$1'
        docker() {
            case \"\$1 \${2:-}\" in
                'info ') [[ \$MODE != down ]] ;;
                'info --format') [[ \$MODE == running-lr ]] && echo true || echo false ;;
                'ps -aq'|'images -q'|'volume ls') [[ \$MODE == empty ]] || echo abc123 ;;
                'ps -q') [[ \$MODE == running* ]] && echo abc123 ;;
            esac
            [[ \$MODE != down ]]
        }
        apply_docker_security" >"$W/out" 2>&1
}
json() { python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1])); print(json.dumps(c.get(sys.argv[2])))' "$W/daemon.json" "$1"; }

# --- an admin's config on a host that already has containers -----------------
printf '{ "data-root": "/srv/docker", "log-driver": "journald", "registry-mirrors": ["https://m.example"] }\n' > "$W/daemon.json"
run data
[[ "$(json data-root)" == '"/srv/docker"' ]] && pass_msg "the admin's data-root is kept" || fail "data-root is $(json data-root)"
[[ "$(json registry-mirrors)" == '["https://m.example"]' ]] && pass_msg "and their registry mirrors" || fail "registry-mirrors is $(json registry-mirrors)"
[[ "$(json log-driver)" == '"journald"' && "$(json log-opts)" == null ]] && pass_msg "their log driver is left alone" || fail "log-driver $(json log-driver), log-opts $(json log-opts)"
[[ "$(json icc)" == false && "$(json live-restore)" == true ]] && pass_msg "icc off and live-restore on are added" || fail "icc $(json icc), live-restore $(json live-restore)"
[[ "$(json userns-remap)" == null ]] && pass_msg "userns-remap is left off where Docker already holds data" || fail "userns-remap was turned on over existing data"
assert_output_contains "$(cat "$W/out")" 'userns-remap left off' "and the operator is told why"
assert_output_contains "$(cat "$W/calls")" '^RESTART docker$' "Docker is restarted when no container is running"

# --- a fresh host with no daemon.json ------------------------------------------
rm -f "$W/daemon.json"; rm -rf "$W/backups"
run empty
[[ "$(json userns-remap)" == '"default"' ]] && pass_msg "userns-remap is on where Docker holds nothing yet" || fail "userns-remap missing on an empty Docker"

# --- running containers, live-restore not on yet -------------------------------
printf '{}\n' > "$W/daemon.json"; rm -rf "$W/backups"
run running
if grep -q '^RESTART' "$W/calls"; then fail "Docker was restarted with containers running and no live-restore"; else pass_msg "Docker is not restarted while that would stop running containers"; fi
assert_output_contains "$(cat "$W/out")" 'not restarted' "and the operator is told"
run running-lr
assert_output_contains "$(cat "$W/calls")" '^RESTART docker$' "with live-restore already on, the restart goes ahead"

# --- Docker not running: userns-remap cannot be judged, so it stays off --------
rm -f "$W/daemon.json"; rm -rf "$W/backups"
run down
[[ "$(json userns-remap)" == null ]] && pass_msg "with Docker down, userns-remap stays off (cannot tell if data exists)" || fail "userns-remap turned on blind"

# --- a file that is not valid JSON is left alone -------------------------------
printf '{ "debug": true, \n' > "$W/daemon.json"; before=$(checksum "$W/daemon.json"); rm -rf "$W/backups"
run data
assert_unchanged "$W/daemon.json" "$before" "an unreadable daemon.json is left unchanged"
assert_output_contains "$(cat "$W/out")" 'could not be merged' "and the operator is told"

# --- reverting module 17 must not stop running containers either --------------
# The restored daemon.json may lack live-restore; a daemon started without it
# stopped a running container on a lab guest.
revert_run() {   # $1 = docker stub mode
    : > "$W/calls"
    env DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
        bash -c "set -uo pipefail
        source '$REPO/lib/core.sh'; source '$REPO/lib/platform.sh'; source '$REPO/lib/modules.sh'
        source '$REPO/lib/cis.sh'; source '$REPO/lib/menu.sh'
        AUTO_MODE=true; DRY_RUN=false; LOG_FILE='$W/run.log'
        UH_BACKUP_ROOT='$W/backups'; BACKUP_GENESIS_DIR='$W/backups/genesis'
        revert_backed_up_file() { return 0; }
        is_service_active() { [[ \$1 == docker ]]; }
        restart_service() { echo \"RESTART \$1\" >> '$W/calls'; }
        systemctl() { echo FORBIDDEN >> '$W/calls'; return 1; }
        docker() { [[ \"\$1 \${2:-}\" == 'ps -q' && '$1' == running ]] && echo abc123; return 0; }
        revert_module docker" >"$W/out" 2>&1
}
revert_run running
if grep -q '^RESTART' "$W/calls"; then fail "revert restarted Docker with a container running"; else pass_msg "revert does not restart Docker while a container runs"; fi
assert_output_contains "$(cat "$W/out")" 'not restarted' "and says so"
revert_run idle
assert_output_contains "$(cat "$W/calls")" '^RESTART docker$' "with nothing running, revert restarts Docker to load the restored file"

grep -q FORBIDDEN "$W/calls" && fail "the host's real systemctl was reached" || pass_msg "no real service manager was reached"
finish
