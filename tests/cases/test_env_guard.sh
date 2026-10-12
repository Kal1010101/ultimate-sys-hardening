#!/bin/bash
# Env files with credentials never enter the repository. Real env files
# (.env, .env.local, app.env, .envrc, ...) are refused; templates
# (.env.example/.sample/.template/.dist) are allowed unless a secret-looking key
# has a value or a private key is pasted in. pre-commit checks staged files;
# pre-push also catches `git add -f`, `commit --no-verify` and older commits.
#
# Runs in a scratch repository with a scratch bare "remote". Needs no root.
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"
HOOKS="$REPO/scripts/hooks"
require_cmd git

[[ -x "$HOOKS/pre-push" && -f "$HOOKS/env-guard.sh" ]] || { fail "env guard hooks are missing"; finish; }

W="${TMPDIR:-/tmp}/uh_envguard_$$"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
git init -q --bare "$W/remote.git"
git init -q "$W/work"
cd "$W/work" || exit 1
git config user.name t; git config user.email t@t; git config commit.gpgsign false
git config core.hooksPath "$HOOKS"
git remote add origin "$W/remote.git"

# $1 = path, $2 = content, $3 = expect (refuse|allow)
try_commit() {
    mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; git add -f "$1"
    if git commit -q -m "add $1" >/dev/null 2>&1; then
        [[ "$3" == allow ]] && pass_msg "pre-commit allows $1 ($4)" || { fail "pre-commit let $1 through ($4)"; git reset -q --hard HEAD~1; }
    else
        [[ "$3" == refuse ]] && pass_msg "pre-commit refuses $1 ($4)" || fail "pre-commit refused $1 ($4)"
        git rm -q --cached "$1"; rm -f "$1"
    fi
}

# --- real env files: always refused --------------------------------------------
for f in .env .env.local .env.production config/.env app.env app.env.local .envrc; do
    try_commit "$f" "DEBUG=1" refuse "real env file"
done

# --- templates: allowed when clean, refused with a secret filled in -------------
try_commit .env.example          $'UH_BACKUP_ROOT=/root\nAPI_TOKEN=\nDB_PASSWORD=<your-password>' allow  "empty and placeholder secrets"
try_commit config/app.env.sample $'# API_KEY=fill-me-in later\nLOG_LEVEL=info'                  allow  "secret only in a comment"
try_commit secrets.env.example   'API_TOKEN=abc123'                                           refuse "token filled in"
try_commit db.env.template       'export DB_PASSWORD="hunter2"'                               refuse "password filled in"
try_commit key.env.dist          $'SSH_KEY=\n-----BEGIN OPENSSH PRIVATE KEY-----'            refuse "private key pasted in"

# --- ordinary files are untouched ------------------------------------------------
for f in environment.md docs/env-setup.md README.md; do
    try_commit "$f" "x" allow "not an env file"
done

# --- push --------------------------------------------------------------------------
git branch -q -M main
git push -q origin main >/dev/null 2>&1 && pass_msg "pre-push allows a push with only clean templates" \
                                        || fail "pre-push refused a clean push"

echo "DEBUG=1" > .env; git add -f .env; git commit -q --no-verify -m sneak >/dev/null 2>&1
out=$(git push origin main 2>&1); rc=$?
[[ $rc -ne 0 ]] && pass_msg "pre-push refuses a real .env committed with --no-verify" \
                || fail "pre-push let a --no-verify .env through"
assert_output_contains "$out" '.env' "and names the file"

git rm -q .env; git commit -q --no-verify -m remove >/dev/null 2>&1
git push origin main >/dev/null 2>&1 && fail "pre-push let history carrying a .env through" \
                                     || pass_msg "pre-push still refuses while an unpushed commit carries it"
git reset -q --hard origin/main

echo 'API_TOKEN=abc123' > .env.example; git add .env.example; git commit -q --no-verify -m leak >/dev/null 2>&1
git push origin main >/dev/null 2>&1 && fail "pre-push let a template with a token through" \
                                     || pass_msg "pre-push refuses a template with a token filled in"

finish
