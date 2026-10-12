
ENV_NAME_RE='(^|/)[^/]*\.env(\.[^/]*)?$|(^|/)\.envrc$'
ENV_TEMPLATE_RE='(^|/)[^/]*\.env\.(example|sample|template|dist)$'
ENV_SECRET_RE='^[[:space:]]*(export[[:space:]]+)?[A-Z0-9_]*(PASS|SECRET|TOKEN|KEY|CRED|PRIVATE|AUTH)[A-Z0-9_]*[[:space:]]*=[[:space:]]*["'\'']?[^"'\''[:space:]#<]'
ENV_PEM_RE='-----BEGIN [A-Z ]*PRIVATE KEY-----'


env_guard_check() {
    local path="$1" content="$2"
    grep -qE "$ENV_NAME_RE" <<< "$path" || return 0
    if ! grep -qE "$ENV_TEMPLATE_RE" <<< "$path"; then
        echo "$path: real env file (only .env.example/.sample/.template/.dist templates are allowed)"
        return 1
    fi
    if grep -qE "$ENV_SECRET_RE" <<< "$content" || grep -qE -- "$ENV_PEM_RE" <<< "$content"; then
        echo "$path: template has a value for a secret-looking key (leave it empty or use <placeholder>)"
        return 1
    fi
    return 0
}
