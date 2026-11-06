#!/bin/bash
source "${REPO_ROOT:-/repo}/tests/lib/assert.sh"
REPO="${REPO_ROOT:-/repo}"

require_cmd python3

shopt -s nullglob
pages=("$REPO"/docs/*.html)
[[ ${#pages[@]} -gt 0 ]] || skip "no docs/*.html pages"

for page in "${pages[@]}"; do
    name="docs/${page##*/}"
    out=$(python3 -I - "$page" <<'EOF'
import base64, hashlib, re, sys

html = open(sys.argv[1], encoding="utf-8").read()
problems = []

csp_tags = re.findall(r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"', html, re.I)
if len(csp_tags) != 1:
    problems.append(f"expected one Content-Security-Policy meta tag, found {len(csp_tags)}")
    csp = ""
else:
    csp = csp_tags[0]

directives = {}
for part in csp.split(";"):
    words = part.split()
    if words:
        directives[words[0].lower()] = words[1:]

if csp:
    if directives.get("default-src") != ["'none'"]:
        problems.append("CSP default-src is not 'none'")
    for name in ("base-uri", "form-action"):
        if directives.get(name) != ["'none'"]:
            problems.append(f"CSP {name} is not 'none'")
    script_src = directives.get("script-src", [])
    for unsafe in ("'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:"):
        if unsafe in script_src:
            problems.append(f"CSP script-src allows {unsafe}")
    lower = html.lower()
    first_script = lower.find("<script")
    if first_script != -1 and lower.find('http-equiv="content-security-policy"') > first_script:
        problems.append("CSP meta tag comes after a script")

    allowed_hashes = {w[len("'sha256-"):-1] for w in script_src if w.startswith("'sha256-")}
    for body in re.findall(r"<script>(.*?)</script>", html, re.S):
        digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        if digest not in allowed_hashes:
            problems.append(f"inline script sha256-{digest} is not listed in script-src")

if re.search(r"<script[^>]*\bsrc=", html, re.I):
    problems.append("page loads an external script")
for tag in ("iframe", "object", "embed", "form"):
    if re.search(rf"<{tag}\b", html, re.I):
        problems.append(f"page contains <{tag}>")
if re.search(r"\son[a-z]+\s*=", html, re.I):
    problems.append("page uses an inline event handler attribute")

for attr, url in re.findall(r'\b(src|srcset|poster|data-full)="((?:https?:)?//[^"]*)"', html, re.I):
    problems.append(f"{attr} loads from another site: {url}")
for url in re.findall(r'<link\b[^>]*\bhref="((?:https?:)?//[^"]*)"', html, re.I):
    problems.append(f"<link> loads from another site: {url}")
for url in re.findall(r"url\(\s*['\"]?((?:https?:)?//[^'\")]*)", html, re.I):
    problems.append(f"CSS loads from another site: {url}")
if re.search(r"@import|@font-face", html, re.I):
    problems.append("CSS imports a stylesheet or font")

for url in re.findall(r'href="(http://[^"]*)"', html, re.I):
    problems.append(f"link over plain http: {url}")
for tag in re.findall(r"<a\b[^>]*>", html, re.I):
    if re.search(r'target="_blank"', tag, re.I) and not re.search(r'rel="[^"]*noopener', tag, re.I):
        problems.append(f"target=_blank link without rel=noopener: {tag}")

mails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html))
mails.discard("ultimate-sys-hardening@protonmail.com")
for mail in sorted(mails):
    problems.append(f"address other than the project's: {mail}")

print("\n".join(problems))
EOF
    ) || { fail "$name: the page check itself failed"; continue; }
    if [[ -z "$out" ]]; then
        pass_msg "$name: CSP covers every script, nothing loads from another site, only the project address"
    else
        while IFS= read -r problem; do fail "$name: $problem"; done <<<"$out"
    fi
done

for doc in "$REPO"/docs/*.md "$REPO"/README.md "$REPO"/SECURITY.md "$REPO"/CONTRIBUTING.md; do
    [[ -f "$doc" ]] || continue
    others=$(grep -o -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$doc" \
             | grep -v -x -E 'ultimate-sys-hardening@protonmail\.com|git@github\.com|user@[0-9x.]+' | sort -u)
    [[ -z "$others" ]] && pass_msg "${doc#"$REPO"/}: only the project address" \
                       || fail "${doc#"$REPO"/}: address other than the project's: $(tr '\n' ' ' <<<"$others")"
done

finish
