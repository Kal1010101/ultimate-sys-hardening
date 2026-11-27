#!/bin/bash
# =============================================================================
#  docs/build-demo.sh — build docs/demo.html's replay from real recordings
#
#  docs/capture-demo.sh records the tool in a real terminal, once per menu
#  choice, on a throwaway VM. This turns those recordings into the JSON block
#  docs/demo.html plays back, and keeps the page's CSP script hash in step with
#  its inline script.
#
#  Nothing is written by hand. Each screen is cut out of the terminal's own
#  bytes and its ANSI colour turned into spans, the same way build-terminals.sh
#  does it for the homepage. The build refuses to run if a recording is
#  incomplete, or if the menu drawn after any choice differs from the menu
#  drawn before it: every recording is --dry-run, so a changed menu would mean
#  a dry run changed the machine, and that must not be published as a demo.
#
#  Usage: ./docs/build-demo.sh <recordings-dir>   rewrite docs/demo.html
#         ./docs/build-demo.sh --hash-only        only refresh the CSP hash
# =============================================================================
set -euo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PAGE="$REPO/docs/demo.html"
ARG="${1:?usage: $0 <recordings-dir> | --hash-only}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# --- recordings -> JSON -------------------------------------------------------
cat > "$work/build.py" <<'PY'
import html, io, json, pathlib, re, sys

rec_dir, page = pathlib.Path(sys.argv[1]), sys.argv[2]

# Choices in menu order, and the short labels for the buttons under the
# terminal: the paths a first-time visitor most wants to see.
ORDER = [str(n) for n in range(1, 26)] + ["C", "U", "R", "S"]
QUICK = [("2", "SSH hardening"), ("3", "Firewall"), ("6", "Kernel & network"),
         ("24", "Apply all safe"), ("C", "Compliance check"), ("R", "Revert")]

CLEAR = "\x1b[H\x1b[2J\x1b[3J"
SGR = re.compile(r"\x1b\[([0-9;]*)m")
# Every escape except colour (SGR, the ones ending in "m"): cursor moves,
# mode switches, charset selects. They mean nothing once the text is HTML.
OTHER_ESC = re.compile(r"\x1b\[[0-9;?]*[A-Za-ln-z]|\x1b[()][A-Z0-9]")
CLASS = {"0;32": "c-g", "0;36": "c-c", "1;33": "c-a", "1;37": "c-w",
         "0;31": "c-r", "0;34": "c-b", "0;35": "c-c"}
PRESS_ENTER = "  Press Enter to return to the menu..."
CHOICE_PROMPT = "\x1b[1;37mChoice:\x1b[0m "
DISTRO_PROMPT = "Enter choice (0-13): "
# The run opens on the profile screen (same Choice: prompt as the menu); the
# demo answers it with cis, and P at the end of each run comes back to it.
PROFILE_TITLE = "CHOOSE A HARDENING PROFILE"
PROFILE_KEY = "2"


def fail(msg):
    sys.exit("build-demo: " + msg)


def to_html(text):
    """ANSI-coloured text -> escaped HTML with <span class="c-*"> runs."""
    out = []
    for line in text.split("\n"):
        pos, buf, open_span = 0, [], False
        for m in SGR.finditer(line):
            buf.append(html.escape(line[pos:m.start()]))
            if open_span:
                buf.append("</span>"); open_span = False
            cls = CLASS.get(m.group(1))
            if cls:
                buf.append('<span class="%s">' % cls); open_span = True
            pos = m.end()
        buf.append(html.escape(line[pos:]))
        if open_span:
            buf.append("</span>")
        out.append("".join(buf))
    return "\n".join(out)


def load(choice):
    path = rec_dir / ("choice-%s.raw" % choice)
    if not path.is_file():
        fail("missing recording %s" % path)
    raw = path.read_bytes().decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
    # [profile, distro, menu+choice, menu+..., profile+Q] (no trailing profile
    # screen when the tool exited after the choice)
    screens = raw.split(CLEAR)[1:]
    screens = [OTHER_ESC.sub("", s) for s in screens]
    if len(screens) < 3:
        fail("%s: expected the profile screen, the distro menu and the main menu, "
             "got %d screens" % (path.name, len(screens)))
    if PROFILE_TITLE not in screens[0]:
        fail("%s: the recording does not open on the profile screen" % path.name)
    return path.name, screens


def is_profile(screen):
    return PROFILE_TITLE in screen


def split_menu(name, screen):
    """A main-menu screen -> (menu text, what followed the Choice: prompt)."""
    i = screen.find("  " + CHOICE_PROMPT)
    if i < 0:
        fail("%s: no Choice: prompt in a menu screen" % name)
    return screen[:i], screen[i + len("  " + CHOICE_PROMPT):]


def choice_output(name, choice, after_prompt, is_last_screen):
    """-> (output text, whether the tool exited instead of returning to the menu).

    A choice normally ends at "Press Enter to return to the menu". When the
    tool exits instead, the menu screen is the recording's last one and the
    output simply stops; the replay shows that as it happened, ending at a
    shell prompt. A choice cut off by CHOICE_WAIT looks different: more
    screens follow it, because the later answers landed in a fresh menu.
    """
    typed, _, rest = after_prompt.partition("\n")
    if typed.strip() != choice:
        fail("%s: the recording answered %r, not %r" % (name, typed.strip(), choice))
    end = rest.find(PRESS_ENTER)
    if end >= 0:
        return rest[:end].rstrip("\n") + "\n", False
    if not is_last_screen:
        fail("%s: no 'Press Enter' line; the choice did not finish in time. "
             "Raise CHOICE_WAIT in capture-demo.sh and record again." % name)
    return rest.rstrip("\n") + "\n", True


name, first = load(ORDER[0])
profile_screen = first[0]
profile, after = split_menu(name, profile_screen)
if after.partition("\n")[0].strip() != PROFILE_KEY:
    fail("%s: the profile screen was not answered %s (cis)" % (name, PROFILE_KEY))
profile = profile.rstrip("\n") + "\n"
distro_screen = first[1]
d = distro_screen.find(DISTRO_PROMPT)
if d < 0:
    fail("%s: no distro prompt" % name)
distro = distro_screen[:d].rstrip("\n") + "\n"
detected = distro_screen[d + len(DISTRO_PROMPT):].partition("\n")[2].strip("\n")
menu, _ = split_menu(name, first[2])
menu = menu.rstrip("\n") + "\n"

choices = {}
for choice in ORDER:
    name, screens = load(choice)
    if screens[0] != profile_screen:
        fail("%s: the profile screen differs from %s" % (name, "choice-1.raw"))
    if screens[1] != distro_screen:
        fail("%s: the distro screen differs from %s" % (name, "choice-1.raw"))
    body = screens[2:]
    back_to_profile = is_profile(body[-1])
    menus = body[:-1] if back_to_profile else body
    if not menus:
        fail("%s: no main menu between the distro screen and the profile screen" % name)
    for n, screen in enumerate(menus, start=1):
        this_menu, _ = split_menu(name, screen)
        if this_menu.rstrip("\n") + "\n" != menu:
            fail("%s: menu #%d differs from the first one. A --dry-run choice changed "
                 "a module's state, which is a bug to fix before this is published." % (name, n))
    if back_to_profile and split_menu(name, body[-1])[0].rstrip("\n") + "\n" != profile:
        fail("%s: the profile screen after P differs from the first one" % name)
    exited = not back_to_profile and len(menus) == 1
    text, exits = choice_output(name, choice, split_menu(name, menus[0])[1], exited)
    choices[choice] = {"html": to_html(text), "exits": exits}

# The quit screen: P went back to the profile screen, which was answered Q;
# what follows is the tool's goodbye (log file, backup location).
name, screens = load(ORDER[0])
if not is_profile(screens[-1]):
    fail("%s: the recording does not end on the profile screen" % name)
_, after = split_menu(name, screens[-1])
typed, _, quit_text = after.partition("\n")
if typed.strip() != "Q":
    fail("%s: the profile screen at the end was not answered Q" % name)

meta = {}
for line in (rec_dir / "meta.txt").read_text(encoding="utf-8").splitlines():
    k, _, v = line.partition("=")
    meta[k] = v
for key in ("version", "profile", "os", "date"):
    if not meta.get(key):
        fail("meta.txt has no %s" % key)

data = {
    "launch": '<span class="c-f">#</span> <span class="c-w">./src/free/ultimate_hardening.sh --dry-run</span>',
    "profile": to_html(profile),
    "profileKey": PROFILE_KEY,
    "distro": to_html(distro),
    "distroPrompt": html.escape(DISTRO_PROMPT),
    "detected": to_html(detected),
    "menu": to_html(menu),
    "choicePrompt": "  " + to_html(CHOICE_PROMPT),
    "choices": choices,
    "pressEnter": html.escape(PRESS_ENTER),
    "quit": to_html(quit_text.rstrip("\n")),
    "quick": [{"key": k, "label": label} for k, label in QUICK],
    "provenance": ("Recorded with Ultimate Hardening %s (%s profile) on %s, a fresh lab VM, "
                   "on %s, by docs/capture-demo.sh. Every line is the tool's own output; "
                   "only the colours were converted to HTML."
                   % (meta["version"], meta["profile"], meta["os"], meta["date"])),
}

# "</" inside a <script> block would end it early; JSON allows "<\/".
blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
begin = "<!-- BEGIN generated demo-data: ./docs/build-demo.sh -->"
end = "<!-- END generated demo-data -->"
s = io.open(page, encoding="utf-8").read()
i, j = s.find(begin), s.find(end)
if i < 0 or j < 0:
    fail("demo-data markers not found in %s" % page)
new = '%s\n<script type="application/json" id="demo-data">%s</script>\n%s' % (begin, blob, end)
io.open(page, "w", encoding="utf-8").write(s[:i] + new + s[j + len(end):])
exiting = [k for k, v in choices.items() if v["exits"]]
print("  demo-data  %d choices, %d KB" % (len(choices), len(blob) // 1024))
if exiting:
    print("  note       the tool exits instead of returning to the menu after: %s"
          % " ".join(exiting))
PY

# --- CSP hash -----------------------------------------------------------------
# The browser hashes the exact text between <script> and </script>, so this
# reads the one executable inline script the same way and writes its hash into
# the CSP meta tag. The JSON block has a type attribute and is not hashed.
cat > "$work/hash.py" <<'PY'
import base64, hashlib, io, re, sys
page = sys.argv[1]
s = io.open(page, encoding="utf-8").read()
scripts = re.findall(r"<script>(.*?)</script>", s, re.S)
if len(scripts) != 1:
    sys.exit("build-demo: expected exactly one inline <script>, found %d" % len(scripts))
digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode()
new, n = re.subn(r"script-src 'sha256-[^']*'", "script-src 'sha256-%s'" % digest, s, count=1)
if n != 1:
    sys.exit("build-demo: no script-src hash in the CSP meta tag")
if new != s:
    io.open(page, "w", encoding="utf-8").write(new)
    print("  csp-hash   updated")
else:
    print("  csp-hash   up to date")
PY

if [[ "$ARG" != "--hash-only" ]]; then
    [[ -d "$ARG" ]] || { echo "build-demo: $ARG is not a directory" >&2; exit 1; }
    python3 -I "$work/build.py" "$ARG" "$PAGE"
fi
python3 -I "$work/hash.py" "$PAGE"
