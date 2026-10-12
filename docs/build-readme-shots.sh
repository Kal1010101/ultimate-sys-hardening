#!/bin/bash
# =============================================================================
#  docs/build-readme-shots.sh — the README's screenshots, drawn like the site
#
#  GitHub strips CSS and scripts from READMEs, so the site's terminal windows
#  (.term in docs/index.html) are rendered to PNG instead: same title bar and
#  dots, same colours, same text. The text is read from the blocks
#  docs/build-terminals.sh generates into index.html from the real code, so the
#  README and the site cannot disagree. Run build-terminals.sh first.
#
#  Needs python3 and rsvg-convert (librsvg); fonts DejaVu Sans Mono and Noto
#  Color Emoji for the box drawing and the emoji.
#  Usage: ./docs/build-readme-shots.sh
# =============================================================================
set -euo pipefail

DOCS="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DOCS/images/readme"
command -v rsvg-convert >/dev/null || { echo "rsvg-convert (librsvg) not found" >&2; exit 1; }
mkdir -p "$OUT"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/render.py" <<'PY'
import html, re, sys
index, outdir = sys.argv[1:3]
src = open(index, encoding="utf-8").read()

FS, LH, PAD, BAR = 13.0, 1.5, 18.0, 31.0
CW = 0.6021 * FS                       # DejaVu Sans Mono advance width
MONO = "DejaVu Sans Mono, Noto Color Emoji, monospace"
COL = {"c-g": "#3fb950", "c-c": "#39c5cf", "c-a": "#d29922",
       "c-w": "#e6edf3", "c-f": "#6e7d8d", "c-r": "#f85149"}
SPAN = re.compile(r'<span class="(c-[a-z])">(.*?)</span>', re.S)

def segments(line):
    out, pos = [], 0
    for m in SPAN.finditer(line):
        if m.start() > pos: out.append((None, line[pos:m.start()]))
        out.append((m.group(1), m.group(2))); pos = m.end()
    if pos < len(line): out.append((None, line[pos:]))
    return [(c, text_symbols(html.unescape(t))) for c, t in out]

# librsvg cannot draw colour emoji, so swap each for a text symbol the mono font
# has, padded to the two columns the emoji takes in a terminal.
EMOJI = {"\u2705": "\u2714 ", "\u26a0\ufe0f": "\u26a0 ", "\U0001f4ca": "\u25b8 "}
def text_symbols(t):
    for k, v in EMOJI.items(): t = t.replace(k, v)
    return t

def block(name):
    b = src.index("<!-- BEGIN generated %s:" % name)
    e = src.index("<!-- END generated %s -->" % name)
    body = src[src.index("-->", b) + 3:e].strip("\n")
    title = re.findall(r'class="term-title">([^<]*)<', src[:b])[-1]
    tag = '<div class="term-body">'
    pre = src[src.rindex(tag, 0, b) + len(tag):b]
    return html.unescape(title), pre.strip("\n"), body

def wrap(segs, width=96, indent=7):
    # The site hangs wrapped compliance lines under the message (7ch); do the same.
    if len("".join(t for _, t in segs)) <= width: return [segs]
    lines, cur, n = [], [], 0
    for c, t in segs:
        for word in re.split(r"(\s+)", t):
            if n + len(word) > width and n > indent:
                lines.append(cur); cur, n = [(None, " " * indent)], indent
                if word.isspace(): continue
            cur.append((c, word)); n += len(word)
    lines.append(cur)
    return lines

def render(name, out, lines_mode):
    title, pre, body = block(name)
    rows = [segments(l) for l in pre.split("\n")] if pre else []
    if lines_mode:
        for ln in re.findall(r'<div class="ln">(.*?)</div>', body, re.S):
            rows.extend(wrap(segments(ln)))
    else:
        rows.extend(segments(l) for l in body.split("\n"))
    cols = max(len("".join(t for _, t in r)) for r in rows)
    W = round(cols * CW + 2 * PAD + 4)
    H = round(BAR + 2 * PAD + len(rows) * FS * LH)
    e = html.escape
    s = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">' % (W, H),
         '<defs><clipPath id="c"><rect width="%d" height="%d" rx="10"/></clipPath></defs>' % (W, H),
         '<g clip-path="url(#c)"><rect width="%d" height="%d" fill="#0b0f14"/>' % (W, H),
         '<rect width="%d" height="%d" fill="#161b22"/>' % (W, BAR),
         '<line x1="0" y1="%.1f" x2="%d" y2="%.1f" stroke="#232c38"/></g>' % (BAR - .5, W, BAR - .5),
         '<rect x=".5" y=".5" width="%d" height="%d" rx="10" fill="none" stroke="#232c38"/>' % (W - 1, H - 1)]
    for i, c in enumerate(("#f85149", "#d29922", "#3fb950")):
        s.append('<circle cx="%.1f" cy="15.5" r="5.5" fill="%s"/>' % (19.5 + i * 18, c))
    s.append('<text x="69" y="20" font-family="%s" font-size="12" fill="#6e7d8d">%s</text>' % (MONO, e(title)))
    for i, r in enumerate(rows):
        y = BAR + PAD + i * FS * LH + (FS * LH + FS * .72) / 2
        spans = "".join('<tspan fill="%s">%s</tspan>' % (COL.get(c, "#9aa7b4"), e(t)) for c, t in r if t)
        s.append('<text x="%.1f" y="%.1f" xml:space="preserve" font-family="%s" font-size="%g" fill="#9aa7b4">%s</text>'
                 % (PAD, y, MONO, FS, spans))
    s.append("</svg>")
    open("%s/%s.svg" % (outdir, out), "w", encoding="utf-8").write("\n".join(s))
    print("  %-16s %d rows, %d cols" % (out, len(rows), cols))

render("distro",  "distro-menu",      False)
render("modules", "overview",         False)
render("cis",     "compliance-check", True)
PY

python3 -I "$tmp/render.py" "$DOCS/index.html" "$tmp"
for n in distro-menu overview compliance-check; do
    rsvg-convert --zoom 2 -o "$OUT/$n.png" "$tmp/$n.svg"
done
echo "  wrote $OUT/{distro-menu,overview,compliance-check}.png"
