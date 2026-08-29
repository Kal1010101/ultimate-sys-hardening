# Installation

This repository is the free tier. Pro and Enterprise are separate products —
see [PRICING.md](https://Kal1010101.github.io/ultimate-sys-hardening/#pricing).

## Quick install

```bash
git clone https://github.com/Kal1010101/ultimate-sys-hardening.git
cd ultimate-sys-hardening
sudo ./scripts/install.sh
```

That copies `lib/` and `src/` to `/opt/ultimate-hardening`, links
`ultimate-harden` into `/usr/local/bin`, and then **verifies the installed
command actually runs** before reporting success. If verification fails it
tells you so rather than leaving a broken command on your PATH.

## Run it

```bash
sudo ultimate-harden                          # interactive menu
sudo ultimate-harden --dry-run --auto-mode    # preview everything, change nothing
sudo ultimate-harden --cis-only               # score the system, change nothing
sudo ultimate-harden --revert                 # undo the most recent run
```

Start with `--dry-run`. It prints every change it would make and writes
nothing.

## Running without installing

The installer is optional — the script runs from a checkout as-is:

```bash
git clone https://github.com/Kal1010101/ultimate-sys-hardening.git
cd ultimate-sys-hardening
chmod +x src/free/ultimate_hardening.sh
sudo ./src/free/ultimate_hardening.sh --dry-run --auto-mode
```

## Manual installation

If you would rather not use the installer, the only real requirement is that
`lib/` sits where the script can find it. The script looks, in order, at:

```
<script>/../../lib          # i.e. /opt/ultimate-hardening/lib for the layout below
<script>/../lib
<script>/lib
/usr/local/share/ultimate-hardening/lib
/usr/share/ultimate-hardening/lib
```

So a working manual install is:

```bash
sudo mkdir -p /opt/ultimate-hardening
sudo cp -r lib src /opt/ultimate-hardening/
sudo chmod +x /opt/ultimate-hardening/src/free/ultimate_hardening.sh
sudo ln -s /opt/ultimate-hardening/src/free/ultimate_hardening.sh \
           /usr/local/bin/ultimate-harden

sudo ultimate-harden --version    # confirm it works before relying on it
```

**`lib/` is not optional.** Copying `src/` alone produces a command that exits
with "Could not locate lib/" on every invocation. Symlinking the script onto
your PATH is fine — it resolves the link before searching.

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

This removes the installed files. It does **not** revert hardening changes —
run `sudo ultimate-harden --revert` first if that is what you want, while the
command still exists.

## Configuration files

The free tier takes its options from command-line flags; it has no config
file. `--config` is a Pro/Enterprise flag, and the example config that used
to live here moved to the commercial repository with it.
