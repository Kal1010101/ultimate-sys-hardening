# Two-factor SSH with Google Authenticator

This is a manual guide, not an automated module — deliberately.

Up to v2.2.0 the menu carried a "Google Authenticator MFA" entry. It printed
these instructions, explicitly declined to edit any file, and reported
success. It hardened nothing. Rather than keep a menu item that only
pretends to act, the guidance lives here and the menu is limited to modules
that actually change the system.

The reason it never automated the change is worth understanding before you
make it by hand.

## Why this tool will not edit PAM for you

Enabling MFA for SSH means adding a line to `/etc/pam.d/sshd`. On Debian and
Ubuntu, files under `/etc/pam.d/` are assembled by `pam-auth-update` from
profiles in `/usr/share/pam-configs/`. A hand-written line sits outside the
markers `pam-auth-update` tracks.

That is not hypothetical. An early version of this tool edited
`/etc/pam.d/common-password` directly. On a Mint box running KDE Plasma, a
later `pam-auth-update` run — triggered by installing an unrelated desktop
environment — reconciled around the untracked edit and broke the SDDM login
screen. On a system with an encrypted home directory, a broken PAM stack can
mean you cannot log in to fix it.

So: **PAM is never modified by this tool, at any tier.** See
[SECURITY.md](../SECURITY.md).

## Before you start

Have a second, already-authenticated SSH session open to the same host, and
keep it open until you have confirmed the new login works. If you lock
yourself out, that session is how you undo it.

Take a backup:

```bash
sudo cp /etc/pam.d/sshd        /root/pam-sshd.bak
sudo cp /etc/ssh/sshd_config   /root/sshd_config.bak
```

## 1. Install

```bash
# Debian / Ubuntu
sudo apt-get install -y libpam-google-authenticator

# RHEL / Rocky / Alma / Fedora
sudo dnf install -y google-authenticator

# Arch
sudo pacman -S --noconfirm libpam-google-authenticator
```

## 2. Enrol each user

Run as the user who will log in — **not** as root, and not with `sudo`. The
secret is written to that user's `~/.google_authenticator`.

```bash
google-authenticator
```

Answer `y` to time-based tokens. Scan the QR code with your authenticator
app. **Save the emergency scratch codes somewhere off the machine** — they
are the only way in if you lose the phone.

Every user who logs in over SSH needs to do this. A user who has not
enrolled will be unable to authenticate once step 4 is in force.

## 3. Add the PAM line

```bash
sudo nano /etc/pam.d/sshd
```

Add at the top:

```
auth required pam_google_authenticator.so nullok
```

Keep `nullok` while you roll this out — it lets users who have not yet
enrolled continue to log in. Remove it only once every user has completed
step 2, and verify each of them can still authenticate before you do.

## 4. Tell sshd to use it

In `/etc/ssh/sshd_config`:

```
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

On OpenSSH older than 8.7 the first directive is spelled
`ChallengeResponseAuthentication`.

`AuthenticationMethods publickey,keyboard-interactive` requires **both** an
SSH key and a token. Note that module 2 (SSH hardening) sets
`ChallengeResponseAuthentication no`; if you run it after this, re-apply the
setting above.

## 5. Validate before you trust it

```bash
sudo sshd -t && sudo systemctl restart sshd
```

`sshd -t` must pass before the restart. Then, **from a new terminal** and
with your existing session still open, log in again. Only close the original
session once the new login has succeeded with a token.

## Rolling it back

```bash
sudo cp /root/pam-sshd.bak      /etc/pam.d/sshd
sudo cp /root/sshd_config.bak   /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl restart sshd
```

`--revert` does not undo any of this. The hardening tool did not make these
changes, so it does not track them.
