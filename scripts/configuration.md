
### `docs/configuration.md`

```markdown
# Configuration Guide

## Configuration File Location

Default: `/etc/hardening/hardening.conf`

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `AUTO_MODE` | Run without prompts | `false` |
| `SKIP_BACKUP` | Skip backup creation | `false` |
| `AUTO_FIX` | Auto-fix CIS issues | `false` |
| `EMAIL_NOTIFY` | Enable email notifications | `false` |
| `EMAIL_RECIPIENT` | Email address for alerts | `""` |
| `SMTP_HOST` | SMTP server hostname | `""` |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username | `""` |
| `SMTP_PASS` | SMTP password | `""` |
| `SCHEDULE_FREQUENCY` | Schedule frequency | `"daily"` |
| `STATE_DB` | SQLite database path | `"/var/lib/hardening/state.db"` |

## Example Configuration

```bash
# /etc/hardening/hardening.conf
AUTO_MODE=true
SKIP_BACKUP=false
AUTO_FIX=true
EMAIL_NOTIFY=true
EMAIL_RECIPIENT="security-team@example.com"
SMTP_HOST="smtp.example.com"
SMTP_PORT="587"
SMTP_USER="hardening-bot"
SMTP_PASS="secure-password"
SCHEDULE_FREQUENCY="weekly"
STATE_DB="/var/lib/hardening/state.db"
