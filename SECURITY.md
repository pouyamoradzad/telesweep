# Security Policy

## Reporting a Vulnerability

TeleSweep handles Telegram account credentials, so security issues are taken
seriously. If you find a vulnerability, please report it privately:

1. **Do not open a public GitHub issue.**
2. Email the maintainers with a description, reproduction steps, and impact.
3. You should receive an acknowledgment within 48 hours.

## Threat Model

TeleSweep is a **local-first** tool. It is designed under the assumption that
the user's own machine is the only trusted environment.

### What TeleSweep does

- **No network calls except to Telegram's own MTProto servers.** The web UI
  binds to `127.0.0.1` only, so it is unreachable from other devices.
- **Credentials at rest are encrypted.** `api_id`, `api_hash`, and the phone
  number are stored in `config/secrets.enc` using AES-256-GCM. The key is
  derived from your passphrase with PBKDF2-HMAC-SHA256 (200,000 iterations).
  The file has `0600` permissions.
- **The Telethon session file also uses `0600` permissions.**
- **Logs are sanitized.** A logging filter strips phone numbers, login codes,
  API hashes, bot tokens, and session strings from every log record before it
  is written.
- **The web UI requires a per-session random token** and uses constant-time
  comparison to prevent timing attacks.

### What TeleSweep deliberately does not do

- It never sends your data to any third party.
- It never uploads dialogs, messages, or reports anywhere.
- The web UI never binds to `0.0.0.0`.

## Hardcoded protections

The following are protected at the code level and cannot be disabled by
configuration, because a deletion there is virtually always a mistake:

- **Saved Messages**
- **Pinned dialogs**
- **Real contacts**

## Best practices for users

- Run `telesweep logout` when you are done to remove the session from disk.
- Use a strong passphrase for `secrets.enc`.
- Keep `dry-run` as the default; pass `--apply` / confirm explicitly only after
  reviewing the report.
- Do not share `config/secrets.enc`, `config/passphrase.txt`, or
  `data/webui_token.txt`. They are all in `.gitignore`.

## Disclosure

Public disclosure happens after a fix is released, coordinated with the
reporter.
