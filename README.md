# 🧹 TeleSweep

**Automatically clean worthless Telegram chats — local, secure, and dry-run by default.**

[![CI](https://github.com/pouyamoradzad/telesweep/actions/workflows/ci.yml/badge.svg)](https://github.com/pouyamoradzad/telesweep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Languages: 10](https://img.shields.io/badge/Languages-10-orange.svg)](#internationalization)
[![GitHub Pages](https://img.shields.io/badge/Website-online-brightgreen.svg)](https://pouyamoradzad.github.io/telesweep/)

🌐 **[Visit the landing page](https://pouyamoradzad.github.io/telesweep/)** — a full
visual tour of the project.

TeleSweep scans every dialog on your Telegram account, scores each one against
strict rules (deleted accounts, dead bots, abandoned channels, one-way spam,
empty chats), and shows you exactly what is worthless — with the reason for
every single verdict. Nothing is ever deleted until you confirm it.

Everything runs on your own machine. No servers, no telemetry, no uploads.

---

## Why TeleSweep

Telegram accounts accumulate hundreds of dead dialogs over the years: bots you
used once, channels that stopped posting in 2023, accounts that were deleted,
chats that are pure one-way advertising. Cleaning them by hand is hopeless.

TeleSweep does the audit for you — but it never deletes on its own. It gives
you the evidence, and you decide.

## Features

- **Strict rules engine** — every dialog gets a 0–100 risk score with
  per-rule evidence. A dialog is only flagged when the score reaches the
  threshold **and** at least two independent rules agree.
- **Dry-run by default** — every interface shows exactly what would happen
  before anything changes. Real deletion always needs explicit confirmation.
- **Hardcoded protections** — Saved Messages, pinned chats, and real contacts
  are never deleted, at the code level.
- **Two interfaces** — a terminal UI (Textual) and a local web UI (FastAPI).
- **Detailed reports** — JSON, CSV, and HTML with per-dialog reasons, scores,
  and outcomes.
- **Security-first** — credentials encrypted at rest with AES-256-GCM,
  sanitized logging, rate limiting, FloodWait handling.
- **10 languages** — English, Arabic, German, Spanish, Persian, French,
  Portuguese, Russian, Turkish, Chinese, with full RTL support.

## Installation

```bash
git clone https://github.com/pouyamoradzad/telesweep.git
cd telesweep
pip install -r requirements.txt
```

Requires Python 3.9+.

## Getting started

### 1. Create your Telegram API credentials

Get your own `api_id` and `api_hash` from
[my.telegram.org](https://my.telegram.org) → *API development tools*. This is
your personal app key — keep it private.

### 2. Initialize TeleSweep

```bash
python main.py init
```

You will be asked for your `api_id`, `api_hash`, and a passphrase. The
credentials are encrypted with AES-256-GCM and stored in
`config/secrets.enc` with `0600` permissions. Only your passphrase can
recover them.

### 3. Scan (dry-run — nothing is deleted)

```bash
python main.py scan
```

This writes reports to `reports/` in JSON, CSV, and HTML. Open the HTML one
to browse everything.

### 4. Review and delete

**Terminal UI:**

```bash
python main.py review          # dry-run
python main.py review --apply  # real deletion, with final confirmation
```

| Key | Action |
|---|---|
| `Enter` | select / unselect a row |
| `a` / `n` | select all / clear |
| `p` | switch between deletable and protected chats |
| `d` | delete the selected rows (asks for confirmation) |
| `q` | quit |

**Web UI:**

```bash
python main.py web
```

Opens a local server on `http://127.0.0.1:8462` (localhost only — it is
unreachable from any other device). A one-time token is printed in the
terminal to sign in.

### 5. Automation (destructive — needs an explicit flag)

```bash
python main.py auto --i-know
```

Without `--i-know`, the command refuses to run.

### 6. Log out

```bash
python main.py logout
```

Removes the Telethon session from disk.

## The deletion contract

A dialog is flagged for deletion **only when both** hold:

1. `risk_score >= 80` (default, configurable), **and**
2. at least `min_evidence` (default 2) independent rules fired.

The one exception is `deleted_account` — a deleted account is an absolute
verdict, because the person is gone from Telegram and the dialog is pure dead
data.

| Rule | Condition | Weight |
|---|---|---|
| `deleted_account` | The account was deleted | 100 (absolute) |
| `scam_spam_flag` | Telegram scam/fake flag, or spam keywords in name/bio | 80–90 |
| `dead_bot` | A bot with no messages in 180 days | 85 |
| `abandoned_channel` | Channel/group inactive for 180 days | 70–80 |
| `one_way_spam` | >80% one-way messages with links/ads, no reply from you in 90 days | 65–75 |
| `empty_chat` | Zero or 1–2 very old messages | 70–72 |

The inactivity threshold (180 days), the risk threshold (80), and the minimum
evidence count (2) are all configurable in `config/config.yaml`.

## Security

Read [`SECURITY.md`](SECURITY.md) for the full policy. The essentials:

- **Local only.** The only network calls are to Telegram's own MTProto
  servers. The web UI binds to `127.0.0.1` and nothing else.
- **Credentials at rest are encrypted** with AES-256-GCM; the key is derived
  from your passphrase via PBKDF2-HMAC-SHA256 (200,000 iterations).
- **Logs are sanitized** — a filter strips phone numbers, login codes, API
  hashes, bot tokens, and session strings from every log record.
- **Rate limiting + FloodWait handling** with per-dialog timeouts, so a scan
  can never get your account restricted.
- **Constant-time token comparison** for the web UI.
- **No telemetry, no analytics, no uploads of any kind.**

`config/secrets.enc`, `*.session`, `data/`, and `reports/` are all in
`.gitignore`. Keep them there.

## Internationalization

TeleSweep ships with 10 locales in `telesweep/locales/`. Set the interface
language with `--lang`:

```bash
python main.py --lang fa review
python main.py --lang es web
```

The web UI also has a language picker in the top-right corner.

Adding a language is a single JSON file — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Project layout

```
telesweep/
├── main.py              # CLI entry point
├── telesweep/
│   ├── i18n.py          # locale loading + t()
│   ├── client.py        # Telethon client + AES-256-GCM credentials
│   ├── scanner.py       # dialog iteration + metadata extraction
│   ├── rules.py         # the scoring engine
│   ├── actions.py       # delete/leave/block, dry-run aware
│   ├── report.py        # JSON/CSV/HTML reports
│   ├── tui.py           # terminal UI (Textual)
│   ├── webui.py         # local web UI (FastAPI)
│   ├── utils.py         # sanitized logging, rate limiter, config
│   └── locales/         # one JSON file per language
├── web/static/          # web UI assets
└── tests/               # pytest suite
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
black --check .
```

## Disclaimer

TeleSweep operates **your own Telegram account** and can delete chats. Deletion
is irreversible. Use dry-run first, review the reports, and test on a throwaway
bot or channel before cleaning anything you care about.

You are responsible for your account. TeleSweep is not affiliated with
Telegram.

## Support

TeleSweep is free, ad-free, and will stay that way. If it saved you some time,
[**buying a coffee**](DONATE.md) helps keep it alive — or just star the repo,
which costs nothing and helps others find it.

## License

[MIT](LICENSE) — © TeleSweep contributors
