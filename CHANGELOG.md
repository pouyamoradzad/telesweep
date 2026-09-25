# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Packaging.** The `telesweep` console script pointed at `main:main`, but
  `main.py` was not declared as a top-level module, so `pip install telesweep`
  installed a broken command. `main` is now declared via `py-modules` and the
  installed entry point works.
- **Message counts.** `Scanner` counted messages by iterating the sampled
  window, so `DialogMeta.message_count` was silently capped at the sample
  limit (default 20). This made the `abandoned_channel` weight branch for
  channels with ≥ 50 messages unreachable and misreported counts in every
  report. The total is now fetched with `get_messages(..., limit=0)`, which
  returns the count without downloading messages.
- **Dead config key.** `protection.skip_saved_messages` was documented but
  never read; Saved Messages are now protected through that switch.
- **Internationalization.** Five developer-facing log messages were hardcoded
  Persian strings that bypassed the locale catalogs. They now use
  `scanner.*` and `actions.*` keys translated into all ten locales.
- **Rules robustness.** `one_way_spam` derived the latest reply from the first
  message attributed to the user, assuming the API always returns messages
  newest-first. It now picks the newest by date, so an unsorted sample cannot
  produce a wrong verdict.

## [1.0.0] — 2026-09-25

### Added

- **Core scanning engine.** Iterates every dialog of a userbot account via
  Telethon and extracts entity type, message counts, last activity, pinned /
  unread / muted state, and a sample of recent messages.
- **Strict rules engine** with a 0–100 `risk_score` per dialog and per-rule
  evidence records: `deleted_account`, `scam_spam_flag`, `dead_bot`,
  `abandoned_channel`, `one_way_spam`, and `empty_chat`.
- **Deletion contract.** A dialog is flagged only when the risk score reaches
  the threshold (default 80) **and** at least two independent rules fired.
  `deleted_account` is an absolute verdict.
- **Hardcoded protections.** Saved Messages, pinned dialogs, and real contacts
  are never deleted, at the code level.
- **Dry-run by default.** Every path — CLI, TUI, and web UI — shows exactly
  what would happen before anything is changed.
- **Two interfaces.** A terminal UI (Textual) and a local web UI (FastAPI)
  that binds to `127.0.0.1` only.
- **Detailed reports** in JSON, CSV, and HTML with per-dialog reasons, risk
  scores, and action outcomes.
- **Security-first credential storage.** AES-256-GCM encryption at rest with a
  PBKDF2-derived key, `0600` permissions on secrets and session files, and a
  logging filter that strips phone numbers, codes, and tokens.
- **Rate limiting and FloodWait handling** with per-dialog timeouts, so a scan
  can never get the account restricted.
- **Internationalization.** Ten locales out of the box (English, Arabic,
  German, Spanish, Persian, French, Portuguese, Russian, Turkish, Chinese)
  with full RTL support in the terminal, web, and HTML reports.
- **Automation** via `telesweep auto --i-know`, plus a safe `logout` command.

### Security

- No network calls except to Telegram's own MTProto servers.
- The web UI uses a per-session random token compared in constant time.
- No telemetry, no upload of any kind.
