# Contributing

Contributions are welcome — TeleSweep is a community tool, and every
translation, bug fix, and rule improvement helps.

## Getting started

```bash
git clone https://github.com/pouyamoradzad/telesweep.git
cd telesweep
pip install -e ".[dev]"
```

Verify the setup:

```bash
pytest
ruff check .
black --check .
```

## Project layout

```
telesweep/
├── main.py              # CLI entry point (argparse: init/scan/review/web/auto/logout)
├── telesweep/
│   ├── i18n.py          # locale loading + t()
│   ├── client.py        # Telethon client + AES-256-GCM credentials
│   ├── scanner.py       # dialog iteration + metadata extraction
│   ├── rules.py         # scoring engine (risk_score 0-100)
│   ├── actions.py       # delete/leave/block, dry-run aware
│   ├── report.py        # JSON/CSV/HTML reports
│   ├── tui.py           # terminal UI (Textual)
│   ├── webui.py         # local web UI (FastAPI, 127.0.0.1 only)
│   └── utils.py         # sanitized logging, rate limiter, config
├── telesweep/locales/   # one JSON file per language
├── web/static/          # the web UI assets
└── tests/               # pytest suite
```

## Adding a new language

1. Copy `telesweep/locales/en.json` to `telesweep/locales/<code>.json`.
2. Translate every **value**. Keep all keys, nesting, and `{placeholders}`
   exactly as they are — they are filled in at runtime.
3. Set `meta.direction` to `"rtl"` if the language is right-to-left.
4. Add the code to `LANGUAGE_NAMES` in `telesweep/i18n.py` with its native name.
5. Run `pytest tests/test_i18n.py` — the suite verifies that every locale has
   the same key set as English.

## Adding a new detection rule

Rules live in `telesweep/rules.py`. A rule is a function that takes a
`DialogMeta` and returns an evidence dict (`rule`, `weight`, `reason`,
`details`), or `None` when it does not apply.

1. Add the rule function and register it in `evaluate()`.
2. Add a short key under the `rules.*` namespace in **every** locale file.
3. Add a test in `tests/test_rules.py` covering both the match and non-match
   cases.

Remember the deletion contract: a dialog is only flagged when
`risk_score >= 80` **and** at least `min_evidence` independent rules fired —
unless the match is `deleted_account`, which is an absolute verdict.

## Rules everyone follows

- **Never log credentials.** The sanitizer in `utils.py` is a safety net, not
  an excuse to log a phone number.
- **Never bind the web UI to anything but 127.0.0.1.**
- **Keep the default non-destructive.** Any change that deletes data requires
  an explicit confirmation path.
- **Never remove the hardcoded protections** (Saved Messages, pinned chats,
  contacts).
- **Add tests** for anything behaviorally new.
- **Do not commit** `secrets.enc`, `*.session`, `data/`, or `reports/`. They
  are already in `.gitignore` — keep them there.

## Commit style

Use clear, imperative commits, e.g. `Add rule for inactive megagroups`.
Keep one logical change per commit.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make sure `pytest`, `ruff check .`, and `black --check .` all pass.
3. Open the PR with a description of **what** changed and **why**.

Thank you for helping make Telegram cleaner and safer.
