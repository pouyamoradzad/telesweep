# AGENTS.md — TeleSweep project context

> **Purpose:** complete, precise context for any future session (bug reports,
> updates, refactors). Read this before touching the codebase.

**Last updated:** 2026-09-26 · **Version:** 1.0.0 · **License:** MIT

---

## 1. What this project is

TeleSweep audits a Telegram account via the **userbot API** (Telethon) and finds
"worthless" dialogs — deleted accounts, dead bots, abandoned channels, one-way
spam, empty chats. It scores every dialog 0–100 with per-rule evidence and can
delete them **only after explicit human confirmation**. Dry-run is the default
everywhere.

**Non-negotiable design rules:**

1. **Local only.** The only network calls are to Telegram MTProto servers. The
   web UI binds `127.0.0.1` and refuses anything else (`serve()` in
   `webui.py` raises `ValueError` otherwise).
2. **Dry-run by default.** Every interface shows what *would* happen first.
3. **Hardcoded protections.** Saved Messages (id `7770000`), pinned chats, real
   contacts and whitelisted usernames are never deleted — checked twice
   (in `rules.py` *and* again in `actions.py._is_protected`).
4. **No telemetry, no uploads, no servers, no ads, no premium tier.**
5. **The deletion contract** — a dialog is flagged only when BOTH hold:
   - `risk_score >= thresholds.risk_score` (default 80), AND
   - at least `thresholds.min_evidence` (default 2) *independent* rules fired.
   - The single exception is `deleted_account` — an absolute verdict (weight
     100) that bypasses the evidence minimum.

---

## 2. Repository facts

| Item | Value |
|---|---|
| GitHub repo | `pouyamoradzad/telesweep` (public) |
| Default branch | `main` |
| Landing page | https://pouyamoradzad.github.io/telesweep/ (from `/docs`, deployed by `.github/workflows/pages.yml`) |
| Python support | 3.9, 3.10, 3.11, 3.12, 3.13 |
| Test count | 123 (all passing as of last commit) |
| Locales | 10 — en, ar, de, es, fa, fr, pt, ru, tr, zh (201 keys each, full parity) |
| CI matrix | ubuntu-latest + macos-latest × Python 3.9–3.13 |

**Commit history (chronological):**

```
459fe3a feat: TeleSweep v1.0.0 — local Telegram dialog cleanup
a1cafa0 docs: add landing page and GitHub Pages workflow
afa87ba ci: fix Python 3.9 event loop, black 26 formatting, locale job deps
395baf1 ci: pin black per Python version, formatting-compatible report.py
dfb8cd5 ci: use strict asyncio mode to fix Python 3.9 sync fixtures
dac055b fix(webui): create asyncio.Lock lazily for Python 3.9
d49f5c2 docs: add CI badges and landing page link to README
```

---

## 3. Architecture

```
main.py              CLI entry point (argparse). Commands: init|scan|review|web|auto|logout
telesweep/
├── i18n.py          locale loading, t(), catalog merge, RTL detection
├── client.py        TelegramClientWrapper + SecretsStore (AES-256-GCM)
├── scanner.py       dialog iteration + metadata extraction
├── rules.py         the 6-rule scoring engine
├── actions.py       delete/leave/block executor (dry-run aware)
├── report.py        JSON/CSV/HTML report generation
├── tui.py           terminal UI (Textual)
├── webui.py         local web UI (FastAPI)
├── utils.py         sanitizing logger, rate limiter, config loader
└── locales/         one JSON per language (en.json is the source of truth)
web/static/          the web UI's own frontend (NOT the landing page)
docs/index.html      the public landing page (GitHub Pages)
tests/               pytest suite
```

**Data flow:** `scan → Scanner.scan_dialog → DialogMeta → rules.evaluate →
ActionExecutor.execute → ActionRecord → report.generate_report`.

### Module notes

- **`scanner.py`** — `MAX_SAMPLE = 20`, `PER_DIALOG_TIMEOUT = 60.0`.
  `message_count` is the **true total**, fetched with
  `get_messages(dialog, limit=0)` (returns a count, downloads nothing). The
  sample list is separately capped by `recent_sample`. Do not re-introduce the
  old bug of counting only the sampled window.
- **`rules.py`** — `evaluate()` applies rules, catches per-rule exceptions,
  computes `base = max(weight) + bonus = min(20, (n-1)*10)`. `_check_protection`
  is imported by `actions.py` as a second line of defense — keep that
  double-check.
- **`client.py`** — `_PBKDF2_ITERATIONS = 200_000`, AES-256-GCM, per-file
  random salt+nonce, secrets written atomically via `os.open(..., O_EXCL, 0600)`.
  Login code / 2FA password can come from env vars
  (`TGCLEANER_LOGIN_CODE`, `TGCLEANER_2FA_PASSWORD`) or files in `data/`; those
  files are deleted after a successful login.
- **`webui.py`** — token is a per-session `secrets.token_urlsafe(32)`, compared
  with `hmac.compare_digest`. `create_app()` builds `state_lock` **lazily**
  (see gotcha #1 below).
- **`utils.py`** — `SanitizingFilter` strips phone numbers, api hashes, bot
  tokens, session strings, codes and passphrases from every log record.
  `RateLimiter` caps ops/hour with random jitter.

---

## 4. The rules engine

| Rule | Fires when | Weight |
|---|---|---|
| `deleted_account` | account deleted | **100 (absolute)** |
| `scam_spam_flag` | Telegram scam/fake flag, or spam keywords in name/bio | 80–90 |
| `dead_bot` | bot with no message in `inactivity_days` | 85 |
| `abandoned_channel` | channel/group inactive; weight scales with message count (`<50` → 80, else 70) | 70–80 |
| `one_way_spam` | `>`80% one-way msgs with links/ads, no reply from me in 90 days | 65–75 |
| `empty_chat` | 0 msgs, or 1–2 very old msgs | 70–72 |

Configurable thresholds (all in `config/config.yaml`, see `config.example.yaml`):
`inactivity_days` (180), `risk_score` (80), `min_evidence` (2), `one_way_ratio`
(0.8), `one_way_reply_days` (90), `recent_message_sample` (20).

`one_way_spam` derives the latest reply by **min date across my messages**, not
by list position — it must not assume the API returns messages newest-first.

---

## 5. Development workflow

```bash
pip install -e ".[dev]"     # pytest, pytest-asyncio, httpx, ruff, black
pytest                      # 123 tests, ~1.5s
ruff check telesweep tests main.py
black --check telesweep tests main.py
```

### Testing specifics

- `pytest.ini_options` in `pyproject.toml`: `asyncio_mode = "strict"` and
  `asyncio_default_fixture_loop_scope = "function"`.
- **All async tests must carry `@pytest.mark.asyncio`** explicitly (strict mode
  does not auto-mark them). They currently live in `tests/test_scanner.py`.
- `tests/conftest.py` provides: `config` fixture (loads
  `config/config.example.yaml`), `make_meta()`, `days_ago()`, `make_message()`,
  and `build_test_client()` (creates a FastAPI `TestClient`, working on Py 3.9).
- Tests construct `DialogMeta` **directly** in most suites; only
  `test_scanner.py` exercises the real `Scanner` against a fake Telethon
  client. Keep it that way — that is what caught the message_count bug.
- `tests/test_i18n.py` asserts every locale has the exact same key set as
  `en.json` **and** preserves every `{placeholder}`. This is enforced in CI as a
  separate job. **When you add an i18n key you must add it to all 10 files.**

### Formatter pinning (important)

`black` is pinned per interpreter in the `dev` extra:

```toml
"black>=24.0; python_version < '3.10'",
"black>=26.0; python_version >= '3.10'",
```

Black 26 changed how it wraps triple-quoted f-strings passed directly as a
`call` argument. `report.py` therefore assigns the row template to a `row`
variable first so **both** black versions produce identical output. Do not
inline it back into `rows_html.append(...)`.

---

## 6. Deployment & release

- **CI** (`.github/workflows/ci.yml`): matrix over ubuntu/macos × 3.9–3.13,
  runs ruff + black + pytest, plus a `locale-integrity` job running
  `tests/test_i18n.py`. **That job must install `-e ".[dev]"`** — it once failed
  with exit 127 because pytest was missing.
- **Landing page** (`.github/workflows/pages.yml`): deploys `docs/` to GitHub
  Pages on every push to `main` that touches `docs/**` or the workflow itself.
  Permissions: `contents: read`, `pages: write`, `id-token: write`.
- **Packaging:** `pyproject.toml` declares `packages = ["telesweep"]` **and**
  `py-modules = ["main"]`. The console script `telesweep = "main:main"` requires
  both — dropping `py-modules` silently ships a broken command.
- Locales are shipped via `[tool.setuptools.package-data] telesweep =
  ["locales/*.json"]`.

### Release checklist

1. Update `version` in `pyproject.toml`.
2. Add a `## [x.y.z] — YYYY-MM-DD` section to `CHANGELOG.md` (Keep a Changelog
   format).
3. Run full verification: `pytest && ruff check && black --check`.
4. Build a wheel and **open it** to confirm `main.py` + all 10 locales are
   inside: `pip wheel --no-deps . && python -c "import zipfile; ..."`
5. Install the wheel in a clean venv and run `telesweep --help`.
6. Commit, tag, push.

---

## 7. Donations (official addresses)

The **only** official addresses — also in `DONATE.md` and on the landing page:

| Network | Address |
|---|---|
| Toncoin (TON) | `TBCQztfSB4kbduM26bgJMRHgXzDZD6PL4L` |
| Bitcoin (BTC) | `bc1q7pvrm7hyftyxz0epzz5422dpf79ep668pltysa` |
| Ethereum (ETH) | `0xdfDf1A851Ce5A817916c4412EBB34d863e23F8` |

Any address change must be updated in **three** places: `DONATE.md`,
`docs/index.html` (donation section) and the `FUNDING.yml` if applicable. The
landing page carries an explicit scam warning that these are the only official
addresses.

---

## 8. Gotchas — read before changing asyncio/webui code

1. **`asyncio.Lock()` on Python 3.9** binds to the running loop at construction.
   `create_app()` runs before any loop exists, so `state_lock` is created lazily
   via `_lock()` on first use. Do not eagerly construct asyncio primitives at
   import/app-build time.
2. **`asyncio_mode = "strict"`** is deliberate. In `auto` mode,
   pytest-asyncio leaves the main thread without a current loop on Python 3.9,
   which broke every sync `TestClient` fixture with
   `RuntimeError: There is no current event loop in thread 'MainThread'`.
3. **`black>=26.0` requires Python ≥3.10.** A single flat `black>=26.0` pin
   makes the 3.9 CI job unresolvable.
4. **`message_count` must stay the true total**, never the sampled window
   length, or the `abandoned_channel` weight branch for `>= 50` messages becomes
   dead code and every report understates chat size.
5. **The `protection.skip_saved_messages` config key is honored** — Saved
   Messages protection is gated on it (defaults to `True`). Do not hardcode it
   back to always-on.
6. **Never log credentials.** All logging goes through `setup_logger`, which
   installs `SanitizingFilter`. If you add a logger, use `setup_logger`, not
   `logging.getLogger` directly.
7. **`.gitignore` covers** `config/secrets.enc`, `config/passphrase.txt`,
   `*.session*`, `data/`, `reports/`, logs. Never commit any of them.

---

## 9. Bugs already found and fixed (do not reintroduce)

| Bug | Symptom | Fix |
|---|---|---|
| Missing `py-modules` | `pip install telesweep` → `ModuleNotFoundError: main` | added `py-modules = ["main"]` |
| `message_count` capped at sample size | `abandoned_channel` 50+ branch unreachable; reports understated counts | total via `get_messages(..., limit=0)` |
| Dead config key | `protection.skip_saved_messages` ignored | gated the Saved Messages check on it |
| Redundant condition | `rules.py` `id==7770000 or (... and id==7770000)` | simplified |
| Hardcoded Persian log strings | 5 messages bypassed i18n (only Persian speakers could read them) | new `scanner.*` / `actions.*` keys in all 10 locales |
| `one_way_spam` order dependence | newest reply assumed to be first in list | pick by min date |
| Eager `asyncio.Lock()` | Python 3.9 CI failure at `create_app` | lazy `_lock()` |
| Wrong asyncio mode | Python 3.9 sync fixtures had no event loop | `strict` mode + explicit markers |
| Locale job missing deps | exit 127 in CI | install `-e ".[dev]"` |
| Flat black pin | 3.9 could not resolve `black>=26` | per-interpreter pin |
| Inline triple-quoted f-string in `append()` | black 24 vs 26 disagree | extract to `row` variable |

---

## 10. Suggested next work

- Increase coverage for `tui.py` (currently untested) and `report.py` HTML
  rendering.
- Consider `mypy`/type checking — not currently configured.
- `actions.py` and `client.py` have no direct unit tests; they are only covered
  indirectly.
- The `web/static/index.html` frontend has no automated tests.
