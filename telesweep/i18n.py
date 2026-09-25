"""i18n.py — internationalization for TeleSweep.

Loads locale catalogs from the ``locales/`` directory and exposes a small
``t()`` helper. English (``en``) is the default and always fully populated;
other locales fall back to English for any missing key.

Usage::

    from telesweep.i18n import t, set_locale, available_locales

    set_locale("fa")
    print(t("app.title"))
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

LOCALES_DIR = Path(__file__).parent / "locales"
DEFAULT_LOCALE = "en"

# RTL languages that need direction switching in the UI
RTL_LOCALES = {"fa", "ar", "ur", "he", "yi"}

# Display names for the language picker (native names, self-describing)
LANGUAGE_NAMES = {
    "en": "English",
    "fa": "فارسی",
    "ar": "العربية",
    "de": "Deutsch",
    "es": "Español",
    "fr": "Français",
    "ru": "Русский",
    "tr": "Türkçe",
    "zh": "中文",
    "it": "Italiano",
    "pt": "Português",
    "nl": "Nederlands",
    "pl": "Polski",
    "ja": "日本語",
    "ko": "한국어",
}

_current_locale = DEFAULT_LOCALE
_catalogs: dict[str, dict[str, Any]] = {}


def available_locales() -> list[str]:
    """Return codes of all installed locales, default first."""
    if not LOCALES_DIR.exists():
        return [DEFAULT_LOCALE]
    found = sorted(p.stem for p in LOCALES_DIR.glob("*.json") if p.is_file())
    if DEFAULT_LOCALE in found:
        found.remove(DEFAULT_LOCALE)
        found.insert(0, DEFAULT_LOCALE)
    return found


def _load(locale: str) -> dict[str, Any]:
    """Load (and cache) a single locale catalog."""
    if locale in _catalogs:
        return _catalogs[locale]
    path = LOCALES_DIR / f"{locale}.json"
    catalog: dict[str, Any] = {}
    if path.exists():
        try:
            catalog = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            catalog = {}
    _catalogs[locale] = catalog
    return catalog


def set_locale(locale: str) -> str:
    """Set the active locale. Falls back to English if unavailable."""
    global _current_locale
    if locale in available_locales():
        _current_locale = locale
    else:
        _current_locale = DEFAULT_LOCALE
    return _current_locale


def get_locale() -> str:
    """Return the currently active locale code."""
    return _current_locale


def is_rtl(locale: Optional[str] = None) -> bool:
    """Whether the (current) locale is right-to-left."""
    return (locale or _current_locale) in RTL_LOCALES


def _lookup(catalog: dict[str, Any], dotted_key: str) -> Optional[Any]:
    """Resolve a dotted key like ``app.title`` inside a nested dict."""
    node: Any = catalog
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def t(key: str, locale: Optional[str] = None, **kwargs: Any) -> str:
    """Translate ``key`` into the active (or given) locale.

    Missing keys fall back to English, then to the key itself.
    ``kwargs`` fill ``{placeholders}`` in the string.
    """
    locale = locale or _current_locale
    value: Optional[Any] = None
    if locale != DEFAULT_LOCALE:
        value = _lookup(_load(locale), key)
        # Missing in this locale -> fall back to English, never to the key.
        if value is None:
            value = _lookup(_load(DEFAULT_LOCALE), key)
    else:
        value = _lookup(_load(DEFAULT_LOCALE), key)
    if value is None:
        return key

    text = value if isinstance(value, str) else str(value)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            pass
    return text


def catalog(locale: str) -> dict[str, Any]:
    """Return the merged (locale + English fallback) catalog for the UI."""
    merged = json.loads(json.dumps(_load(DEFAULT_LOCALE)))  # deep copy
    if locale != DEFAULT_LOCALE:
        _deep_update(merged, _load(locale))
    return merged


def _deep_update(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value


def detect_locale() -> str:
    """Best-effort locale detection from the LANG env var."""
    import os

    raw = os.environ.get("LANG", "") or os.environ.get("LC_ALL", "")
    code = raw.split(".")[0].replace("-", "_").split("_")[0].lower()
    if code in available_locales():
        return code
    return DEFAULT_LOCALE
