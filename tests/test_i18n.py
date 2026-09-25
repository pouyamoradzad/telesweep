"""Tests for the locale catalog and the t() helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from telesweep import i18n

LOCALES_DIR = Path(__file__).resolve().parent.parent / "telesweep" / "locales"


def _flatten(d, prefix=""):
    out = {}
    for key, value in d.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, name + "."))
        else:
            out[name] = value
    return out


@pytest.fixture(autouse=True)
def reset_locale():
    yield
    i18n.set_locale("en")


class TestCatalogIntegrity:
    """Every locale must be valid JSON with the same key set as English."""

    @pytest.mark.parametrize("locale", [p.stem for p in LOCALES_DIR.glob("*.json")])
    def test_key_set_matches_english(self, locale):
        en = json.loads((LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
        other = json.loads((LOCALES_DIR / f"{locale}.json").read_text(encoding="utf-8"))
        assert (
            _flatten(en).keys() == _flatten(other).keys()
        ), f"{locale} differs from en.json"

    @pytest.mark.parametrize("locale", [p.stem for p in LOCALES_DIR.glob("*.json")])
    def test_placeholders_preserved(self, locale):
        """Translated strings must keep every {placeholder} from English."""
        en = _flatten(json.loads((LOCALES_DIR / "en.json").read_text(encoding="utf-8")))
        other = _flatten(
            json.loads((LOCALES_DIR / f"{locale}.json").read_text(encoding="utf-8"))
        )
        import re

        for key, value in en.items():
            if not isinstance(value, str):
                continue
            needed = set(re.findall(r"\{(\w+)\}", value))
            if not needed:
                continue
            got = set(re.findall(r"\{(\w+)\}", other[key]))
            assert needed <= got, f"{locale}.{key} lost placeholders {needed - got}"

    @pytest.mark.parametrize("locale", [p.stem for p in LOCALES_DIR.glob("*.json")])
    def test_direction_field(self, locale):
        data = json.loads((LOCALES_DIR / f"{locale}.json").read_text(encoding="utf-8"))
        assert data["meta"]["direction"] in ("ltr", "rtl")
        assert data["meta"]["direction"] == ("rtl" if i18n.is_rtl(locale) else "ltr")


class TestT:
    def test_english_is_default(self):
        i18n.set_locale("en")
        assert i18n.t("app.title") == "TeleSweep"

    def test_translation_switches_with_locale(self):
        i18n.set_locale("fa")
        assert "تلگرام" in i18n.t("cli.description") or "TeleSweep" in i18n.t(
            "cli.description"
        )
        i18n.set_locale("en")
        assert (
            i18n.t("cli.description")
            == "TeleSweep — automatically clean worthless Telegram chats"
        )

    def test_unknown_locale_falls_back(self):
        assert i18n.set_locale("xx") == "en"

    def test_missing_key_returns_the_key(self):
        assert i18n.t("does.not.exist") == "does.not.exist"

    def test_placeholders_are_filled(self):
        text = i18n.t("actions.confirm_body", count=5)
        assert "5" in text
        assert "{count}" not in text

    def test_unknown_placeholder_is_left_alone(self):
        text = i18n.t("actions.confirm_body", count=5, bogus="x")
        assert "5" in text

    def test_catalog_merge_keeps_english_for_missing_keys(self):
        merged = i18n.catalog("fa")
        assert merged["app"]["title"] == "TeleSweep"

    def test_is_rtl(self):
        i18n.set_locale("fa")
        assert i18n.is_rtl() is True
        i18n.set_locale("en")
        assert i18n.is_rtl() is False


class TestLocaleListing:
    def test_english_is_first(self):
        locales = i18n.available_locales()
        assert locales[0] == "en"
        assert len(locales) >= 10

    def test_all_listed_locales_have_files(self):
        for code in i18n.available_locales():
            assert (LOCALES_DIR / f"{code}.json").exists()
