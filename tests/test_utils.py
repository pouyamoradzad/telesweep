"""Tests for encrypted credential storage and the sanitizing log filter."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from telesweep.client import Secrets, SecretsStore
from telesweep.utils import (
    RateLimiter,
    SanitizingFilter,
    in_whitelist,
    sanitize_text,
)


class TestSecretsStore:
    def test_roundtrip(self, tmp_path: Path):
        store = SecretsStore(tmp_path / "secrets.enc")
        store.store(
            Secrets(api_id=12345, api_hash="a" * 32, phone="+989123456789"),
            "correct-horse-battery",
        )
        loaded = store.load("correct-horse-battery")
        assert loaded.api_id == 12345
        assert loaded.api_hash == "a" * 32
        assert loaded.phone == "+989123456789"

    def test_wrong_passphrase_is_rejected(self, tmp_path: Path):
        store = SecretsStore(tmp_path / "secrets.enc")
        store.store(Secrets(api_id=1, api_hash="b" * 32), "good-passphrase-1")
        with pytest.raises(ValueError):
            store.load("wrong-passphrase")

    def test_file_permissions_are_600(self, tmp_path: Path):
        path = tmp_path / "secrets.enc"
        SecretsStore(path).store(Secrets(api_id=1, api_hash="c" * 32), " passphrase1")
        assert path.stat().st_mode & 0o777 == 0o600

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            SecretsStore(tmp_path / "missing.enc").load("x" * 10)

    def test_corrupt_file_raises(self, tmp_path: Path):
        path = tmp_path / "secrets.enc"
        path.write_bytes(b"short")
        with pytest.raises(ValueError):
            SecretsStore(path).load("x" * 10)

    def test_two_files_do_not_share_keys(self, tmp_path: Path):
        """A random salt per file means the same passphrase yields different bytes."""
        a = tmp_path / "a.enc"
        b = tmp_path / "b.enc"
        for p in (a, b):
            SecretsStore(p).store(
                Secrets(api_id=1, api_hash="d" * 32), "same-passphrase"
            )
        assert a.read_bytes() != b.read_bytes()


class TestSanitizer:
    @pytest.mark.parametrize(
        "raw, must_not_contain",
        [
            ("call me at +989123456789", "+989123456789"),
            ("phone 09123456789 today", "09123456789"),
            (
                "hash 00000000000000000000000000000000",
                "00000000000000000000000000000000",
            ),
        ],
    )
    def test_sensitive_data_is_redacted(self, raw, must_not_contain):
        assert must_not_contain not in sanitize_text(raw)

    def test_contextual_code_is_redacted(self):
        assert "123456" not in sanitize_text("login code: 123456 accepted")

    def test_filenames_are_not_mangled(self):
        out = sanitize_text("wrote reports/report-20260925-101530.json")
        assert "20260925-101530" in out

    def test_counts_are_not_mangled(self):
        out = sanitize_text("scanned 1273 dialogs, 155 flagged")
        assert "1273" in out and "155" in out

    def test_non_string_input(self):
        assert sanitize_text(42) == "42"


class TestSanitizingFilter:
    def test_format_specifiers_still_work(self):
        # The filter must format the message first, so %d / %s keep working.
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 1, "count %d of %d", (3, 10), None
        )
        SanitizingFilter().filter(record)
        assert "count 3 of 10" in record.getMessage()

    def test_phone_is_stripped_from_record(self):
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 1, "phone is +989123456789", (), None
        )
        SanitizingFilter().filter(record)
        assert "+989123456789" not in record.getMessage()

    def test_args_are_consumed(self):
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 1, "a %s b %d", ("x", 7), None
        )
        SanitizingFilter().filter(record)
        assert record.getMessage() == "a x b 7"


class TestRateLimiter:
    def test_respects_min_delay(self):
        import asyncio
        import time

        async def run():
            rl = RateLimiter(min_delay=0.05, max_delay=0.05, max_ops_per_hour=1000)
            start = time.monotonic()
            for _ in range(3):
                await rl.wait()
            return time.monotonic() - start

        elapsed = asyncio.run(run())
        assert elapsed >= 0.1  # at least the spacing between three calls

    def test_never_blocks_indefinitely(self):
        """The hourly cap must degrade gracefully instead of sleeping an hour."""
        import asyncio

        async def run():
            rl = RateLimiter(min_delay=0.0, max_delay=0.0, max_ops_per_hour=3)
            for _ in range(10):
                await rl.wait()

        asyncio.run(run())  # returns quickly rather than blocking


class TestWhitelist:
    def test_match_with_at_sign(self):
        assert in_whitelist("@SomeUser", ["someuser"]) is True

    def test_match_without_at_sign(self):
        assert in_whitelist("someuser", ["SomeUser"]) is True

    def test_no_match(self):
        assert in_whitelist("other", ["someuser"]) is False

    def test_empty_whitelist(self):
        assert in_whitelist("x", []) is False

    def test_none_identifier(self):
        assert in_whitelist(None, ["x"]) is False
