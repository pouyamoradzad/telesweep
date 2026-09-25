"""Tests for the Scanner — dialog metadata extraction.

These use a fake Telethon client to exercise the real Scanner code paths,
especially the total message count (which must not be capped by the sample
limit) and message sampling.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from telesweep.scanner import DialogMeta, Scanner


class FakeMessage:
    def __init__(self, i: int, days_ago: int = 10, out: bool = False, text: str = ""):
        self.id = i
        self.date = datetime.now(timezone.utc) - timedelta(days=days_ago)
        self.out = out
        self.media = None
        self.text = text


class FakeEntity:
    def __init__(self, etype: str = "channel"):
        self.bot = etype == "bot"
        self.id = 100
        self.username = None
        self.first_name = None
        self.last_name = None
        self.title = "Test Channel"
        self.deleted = False
        self.scam = False
        self.fake = False
        self.verified = False
        self.restricted = False
        self.phone = None
        self.is_contact = False
        self.is_mutual_contact = False


class FakeDialog:
    def __init__(self, etype: str = "channel"):
        self.entity = FakeEntity(etype)
        self.title = "Test Channel"
        self.id = 100
        self.pinned = False
        self.unread_count = 0
        self.muted = False
        self.archived = False
        self.marked_as_unread = False
        self.is_channel = etype in ("channel", "megagroup")
        self.is_group = etype in ("group", "megagroup")
        self.megagroup = etype == "megagroup"


class FakeClient:
    """Minimal Telethon stand-in.

    ``get_messages(dialog, limit=0)`` returns the *total* message count,
    matching real Telethon behaviour. ``iter_messages`` yields at most
    ``limit`` messages, newest first.
    """

    def __init__(self, total: int, sample_text: str = "hi"):
        self.total = total
        self.sample_text = sample_text
        self.calls: list[tuple[str, Any]] = []

    async def get_messages(self, dialog: Any, limit: Optional[int] = None) -> Any:
        self.calls.append(("get_messages", limit))
        if limit == 0:
            return self.total
        if limit == 1:
            return FakeMessage(self.total, days_ago=1)
        return [FakeMessage(i) for i in range(limit or self.total)]

    async def iter_messages(self, dialog: Any, limit: Optional[int] = None):
        n = min(self.total, limit or self.total)
        for i in range(n):
            yield FakeMessage(i, days_ago=1 + i, text=self.sample_text)


class FakeWrapper:
    def __init__(self, client: Any):
        self.client = client


def _scanner(total: int, recent_sample: int = 20) -> Scanner:
    return Scanner(
        FakeWrapper(FakeClient(total)),
        recent_sample=recent_sample,
        rate_limiter=_NoWaitLimiter(),
    )


class _NoWaitLimiter:
    async def wait(self) -> None:
        return None


@pytest.mark.parametrize("total", [0, 1, 3, 20, 25, 60, 500, 1000])
@pytest.mark.asyncio
async def test_message_count_is_total_not_sampled(total: int):
    """message_count must reflect the real total, not the sample cap."""
    scanner = _scanner(total)
    meta = await scanner.scan_dialog(FakeDialog())
    assert meta.message_count == total


@pytest.mark.parametrize("total", [5, 25, 500])
@pytest.mark.asyncio
async def test_message_sample_capped_by_recent_sample(total: int):
    """The sample list is capped, independent of the total count."""
    scanner = _scanner(total, recent_sample=20)
    meta = await scanner.scan_dialog(FakeDialog())
    assert len(meta.messages) == min(total, 20)


@pytest.mark.asyncio
async def test_sample_size_respects_configured_limit():
    scanner = _scanner(500, recent_sample=10)
    meta = await scanner.scan_dialog(FakeDialog())
    assert len(meta.messages) == 10
    assert meta.message_count == 500


@pytest.mark.asyncio
async def test_last_message_date_taken_from_newest_sample():
    scanner = _scanner(5, recent_sample=20)
    meta = await scanner.scan_dialog(FakeDialog())
    # FakeClient yields newest first (days_ago=1), so the newest is day 1.
    assert meta.last_message_date is not None
    parsed = datetime.fromisoformat(meta.last_message_date)
    delta = datetime.now(timezone.utc) - parsed
    assert timedelta(days=1, hours=-1) < delta < timedelta(days=2)


@pytest.mark.asyncio
async def test_abandoned_channel_weight_uses_real_count():
    """Regression: with message_count capped at 20, a channel with >= 50
    messages wrongly received weight 80 (the '< 50' branch). The real count
    must select weight 70 instead."""
    from telesweep.rules import _rule_abandoned_channel

    old = _rule_abandoned_channel(_meta_channel(500), 180)
    assert old is not None and old["weight"] == 70

    small = _rule_abandoned_channel(_meta_channel(10), 180)
    assert small is not None and small["weight"] == 80


def _meta_channel(count: int) -> DialogMeta:
    from datetime import datetime, timedelta, timezone

    return DialogMeta(
        id=100,
        name="Test Channel",
        username=None,
        entity_type="channel",
        is_pinned=False,
        is_unread=False,
        is_muted=False,
        is_archived=False,
        is_marked_as_unread=False,
        last_message_date=(
            datetime.now(timezone.utc) - timedelta(days=400)
        ).isoformat(),
        message_count=count,
        deleted=False,
        is_scam=False,
        is_fake=False,
        is_bot=False,
        is_verified=False,
        is_restricted=False,
        first_name=None,
        last_name=None,
        bio=None,
        phone=None,
        is_contact=False,
        is_mutual_contact=False,
    )
