"""Shared fixtures for the TeleSweep test suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from telesweep.scanner import DialogMeta, MessageSample
from telesweep.utils import load_config

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def config() -> dict[str, Any]:
    return load_config(PROJECT_ROOT / "config" / "config.example.yaml")


def make_meta(**overrides: Any) -> DialogMeta:
    """Build a DialogMeta with sensible defaults for tests."""
    base: dict[str, Any] = dict(
        id=1,
        name="Test",
        username=None,
        entity_type="user",
        is_pinned=False,
        is_unread=False,
        is_muted=False,
        is_archived=False,
        is_marked_as_unread=False,
        last_message_date=None,
        message_count=0,
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
    base.update(overrides)
    return DialogMeta(**base)


def days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def make_message(msg_id: int, days: int, from_me: bool, text: str) -> MessageSample:
    return MessageSample(
        id=msg_id,
        date=days_ago(days),
        from_me=from_me,
        has_link=("http" in text.lower()),
        has_media=False,
        text_preview=text,
    )
