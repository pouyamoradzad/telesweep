"""Tests for the rules engine and the deletion contract."""

from __future__ import annotations

import pytest

from telesweep.rules import evaluate, summary

from .conftest import days_ago, make_message, make_meta

SAVED_MESSAGES_ID = 7770000


class TestHardcodedProtection:
    """Nothing protected should ever be flagged, regardless of other signals."""

    def test_saved_messages_is_protected(self, config):
        meta = evaluate(
            make_meta(
                id=SAVED_MESSAGES_ID,
                name="Saved Messages",
                message_count=999,
                last_message_date=days_ago(1),
            ),
            config,
        )
        assert meta.should_delete is False
        assert meta.risk_score == 0
        assert meta.protection_reason is not None

    def test_pinned_chat_is_protected(self, config):
        meta = evaluate(
            make_meta(
                id=2,
                name="Important",
                is_pinned=True,
                deleted=True,
                last_message_date=days_ago(400),
            ),
            config,
        )
        assert meta.should_delete is False
        assert meta.protection_reason is not None

    def test_real_contact_is_protected(self, config):
        meta = evaluate(
            make_meta(
                id=3,
                name="Mom",
                is_contact=True,
                deleted=True,
                last_message_date=days_ago(400),
            ),
            config,
        )
        assert meta.should_delete is False
        assert meta.protection_reason is not None

    def test_whitelist_is_protected(self, config):
        config = dict(config)
        config["whitelist"] = ["someuser"]
        meta = evaluate(
            make_meta(
                id=4,
                name="Whitelisted",
                username="someuser",
                deleted=True,
                last_message_date=days_ago(400),
            ),
            config,
        )
        assert meta.should_delete is False
        assert meta.protection_reason is not None

    def test_saved_messages_can_be_opted_out(self, config):
        """skip_saved_messages is a real config switch, not a dead key."""
        config = dict(config)
        config["protection"] = dict(config.get("protection", {}))
        config["protection"]["skip_saved_messages"] = False
        meta = evaluate(
            make_meta(
                id=SAVED_MESSAGES_ID,
                name="Saved Messages",
                deleted=True,
                last_message_date=days_ago(400),
            ),
            config,
        )
        assert meta.protection_reason is None
        assert meta.should_delete is True


class TestDeletedAccount:
    def test_deleted_account_is_absolute_verdict(self, config):
        meta = evaluate(
            make_meta(
                id=10,
                deleted=True,
                last_message_date=days_ago(400),
                message_count=3,
            ),
            config,
        )
        assert meta.should_delete is True
        assert meta.risk_score == 100
        rules = {e["rule"] for e in meta.evidence}
        assert "deleted_account" in rules


class TestScamAndSpam:
    def test_telegram_scam_flag(self, config):
        meta = evaluate(
            make_meta(
                id=11,
                name="Giveaway Bot",
                entity_type="bot",
                is_bot=True,
                is_scam=True,
                last_message_date=days_ago(400),
                message_count=2,
            ),
            config,
        )
        assert meta.should_delete is True
        assert meta.risk_score >= 80
        rules = {e["rule"] for e in meta.evidence}
        assert "scam_spam_flag" in rules
        assert len(rules) >= 2

    def test_spam_keywords_in_name(self, config):
        meta = evaluate(
            make_meta(
                id=12,
                name="خرید پکیج تخفیف فروش",
                last_message_date=days_ago(400),
                message_count=1,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "scam_spam_flag" in rules

    def test_clean_name_is_not_flagged(self, config):
        meta = evaluate(
            make_meta(
                id=13,
                name="John Smith",
                last_message_date=days_ago(10),
                message_count=50,
            ),
            config,
        )
        assert meta.should_delete is False
        assert meta.risk_score == 0


class TestDeadBot:
    def test_inactive_bot(self, config):
        meta = evaluate(
            make_meta(
                id=14,
                name="Some Bot",
                entity_type="bot",
                is_bot=True,
                last_message_date=days_ago(400),
                message_count=2,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "dead_bot" in rules
        assert meta.should_delete is True

    def test_active_bot_is_not_flagged(self, config):
        meta = evaluate(
            make_meta(
                id=15,
                name="Some Bot",
                entity_type="bot",
                is_bot=True,
                last_message_date=days_ago(5),
                message_count=50,
            ),
            config,
        )
        assert meta.should_delete is False


class TestAbandonedChannel:
    def test_abandoned_channel(self, config):
        meta = evaluate(
            make_meta(
                id=16,
                name="Dead News",
                entity_type="channel",
                last_message_date=days_ago(400),
                message_count=20,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "abandoned_channel" in rules

    def test_active_channel_is_not_flagged(self, config):
        meta = evaluate(
            make_meta(
                id=17,
                name="Active News",
                entity_type="channel",
                last_message_date=days_ago(3),
                message_count=500,
            ),
            config,
        )
        assert meta.should_delete is False


class TestOneWaySpam:
    def test_one_way_spam_chat(self, config):
        messages = [
            make_message(i, 5, from_me=False, text="buy now http://t.me/x")
            for i in range(10)
        ]
        meta = evaluate(
            make_meta(
                id=18,
                name="Spammer",
                entity_type="user",
                last_message_date=days_ago(5),
                message_count=10,
                messages=messages,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "one_way_spam" in rules

    def test_mutual_chat_is_not_flagged(self, config):
        messages = [
            make_message(i, 5, from_me=(i % 2 == 0), text="hi") for i in range(10)
        ]
        meta = evaluate(
            make_meta(
                id=19,
                name="Friend",
                entity_type="user",
                last_message_date=days_ago(5),
                message_count=10,
                messages=messages,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "one_way_spam" not in rules

    def test_recent_reply_in_unsorted_order_is_detected(self, config):
        """The newest reply must be found regardless of list order — the
        rule must not depend on the API returning messages newest-first."""
        messages = [
            make_message(1, days=400, from_me=True, text="hi"),
            make_message(2, days=5, from_me=True, text="hello"),
            make_message(3, days=5, from_me=False, text="buy now http://t.me/x"),
            make_message(4, days=5, from_me=False, text="sale http://t.me/y"),
        ]
        meta = evaluate(
            make_meta(
                id=190,
                name="Spammer",
                entity_type="user",
                last_message_date=days_ago(5),
                message_count=4,
                messages=messages,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "one_way_spam" not in rules

    def test_no_reply_in_unsorted_order_is_flagged(self, config):
        """Same ordering, but my only reply is old → one_way_spam fires."""
        messages = [
            make_message(1, days=400, from_me=True, text="hi"),
            make_message(2, days=400, from_me=False, text="buy now http://t.me/x"),
            make_message(3, days=400, from_me=False, text="sale http://t.me/y"),
            make_message(4, days=400, from_me=False, text="deal http://t.me/z"),
            make_message(5, days=400, from_me=False, text="offer http://t.me/w"),
        ]
        meta = evaluate(
            make_meta(
                id=191,
                name="Spammer",
                entity_type="user",
                last_message_date=days_ago(400),
                message_count=5,
                messages=messages,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "one_way_spam" in rules


class TestEmptyChat:
    def test_completely_empty(self, config):
        meta = evaluate(make_meta(id=20, name="Empty"), config)
        rules = {e["rule"] for e in meta.evidence}
        assert "empty_chat" in rules

    def test_two_old_messages(self, config):
        meta = evaluate(
            make_meta(
                id=21,
                name="Old",
                message_count=2,
                last_message_date=days_ago(300),
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert "empty_chat" in rules


class TestDeletionContract:
    """score >= 80 AND >= 2 independent rules (unless deleted_account)."""

    def test_single_rule_below_evidence_minimum_is_not_flagged(self, config):
        """A channel that only trips abandoned_channel has just one evidence."""
        meta = evaluate(
            make_meta(
                id=22,
                name="Channel",
                entity_type="channel",
                last_message_date=days_ago(400),
                message_count=500,  # not empty -> only one rule fires
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert rules == {"abandoned_channel"}
        assert meta.should_delete is False

    def test_two_rules_meets_the_contract(self, config):
        meta = evaluate(
            make_meta(
                id=23,
                name="Buy Now Discount",
                entity_type="channel",
                last_message_date=days_ago(400),
                message_count=1,
            ),
            config,
        )
        rules = {e["rule"] for e in meta.evidence}
        assert len(rules) >= 2
        assert meta.risk_score >= 80
        assert meta.should_delete is True


class TestSummary:
    def test_summary_counts(self, config):
        metas = [
            make_meta(id=SAVED_MESSAGES_ID, name="Saved", message_count=5),
            make_meta(
                id=30,
                name="Bot",
                entity_type="bot",
                is_bot=True,
                is_scam=True,
                last_message_date=days_ago(400),
                message_count=1,
            ),
            make_meta(
                id=31, name="Active", last_message_date=days_ago(1), message_count=50
            ),
        ]
        evaluated = [evaluate(m, config) for m in metas]
        stats = summary(evaluated)
        assert stats["total"] == 3
        assert stats["flagged_for_deletion"] == 1
        assert stats["protected"] == 1
        assert stats["by_entity_type"]["bot"] == 1


class TestPlaceholders:
    @pytest.mark.parametrize(
        "locale", ["en", "fa", "ar", "de", "es", "fr", "pt", "ru", "tr", "zh"]
    )
    def test_rule_reasons_render_placeholders(self, config, locale):
        from telesweep import i18n

        i18n.set_locale(locale)
        meta = evaluate(
            make_meta(
                id=40,
                name="Bot",
                entity_type="bot",
                is_bot=True,
                last_message_date=days_ago(400),
                message_count=1,
            ),
            config,
        )
        dead_bot = next(e for e in meta.evidence if e["rule"] == "dead_bot")
        assert "{" not in dead_bot["reason"]
        assert "}" not in dead_bot["reason"]
        i18n.set_locale("en")
