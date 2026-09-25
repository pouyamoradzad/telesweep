"""rules.py — موتور قوانین + امتیازدهی خطر (risk_score ۰–۱۰۰).

قوانین (هر کدام evidence ثبت می‌کنند):
- deleted_account: entity.deleted == True → حذف قطعی (score ۱۰۰)
- scam_spam_flag: نام/bio شامل علائم اسپم یا کلمات scam → score بالا
- dead_bot: نوع bot + بدون پیام در ۱۸۰ روز → score بالا
- abandoned_channel: کانال/گروه + آخرین پیام >۱۸۰ روز + تعداد پیام کم → score بالا
- one_way_spam: چت شخصی که >۸۰٪ پیام‌ها فقط از طرف مقابل + شامل لینک/تبلیغ
                + بدون پاسخ از کاربر در ۹۰ روز → score بالا
- empty_chat: صفر پیام یا فقط ۱–۲ پیام از مدت‌ها پیش

حذف قطعی فقط اگر score ≥ آستانه (۸۰) و حداقل ۲ evidence مستقل باشد.

حفاظت hardcoded (هیچ‌وقت حذف نمی‌شوند):
- Saved Messages
- دیالوگ‌های پین‌شده
- مخاطبین واقعی
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from . import i18n
from .scanner import DialogMeta
from .utils import in_whitelist, setup_logger

log = setup_logger("telesweep.rules")

# کلمات کلیدی اسپم/تبلیغات/اسکم (فارسی + انگلیسی)
SPAM_KEYWORDS = [
    # انگلیسی
    "http://",
    "https://",
    "www.",
    "click here",
    "subscribe",
    "free money",
    "crypto giveaway",
    "bitcoin",
    "airdrop",
    "investment",
    "earn money",
    "make money",
    "bonus",
    "discount code",
    "promo code",
    "follow us",
    "buy now",
    "limited offer",
    "casino",
    "betting",
    "18+",
    # فارسی
    "خرید",
    "فروش",
    "تخفیف",
    "کد تخفیف",
    "عضو شوید",
    "کانال ما",
    "پیج ما",
    "دنبال کنید",
    "تخفیف ویژه",
    "فرصت",
    "درآمد",
    "کسب درآمد",
    "سرمایه‌گذاری",
    "پکیج",
    "دوره آموزشی",
    "ثبت‌نام",
    "رایگان",
    "هدیه",
    "شوک",
    "ترک",
    "لیست",
    "فالو",
    "لایو",
    "استوری",
]

SCAM_KEYWORDS = [
    "scam",
    "fraud",
    "phishing",
    "verify your account",
    "you won",
    "winner",
    "congratulations",
    "claim your",
    "suspicious activity",
    "click to verify",
    "giveaway",
    "double your",
    "send crypto",
    "wallet address",
    "کتاب",
    "اسکم",
    "کلاهبرداری",
    "برنده شدید",
    "آدرس کیف پول",
    "احراز هویت",
]

# الگوهای مشکوک در نام کاربری
SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"(?i)(bot|admin|support|help|official|verify)"),
    re.compile(r"(?i)(casino|bet|porn|xxx|18\+|sex)"),
    re.compile(r"(?i)\b(promo|advertis|market|shop|store|deal)\b"),
]

AD_INDICATORS = [
    "t.me/",
    "telegram.me/",
    "instagram.com/",
    "t.me/joinchat",
]


def _days_since(date_str: Optional[str]) -> Optional[float]:
    """تعداد روزهای گذشته از یک تاریخ ISO."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - dt).total_seconds() / 86400.0
    except (ValueError, TypeError):
        return None


def _text_spam_score(text: str) -> tuple[int, list[str]]:
    """امتیازدهی به یک متن بر اساس کلمات اسپم. (score, matched)"""
    if not text:
        return 0, []
    lowered = text.lower()
    matched: list[str] = []
    for kw in SPAM_KEYWORDS:
        if kw in lowered:
            matched.append(kw)
    for kw in SCAM_KEYWORDS:
        if kw in lowered:
            matched.append(kw)
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern.search(lowered):
            matched.append(pattern.pattern)
    score = min(60, len(matched) * 12)
    return score, matched


def _check_protection(meta: DialogMeta, config: dict[str, Any]) -> Optional[str]:
    """بررسی حفاظت‌های hardcoded. اگر محافظت دارد، دلیل را برمی‌گرداند."""
    prot = config.get("protection", {})

    # Saved Messages (شناسه ۷۷۷۰۰۰۰ در تلگرام)
    if prot.get("skip_saved_messages", True) and meta.id == 7770000:
        return i18n.t("protection.saved")

    if prot.get("skip_pinned", True) and meta.is_pinned:
        return i18n.t("protection.pinned")

    if prot.get("skip_contacts", True) and meta.is_contact:
        return i18n.t("protection.contact")

    if in_whitelist(meta.username, config.get("whitelist", [])):
        return i18n.t("protection.whitelist")

    return None


def _rule_deleted_account(meta: DialogMeta) -> Optional[dict[str, Any]]:
    """حساب حذف‌شده → حذف قطعی."""
    if meta.deleted:
        return {
            "rule": "deleted_account",
            "weight": 100,
            "reason": "حساب کاربر حذف‌شده است (deleted account).",
            "details": {"entity_type": meta.entity_type},
        }
    return None


def _rule_scam_flag(meta: DialogMeta) -> Optional[dict[str, Any]]:
    """علائم اسپم/اسکم در نام یا bio."""
    evidence: list[str] = []
    name_score = 0
    bio_score = 0

    if meta.name:
        name_score, name_matches = _text_spam_score(meta.name)
        evidence.extend(f"name:{m}" for m in name_matches)
    if meta.username:
        u_score, u_matches = _text_spam_score(meta.username)
        name_score = max(name_score, u_score)
        evidence.extend(f"username:{m}" for m in u_matches)
    if meta.bio:
        bio_score, bio_matches = _text_spam_score(meta.bio)
        evidence.extend(f"bio:{m}" for m in bio_matches)

    if meta.is_scam:
        return {
            "rule": "scam_spam_flag",
            "weight": 90,
            "reason": "تلگرام این حساب را به‌عنوان scam علامت‌گذاری کرده است.",
            "details": {"flag": "scam", "matches": evidence[:10]},
        }
    if meta.is_fake:
        return {
            "rule": "scam_spam_flag",
            "weight": 85,
            "reason": "تلگرام این حساب را به‌عنوان fake علامت‌گذاری کرده است.",
            "details": {"flag": "fake", "matches": evidence[:10]},
        }

    total = max(name_score, bio_score)
    if total >= 36 and evidence:
        return {
            "rule": "scam_spam_flag",
            "weight": min(80, total),
            "reason": "نام یا بیوگرافی حاوی کلمات کلیدی اسپم/تبلیغات است.",
            "details": {"matches": evidence[:10]},
        }
    return None


def _rule_dead_bot(meta: DialogMeta, inactivity_days: int) -> Optional[dict[str, Any]]:
    """ربات مرده: نوع bot + بی‌تحرکی طولانی."""
    if meta.entity_type != "bot" and not meta.is_bot:
        return None
    days = _days_since(meta.last_message_date)
    if days is None:
        return None
    if days >= inactivity_days:
        return {
            "rule": "dead_bot",
            "weight": 85,
            "reason": f"ربات در {int(days)} روز گذشته هیچ پیامی نداشته است.",
            "details": {
                "days_inactive": int(days),
                "threshold_days": inactivity_days,
            },
        }
    return None


def _rule_abandoned_channel(
    meta: DialogMeta, inactivity_days: int
) -> Optional[dict[str, Any]]:
    """کانال/گروه متروکه: بی‌تحرکی + تعداد پیام کم."""
    if meta.entity_type not in ("channel", "group", "megagroup"):
        return None
    days = _days_since(meta.last_message_date)
    if days is None:
        return None
    if days >= inactivity_days:
        # کانال‌های متروکه با پیام کم خطرناک‌ترند
        weight = 80 if meta.message_count < 50 else 70
        return {
            "rule": "abandoned_channel",
            "weight": weight,
            "reason": (
                f"کانال/گروه در {int(days)} روز گذشته فعال نبوده است "
                f"({meta.message_count} پیام)."
            ),
            "details": {
                "days_inactive": int(days),
                "threshold_days": inactivity_days,
                "message_count": meta.message_count,
            },
        }
    return None


def _rule_one_way_spam(
    meta: DialogMeta, ratio_threshold: float, reply_days: int
) -> Optional[dict[str, Any]]:
    """چت شخصی یک‌طرفه‌ی اسپم: >۸۰٪ پیام از طرف مقابل + لینک + بدون پاسخ."""
    if meta.entity_type not in ("user", "unknown"):
        return None
    if not meta.messages:
        return None

    from_them = [m for m in meta.messages if not m.from_me]
    total = len(meta.messages)
    if total < 3:
        return None

    ratio = len(from_them) / total
    my_messages = [m for m in meta.messages if m.from_me]

    # آخرین پاسخ من — جدیدترین پیامِ من بر اساس تاریخ (مستقل از ترتیب
    # بازگشتِ پیام‌ها توسط API).
    last_reply_days: Optional[float] = None
    if my_messages:
        my_dates = [_days_since(m.date) for m in my_messages]
        my_dates = [d for d in my_dates if d is not None]
        if my_dates:
            # کمترین مقدار = نزدیک‌ترین به اکنون
            last_reply_days = min(my_dates)

    has_links = any(m.has_link for m in from_them)
    sample_spam_score, _ = _text_spam_score(" ".join(m.text_preview for m in from_them))

    if ratio >= ratio_threshold and (has_links or sample_spam_score >= 24):
        # اگر در مدت reply_days پاسخی نداده‌ام
        no_reply = last_reply_days is None or last_reply_days >= reply_days
        if no_reply:
            weight = 75 if sample_spam_score >= 36 else 65
            return {
                "rule": "one_way_spam",
                "weight": weight,
                "reason": (
                    f"{int(ratio * 100)}٪ پیام‌ها یک‌طرفه از طرف مقابل است "
                    f"با لینک/محتوای تبلیغاتی و بدون پاسخ شما در "
                    f"{reply_days} روز گذشته."
                ),
                "details": {
                    "one_way_ratio": round(ratio, 3),
                    "threshold_ratio": ratio_threshold,
                    "has_links": has_links,
                    "spam_score": sample_spam_score,
                    "days_since_my_reply": (
                        int(last_reply_days) if last_reply_days is not None else None
                    ),
                },
            }
    return None


def _rule_empty_chat(
    meta: DialogMeta, inactivity_days: int
) -> Optional[dict[str, Any]]:
    """چت خالی: صفر یا ۱–۲ پیام از مدت‌ها پیش."""
    if meta.message_count == 0 and meta.last_message_date is None:
        return {
            "rule": "empty_chat",
            "weight": 70,
            "reason": "چت کاملاً خالی است (هیچ پیامی وجود ندارد).",
            "details": {"message_count": 0},
        }
    if meta.message_count <= 2:
        days = _days_since(meta.last_message_date)
        if days is not None and days >= inactivity_days / 2:
            return {
                "rule": "empty_chat",
                "weight": 72,
                "reason": (
                    f"فقط {meta.message_count} پیام وجود دارد و آخرین پیام "
                    f"{int(days)} روز پیش بوده است."
                ),
                "details": {
                    "message_count": meta.message_count,
                    "days_inactive": int(days),
                },
            }
    return None


def evaluate(meta: DialogMeta, config: dict[str, Any]) -> DialogMeta:
    """اعمال همه‌ی قوانین روی یک دیالوگ و محاسبه‌ی risk_score.

    خروجی: همان DialogMeta با risk_score، evidence و should_delete پر شده.
    """
    th = config.get("thresholds", {})
    inactivity_days = int(th.get("inactivity_days", 180))
    risk_threshold = int(th.get("risk_score", 80))
    min_evidence = int(th.get("min_evidence", 2))
    one_way_ratio = float(th.get("one_way_ratio", 0.8))
    reply_days = int(th.get("one_way_reply_days", 90))

    # ۱) حفاظت hardcoded — اولویت اول
    protection = _check_protection(meta, config)
    if protection:
        meta.protection_reason = protection
        meta.risk_score = 0
        meta.evidence = []
        meta.should_delete = False
        return meta

    # ۲) اعمال قوانین
    findings: list[dict[str, Any]] = []
    for fn in (
        lambda: _rule_deleted_account(meta),
        lambda: _rule_scam_flag(meta),
        lambda: _rule_dead_bot(meta, inactivity_days),
        lambda: _rule_abandoned_channel(meta, inactivity_days),
        lambda: _rule_one_way_spam(meta, one_way_ratio, reply_days),
        lambda: _rule_empty_chat(meta, inactivity_days),
    ):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            log.debug("rule evaluation error: %s", exc)
            result = None
        if result:
            findings.append(result)

    # ۳) محاسبه‌ی score: وزن قانون حداکثر + پاداش برای تعدد evidence
    if not findings:
        meta.risk_score = 0
        meta.evidence = []
        meta.should_delete = False
        return meta

    base = max(f["weight"] for f in findings)
    bonus = min(20, (len(findings) - 1) * 10)
    meta.risk_score = min(100, base + bonus)
    meta.evidence = findings

    # ۴) تصمیم نهایی: score ≥ آستانه و حداقل N evidence مستقل
    rules_seen = {f["rule"] for f in findings}
    # deleted_account حذف قطعی است — فارغ از تعداد evidence
    absolute_delete = "deleted_account" in rules_seen
    meta.should_delete = absolute_delete or (
        meta.risk_score >= risk_threshold and len(rules_seen) >= min_evidence
    )

    return meta


def evaluate_all(metas: list[DialogMeta], config: dict[str, Any]) -> list[DialogMeta]:
    """اعمال قوانین روی همه‌ی دیالوگ‌ها."""
    results = []
    for meta in metas:
        results.append(evaluate(meta, config))

    flagged = [m for m in results if m.should_delete]
    protected = [m for m in results if m.protection_reason]
    log.info(
        i18n.t(
            "rules.evaluate_done",
            total=len(results),
            flagged=len(flagged),
            protected=len(protected),
        )
    )
    return results


def summary(metas: list[DialogMeta]) -> dict[str, Any]:
    """خلاصه‌ی آماری برای گزارش."""
    by_type: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for meta in metas:
        by_type[meta.entity_type] = by_type.get(meta.entity_type, 0) + 1
        for ev in meta.evidence:
            rule = ev.get("rule", "unknown")
            by_rule[rule] = by_rule.get(rule, 0) + 1

    return {
        "total": len(metas),
        "flagged_for_deletion": sum(1 for m in metas if m.should_delete),
        "protected": sum(1 for m in metas if m.protection_reason),
        "by_entity_type": by_type,
        "by_rule": by_rule,
        "high_risk": sum(
            1 for m in metas if m.risk_score >= 60 and not m.protection_reason
        ),
    }
