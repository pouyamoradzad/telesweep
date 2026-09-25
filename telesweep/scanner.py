"""scanner.py — اسکن دیالوگ‌های تلگرام و استخراج متادیتا.

برای هر دیالوگ این اطلاعات استخراج می‌شود:
- نوع موجودیت (user/bot/channel/group/megagroup)
- تاریخ آخرین پیام، تعداد پیام
- وضعیت pinned/unread/muted
- اطلاعات فرستنده (نام، یوزرنیم، bio، deleted flag، scam flag)
- نمونه‌ی پیام‌های اخیر برای تحلیل اسپم/یک‌طرفه بودن

کش نتایج در data/scan-<timestamp>.json ذخیره می‌شود تا UIها نیازی به اسکن مجدد نداشته باشند.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import i18n
from .utils import RateLimiter, setup_logger, utc_timestamp

log = setup_logger("telesweep.scanner")

MAX_SAMPLE = 20
# خواندن دیالوگ‌ها محدودیت‌های ملایم‌تری نسبت به عملیات تخریبی دارد.
# ۱۲۰۰ درخواست در ساعت ≈ ۲ در ثانیه — امن برای خواندن.
RATE_LIMIT = RateLimiter(min_delay=0.2, max_delay=0.4, max_ops_per_hour=1200)
# timeout برای هر دیالوگ تا یک چت کند، کل اسکن را متوقف نکند
PER_DIALOG_TIMEOUT = 60.0


@dataclass
class MessageSample:
    """نمونه‌ی یک پیام برای تحلیل قوانین."""

    id: int
    date: Optional[str]
    from_me: bool
    has_link: bool
    has_media: bool
    text_preview: str


@dataclass
class DialogMeta:
    """متادیتای کامل یک دیالوگ."""

    id: int
    name: str
    username: Optional[str]
    entity_type: str  # user | bot | channel | group | megagroup | unknown
    is_pinned: bool
    is_unread: bool
    is_muted: bool
    is_archived: bool
    is_marked_as_unread: bool
    last_message_date: Optional[str]
    message_count: int
    # اطلاعات موجودیت
    deleted: bool
    is_scam: bool
    is_fake: bool
    is_bot: bool
    is_verified: bool
    is_restricted: bool
    first_name: Optional[str]
    last_name: Optional[str]
    bio: Optional[str]
    phone: Optional[str]
    is_contact: bool
    is_mutual_contact: bool
    # نمونه پیام‌ها
    messages: list[MessageSample] = field(default_factory=list)
    # محاسبه‌شده توسط rules.py
    risk_score: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    should_delete: bool = False
    protection_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _classify_entity(dialog: Any, entity: Any) -> str:
    """تشخیص نوع موجودیت."""
    try:
        if entity is None:
            return "unknown"
        if getattr(entity, "bot", False):
            return "bot"
        if hasattr(entity, "megagroup") and entity.megagroup:
            return "megagroup"
        if getattr(dialog, "is_channel", False):
            return "channel"
        if getattr(dialog, "is_group", False):
            return "group"
        if getattr(entity, "bot", False) is False and hasattr(entity, "first_name"):
            return "user"
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


class Scanner:
    """اسکن‌کننده‌ی دیالوگ‌ها."""

    def __init__(
        self,
        client_wrapper: Any,
        recent_sample: int = MAX_SAMPLE,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.wrapper = client_wrapper
        self.client = client_wrapper.client
        self.recent_sample = max(1, min(recent_sample or MAX_SAMPLE, 100))
        # خواندن نیازی به محدودیت‌های سختِ عملیات تخریبی ندارد
        self.rate_limiter = rate_limiter or RATE_LIMIT

    async def _fetch_bio(self, entity: Any) -> Optional[str]:
        """دریافت bio (با rate limiting)."""
        await self.rate_limiter.wait()
        try:
            full = await self.client.get_entity(entity)
            if full is None:
                return None
            bio = getattr(full, "about", None) or getattr(full, "bio", None)
            return bio if bio else None
        except Exception:  # noqa: BLE001
            return None

    async def scan_dialog(self, dialog: Any) -> DialogMeta:
        """استخراج متادیتای یک دیالوگ."""
        await self.rate_limiter.wait()

        entity = dialog.entity
        etype = _classify_entity(dialog, entity)

        eid = getattr(entity, "id", getattr(dialog, "id", 0)) or getattr(
            dialog, "id", 0
        )
        username = getattr(entity, "username", None)
        first_name = getattr(entity, "first_name", None)
        last_name = getattr(entity, "last_name", None)
        title = getattr(dialog, "title", None) or getattr(entity, "title", None)

        if title:
            name = title
        elif first_name or last_name:
            name = " ".join(filter(None, [first_name, last_name]))
        else:
            # حساب‌های حذف‌شده نام ندارند — شناسه برای تشخیص نمایش می‌دهیم
            deleted = bool(getattr(entity, "deleted", False))
            prefix = "حساب حذف‌شده" if deleted else "بدون نام"
            name = f"<{prefix} {eid}>"

        # تعداد واقعی پیام‌ها (مستقل از نمونه‌ی محدود) — Telethon با limit=0
        # فقط شمارش را برمی‌گرداند و هیچ پیامی را دانلود نمی‌کند.
        message_count = 0
        try:
            message_count = int(await self.client.get_messages(dialog, limit=0) or 0)
        except Exception as exc:  # noqa: BLE001
            log.debug(i18n.t("scanner.count_fail", error=exc))

        # نمونه‌ی پیام‌های اخیر برای تحلیل قوانین
        messages: list[MessageSample] = []
        last_date: Optional[str] = None
        try:
            async for msg in self.client.iter_messages(
                dialog, limit=self.recent_sample
            ):
                if len(messages) < self.recent_sample:
                    text = (msg.text or "") or ""
                    messages.append(
                        MessageSample(
                            id=msg.id,
                            date=_parse_dt(getattr(msg, "date", None)),
                            from_me=bool(getattr(msg, "out", False)),
                            has_link=("http://" in text.lower())
                            or ("https://" in text.lower()),
                            has_media=bool(getattr(msg, "media", None)),
                            text_preview=text[:120],
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            log.debug(i18n.t("scanner.fetch_fail", error=exc))

        # iter_messages جدیدترین‌ها را اول می‌آورد؛ اگر نمونه‌ای هست،
        # اولین نمونه جدیدترین پیام است. در غیر این‌صورت چت خالی است.
        if messages:
            last_date = messages[0].date
        elif message_count > 0:
            # نمونه در دسترس نیست ولی پیام وجود دارد — تاریخ آخرین پیام
            # از یک درخواست‌ی تک‌پیامی (در حد امکان) برداشته می‌شود.
            try:
                last = await self.client.get_messages(dialog, limit=1)
                last_date = _parse_dt(getattr(last, "date", None)) if last else None
            except Exception as exc:  # noqa: BLE001
                log.debug(i18n.t("scanner.last_date_fail", error=exc))

        bio = None
        if etype in ("user", "bot"):
            bio = await self._fetch_bio(entity)

        return DialogMeta(
            id=int(eid),
            name=str(name),
            username=username,
            entity_type=etype,
            is_pinned=bool(getattr(dialog, "pinned", False)),
            is_unread=bool(getattr(dialog, "unread_count", 0) or 0) > 0,
            is_muted=bool(getattr(dialog, "muted", False)),
            is_archived=bool(getattr(dialog, "archived", False)),
            is_marked_as_unread=bool(getattr(dialog, "marked_as_unread", False)),
            last_message_date=last_date,
            message_count=message_count,
            deleted=bool(getattr(entity, "deleted", False)),
            is_scam=bool(getattr(entity, "scam", False)),
            is_fake=bool(getattr(entity, "fake", False)),
            is_bot=bool(getattr(entity, "bot", False)),
            is_verified=bool(getattr(entity, "verified", False)),
            is_restricted=bool(getattr(entity, "restricted", False)),
            first_name=first_name,
            last_name=last_name,
            bio=bio,
            phone=getattr(entity, "phone", None),
            is_contact=bool(getattr(entity, "is_contact", False)),
            is_mutual_contact=bool(getattr(entity, "is_mutual_contact", False)),
            messages=messages,
        )

    async def scan_all(
        self,
        progress_cb: Optional[Any] = None,
        skip_protected: bool = True,
    ) -> list[DialogMeta]:
        """اسکن همه‌ی دیالوگ‌ها. progress_cb(current, total, name) فراخوانی می‌شود."""
        dialogs = await self.client.get_dialogs()
        total = len(dialogs)
        log.info(i18n.t("cli.scan_start", total=total))

        results: list[DialogMeta] = []
        for idx, dialog in enumerate(dialogs, start=1):
            try:
                meta = await asyncio.wait_for(
                    self.scan_dialog(dialog), timeout=PER_DIALOG_TIMEOUT
                )
                results.append(meta)
                if progress_cb:
                    await _maybe_await(progress_cb(idx, total, meta.name))
                if idx % 25 == 0:
                    log.info("%d/%d", idx, total)
            except asyncio.TimeoutError:
                log.warning(
                    "timeout: dialog %s skipped",
                    getattr(dialog, "id", "?"),
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "scan error on dialog %s: %s",
                    getattr(dialog, "id", "?"),
                    exc,
                )

        log.info(i18n.t("scan.done") + " (%d)", len(results))
        return results


async def _maybe_await(result: Any) -> None:
    """اگر نتیجه‌ی callback یک coroutine است، منتظر آن می‌ماند."""
    if asyncio.iscoroutine(result):
        await result


def save_scan_cache(metas: list[DialogMeta], data_dir: str | Path) -> Path:
    """ذخیره‌ی کش اسکن در data/."""
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / f"scan-{utc_timestamp()}.json"

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(metas),
        "dialogs": [m.to_dict() for m in metas],
    }
    path.write_text(
        __import__("json").dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log.info("scan cache saved: %s", path)
    return path


def load_latest_scan(data_dir: str | Path) -> Optional[dict[str, Any]]:
    """بارگذاری جدیدترین کش اسکن."""
    data_dir = Path(data_dir)
    if not data_dir.exists():
        return None
    files = sorted(data_dir.glob("scan-*.json"))
    if not files:
        return None
    import json

    return json.loads(files[-1].read_text(encoding="utf-8"))
