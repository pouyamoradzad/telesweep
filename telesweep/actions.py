"""actions.py — اجرای عملیات delete/leave/block با درایت و امنیت.

اصول:
- حالت dry-run پیش‌فرض است: هیچ تغییری اعمال نمی‌شود.
- حذف نیازمند تأیید صریح کاربر است.
- حفاظت‌های hardcoded (Saved Messages، پین‌شده، مخاطبین) دوباره بررسی می‌شوند
  — حتی اگر rules.py اشتباهی داشته باشد، actions.py هرگز آن‌ها را حذف نمی‌کند.
- هر عملیات با try/except و تأخیر بین درخواست‌ها (rate limiter).
- مدیریت FloodWait با تلاش مجدد.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from . import i18n
from .rules import _check_protection
from .scanner import DialogMeta
from .utils import RateLimiter, setup_logger

log = setup_logger("telesweep.actions")


class ActionResult(str, Enum):
    DELETED = "deleted"
    LEFT = "left"
    BLOCKED = "blocked"
    SKIPPED_DRY_RUN = "skipped_dry_run"
    SKIPPED_PROTECTED = "skipped_protected"
    SKIPPED_WHITELIST = "skipped_whitelist"
    FAILED = "failed"
    NOT_FOUND = "not_found"


@dataclass
class ActionRecord:
    """نتیجه‌ی یک عملیات روی یک دیالوگ."""

    dialog_id: int
    name: str
    entity_type: str
    risk_score: int
    action: str
    result: str
    reason: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: Optional[str] = None
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dialog_id": self.dialog_id,
            "name": self.name,
            "entity_type": self.entity_type,
            "risk_score": self.risk_score,
            "action": self.action,
            "result": self.result,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "error": self.error,
            "evidence": self.evidence,
        }


class ActionExecutor:
    """اجرای عملیات روی دیالوگ‌ها با حفاظت و rate limiting."""

    def __init__(
        self,
        client_wrapper: Any,
        config: dict[str, Any],
        dry_run: bool = True,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.wrapper = client_wrapper
        self.client = client_wrapper.client
        self.config = config
        self.dry_run = dry_run
        rl_cfg = config.get("rate_limit", {})
        self.rate_limiter = rate_limiter or RateLimiter(
            min_delay=float(rl_cfg.get("min_delay", 0.5)),
            max_delay=float(rl_cfg.get("max_delay", 1.0)),
            max_ops_per_hour=int(rl_cfg.get("max_ops_per_hour", 100)),
        )

    # ------------------------------------------------------------------
    # حفاظت
    # ------------------------------------------------------------------

    def _is_protected(self, meta: DialogMeta) -> Optional[str]:
        """بررسی مجدد حفاظت — لایه‌ی دوم دفاعی در actions.py."""
        if meta.protection_reason:
            return meta.protection_reason
        return _check_protection(meta, self.config)

    # ------------------------------------------------------------------
    # عملیات پایه
    # ------------------------------------------------------------------

    async def _delete_history(self, entity: Any) -> None:
        """پاک‌سازی تاریخچه‌ی چت شخصی/ربات."""
        await self.rate_limiter.wait()
        await self.wrapper.safe_request(self.client.delete_dialog, entity)

    async def _leave_channel(self, entity: Any) -> None:
        """ترک کانال/گروه."""
        from telethon.tl.functions.channels import LeaveChannelRequest

        await self.rate_limiter.wait()
        await self.wrapper.safe_request(LeaveChannelRequest, entity)

    async def _block_entity(self, entity: Any) -> None:
        """مسدود کردن یک کاربر/ربات."""
        from telethon.tl.functions.contacts import BlockRequest

        await self.rate_limiter.wait()
        await self.wrapper.safe_request(BlockRequest, id=entity)

    # ------------------------------------------------------------------
    # عملیات اصلی
    # ------------------------------------------------------------------

    async def execute(self, meta: DialogMeta, block_bots: bool = False) -> ActionRecord:
        """اجرای عملیات مناسب روی یک دیالوگ.

        - چت شخصی/ربات: delete (history)
        - کانال/گروه: leave
        - ربات‌ها: optionally block پس از تأیید جداگانه
        """
        # 1) Protection — always checked first
        protection = self._is_protected(meta)
        if protection:
            log.info(
                i18n.t("actions.protected_stop", name=meta.name, reason=protection)
            )
            return ActionRecord(
                dialog_id=meta.id,
                name=meta.name,
                entity_type=meta.entity_type,
                risk_score=meta.risk_score,
                action="none",
                result=ActionResult.SKIPPED_PROTECTED.value,
                reason=protection,
                evidence=meta.evidence,
            )

        # ۲) dry-run — هیچ تغییری اعمال نمی‌شود
        if self.dry_run:
            planned = self._plan_action(meta, block_bots)
            log.info(
                i18n.t(
                    "actions.dry_preview",
                    name=meta.name,
                    action=self._plan_action(meta, block_bots),
                    score=meta.risk_score,
                    reasons=[e["rule"] for e in meta.evidence],
                )
            )
            return ActionRecord(
                dialog_id=meta.id,
                name=meta.name,
                entity_type=meta.entity_type,
                risk_score=meta.risk_score,
                action=planned,
                result=ActionResult.SKIPPED_DRY_RUN.value,
                reason=i18n.t("actions.skipped_dry_run"),
                evidence=meta.evidence,
            )

        # ۳) اجرای واقعی
        return await self._apply(meta, block_bots)

    def _plan_action(self, meta: DialogMeta, block_bots: bool) -> str:
        """تعیین عملیات برنامه‌ریزی‌شده بدون اجرا."""
        if meta.entity_type in ("channel", "group", "megagroup"):
            return "leave"
        action = "delete"
        if block_bots and (meta.entity_type == "bot" or meta.is_bot):
            action = "delete+block"
        return action

    async def _apply(self, meta: DialogMeta, block_bots: bool) -> ActionRecord:
        """اجرای تخریبی واقعی."""
        try:
            entity = await self._resolve_entity(meta)
            if entity is None:
                return ActionRecord(
                    dialog_id=meta.id,
                    name=meta.name,
                    entity_type=meta.entity_type,
                    risk_score=meta.risk_score,
                    action="none",
                    result=ActionResult.NOT_FOUND.value,
                    reason=i18n.t("actions.not_found"),
                    evidence=meta.evidence,
                )

            if meta.entity_type in ("channel", "group", "megagroup"):
                await self._leave_channel(entity)
                log.info(i18n.t("actions.left_log", name=meta.name))
                return ActionRecord(
                    dialog_id=meta.id,
                    name=meta.name,
                    entity_type=meta.entity_type,
                    risk_score=meta.risk_score,
                    action="leave",
                    result=ActionResult.LEFT.value,
                    reason=i18n.t("actions.left"),
                    evidence=meta.evidence,
                )

            await self._delete_history(entity)
            log.info(i18n.t("actions.deleted_log", name=meta.name))

            blocked = False
            if block_bots and (meta.entity_type == "bot" or meta.is_bot):
                try:
                    await self._block_entity(entity)
                    blocked = True
                    log.info(i18n.t("actions.blocked_log", name=meta.name))
                except Exception as exc:  # noqa: BLE001
                    log.warning(i18n.t("actions.block_fail", error=exc))

            return ActionRecord(
                dialog_id=meta.id,
                name=meta.name,
                entity_type=meta.entity_type,
                risk_score=meta.risk_score,
                action="delete+block" if blocked else "delete",
                result=ActionResult.DELETED.value,
                reason=i18n.t("actions.deleted")
                + (i18n.t("actions.blocked_note") if blocked else ""),
                evidence=meta.evidence,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("%s: %s", meta.name, exc)
            return ActionRecord(
                dialog_id=meta.id,
                name=meta.name,
                entity_type=meta.entity_type,
                risk_score=meta.risk_score,
                action=self._plan_action(meta, block_bots),
                result=ActionResult.FAILED.value,
                reason=i18n.t("actions.failed"),
                error=str(exc),
                evidence=meta.evidence,
            )

    async def _resolve_entity(self, meta: DialogMeta) -> Any:
        """بازیابی موجودیت تلگرام از روی متادیتای کش‌شده."""
        try:
            if meta.username:
                try:
                    return await self.client.get_entity(meta.username)
                except Exception:  # noqa: BLE001
                    pass
            return await self.client.get_entity(meta.id)
        except Exception as exc:  # noqa: BLE001
            log.debug(i18n.t("actions.resolve_fail", id=meta.id, error=exc))
            return None

    # ------------------------------------------------------------------
    # اجرای دسته‌ای
    # ------------------------------------------------------------------

    async def execute_batch(
        self,
        metas: list[DialogMeta],
        block_bots: bool = False,
        progress_cb: Optional[Any] = None,
    ) -> list[ActionRecord]:
        """اجرای عملیات روی چند دیالوگ به‌صورت متوالی و امن."""
        records: list[ActionRecord] = []
        total = len(metas)

        for idx, meta in enumerate(metas, start=1):
            record = await self.execute(meta, block_bots=block_bots)
            records.append(record)
            if progress_cb:
                res = progress_cb(idx, total, record)
                if hasattr(res, "__await__"):
                    await res

        done = sum(
            1
            for r in records
            if r.result in (ActionResult.DELETED.value, ActionResult.LEFT.value)
        )
        log.info(i18n.t("actions.batch_done", done=done, total=total, dry=self.dry_run))
        return records
