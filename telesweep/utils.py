"""utils.py — logging! امن، rate limiter، بارگذاری کانفیگ، کمک‌گرها.

الزامهای امنیتی:
- هیچ‌وقت شماره تلفن، کد ورود، api_hash، توکن یا session string لاگ نمی‌شود.
- rate limiter برای جلوگیری از FloodWait و مسدود شدن حساب.
"""

from __future__ import annotations

import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

# ------------------------------------------------------------------
# sanitize: پاک‌سازی متن لاگ از اطلاعات حساس
# ------------------------------------------------------------------

# الگوهای حساسی که نباید در لاگ ظاهر شوند
_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # شماره تلفن بین‌المللی / ایرانی
    (re.compile(r"\+98\d{8,12}"), "+98**********"),
    (re.compile(r"\b09\d{9}\b"), "09*********"),
    # api_hash تلگرام (۳۲ کاراکتر hex)
    (re.compile(r"\b[0-9a-fA-F]{32}\b"), "<api_hash>"),
    # توکن‌های بات
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "<bot_token>"),
    # session string تلگرام
    (re.compile(r"1[A-Za-z0-9_-]{30,}"), "<session_string>"),
    # کد ورود تلگرام در بافتار صریح (مثلاً "code: 12345")
    (re.compile(r"(?i)(code|کد)[:\s]+(\d{4,6})"), r"\1: <code>"),
    # passphrase در بافتار key=value
    (
        re.compile(r"(?i)(passphrase|password|api_hash|token|secret)[:=]\s*\S+"),
        r"\1=<redacted>",
    ),
]

_REDACT_KEYWORDS = (
    "api_hash",
    "api_id",
    "phone",
    "password",
    "token",
    "session",
    "code",
    "secret",
    "passphrase",
)


def sanitize_text(text: str) -> str:
    """متن را از اطلاعات حساس پاک می‌کند."""
    if not isinstance(text, str):
        text = str(text)
    out = text
    for pattern, replacement in _SENSITIVE_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


class SanitizingFilter(logging.Filter):
    """فیلتر لاگر که پیام نهایی را از اطلاعات حساس پاک می‌کند.

    ابتدا پیام را با args قالب‌بندی می‌کند (تا %d/%s درست کار کنند)،
    سپس نتیجه را سانی‌تایز می‌کند.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            formatted = record.getMessage()
        except Exception:  # noqa: BLE001 - قالب‌بندی نامعتبر
            formatted = str(record.msg)
        record.msg = sanitize_text(formatted)
        record.args = None
        return True


def setup_logger(
    name: str = "telesweep",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """لاگر امن با سانی‌تایز اجباری. هیچ اعتباری لاگ نمی‌شود."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console.addFilter(SanitizingFilter())
    logger.addHandler(console)

    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.addFilter(SanitizingFilter())
        logger.addHandler(fh)

    return logger


# ------------------------------------------------------------------
# Rate limiter: جلوگیری از FloodWait
# ------------------------------------------------------------------


@dataclass
class RateLimiter:
    """rate limiter ساده با تأخیر تصادفی و سقف عملیات در ساعت."""

    min_delay: float = 0.5
    max_delay: float = 1.0
    max_ops_per_hour: int = 100
    _timestamps: list[float] = field(default_factory=list)

    def _prune(self, now: float) -> None:
        cutoff = now - 3600.0
        self._timestamps = [t for t in self._timestamps if t > cutoff]

    async def wait(self) -> None:
        """منتظر می‌ماند تا مجاز بودن درخواست بعدی."""
        now = time.monotonic()
        self._prune(now)

        if len(self._timestamps) >= self.max_ops_per_hour:
            sleep_for = self._timestamps[0] + 3600.0 - now
            # هیچ‌وقت بیش از ۳۰ ثانیه در یک مرحله نخواب — ترجیح بر ادامه با تأخیر است
            if sleep_for > 30.0:
                import logging

                logging.getLogger("telesweep").warning(
                    "سقف ساعتی رسیده (%s) — به‌جای انتظار کامل، ادامه با تأخیر.",
                    self.max_ops_per_hour,
                )
                self._timestamps = self._timestamps[-self.max_ops_per_hour // 2 :]
            elif sleep_for > 0:
                import asyncio

                await asyncio.sleep(sleep_for)
                now = time.monotonic()
                self._prune(now)

        if self._timestamps:
            elapsed = now - self._timestamps[-1]
            needed = random.uniform(self.min_delay, self.max_delay)
            if elapsed < needed:
                import asyncio

                await asyncio.sleep(needed - elapsed)

        self._timestamps.append(time.monotonic())


def compute_floodwait_sleep(seconds: int) -> float:
    """محاسبه زمان خواب امن بعد از FloodWaitError (با حاشیه امنیت)."""
    return float(seconds) + 5.0


# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "thresholds": {
        "inactivity_days": 180,
        "risk_score": 80,
        "min_evidence": 2,
        "one_way_ratio": 0.8,
        "one_way_reply_days": 90,
        "recent_message_sample": 20,
    },
    "rate_limit": {
        "min_delay": 0.5,
        "max_delay": 1.0,
        "max_ops_per_hour": 100,
    },
    "security": {
        "secrets_file": "config/secrets.enc",
        "session_file": "data/telesweep.session",
        "webui_host": "127.0.0.1",
        "webui_port": 8462,
        "require_final_confirm": True,
    },
    "protection": {
        "skip_saved_messages": True,
        "skip_pinned": True,
        "skip_contacts": True,
    },
    "whitelist": [],
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """ادغام عمیق override روی base."""
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Optional[str | Path] = None) -> dict[str, Any]:
    """بارگذاری کانفیگ با مقادیر پیش‌فرض. در صورت نبود فایل، پیش‌فرض برمی‌گرداند."""
    if path is None:
        path = Path("config/config.yaml")
    path = Path(path)

    config = dict(DEFAULT_CONFIG)
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
        config = _deep_merge(config, user_cfg)

    # مسیرها را نسبت به cwd پروژه نرمال‌سازی کن
    base = Path(os.getcwd())
    sec = config.setdefault("security", {})
    for key in ("secrets_file", "session_file"):
        if sec.get(key):
            p = Path(sec[key])
            sec[key] = str(p if p.is_absolute() else base / p)

    # whitelist را به lowercase string نرمال کن
    wl = config.get("whitelist") or []
    config["whitelist"] = [str(w).lower().lstrip("@") for w in wl if str(w).strip()]

    # اعتبارسنجی عددی
    th = config["thresholds"]
    th["inactivity_days"] = int(th["inactivity_days"])
    th["risk_score"] = int(th["risk_score"])
    th["min_evidence"] = int(th["min_evidence"])
    th["one_way_ratio"] = float(th["one_way_ratio"])
    th["one_way_reply_days"] = int(th["one_way_reply_days"])
    th["recent_message_sample"] = int(th["recent_message_sample"])

    rl = config["rate_limit"]
    rl["min_delay"] = float(rl["min_delay"])
    rl["max_delay"] = float(rl["max_delay"])
    rl["max_ops_per_hour"] = int(rl["max_ops_per_hour"])

    return config


# ------------------------------------------------------------------
# Helpertools
# ------------------------------------------------------------------


def utc_timestamp() -> str:
    """timestamp ایمن برای نام فایل گزارش."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def secure_file_permissions(path: str | Path) -> None:
    """تنظیم دسترسی ۶۰۰ فقط برای فایل‌های حساس (owner read/write)."""
    p = Path(path)
    if p.exists():
        p.chmod(0o600)


def in_whitelist(identifier: Optional[str], whitelist: list[str]) -> bool:
    """بررسی اینکه آیا شناسه در لیست سفید است."""
    if not identifier or not whitelist:
        return False
    normalized = str(identifier).lower().lstrip("@")
    return normalized in [str(w).lower().lstrip("@") for w in whitelist]
