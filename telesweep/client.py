"""client.py — کلاینت Telethon + رمزنگاری اعتبارنامه‌ها at-rest.

امنیت:
- api_id/api_hash در فایل secrets.enc با AES-256-GCM رمزنگاری می‌شوند.
- کلید از passphrase کاربر با PBKDF2-HMAC-SHA256 (۲۰۰٬۰۰۰ تکرار) مشتق می‌شود.
- salt تصادفی و nonce تصادفی برای هر فایل.
- فایل‌های سشن و secrets با دسترسی ۶۰۰ (owner-only) ذخیره می‌شوند.
- هیچ‌وقت شماره/کد/api_hash در لاگ قرار نمی‌گیرد (سانی‌تایز در utils).
"""

from __future__ import annotations

import getpass
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import i18n
from .utils import secure_file_permissions, setup_logger

log = setup_logger("telesweep.client")

# پارامترهای رمزنگاری
_PBKDF2_ITERATIONS = 200_000
_KEY_SIZE = 32  # AES-256
_NONCE_SIZE = 12  # GCM nonce
_SALT_SIZE = 16
_MAGIC = b"TGCLEANER\x01"

# کلمات حساسی که در لاگ نیازی به چاپ آن‌ها نیست
_REDACTED = "<redacted>"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """مشتق‌سازی کلید ۲۵۶ بیتی از passphrase با PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


@dataclass
class Secrets:
    """اعتبارنامه‌های رمزگشایی‌شده (هرگز لاگ نمی‌شوند)."""

    api_id: int
    api_hash: str
    phone: Optional[str] = None

    def redacted(self) -> dict[str, Any]:
        """نمای بدون اطلاعات حساس برای لاگ/دیباگ."""
        return {
            "api_id": self.api_id,
            "api_hash": _REDACTED,
            "phone": _REDACTED if self.phone else None,
        }


class SecretsStore:
    """ذخیره/بازیابی رمزنگاری‌شده‌ی api_id/api_hash."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def store(self, secrets_obj: Secrets, passphrase: str) -> None:
        """رمزنگاری و ذخیره‌ی اعتبارنامه‌ها."""
        salt = os.urandom(_SALT_SIZE)
        nonce = os.urandom(_NONCE_SIZE)
        key = _derive_key(passphrase, salt)
        aesgcm = AESGCM(key)

        payload = json.dumps(
            {
                "api_id": secrets_obj.api_id,
                "api_hash": secrets_obj.api_hash,
                "phone": secrets_obj.phone,
            },
            ensure_ascii=False,
        ).encode("utf-8")

        ciphertext = aesgcm.encrypt(nonce, payload, _MAGIC)
        blob = salt + nonce + ciphertext

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # قبل از نوشتن، فایل قبلی را حذف کن تا دسترسی صحیح اعمال شود
        if self.path.exists():
            self.path.unlink()

        fd = os.open(
            str(self.path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)

        secure_file_permissions(self.path)
        log.info(i18n.t("client.stored", path=self.path))

    def load(self, passphrase: str) -> Secrets:
        """بازیابی و رمزگشایی اعتبارنامه‌ها."""
        if not self.path.exists():
            raise FileNotFoundError(i18n.t("client.not_found", path=self.path))

        blob = self.path.read_bytes()
        if len(blob) < _SALT_SIZE + _NONCE_SIZE + 16:
            raise ValueError(i18n.t("client.corrupt"))

        salt = blob[:_SALT_SIZE]
        nonce = blob[_SALT_SIZE : _SALT_SIZE + _NONCE_SIZE]
        ciphertext = blob[_SALT_SIZE + _NONCE_SIZE :]

        key = _derive_key(passphrase, salt)
        aesgcm = AESGCM(key)

        try:
            payload = aesgcm.decrypt(nonce, ciphertext, _MAGIC)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(i18n.t("client.wrong_passphrase")) from exc

        data = json.loads(payload.decode("utf-8"))
        return Secrets(
            api_id=int(data["api_id"]),
            api_hash=str(data["api_hash"]),
            phone=data.get("phone"),
        )


def _prompt_secrets() -> Secrets:
    """Interactively collect api_id/api_hash from the user."""
    print("\n" + "=" * 60)
    print(i18n.t("client.setup_title"))
    print("=" * 60)
    print(i18n.t("client.setup_body"))

    while True:
        raw_id = getpass.getpass(i18n.t("client.api_id_prompt")).strip()
        try:
            api_id = int(raw_id)
            break
        except ValueError:
            print(i18n.t("client.api_id_invalid"))

    while True:
        api_hash = getpass.getpass(i18n.t("client.api_hash_prompt")).strip()
        if len(api_hash) >= 20:
            break
        print(i18n.t("client.api_hash_invalid"))

    phone = getpass.getpass(i18n.t("client.phone_prompt")).strip() or None
    return Secrets(api_id=api_id, api_hash=api_hash, phone=phone)


def _prompt_passphrase(confirm: bool = True) -> str:
    """Get a passphrase from the user (without terminal echo)."""
    while True:
        pw = getpass.getpass(i18n.t("client.passphrase_prompt"))
        if len(pw) < 8:
            print(i18n.t("client.passphrase_short"))
            continue
        if confirm:
            pw2 = getpass.getpass(i18n.t("client.passphrase_confirm"))
            if pw != pw2:
                print(i18n.t("client.passphrase_mismatch"))
                continue
        return pw


def init_secrets(secrets_path: str | Path) -> Secrets:
    """ساخت یا بازیابی اعتبارنامه‌ها. در صورت نبود، تعاملی می‌سازد."""
    store = SecretsStore(secrets_path)

    if store.exists():
        passphrase = _prompt_passphrase(confirm=False)
        return store.load(passphrase)

    log.info(i18n.t("client.setup_title"))
    creds = _prompt_secrets()
    passphrase = _prompt_passphrase(confirm=True)
    store.store(creds, passphrase)
    # پاک‌سازی متغیرها از حافظه به محتمال
    del passphrase
    return creds


def load_or_init_secrets(
    secrets_path: str | Path, passphrase: Optional[str] = None
) -> Secrets:
    """بارگذاری اعتبارنامه با passphrase اختیاری (غیر تعاملی)."""
    store = SecretsStore(secrets_path)
    if not store.exists():
        raise FileNotFoundError(i18n.t("client.not_found", path=secrets_path))
    if passphrase is None:
        passphrase = _prompt_passphrase(confirm=False)
    return store.load(passphrase)


# ------------------------------------------------------------------
# Telethon client
# ------------------------------------------------------------------


class TelegramClientWrapper:
    """پوشش امن روی TelegramClient.

    - سشن را در فایل با دسترسی ۶۰۰ نگه می‌دارد.
    - در صورت FloodWait به‌صورت خودکار منتظر می‌ماند.
    - هیچ اعتباری لاگ نمی‌کند.
    """

    def __init__(self, secrets: Secrets, session_path: str | Path):
        from telethon import TelegramClient

        self.secrets = secrets
        self.session_path = Path(session_path)
        self.session_path.parent.mkdir(parents=True, exist_ok=True)

        # اطمینان از اینکه سشن قبلی با مجوز مناسب ساخته می‌شود
        session_exists = self.session_path.exists()
        self.client = TelegramClient(
            str(self.session_path.with_suffix("")),
            secrets.api_id,
            secrets.api_hash,
        )
        if not session_exists:
            secure_file_permissions(self.session_path)

    async def __aenter__(self) -> TelegramClientWrapper:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def start(self) -> None:
        """اتصال و لاگین. شماره/کد/رمز هرگز لاگ نمی‌شوند.

        کد ورود و رمز 2FA می‌توانند از این منابع خوانده شوند (به‌ترتیب):
        1. env vars: TGCLEANER_LOGIN_CODE / TGCLEANER_2FA_PASSWORD
        2. فایل‌ها: data/login_code.txt / data/2fa_password.txt
        3. درگاه تعاملی (اگر available باشد)
        """
        import asyncio

        from telethon.errors import FloodWaitError

        phone = self.secrets.phone or None

        def _read_credential(env_name: str, file_name: str, prompt: str) -> str:
            """خواندن اعتبارنامه — هر بار فایل را تازه می‌خواند.

            اگر فایل از تلاش قبلی تغییر نکرده باشد، تعاملی می‌پرسد.
            """
            import getpass
            import os

            value = os.environ.get(env_name, "").strip()
            if value:
                return value
            path = Path(file_name)
            if path.exists():
                mtime = path.stat().st_mtime
                seen = _read_credential._seen
                if file_name not in seen or seen[file_name] != mtime:
                    seen[file_name] = mtime
                    value = path.read_text(encoding="utf-8").strip()
                    if value:
                        return value
            return getpass.getpass(prompt)

        _read_credential._seen: dict[str, float] = {}

        def code_callback() -> str:
            return _read_credential(
                "TGCLEANER_LOGIN_CODE",
                "data/login_code.txt",
                i18n.t("client.code_prompt"),
            )

        def password_callback() -> str:
            return _read_credential(
                "TGCLEANER_2FA_PASSWORD",
                "data/2fa_password.txt",
                i18n.t("client.password_prompt"),
            )

        for attempt in range(3):
            try:
                await self.client.start(
                    phone=phone,
                    code_callback=code_callback,
                    password=password_callback,
                )
                break
            except FloodWaitError as exc:
                wait = float(exc.seconds) + 5.0
                log.warning(i18n.t("client.floodwait_login", seconds=int(wait)))
                if attempt == 2:
                    raise
                await asyncio.sleep(wait)
        else:
            raise RuntimeError(i18n.t("client.connect_fail"))

        # پاک‌سازی فایل‌های حساس بعد از لاگین موفق
        for name in ("data/login_code.txt", "data/2fa_password.txt"):
            path = Path(name)
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass

        # مجدد اطمینان از دسترسی سشن
        if self.session_path.exists():
            secure_file_permissions(self.session_path)

        me = await self.client.get_me()
        log.info(i18n.t("client.connected", id=getattr(me, "id", "?")))

    async def close(self) -> None:
        """بستن امن کلاینت."""
        try:
            await self.client.disconnect()
        except Exception as exc:  # noqa: BLE001
            log.debug("disconnect error: %s", exc)
        log.info(i18n.t("client.disconnected"))

    async def safe_request(self, coro_fn, *args, **kwargs):
        """اجرای درخواست تلگرام با مدیریت FloodWait و تلاش مجدد."""
        import asyncio

        from telethon.errors import FloodWaitError

        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                return await coro_fn(*args, **kwargs)
            except FloodWaitError as exc:
                wait = float(exc.seconds) + 5.0
                log.warning(
                    "FloodWait دریافت شد — %s ثانیه صبر می‌کنیم (تلاش %d/۳).",
                    int(wait),
                    attempt + 1,
                )
                last_exc = exc
                await asyncio.sleep(wait)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                log.error(i18n.t("client.request_error", error=exc))
                raise

        if last_exc:
            raise last_exc
