"""TeleSweep — automatically clean worthless Telegram chats.

A local, security-first tool that scans a Telegram account, scores every
dialog against strict rules, and removes the worthless ones — but only
after explicit confirmation.
"""

__version__ = "1.0.0"
__all__ = [
    "i18n",
    "client",
    "scanner",
    "rules",
    "actions",
    "report",
    "tui",
    "webui",
    "utils",
]
