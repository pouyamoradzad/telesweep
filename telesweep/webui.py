"""webui.py — the local web UI (FastAPI).

Security
--------
* Binds to ``127.0.0.1`` only — never ``0.0.0.0``.
* A random per-session token is required for every API call.
* Destructive calls require an explicit ``confirm: true``; otherwise a
  dry-run preview is returned and nothing is changed.

Internationalization
--------------------
The browser fetches the active locale catalog from ``/api/i18n``; the HTML
shell stays language-neutral and renders everything via JS ``t()``.
"""

from __future__ import annotations

import asyncio
import secrets as pysecrets
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse

from . import i18n
from .actions import ActionExecutor, ActionRecord
from .report import generate_report
from .rules import evaluate_all
from .scanner import DialogMeta, save_scan_cache
from .utils import setup_logger

log = setup_logger("telesweep.webui")

HTML_PATH = Path(__file__).parent.parent / "web" / "static" / "index.html"


class WebUIState:
    """Shared state between endpoints and background work."""

    def __init__(self) -> None:
        self.token: str = pysecrets.token_urlsafe(32)
        self.scan_status: str = "idle"  # idle | scanning | done | error
        self.scan_progress: tuple[int, int] = (0, 0)
        self.scan_error: Optional[str] = None
        self.metas: list[DialogMeta] = []
        self.last_action_results: list[ActionRecord] = []
        self.last_report_paths: dict[str, Path] = {}


def create_app(
    client_wrapper: Any,
    config: dict[str, Any],
    scanner: Any,
    executor: ActionExecutor,
    data_dir: str | Path = "data",
    reports_dir: str | Path = "reports",
) -> FastAPI:
    """Build the FastAPI app with injected dependencies."""
    state = WebUIState()
    app = FastAPI(title="TeleSweep", docs_url=None, redoc_url=None)
    # asyncio.Lock() binds to the running loop at construction time on
    # Python 3.9, so create it lazily inside the first request instead.
    state_lock: Optional[asyncio.Lock] = None

    def _lock() -> asyncio.Lock:
        nonlocal state_lock
        if state_lock is None:
            state_lock = asyncio.Lock()
        return state_lock

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_locale(locale: Optional[str]) -> str:
        """Pick a valid locale from the request, falling back to English."""
        if locale and locale in i18n.available_locales():
            return locale
        return i18n.DEFAULT_LOCALE

    def _verify_token(request: Request, token: Optional[str]) -> None:
        candidate = token
        if candidate is None:
            header = request.headers.get("Authorization", "")
            candidate = header.removeprefix("Bearer ").strip() or None
        if candidate is None:
            candidate = request.cookies.get("telesweep_token")
        if not candidate or not _consttime_eq(candidate, state.token):
            raise HTTPException(status_code=401, detail=i18n.t("errors.unauthorized"))

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index(
        token: Optional[str] = Query(default=None),
        lang: Optional[str] = Query(default=None),
    ) -> HTMLResponse:
        if not HTML_PATH.exists():
            return HTMLResponse(
                f"<h1>{i18n.t('errors.html_missing')}</h1>", status_code=500
            )
        content = HTML_PATH.read_text(encoding="utf-8")
        locale = _resolve_locale(lang)
        token_ok = bool(token) and _consttime_eq(token, state.token)
        content = content.replace("__LOCALE__", locale)
        content = content.replace("__TOKEN__", token if token_ok else "")
        content = content.replace(
            "__LANGUAGES__",
            ",".join(i18n.available_locales()),
        )
        return HTMLResponse(content)

    # ------------------------------------------------------------------
    # i18n
    # ------------------------------------------------------------------

    @app.get("/api/i18n")
    async def api_i18n(
        lang: Optional[str] = Query(default=None),
    ) -> dict[str, Any]:
        """Return the merged catalog + direction for the requested locale."""
        locale = _resolve_locale(lang)
        return {
            "locale": locale,
            "direction": "rtl" if i18n.is_rtl(locale) else "ltr",
            "catalog": i18n.catalog(locale),
            "languages": {
                code: i18n.LANGUAGE_NAMES.get(code, code)
                for code in i18n.available_locales()
            },
        }

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    @app.post("/api/scan")
    async def api_scan(
        token: Optional[str] = Query(default=None),
        request: Request = None,  # type: ignore[assignment]
    ) -> dict[str, Any]:
        _verify_token(request, token)
        async with _lock():
            if state.scan_status == "scanning":
                return {"status": "already_scanning"}
            state.scan_status = "scanning"
            state.scan_progress = (0, 0)
            state.scan_error = None

        async def progress_cb(current: int, total: int, name: str) -> None:
            state.scan_progress = (current, total)

        async def run() -> None:
            try:
                metas = await scanner.scan_all(progress_cb=progress_cb)
                state.metas = evaluate_all(metas, config)
                save_scan_cache(state.metas, data_dir)
                state.scan_status = "done"
                log.info("Scan via web UI complete.")
            except Exception as exc:  # noqa: BLE001
                state.scan_status = "error"
                state.scan_error = str(exc)
                log.error("Web UI scan failed: %s", exc)

        asyncio.create_task(run())
        return {"status": "started"}

    @app.get("/api/scan/status")
    async def api_scan_status(
        token: Optional[str] = Query(default=None),
        request: Request = None,  # type: ignore[assignment]
    ) -> dict[str, Any]:
        _verify_token(request, token)
        current, total = state.scan_progress
        return {
            "status": state.scan_status,
            "current": current,
            "total": total,
            "error": state.scan_error,
        }

    @app.get("/api/chats")
    async def api_chats(
        token: Optional[str] = Query(default=None),
        request: Request = None,  # type: ignore[assignment]
        only_flagged: bool = Query(default=False),
    ) -> dict[str, Any]:
        _verify_token(request, token)
        metas = state.metas
        if only_flagged:
            metas = [m for m in metas if m.should_delete]
        return {
            "total": len(state.metas),
            "dialogs": [m.to_dict() for m in metas],
            "last_results": [r.to_dict() for r in state.last_action_results],
        }

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    @app.post("/api/delete")
    async def api_delete(request: Request) -> dict[str, Any]:
        """Delete selected dialogs.

        Without ``confirm: true`` this is a harmless dry-run preview.
        """
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            payload = {}

        _verify_token(request, payload.get("token"))

        ids = [int(i) for i in (payload.get("ids") or [])]
        confirmed = bool(payload.get("confirm", False))
        block_bots = bool(payload.get("block_bots", True))

        if not ids:
            raise HTTPException(status_code=400, detail=i18n.t("errors.no_ids"))

        metas_by_id = {m.id: m for m in state.metas}
        selected = [metas_by_id[i] for i in ids if i in metas_by_id]
        if not selected:
            raise HTTPException(status_code=404, detail=i18n.t("errors.not_found"))

        if not confirmed:
            preview = [
                {
                    "id": m.id,
                    "name": m.name,
                    "planned_action": _plan(m, block_bots),
                    "risk_score": m.risk_score,
                    "rules": [e["rule"] for e in m.evidence],
                }
                for m in selected
            ]
            return {
                "mode": "dry_run_preview",
                "message": i18n.t("scan.hint"),
                "preview": preview,
            }

        was_dry = executor.dry_run
        executor.dry_run = False
        try:
            records = await executor.execute_batch(selected, block_bots=block_bots)
        finally:
            executor.dry_run = was_dry

        state.last_action_results = records
        paths = generate_report(
            state.metas,
            records=records,
            config=config,
            reports_dir=reports_dir,
            dry_run=False,
        )
        state.last_report_paths = paths

        deleted = sum(1 for r in records if r.result in ("deleted", "left"))
        failed = sum(1 for r in records if r.result == "failed")
        return {
            "mode": "executed",
            "deleted": deleted,
            "failed": failed,
            "total": len(records),
            "results": [r.to_dict() for r in records],
            "report": {k: str(v) for k, v in paths.items()},
        }

    @app.get("/api/report/{fmt}")
    async def api_report(
        fmt: str,
        token: Optional[str] = Query(default=None),
        lang: Optional[str] = Query(default=None),
        request: Request = None,  # type: ignore[assignment]
    ) -> Any:
        _verify_token(request, token)
        i18n.set_locale(_resolve_locale(lang))
        fmt = fmt.lower()
        if fmt not in state.last_report_paths and state.metas:
            state.last_report_paths = generate_report(
                state.metas,
                records=state.last_action_results,
                config=config,
                reports_dir=reports_dir,
                dry_run=executor.dry_run,
            )
        path = state.last_report_paths.get(fmt)
        if not path or not Path(path).exists():
            raise HTTPException(status_code=404, detail=i18n.t("errors.report_missing"))

        media = {
            "json": "application/json",
            "csv": "text/csv",
            "html": "text/html",
        }
        return FileResponse(path, media_type=media.get(fmt, "application/octet-stream"))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @app.on_event("startup")
    async def _startup() -> None:
        log.info(
            "Web UI listening on http://127.0.0.1:%s — localhost only.",
            config.get("security", {}).get("webui_port", 8462),
        )

    app.state.token = state.token
    app.state.shared_state = state
    return app


def _consttime_eq(a: str, b: str) -> bool:
    """Constant-time comparison to avoid timing attacks on the token."""
    import hmac

    return hmac.compare_digest(a.encode(), b.encode())


def _plan(meta: DialogMeta, block_bots: bool) -> str:
    if meta.entity_type in ("channel", "group", "megagroup"):
        return i18n.t("actions.plan_leave")
    if block_bots and (meta.entity_type == "bot" or meta.is_bot):
        return i18n.t("actions.plan_delete_block")
    return i18n.t("actions.plan_delete")


async def serve(
    app: FastAPI,
    host: str = "127.0.0.1",
    port: int = 8462,
) -> None:
    """Run the server on localhost only (async, inside the current loop)."""
    import uvicorn

    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("For security, the web UI can only bind 127.0.0.1.")

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)
    await server.serve()
