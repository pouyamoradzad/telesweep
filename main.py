"""main.py — the TeleSweep CLI entry point.

Commands:
  init      — initial setup (collect api_id/api_hash and encrypt them)
  scan      — scan dialogs and write a dry-run report (nothing is changed)
  review    — interactive review in the TUI (dry-run by default)
  web       — run the local web UI on 127.0.0.1
  auto      — scan and delete automatically (requires an explicit --i-know)
  logout    — log out and delete the session

Security principles:
- The default mode is always non-destructive.
- Real deletion requires explicit confirmation.
- The web UI binds to localhost only.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from telesweep import i18n
from telesweep.actions import ActionExecutor
from telesweep.client import (
    Secrets,
    SecretsStore,
    TelegramClientWrapper,
    _prompt_passphrase,
    _prompt_secrets,
    load_or_init_secrets,
)
from telesweep.report import generate_report
from telesweep.rules import evaluate_all, summary
from telesweep.scanner import Scanner, load_latest_scan, save_scan_cache
from telesweep.utils import load_config, setup_logger

log = setup_logger("telesweep.main")

PROJECT_ROOT = Path(__file__).parent.resolve()
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "config.yaml"
EXAMPLE_CONFIG = PROJECT_ROOT / "config" / "config.example.yaml"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telesweep",
        description=i18n.t("cli.description"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=i18n.t("cli.epilog"),
    )
    parser.add_argument(
        "-c", "--config", default=str(DEFAULT_CONFIG), help=i18n.t("cli.config")
    )
    parser.add_argument("--secrets", default=None, help=i18n.t("cli.secrets"))
    parser.add_argument("--passphrase", default=None, help=i18n.t("cli.passphrase"))
    parser.add_argument("--lang", default=None, help=i18n.t("cli.lang"))
    parser.add_argument(
        "-v", "--verbose", action="store_true", help=i18n.t("cli.verbose")
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help=i18n.t("cli.init"))

    scan_p = sub.add_parser("scan", help=i18n.t("cli.scan"))
    scan_p.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    scan_p.add_argument("--reports-dir", default=str(PROJECT_ROOT / "reports"))

    review_p = sub.add_parser("review", help=i18n.t("cli.review"))
    review_p.add_argument("--apply", action="store_true", help=i18n.t("cli.apply"))
    review_p.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    review_p.add_argument("--reports-dir", default=str(PROJECT_ROOT / "reports"))

    web_p = sub.add_parser("web", help=i18n.t("cli.web"))
    web_p.add_argument("--host", default=None, help=i18n.t("cli.host"))
    web_p.add_argument("--port", default=None, type=int)
    web_p.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    web_p.add_argument("--reports-dir", default=str(PROJECT_ROOT / "reports"))

    auto_p = sub.add_parser("auto", help=i18n.t("cli.auto"))
    auto_p.add_argument("--i-know", action="store_true", help=i18n.t("cli.i_know"))
    auto_p.add_argument(
        "--block-bots", action="store_true", help=i18n.t("cli.block_bots")
    )
    auto_p.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    auto_p.add_argument("--reports-dir", default=str(PROJECT_ROOT / "reports"))

    sub.add_parser("logout", help=i18n.t("cli.logout"))

    return parser


def _resolve_config(args: argparse.Namespace) -> dict[str, Any]:
    """Load config, falling back to the bundled example."""
    config_path = Path(args.config)
    if not config_path.exists():
        config_path = EXAMPLE_CONFIG
    return load_config(config_path)


def _get_secrets(config: dict[str, Any], args: argparse.Namespace) -> Secrets:
    """Load credentials, resolving the passphrase from args/file/interactive."""
    secrets_path = args.secrets or config["security"]["secrets_file"]
    passphrase = args.passphrase
    if passphrase is None:
        pp_path = Path(secrets_path).parent / "passphrase.txt"
        if pp_path.exists():
            passphrase = pp_path.read_text(encoding="utf-8").strip()
    return load_or_init_secrets(secrets_path, passphrase)


async def cmd_init(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Initial setup."""
    secrets_path = config["security"]["secrets_file"]
    store = SecretsStore(secrets_path)
    if store.exists():
        log.info(i18n.t("cli.init_exists") + ": %s", secrets_path)
        return 0

    creds = _prompt_secrets()
    passphrase = _prompt_passphrase(confirm=True)
    store.store(creds, passphrase)
    del passphrase
    log.info(i18n.t("cli.init_done"))
    return 0


async def cmd_scan(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Scan and write a dry-run report."""
    secrets = _get_secrets(config, args)
    async with TelegramClientWrapper(
        secrets, config["security"]["session_file"]
    ) as wrapper:
        scanner = Scanner(
            wrapper,
            recent_sample=config["thresholds"]["recent_message_sample"],
        )
        metas = await scanner.scan_all()
        metas = evaluate_all(metas, config)
        save_scan_cache(metas, args.data_dir)
        paths = generate_report(
            metas,
            records=None,
            config=config,
            reports_dir=args.reports_dir,
            dry_run=True,
        )

    stats = summary(metas)
    log.info(
        i18n.t(
            "cli.scan_done",
            total=stats["total"],
            flagged=stats["flagged_for_deletion"],
            protected=stats["protected"],
        )
    )
    log.info(
        i18n.t(
            "cli.reports_written",
            paths=", ".join(str(p) for p in paths.values()),
        )
    )
    log.info(i18n.t("cli.dry_run_note"))
    return 0


async def cmd_review(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Interactive review in the TUI."""
    from telesweep.tui import run_tui

    secrets = _get_secrets(config, args)
    data_dir = Path(args.data_dir)

    async with TelegramClientWrapper(
        secrets, config["security"]["session_file"]
    ) as wrapper:
        cache = load_latest_scan(data_dir)
        if cache:
            from telesweep.scanner import DialogMeta

            log.info(i18n.t("cli.using_cache", total=cache.get("total", 0)))
            metas = [DialogMeta(**d) for d in cache.get("dialogs", [])]
            metas = evaluate_all(metas, config)
        else:
            log.info(i18n.t("cli.no_cache"))
            scanner = Scanner(
                wrapper,
                recent_sample=config["thresholds"]["recent_message_sample"],
            )
            metas = await scanner.scan_all()
            metas = evaluate_all(metas, config)
            save_scan_cache(metas, data_dir)

        executor = ActionExecutor(wrapper, config, dry_run=not args.apply)
        results, exit_code = run_tui(metas, executor)

    if results:
        generate_report(
            metas,
            records=results,
            config=config,
            reports_dir=args.reports_dir,
            dry_run=not args.apply,
        )
    return exit_code


async def cmd_web(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Run the local web UI."""
    from telesweep.webui import create_app, serve

    host = args.host or config["security"]["webui_host"]
    port = args.port or config["security"]["webui_port"]

    if host not in ("127.0.0.1", "localhost"):
        log.error(i18n.t("cli.host"))
        return 1

    secrets_obj = _get_secrets(config, args)
    wrapper = TelegramClientWrapper(secrets_obj, config["security"]["session_file"])
    await wrapper.start()

    scanner = Scanner(
        wrapper,
        recent_sample=config["thresholds"]["recent_message_sample"],
    )
    executor = ActionExecutor(wrapper, config, dry_run=True)

    app = create_app(
        wrapper,
        config,
        scanner,
        executor,
        data_dir=args.data_dir,
        reports_dir=args.reports_dir,
    )

    token = app.state.token

    # Persist the token so a browser can be opened quickly (localhost only).
    token_path = Path(args.data_dir) / "webui_token.txt"
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(token, encoding="utf-8")
    token_path.chmod(0o600)

    url = f"http://127.0.0.1:{port}/?token={token}"
    print("\n" + "=" * 60)
    print(i18n.t("app.title") + " — web UI")
    print("=" * 60)
    print(i18n.t("cli.web_url", url=url))
    print(i18n.t("cli.web_local"))
    print(i18n.t("cli.web_secret"))
    print("=" * 60 + "\n")
    log.info(i18n.t("cli.web_stop"))

    try:
        await serve(app, host="127.0.0.1", port=port)
    finally:
        await wrapper.close()
    return 0


async def cmd_auto(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Scan and delete automatically. Requires an explicit --i-know."""
    if not args.i_know:
        log.error(i18n.t("cli.auto_refused"))
        return 2

    secrets = _get_secrets(config, args)
    async with TelegramClientWrapper(
        secrets, config["security"]["session_file"]
    ) as wrapper:
        scanner = Scanner(
            wrapper,
            recent_sample=config["thresholds"]["recent_message_sample"],
        )
        metas = await scanner.scan_all()
        metas = evaluate_all(metas, config)
        save_scan_cache(metas, args.data_dir)

        flagged = [m for m in metas if m.should_delete]
        if not flagged:
            log.info(i18n.t("cli.no_flagged"))
            generate_report(
                metas,
                records=None,
                config=config,
                reports_dir=args.reports_dir,
                dry_run=True,
            )
            return 0

        log.info(i18n.t("cli.batch_start", count=len(flagged)))
        executor = ActionExecutor(wrapper, config, dry_run=False)
        records = await executor.execute_batch(flagged, block_bots=args.block_bots)

    paths = generate_report(
        metas,
        records=records,
        config=config,
        reports_dir=args.reports_dir,
        dry_run=False,
    )
    deleted = sum(1 for r in records if r.result in ("deleted", "left"))
    failed = sum(1 for r in records if r.result == "failed")
    log.info(i18n.t("cli.batch_done", deleted=deleted, failed=failed))
    log.info(
        i18n.t("cli.reports_written", paths=", ".join(str(p) for p in paths.values()))
    )
    return 0 if failed == 0 else 1


async def cmd_logout(args: argparse.Namespace, config: dict[str, Any]) -> int:
    """Log out safely and delete the session."""
    secrets = _get_secrets(config, args)
    wrapper = TelegramClientWrapper(secrets, config["security"]["session_file"])
    await wrapper.start()
    try:
        await wrapper.client.log_out()
        log.info(i18n.t("cli.logout_done"))
    except Exception as exc:  # noqa: BLE001
        log.error(i18n.t("cli.logout_fail") + ": %s", exc)
        return 1
    finally:
        await wrapper.close()
    return 0


def main() -> int:
    # Resolve the language before parsing help text so messages localize.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default=None)
    pre.add_argument("rest", nargs=argparse.REMAINDER)
    known, _ = pre.parse_known_args()

    i18n.set_locale(known.lang or i18n.detect_locale())

    parser = _build_parser()
    args = parser.parse_args()

    if args.verbose:
        setup_logger("telesweep", level=10)  # DEBUG

    config = _resolve_config(args)

    commands = {
        "init": cmd_init,
        "scan": cmd_scan,
        "review": cmd_review,
        "web": cmd_web,
        "auto": cmd_auto,
        "logout": cmd_logout,
    }
    handler = commands[args.command]

    try:
        return asyncio.run(handler(args, config))
    except KeyboardInterrupt:
        log.info(i18n.t("cli.interrupted"))
        return 130
    except FileNotFoundError as exc:
        log.error(i18n.t("cli.no_secrets"))
        log.debug("%s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        log.error("%s: %s", type(exc).__name__, exc)
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
