"""tui.py — terminal UI (Textual) for reviewing and deleting flagged chats.

Features:
- browseable table of flagged chats (name, type, score, reasons, last message)
- select/unselect each row
- press 'd' → final confirmation → delete the selected ones
- protected chats and the reasons they are kept are also visible
"""

from __future__ import annotations

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Static,
)

from . import i18n
from .actions import ActionExecutor, ActionRecord
from .scanner import DialogMeta
from .utils import setup_logger

log = setup_logger("telesweep.tui")


class ConfirmModal(ModalScreen[bool]):
    """Final deletion confirmation modal."""

    BINDINGS = [
        Binding("y", "confirm", "yes"),
        Binding("n,escape", "cancel", "no"),
    ]

    def __init__(self, count: int, dry_run: bool):
        super().__init__()
        self.count = count
        self.dry_run = dry_run

    def compose(self) -> ComposeResult:
        mode = i18n.t("tui.mode_dry") if self.dry_run else i18n.t("tui.mode_real")
        yield Static(
            "\n[bold red]"
            + i18n.t("tui.confirm_title")
            + "[/bold red]\n\n"
            + i18n.t("tui.confirm_body", count=self.count, mode=mode)
        )

    def on_mount(self) -> None:
        self.query_one(Static).styles.border = ("round", "red")
        self.query_one(Static).styles.padding = (1, 2)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class CleanerApp(App):
    """TeleSweep terminal UI."""

    TITLE = "TeleSweep"
    CSS = """
    #status { padding: 1 2; background: $panel; border-bottom: solid $primary; }
    #table { height: 1fr; margin: 1 2; }
    #result { padding: 1 2; }
    """

    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("d", "delete_selected", "delete"),
        Binding("a", "select_all", "select all"),
        Binding("n", "select_none", "clear"),
        Binding("p", "toggle_protected", "protected"),
    ]

    def __init__(
        self,
        metas: list[DialogMeta],
        executor: ActionExecutor,
        show_protected: bool = False,
    ):
        super().__init__()
        self.metas = metas
        self.executor = executor
        self.show_protected = show_protected
        self.selected: set[int] = set()
        self.results: list[ActionRecord] = []
        self._confirming = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _columns(self) -> list[str]:
        return [
            "✓",
            i18n.t("table.name"),
            i18n.t("table.type"),
            i18n.t("table.score"),
            i18n.t("table.last_message"),
            i18n.t("table.reasons"),
            i18n.t("table.status"),
        ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(self._status_markup(), id="status")
        yield DataTable(id="table")
        yield Static(id="result")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.cursor_type = "row"
        for col in self._columns():
            table.add_column(col, key=col)
        self._populate_table()

    # ------------------------------------------------------------------
    # Table
    # ------------------------------------------------------------------

    def _status_markup(self) -> str:
        flagged = sum(1 for m in self.metas if m.should_delete)
        protected = sum(1 for m in self.metas if m.protection_reason)
        mode = (
            i18n.t("tui.mode_dry") if self.executor.dry_run else i18n.t("tui.mode_real")
        )
        base = i18n.t(
            "tui.status",
            total=len(self.metas),
            flagged=flagged,
            protected=protected,
            mode=mode,
        )
        return (
            f"[bold]{i18n.t('app.title')}[/bold] — {base}"
            f" · [cyan]{i18n.t('actions.select_all')}: {len(self.selected)}[/cyan]"
        )

    def _visible_metas(self) -> list[DialogMeta]:
        if self.show_protected:
            return [m for m in self.metas if m.protection_reason]
        return [m for m in self.metas if not m.protection_reason]

    def _populate_table(self) -> None:
        table = self.query_one("#table", DataTable)
        table.clear()
        for meta in self._visible_metas():
            checked = "✓" if meta.id in self.selected else ""
            reasons = (
                "; ".join(i18n.t("rules." + e["rule"]) for e in meta.evidence) or "—"
            )
            protection = meta.protection_reason or "—"
            table.add_row(
                checked,
                meta.name[:40],
                i18n.t(
                    "types." + meta.entity_type,
                ),
                str(meta.risk_score),
                (meta.last_message_date or "—")[:10],
                reasons,
                protection,
                key=str(meta.id),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Toggle selection with Enter or click."""
        try:
            dialog_id = int(event.row_key.value)
        except (TypeError, ValueError):
            return
        if dialog_id in self.selected:
            self.selected.discard(dialog_id)
        else:
            self.selected.add(dialog_id)
        self._populate_table()
        self._update_status()

    def _update_status(self) -> None:
        self.query_one("#status", Static).update(self._status_markup())

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_select_all(self) -> None:
        for meta in self._visible_metas():
            if meta.should_delete:
                self.selected.add(meta.id)
        self._populate_table()
        self._update_status()

    def action_select_none(self) -> None:
        self.selected.clear()
        self._populate_table()
        self._update_status()

    def action_toggle_protected(self) -> None:
        self.show_protected = not self.show_protected
        self.selected.clear()
        self._populate_table()
        label = (
            i18n.t("tui.showing_protected")
            if self.show_protected
            else i18n.t("tui.showing_deletable")
        )
        self.query_one("#result", Static).update(
            f"[bold]{label}[/bold] — {i18n.t('tui.toggle_hint')}"
        )

    def action_delete_selected(self) -> None:
        if not self.selected:
            self.query_one("#result", Static).update(
                "[yellow]" + i18n.t("tui.nothing_selected") + "[/yellow]"
            )
            return
        if self._confirming:
            return
        self._confirming = True
        self.push_screen(
            ConfirmModal(len(self.selected), self.executor.dry_run),
            callback=self._handle_confirm,
        )

    def _handle_confirm(self, confirmed: bool) -> None:
        self._confirming = False
        if not confirmed:
            self.query_one("#result", Static).update(
                "[green]" + i18n.t("tui.cancelled") + "[/green]"
            )
            return
        self._run_deletions()

    @work(exclusive=True, group="delete")
    async def _run_deletions(self) -> None:
        result_widget = self.query_one("#result", Static)
        result_widget.update("[yellow]...[/yellow]")

        selected_metas = [m for m in self.metas if m.id in self.selected]
        records: list[ActionRecord] = []
        for idx, meta in enumerate(selected_metas, start=1):
            record = await self.executor.execute(meta, block_bots=True)
            records.append(record)
            result_widget.update(
                "[yellow]"
                + i18n.t(
                    "tui.running",
                    current=idx,
                    total=len(selected_metas),
                    name=meta.name,
                    result=record.result,
                )
                + "[/yellow]"
            )

        self.results.extend(records)
        self.selected.clear()

        deleted = sum(1 for r in records if r.result in ("deleted", "left"))
        failed = sum(1 for r in records if r.result == "failed")
        dry = sum(1 for r in records if r.result == "skipped_dry_run")

        result_widget.update(
            "[bold]"
            + i18n.t("app.title")
            + "[/bold] — "
            + i18n.t("tui.done", deleted=deleted, failed=failed, dry=dry)
        )
        self._populate_table()
        self._update_status()


def run_tui(
    metas: list[DialogMeta],
    executor: ActionExecutor,
    show_protected: bool = False,
) -> tuple[list[ActionRecord], int]:
    """Run the TUI. Returns (action records, exit code)."""
    app = CleanerApp(metas, executor, show_protected=show_protected)
    exit_code = app.run()
    return app.results, int(exit_code or 0)
