"""report.py — تولید گزارش دقیق JSON/CSV/HTML.

هر گزارش شامل:
- خلاصه‌ی آماری (تعداد کل، flagged، محافظت‌شده، تقسیم بر نوع/قانون)
- جزئیات کامل هر چت با دلیل، risk_score و نتیجه‌ی عملیات
- زمان ساخت و تنظیمات استفاده‌شده (بدون اطلاعات حساس)
"""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import i18n
from .actions import ActionRecord
from .rules import summary
from .scanner import DialogMeta
from .utils import setup_logger, utc_timestamp

log = setup_logger("telesweep.report")


def _meta_row(meta: DialogMeta, record: Optional[ActionRecord]) -> dict[str, Any]:
    """تبدیل یک DialogMeta + ActionRecord به ردیف گزارش."""
    return {
        "id": meta.id,
        "name": meta.name,
        "username": meta.username,
        "entity_type": meta.entity_type,
        "risk_score": meta.risk_score,
        "should_delete": meta.should_delete,
        "protection_reason": meta.protection_reason,
        "reasons": "; ".join(f"{e['rule']}: {e['reason']}" for e in meta.evidence),
        "rules": [e["rule"] for e in meta.evidence],
        "evidence_count": len({e["rule"] for e in meta.evidence}),
        "last_message_date": meta.last_message_date,
        "message_count": meta.message_count,
        "is_pinned": meta.is_pinned,
        "is_muted": meta.is_muted,
        "is_contact": meta.is_contact,
        "deleted": meta.deleted,
        "is_scam": meta.is_scam,
        "is_bot": meta.is_bot,
        "action": record.action if record else None,
        "action_result": record.result if record else None,
        "action_error": record.error if record else None,
        "action_timestamp": record.timestamp if record else None,
    }


def _build_report(
    metas: list[DialogMeta],
    records: Optional[list[ActionRecord]] = None,
    config: Optional[dict[str, Any]] = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """ساخت ساختار گزارش کامل."""
    records_by_id: dict[int, ActionRecord] = {r.dialog_id: r for r in (records or [])}

    rows = [_meta_row(m, records_by_id.get(m.id)) for m in metas]
    stats = summary(metas)

    action_stats: dict[str, int] = {}
    for rec in records or []:
        action_stats[rec.result] = action_stats.get(rec.result, 0) + 1

    thresholds = (config or {}).get("thresholds", {})
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": dry_run,
            "version": "1.0.0",
            "thresholds": {
                "inactivity_days": thresholds.get("inactivity_days", 180),
                "risk_score": thresholds.get("risk_score", 80),
                "min_evidence": thresholds.get("min_evidence", 2),
            },
        },
        "summary": stats,
        "action_results": action_stats,
        "dialogs": rows,
    }


def write_json(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def write_csv(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = report.get("dialogs", [])
    if not rows:
        path.write_text("", encoding="utf-8")
        return path

    # فلت‌کردن فیلدهای لیستی برای CSV
    flat_rows = []
    for row in rows:
        flat = dict(row)
        flat["rules"] = "|".join(str(r) for r in row.get("rules", []))
        flat_rows.append(flat)

    fieldnames = list(flat_rows[0].keys())
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flat_rows)
    return path


def write_html(report: dict[str, Any], path: Path) -> Path:
    """Render a self-contained, localized HTML report."""
    path.parent.mkdir(parents=True, exist_ok=True)

    meta = report.get("meta", {})
    stats = report.get("summary", {})
    action_stats = report.get("action_results", {})
    dialogs = report.get("dialogs", [])
    rtl = i18n.is_rtl()
    direction = "rtl" if rtl else "ltr"

    def esc(val: Any) -> str:
        return html.escape(str(val)) if val is not None else "—"

    def tr(key: str, **kw: Any) -> str:
        return html.escape(i18n.t(key, **kw))

    def type_label(code: str) -> str:
        return esc(i18n.t("types." + code)) if code else "—"

    def rule_label(code: str) -> str:
        return esc(i18n.t("rules." + code)) if code else "—"

    rows_html = []
    for d in sorted(dialogs, key=lambda x: -(x.get("risk_score") or 0)):
        badge = ""
        if d.get("protection_reason"):
            badge = f'<span class="badge prot">{tr("badges.protected")}</span>'
        elif d.get("should_delete"):
            badge = f'<span class="badge del">{tr("badges.flagged")}</span>'
        elif (d.get("risk_score") or 0) >= 60:
            badge = f'<span class="badge warn">{tr("badges.high_risk")}</span>'

        result = d.get("action_result")
        result_badge = ""
        if result:
            cls = "ok" if result in ("deleted", "left") else "warn"
            label_key = {
                "deleted": "actions.deleted",
                "left": "actions.left",
                "blocked": "actions.deleted",
                "skipped_dry_run": "actions.skipped_dry_run",
                "skipped_protected": "actions.failed",
                "skipped_whitelist": "actions.failed",
                "failed": "actions.failed",
                "not_found": "actions.not_found",
            }.get(result)
            label = tr(label_key) if label_key else esc(result)
            result_badge = f'<span class="badge {cls}">{label}</span>'

        reasons = "; ".join(rule_label(r) for r in (d.get("rules") or []))

        row = f"""<tr>
  <td class="name">{esc(d.get('name'))}</td>
  <td>{type_label(d.get('entity_type'))}</td>
  <td class="score">{d.get('risk_score', 0)}</td>
  <td>{badge}</td>
  <td>{esc(d.get('last_message_date'))}</td>
  <td>{d.get('message_count', 0)}</td>
  <td class="reasons">{esc(reasons)}</td>
  <td>{result_badge}</td>
</tr>"""
        rows_html.append(row)

    def kv_list(data: dict[str, Any], empty: str) -> str:
        if not data:
            return f"<li>{empty}</li>"
        return "".join(
            f"<li>{esc(k)}: <b>{v}</b></li>" for k, v in sorted(data.items())
        )

    type_rows = kv_list(stats.get("by_entity_type", {}), "—")
    rule_rows = (
        "".join(
            f"<li>{rule_label(k)}: <b>{v}</b></li>"
            for k, v in sorted(stats.get("by_rule", {}).items())
        )
        or "<li>—</li>"
    )
    action_rows = kv_list(action_stats, tr("report.no_outcomes"))

    mode = tr("report.mode_dry") if meta.get("dry_run") else tr("report.mode_real")

    html_doc = f"""<!DOCTYPE html>
<html lang="{i18n.get_locale()}" dir="{direction}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{tr("report.title")}</title>
<style>
  :root {{
    --bg: #f6f8fa; --panel: #ffffff; --border: #d0d7de; --text: #1f2328;
    --muted: #656d76; --accent: #0969da; --danger: #cf222e; --ok: #1a7f37;
    --warn: #9a6700; --head: #f0f3f6;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
            "Helvetica Neue", Arial, "Noto Sans", "Noto Sans Arabic",
            "Vazirmatn", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei",
            "Noto Sans CJK SC", "Malgun Gothic", sans-serif;
  }}
  html[dir="rtl"] {{ --font: "Vazirmatn", "Noto Sans Arabic", "Segoe UI",
                     -apple-system, Tahoma, Arial, sans-serif; }}
  body {{ font-family: var(--font); margin: 28px; background: var(--bg);
          color: var(--text); font-size: 15px; line-height: 1.6; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 4px; }}
  h2 {{ font-size: 1.05rem; margin: 0 0 10px; color: var(--accent); }}
  .meta {{ color: var(--muted); font-size: 0.88rem; margin-bottom: 20px; }}
  .cards {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0; }}
  .card {{ background: var(--panel); border: 1px solid var(--border);
           border-radius: 10px; padding: 16px 22px; min-width: 150px;
           box-shadow: 0 1px 3px rgba(0,0,0,.06); flex: 1 1 150px; }}
  .card .num {{ font-size: 1.8rem; font-weight: 700; line-height: 1.2; }}
  .card .lbl {{ color: var(--muted); font-size: 0.8rem; margin-top: 2px; }}
  .badge {{ display: inline-block; padding: 2px 9px; border-radius: 20px;
            font-size: 0.72rem; font-weight: 600; color: #fff; white-space: nowrap; }}
  .badge.del {{ background: var(--danger); }}
  .badge.prot {{ background: var(--ok); }}
  .badge.warn {{ background: var(--warn); }}
  .badge.ok {{ background: var(--ok); }}
  .cols {{ display: flex; gap: 40px; flex-wrap: wrap; margin: 8px 0 22px; }}
  ul {{ padding-inline-start: 20px; margin: 0; }}
  table {{ border-collapse: collapse; width: 100%; background: var(--panel);
           font-size: 0.85rem; border: 1px solid var(--border); border-radius: 10px;
           overflow: hidden; }}
  th, td {{ padding: 8px 10px; text-align: start; border-bottom: 1px solid var(--border); white-space: nowrap; }}
  th {{ background: var(--head); color: var(--muted); font-weight: 600; }}
  tbody tr:hover {{ background: #f0f5fb; }}
  td.score {{ font-weight: 700; font-variant-numeric: tabular-nums; }}
  td.name {{ font-weight: 600; }}
  td.reasons {{ white-space: normal; min-width: 180px; color: var(--muted); }}
  footer {{ margin-top: 24px; color: var(--muted); font-size: 0.78rem; }}
</style>
</head>
<body>
<h1>🧹 {tr("report.title")}</h1>
<p class="meta">{tr("report.generated", time=esc(meta.get('generated_at')), mode=mode)}</p>

<div class="cards">
  <div class="card"><div class="num" style="color:var(--accent)">{stats.get('total', 0)}</div><div class="lbl">{tr("stats.total")}</div></div>
  <div class="card"><div class="num" style="color:var(--danger)">{stats.get('flagged_for_deletion', 0)}</div><div class="lbl">{tr("stats.flagged")}</div></div>
  <div class="card"><div class="num" style="color:var(--ok)">{stats.get('protected', 0)}</div><div class="lbl">{tr("stats.protected")}</div></div>
  <div class="card"><div class="num" style="color:var(--warn)">{stats.get('high_risk', 0)}</div><div class="lbl">{tr("stats.high_risk")}</div></div>
</div>

<div class="cols">
  <div><h2>{tr("report.by_type")}</h2><ul>{type_rows}</ul></div>
  <div><h2>{tr("report.by_rule")}</h2><ul>{rule_rows}</ul></div>
  <div><h2>{tr("report.by_outcome")}</h2><ul>{action_rows}</ul></div>
</div>

<h2>{tr("report.details")}</h2>
<table>
  <thead><tr>
    <th>{tr("report.col_name")}</th><th>{tr("report.col_type")}</th>
    <th>{tr("report.col_score")}</th><th>{tr("report.col_status")}</th>
    <th>{tr("report.col_last")}</th><th>{tr("report.col_count")}</th>
    <th>{tr("report.col_reasons")}</th><th>{tr("report.col_outcome")}</th>
  </tr></thead>
  <tbody>
{''.join(rows_html) or f'<tr><td colspan="8" style="text-align:center;padding:24px">{tr("report.no_dialogs")}</td></tr>'}
  </tbody>
</table>
<footer>TeleSweep · {tr("footer.security_note")}</footer>
</body>
</html>"""

    path.write_text(html_doc, encoding="utf-8")
    return path


def generate_report(
    metas: list[DialogMeta],
    records: Optional[list[ActionRecord]] = None,
    config: Optional[dict[str, Any]] = None,
    reports_dir: str | Path = "reports",
    dry_run: bool = True,
) -> dict[str, Path]:
    """تولید گزارش JSON + CSV + HTML. مسیرهای تولیدشده را برمی‌گرداند."""
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    stamp = utc_timestamp()
    report = _build_report(metas, records, config, dry_run)

    paths = {
        "json": write_json(report, reports_dir / f"report-{stamp}.json"),
        "csv": write_csv(report, reports_dir / f"report-{stamp}.csv"),
        "html": write_html(report, reports_dir / f"report-{stamp}.html"),
    }

    log.info(
        i18n.t("cli.reports_written", paths=", ".join(str(p) for p in paths.values()))
    )
    return paths
