"""
EDA 3 — Time Alignment and Window Selection (DARPA OpTC)
=========================================================
Streams a pilot sample of events, parses timestamps, computes event-volume
and entity-diversity metrics across five candidate window sizes, and
recommends a primary and backup window for downstream analysis.

No archives are extracted.  No attack / benign / MITRE claims are made.
No ground-truth overlays are applied (deferred to EDA 10).
Outputs are labeled [PILOT SAMPLE] when --max-members / --max-events limits apply.

Candidate window sizes:  1min  5min  15min  1h  1d

Outputs
-------
outputs/eda_03_time/T5_window_size_comparison.csv
outputs/eda_03_time/F3_event_volume_over_time.png  (.pdf)
outputs/eda_03_time/F4_entity_diversity_over_time.png  (.pdf)
outputs/eda_03_time/N1_window_recommendation_note.txt
outputs/eda_03_time/README_eda03_time_alignment.txt
(tables duplicated to outputs/tables/, figures to outputs/figures/)

Usage
-----
python3 src/eda/eda_03_time_window_selection.py \\
    --project-root /content/DARPA_OPTC_EDA_REPO \\
    --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \\
    --archives 2019-09-16.tar \\
    --max-members 25 --max-events 50000
"""

from __future__ import annotations

import argparse
import datetime
import pathlib
import sys
from typing import Optional

# ── Local import ──────────────────────────────────────────────────────────
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from optc_streaming_parser import stream_from_archives   # type: ignore

# ── Window sizes to evaluate ──────────────────────────────────────────────
_WINDOW_SIZES = ["1min", "5min", "15min", "1h", "1d"]

# Pandas frequency aliases
_FREQ_MAP = {
    "1min": "1min",
    "5min": "5min",
    "15min": "15min",
    "1h":   "1h",
    "1d":   "1D",
}

# Entity columns (used for diversity metrics; field may be empty if not present)
_ENTITY_COLS = {
    "unique_hosts"       : "host_raw",
    "unique_processes"   : "process_raw",
    "unique_destinations": "destination_raw",
    "unique_users"       : "user_raw",
}

# Provisional coverage gates before primary/backup window recommendations.
# Documented minimums for a reliable multi-host, multi-day window choice.
_COVERAGE_MIN_HOSTS = 2
_COVERAGE_MIN_MEMBERS = 3
_COVERAGE_MIN_DATES = 2
_COVERAGE_MIN_SPAN_HOURS = 24.0
_COVERAGE_MIN_PARSEABLE_PCT = 95.0


def assess_coverage_metrics(
    *,
    n_events: int,
    n_parseable: int,
    unique_archives: int,
    unique_members: int,
    unique_hosts: int,
    unique_dates: int,
    span_hours: float,
) -> dict:
    """
    Evaluate provisional coverage gates for window recommendations.

    Returns a dict with metrics, failed_conditions (list[str]), and
    status in {"ok", "review_needed"}.
    """
    parseable_pct = round(n_parseable / max(n_events, 1) * 100, 1)
    metrics = {
        "unique_archives": int(unique_archives),
        "unique_members": int(unique_members),
        "unique_hosts": int(unique_hosts),
        "unique_dates": int(unique_dates),
        "span_hours": round(float(span_hours), 2),
        "parseable_timestamp_percent": parseable_pct,
        "n_events": int(n_events),
        "n_parseable": int(n_parseable),
    }
    failed = []
    if metrics["unique_hosts"] < _COVERAGE_MIN_HOSTS:
        failed.append(
            f"unique_hosts={metrics['unique_hosts']} < {_COVERAGE_MIN_HOSTS}"
        )
    if metrics["unique_members"] < _COVERAGE_MIN_MEMBERS:
        failed.append(
            f"unique_members={metrics['unique_members']} < {_COVERAGE_MIN_MEMBERS}"
        )
    if metrics["unique_dates"] < _COVERAGE_MIN_DATES:
        failed.append(
            f"unique_dates={metrics['unique_dates']} < {_COVERAGE_MIN_DATES}"
        )
    if metrics["span_hours"] < _COVERAGE_MIN_SPAN_HOURS:
        failed.append(
            f"span_hours={metrics['span_hours']} < {_COVERAGE_MIN_SPAN_HOURS}"
        )
    if metrics["parseable_timestamp_percent"] < _COVERAGE_MIN_PARSEABLE_PCT:
        failed.append(
            f"parseable_timestamp_percent={metrics['parseable_timestamp_percent']} "
            f"< {_COVERAGE_MIN_PARSEABLE_PCT}"
        )
    metrics["failed_conditions"] = failed
    metrics["status"] = "ok" if not failed else "review_needed"
    return metrics


def assess_coverage_from_df(df, n_events: int, n_parseable: int) -> dict:
    """Coverage metrics from an in-memory event DataFrame."""
    import pandas as pd

    if df is None or df.empty:
        return assess_coverage_metrics(
            n_events=n_events, n_parseable=n_parseable,
            unique_archives=0, unique_members=0, unique_hosts=0,
            unique_dates=0, span_hours=0.0,
        )

    def _nunique(col):
        if col not in df.columns:
            return 0
        s = df[col].fillna("").astype(str).str.strip()
        return int(s[s != ""].nunique())

    unique_archives = _nunique("archive_name")
    unique_members = _nunique("member_name")
    unique_hosts = _nunique("host_raw")

    ts = df["ts"] if "ts" in df.columns else pd.Series(dtype="datetime64[ns]")
    ts_ok = ts.dropna()
    if len(ts_ok) == 0:
        unique_dates = 0
        span_hours = 0.0
    else:
        unique_dates = int(ts_ok.dt.floor("D").nunique())
        span_hours = float((ts_ok.max() - ts_ok.min()).total_seconds() / 3600.0)

    return assess_coverage_metrics(
        n_events=n_events,
        n_parseable=n_parseable,
        unique_archives=unique_archives,
        unique_members=unique_members,
        unique_hosts=unique_hosts,
        unique_dates=unique_dates,
        span_hours=span_hours,
    )


def assess_coverage_from_cache(con, n_events: int, n_parseable: int) -> dict:
    """Coverage metrics via DuckDB over the normalized cache."""
    row = con.execute(
        """
        SELECT
          COUNT(DISTINCT NULLIF(CAST(archive_name AS VARCHAR), '')),
          COUNT(DISTINCT NULLIF(CAST(member_name AS VARCHAR), '')),
          COUNT(DISTINCT NULLIF(CAST(host_raw AS VARCHAR), '')),
          COUNT(DISTINCT date_trunc(
              'day', TRY_CAST(timestamp_parsed AS TIMESTAMP))),
          MIN(TRY_CAST(timestamp_parsed AS TIMESTAMP)),
          MAX(TRY_CAST(timestamp_parsed AS TIMESTAMP))
        FROM events
        WHERE timestamp_parsed IS NOT NULL
          AND CAST(timestamp_parsed AS VARCHAR) != ''
        """
    ).fetchone()
    n_arch, n_mem, n_hosts, n_dates, tmin, tmax = row
    # Archives/members/hosts should count all rows, not only parseable ts.
    n_arch_all = con.execute(
        "SELECT COUNT(DISTINCT NULLIF(CAST(archive_name AS VARCHAR), '')) FROM events"
    ).fetchone()[0]
    n_mem_all = con.execute(
        "SELECT COUNT(DISTINCT NULLIF(CAST(member_name AS VARCHAR), '')) FROM events"
    ).fetchone()[0]
    n_hosts_all = con.execute(
        "SELECT COUNT(DISTINCT NULLIF(CAST(host_raw AS VARCHAR), '')) FROM events"
    ).fetchone()[0]
    span_hours = 0.0
    if tmin is not None and tmax is not None:
        span_hours = (tmax - tmin).total_seconds() / 3600.0
    return assess_coverage_metrics(
        n_events=n_events,
        n_parseable=n_parseable,
        unique_archives=int(n_arch_all or 0),
        unique_members=int(n_mem_all or 0),
        unique_hosts=int(n_hosts_all or 0),
        unique_dates=int(n_dates or 0),
        span_hours=float(span_hours),
    )


def _apply_window_recommendations(rows: list, coverage: dict) -> list:
    """
    Assign primary/backup/no (or review_needed) on T5 rows.

    If coverage gates fail, every window is marked review_needed and no
    primary/backup is issued.
    """
    if not rows:
        return rows

    if coverage.get("status") != "ok":
        failed = coverage.get("failed_conditions") or ["coverage gates failed"]
        detail = "; ".join(failed)
        for r in rows:
            r["recommendation_primary_backup_no"] = "review_needed"
            r["reason"] = (
                "coverage reliability gate failed — no primary/backup window; "
                f"failed: {detail}"
            )
        return rows

    qualify = [
        r for r in rows
        if isinstance(r["empty_window_percent"], float)
        and r["empty_window_percent"] < 50.0
        and isinstance(r["median_events_per_window"], float)
        and r["median_events_per_window"] >= 5.0
    ]
    if not qualify:
        for r in rows:
            r["recommendation_primary_backup_no"] = "review_needed"
            r["reason"] = (
                "data too sparse for reliable window selection; "
                "review timestamp quality and increase sample before recommending"
            )
        return rows

    primary_ws = qualify[0]["window_size"]
    backup_ws = qualify[1]["window_size"] if len(qualify) > 1 else "1h"
    for r in rows:
        ws = r["window_size"]
        if ws == primary_ws:
            r["recommendation_primary_backup_no"] = "primary"
            r["reason"] = (
                f"smallest window with <50% empty ({r['empty_window_percent']}%) "
                f"and median {r['median_events_per_window']} events/window; "
                "supports fine-grained drift analysis"
            )
        elif ws == backup_ws:
            r["recommendation_primary_backup_no"] = "backup"
            r["reason"] = (
                f"fallback if primary is too granular; "
                f"empty_window_percent={r['empty_window_percent']}%"
            )
        else:
            r["recommendation_primary_backup_no"] = "no"
            if ws in _WINDOW_SIZES[:_WINDOW_SIZES.index(primary_ws)]:
                r["reason"] = (
                    f"too fine-grained: {r.get('empty_window_percent', '?')}% empty "
                    f"or <5 median events; primary {primary_ws} is preferred"
                )
            else:
                r["reason"] = (
                    f"coarser than backup {backup_ws}; "
                    f"use only if dataset is very sparse"
                )
    return rows


def format_coverage_block(coverage: dict) -> list[str]:
    """Human-readable coverage gate section for N1 / README."""
    lines = [
        "Coverage reliability gate (provisional minimums)",
        "------------------------------------------------",
        f"  unique_archives              : {coverage.get('unique_archives', 0)}",
        f"  unique_members               : {coverage.get('unique_members', 0)} "
        f"(min {_COVERAGE_MIN_MEMBERS})",
        f"  unique_hosts                 : {coverage.get('unique_hosts', 0)} "
        f"(min {_COVERAGE_MIN_HOSTS})",
        f"  unique_dates                 : {coverage.get('unique_dates', 0)} "
        f"(min {_COVERAGE_MIN_DATES})",
        f"  timestamp_span_hours         : {coverage.get('span_hours', 0)} "
        f"(min {_COVERAGE_MIN_SPAN_HOURS})",
        f"  parseable_timestamp_percent  : "
        f"{coverage.get('parseable_timestamp_percent', 0)} "
        f"(min {_COVERAGE_MIN_PARSEABLE_PCT})",
        f"  gate_status                  : {coverage.get('status', 'unknown')}",
    ]
    failed = coverage.get("failed_conditions") or []
    if failed:
        lines.append("  failed_conditions:")
        for cond in failed:
            lines.append(f"    - {cond}")
    else:
        lines.append("  failed_conditions: (none)")
    return lines


# ── Helpers ───────────────────────────────────────────────────────────────

def _save_csv(df, *destinations) -> None:
    for dest in destinations:
        dest = pathlib.Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(dest, index=False)
    print(f"  [CSV] {destinations[0]}")


def _save_fig(fig, base_name: str, *dirs) -> None:
    import matplotlib
    matplotlib.use("Agg")
    for d in dirs:
        d = pathlib.Path(d)
        d.mkdir(parents=True, exist_ok=True)
        for ext in (".png", ".pdf"):
            fig.savefig(d / (base_name + ext), bbox_inches="tight", dpi=150)
    print(f"  [FIG] {base_name}.png/.pdf → {dirs[0]}")


# ── Event collection → DataFrame ─────────────────────────────────────────

def collect_events_df(
    archive_paths: list,
    max_members: Optional[int],
    max_events: Optional[int],
    max_events_per_member: Optional[int],
    member_name_contains: Optional[str],
):
    """
    Stream events and return a pandas DataFrame.
    Rows with unparseable timestamps are kept but marked with NaT.
    """
    import pandas as pd

    events = list(stream_from_archives(
        archive_paths,
        max_members=max_members,
        max_events=max_events,
        max_events_per_member=max_events_per_member,
        member_name_contains=member_name_contains,
        quiet=False,
    ))

    if not events:
        return pd.DataFrame(), 0, 0

    df = pd.DataFrame(events)
    total_raw = len(df)

    # Parse timestamps
    df["ts"] = pd.to_datetime(df["timestamp_parsed"], errors="coerce")

    n_parseable = int(df["ts"].notna().sum())
    print(f"  [INFO] {total_raw:,} events total; {n_parseable:,} with parseable timestamps "
          f"({n_parseable/max(total_raw,1)*100:.1f}%)")

    return df, total_raw, n_parseable, events


# ── Pilot sampling summary ────────────────────────────────────────────────

def _collection_summary(events: list, max_members: int) -> tuple:
    """Returns (summary_dict, summary_text)."""
    import collections
    ok_events   = [e for e in events if e.get("parse_status") == "ok"]
    member_ctr  = collections.Counter(e.get("member_name", "") for e in events)
    archive_ctr = collections.Counter(e.get("archive_name", "") for e in events)
    src_ctr     = collections.Counter(e.get("source_type", "unknown") for e in ok_events)

    lines = [
        "",
        "=" * 56,
        "PILOT SAMPLING SUMMARY",
        "=" * 56,
        f"  Total events collected       : {len(events):,}",
        f"  OK / parse-error events      : {len(ok_events):,} / {len(events)-len(ok_events):,}",
        f"  Tar members with events      : {len(member_ctr)} (max_members={max_members})",
        f"  Archives with events         : {len(archive_ctr)}",
        "",
        "  Source type counts:",
    ]
    for src, cnt in sorted(src_ctr.items()):
        lines.append(f"    {src:<30s}: {cnt:,}")
    lines += ["", "  Events per member (top 10):"]
    for member, cnt in member_ctr.most_common(10):
        short = pathlib.Path(member).name[:60]
        lines.append(f"    {short}: {cnt:,}")
    lines.append("=" * 56)

    text = "\n".join(lines)
    print(text, flush=True)

    stats = {
        "total": len(events), "ok": len(ok_events),
        "n_members": len(member_ctr), "n_archives": len(archive_ctr),
        "src_counts": dict(src_ctr), "top_members": member_ctr.most_common(10),
    }
    return stats, text


# ── T5: Window Size Comparison ────────────────────────────────────────────

def compute_t5(df, pilot_label: str, coverage: dict | None = None) -> list:
    """
    For each candidate window, compute event-volume and entity-diversity stats.
    Returns list of dicts with the exact T5 column schema.
    """
    import numpy as np
    import pandas as pd

    ts_df = df[df["ts"].notna()].copy()
    if ts_df.empty:
        return []

    ts_df = ts_df.set_index("ts").sort_index()

    rows = []
    best_empty_pct = None   # used later for recommendation

    for ws in _WINDOW_SIZES:
        freq = _FREQ_MAP[ws]
        try:
            # Event count per window
            ev_counts = ts_df.resample(freq).size()
            n_windows = int(len(ev_counts))
            empty_pct = round(float((ev_counts == 0).sum()) / max(n_windows, 1) * 100, 1)
            non_empty = ev_counts[ev_counts > 0]
            median_ev  = round(float(np.median(non_empty)) if len(non_empty) else 0.0, 1)
            mean_ev    = round(float(non_empty.mean())     if len(non_empty) else 0.0, 1)

            # Per-window unique entity counts
            # Replace empty strings with NaN so resample().nunique() ignores them
            entity_stats = {}
            for label, col in _ENTITY_COLS.items():
                if col in ts_df.columns:
                    col_clean = ts_df[col].replace("", float("nan"))
                    windowed = col_clean.resample(freq).nunique()
                    non_empty_windows = windowed[windowed > 0]
                    entity_stats[label] = round(float(np.median(non_empty_windows))
                                                if len(non_empty_windows) else 0.0, 1)
                else:
                    entity_stats[label] = "n/a"

            rows.append({
                "window_size"                : ws,
                "number_of_windows"          : n_windows,
                "median_events_per_window"   : median_ev,
                "mean_events_per_window"     : mean_ev,
                "empty_window_percent"       : empty_pct,
                "median_unique_hosts"        : entity_stats.get("unique_hosts", "n/a"),
                "median_unique_processes"    : entity_stats.get("unique_processes", "n/a"),
                "median_unique_destinations" : entity_stats.get("unique_destinations", "n/a"),
                "recommendation_primary_backup_no": "pending",   # filled below
                "reason"                     : "pending",
            })

        except Exception as exc:
            rows.append({
                "window_size"                : ws,
                "number_of_windows"          : 0,
                "median_events_per_window"   : 0,
                "mean_events_per_window"     : 0,
                "empty_window_percent"       : 100.0,
                "median_unique_hosts"        : "n/a",
                "median_unique_processes"    : "n/a",
                "median_unique_destinations" : "n/a",
                "recommendation_primary_backup_no": "no",
                "reason"                     : f"computation_error: {exc}",
            })

    # Recommendation (coverage gate first, then density rules)
    return _apply_window_recommendations(rows, coverage or {"status": "ok"})


# ── F3: Event Volume Over Time ────────────────────────────────────────────

def plot_f3(df, out_dir: pathlib.Path, figures_dir: pathlib.Path,
            window_label: str, pilot_label: str) -> None:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ts_df = df[df["ts"].notna()].copy()
    if ts_df.empty:
        print("  [F3] No parseable timestamps — skipping event volume plot.", file=sys.stderr)
        return

    ts_series = ts_df.set_index("ts").resample(_FREQ_MAP.get(window_label, "15min")).size()

    fig, ax = plt.subplots(figsize=(13, 4))
    ax.fill_between(ts_series.index, ts_series.values, alpha=0.7, color="#4472C4", step="mid")
    ax.plot(ts_series.index, ts_series.values, color="#2B579A", linewidth=0.8)
    ax.set_xlabel("Time (UTC)", fontsize=11)
    ax.set_ylabel(f"Events per {window_label} window", fontsize=11)
    ax.set_title(
        f"F3 — Event Volume Over Time  (window: {window_label})  {pilot_label}\n"
        "[No ground-truth overlay — attack/benign intervals NOT shown]",
        fontsize=10,
    )
    ax.tick_params(axis="x", rotation=30)
    ax.set_xlim(ts_series.index.min(), ts_series.index.max())
    fig.tight_layout()

    _save_fig(fig, "F3_event_volume_over_time", out_dir, figures_dir)
    plt.close(fig)


# ── F4: Entity Diversity Over Time ────────────────────────────────────────

def plot_f4(df, out_dir: pathlib.Path, figures_dir: pathlib.Path,
            window_label: str, pilot_label: str) -> None:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ts_df = df[df["ts"].notna()].copy()
    if ts_df.empty:
        print("  [F4] No parseable timestamps — skipping entity diversity plot.", file=sys.stderr)
        return

    freq   = _FREQ_MAP.get(window_label, "15min")
    colors = {"unique_hosts": "#4472C4", "unique_processes": "#ED7D31",
              "unique_destinations": "#70AD47", "unique_users": "#A5A5A5"}

    fig, ax = plt.subplots(figsize=(13, 4))
    any_plotted = False

    for label, col in _ENTITY_COLS.items():
        if col not in ts_df.columns:
            continue
        # Count non-empty unique values per window
        series = (
            ts_df.set_index("ts")[col]
            .replace("", float("nan"))
            .resample(freq)
            .agg(lambda s: s.dropna().nunique())
        )
        if series.sum() == 0:
            continue
        ax.plot(series.index, series.values,
                label=label.replace("_", " "),
                color=colors.get(label, None),
                linewidth=1.4, marker=".", markersize=3)
        any_plotted = True

    if not any_plotted:
        ax.text(0.5, 0.5, "No entity data available",
                transform=ax.transAxes, ha="center", va="center", fontsize=12)

    ax.set_xlabel("Time (UTC)", fontsize=11)
    ax.set_ylabel(f"Unique entities per {window_label} window", fontsize=11)
    ax.set_title(
        f"F4 — Entity Diversity Over Time  (window: {window_label})  {pilot_label}\n"
        "[No ground-truth overlay — attack/benign intervals NOT shown]",
        fontsize=10,
    )
    if any_plotted:
        ax.legend(fontsize=9, loc="upper right")
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()

    _save_fig(fig, "F4_entity_diversity_over_time", out_dir, figures_dir)
    plt.close(fig)


# ── N1: Window Recommendation Note ───────────────────────────────────────

def write_n1(t5_rows: list, out_dir: pathlib.Path, pilot_label: str,
             n_events: int, n_parseable: int, ts_rule: str,
             coverage: Optional[dict] = None) -> tuple:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    coverage = coverage or {}
    primary_row  = next((r for r in t5_rows if r.get("recommendation_primary_backup_no") == "primary"), None)
    backup_row   = next((r for r in t5_rows if r.get("recommendation_primary_backup_no") == "backup"), None)
    if coverage.get("status") == "review_needed" or (
        primary_row is None and any(
            r.get("recommendation_primary_backup_no") == "review_needed" for r in t5_rows
        )
    ):
        primary_ws = backup_ws = "review_needed"
    else:
        primary_ws   = primary_row["window_size"]  if primary_row else "review_needed"
        backup_ws    = backup_row["window_size"]   if backup_row  else "review_needed"

    lines = [
        "N1 — Window Size Recommendation",
        "=" * 50,
        f"Generated (UTC) : {now}",
        f"Pilot label     : {pilot_label}",
        "",
        "Timestamp parsing rule",
        "----------------------",
        f"  {ts_rule}",
        f"  Events with parseable timestamps: {n_parseable:,} / {n_events:,} "
        f"({n_parseable/max(n_events,1)*100:.1f}%)",
        "",
    ]
    lines += format_coverage_block(coverage)
    lines += [
        "",
        "Recommendation",
        "--------------",
        f"  Primary window : {primary_ws}",
        f"  Backup window  : {backup_ws}",
        "",
    ]

    if primary_ws == "review_needed":
        lines += [
            "  *** REVIEW NEEDED — no primary/backup window issued ***",
            "  Coverage reliability gates and/or window density rules were not met.",
            "  T5 metrics and F3/F4 figures are still produced for inspection.",
        ]
        failed = coverage.get("failed_conditions") or []
        if failed:
            lines.append("  Failed coverage conditions:")
            for cond in failed:
                lines.append(f"    - {cond}")
        lines += [
            "  Next steps:",
            "    1. Expand the pilot to ≥2 hosts, ≥3 members, ≥2 calendar dates,",
            "       ≥24 hours of timestamp span, and ≥95% parseable timestamps.",
            "    2. Re-run EDA 3 after acquiring a broader multi-host / multi-day sample.",
            "    3. Do not treat 1min/5min density on a single-member sample as final.",
        ]
    else:
        if primary_row:
            lines += [
                f"  Primary {primary_ws} rationale:",
                f"    {primary_row['reason']}",
                "",
            ]
        if backup_row:
            lines += [
                f"  Backup {backup_ws} rationale:",
                f"    {backup_row['reason']}",
                "",
            ]
        lines += [
            "Interpretability notes",
            "----------------------",
            "  1min  : Maximum granularity; many empty windows for sparse endpoint logs.",
            "  5min  : Good for rapid behavioral bursts; ~288 windows/day.",
            "  15min : Balanced; captures gradual behavioral drift; ~96 windows/day.",
            "  1h    : Aggregated; reduces sparsity; ~24 windows/day.",
            "  1d    : Coarsest; use only for multi-day aggregate views.",
        ]

    lines += [
        "",
        "Important constraints",
        "----------------------",
        "  * Recommendation is based on PILOT SAMPLE only — scale before finalizing.",
        "  * No ground-truth or attack-interval overlay is applied (deferred to EDA 10).",
        "  * Window recommendation is for modeling granularity only, not attack detection.",
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "N1_window_recommendation_note.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"  [N1] {out_dir / 'N1_window_recommendation_note.txt'}")

    return primary_ws, backup_ws


# ── README ────────────────────────────────────────────────────────────────

def write_readme(
    out_dir: pathlib.Path,
    args: argparse.Namespace,
    n_events: int,
    n_parseable: int,
    pilot_label: str,
    primary_ws: str,
    backup_ws: str,
    ts_rule: str,
    member_summary: str = "",
    coverage: Optional[dict] = None,
) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    coverage = coverage or {}
    lines = [
        "EDA 3 — Time Alignment and Window Selection",
        "=" * 50,
        f"Generated (UTC): {now}",
        f"Pilot label    : {pilot_label}",
        "",
        "Scope",
        "-----",
        "This script evaluates candidate time window sizes for the DARPA OpTC dataset.",
        "Events are STREAMED from .tar/.json.gz members without extracting archives.",
        "No attack / benign / MITRE claims are made.",
        "No ground-truth overlays are applied (deferred to EDA 10).",
        "",
        "Run parameters",
        "--------------",
        f"  corrected-dir          : {args.corrected_dir}",
        f"  archives processed     : {getattr(args, 'archives', 'all')}",
        f"  max-members per archive: {args.max_members}",
        f"  max-events total       : {args.max_events}",
        f"  max-events-per-member  : {args.max_events_per_member}",
        f"  member-name-contains   : {args.member_name_contains}",
        "",
        "Timestamp conversion rule",
        "-------------------------",
        f"  {ts_rule}",
        f"  Parseable: {n_parseable:,} / {n_events:,} "
        f"({n_parseable/max(n_events,1)*100:.1f}%)",
        "",
    ]
    lines += format_coverage_block(coverage)
    lines += [
        "",
        "Window recommendation",
        "---------------------",
        f"  Primary : {primary_ws}",
        f"  Backup  : {backup_ws}",
        "  (see N1_window_recommendation_note.txt for full rationale)",
        "  Primary/backup are issued ONLY when all coverage gates pass.",
        "  Otherwise status is review_needed (T5/figures still generated).",
        "",
        "Candidate windows evaluated",
        "---------------------------",
        "  1min, 5min, 15min, 1h, 1d",
        "  Metrics: number_of_windows, median/mean events per window,",
        "           empty_window_percent, median unique hosts/processes/destinations.",
        "",
        "Figures",
        "-------",
        "  F3: Event volume over time (no ground-truth overlay).",
        "  F4: Entity diversity over time — unique hosts, processes, destinations.",
        "      Separate lines per entity type where fields are available.",
        "",
        "Important limitations",
        "----------------------",
        f"  * Pilot sample only — {n_events:,} events, ≤{args.max_members} members/archive "
        f"(max {args.max_events_per_member} events/member).",
        "  * Window statistics may shift with larger samples.",
        "  * A 10K single-member / single-host sample must yield review_needed,",
        "    not a final 1min/5min recommendation.",
        "  * Gradual drift analysis requires more archives (2019-09-19 through 2019-09-24 pending).",
        "  * Ground-truth alignment and attack-interval annotation are deferred to EDA 10.",
    ]
    if member_summary:
        lines += ["", "Pilot sampling detail", "---------------------"]
        lines += [f"  {ln}" for ln in member_summary.strip().splitlines()]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "README_eda03_time_alignment.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"  [README] {out_dir / 'README_eda03_time_alignment.txt'}")


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="EDA 3 — DARPA OpTC Time Alignment and Window Selection (pilot).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--project-root", default=None,
                   help="Project root directory (default: cwd)")
    p.add_argument("--corrected-dir", default=None,
                   help="Directory containing corrected .tar archives (legacy mode)")
    p.add_argument("--archives", nargs="+", default=None,
                   help="Archive filenames to process (default: all .tar in corrected-dir)")
    p.add_argument("--output-dir", default=None,
                   help="Output directory (default: <project-root>/outputs/eda_03_time)")
    p.add_argument("--max-members", type=int, default=25,
                   help="Max members to scan per archive (default: 25)")
    p.add_argument("--max-events", type=int, default=50_000,
                   help="Max total events across all archives (default: 50000)")
    p.add_argument("--max-events-per-member", type=int, default=2000,
                   help="Max events per tar member (default: 2000)")
    p.add_argument("--member-name-contains", default=None,
                   help="Filter: only process members whose name contains this string")
    p.add_argument("--manifest-csv", default=None,
                   help="Pilot manifest CSV (with --normalized-cache-dir)")
    p.add_argument("--normalized-cache-dir", default=None,
                   help="Parquet cache dir from build_normalized_pilot_cache.py")
    return p.parse_args()


# ── Cache-mode helpers ────────────────────────────────────────────────────

_DUCK_WINDOW = {
    "1min": "INTERVAL 1 MINUTE",
    "5min": "INTERVAL 5 MINUTE",
    "15min": "INTERVAL 15 MINUTE",
    "1h": "INTERVAL 1 HOUR",
    "1d": "INTERVAL 1 DAY",
}


def _load_cache_metadata(cache_dir: pathlib.Path) -> dict:
    import json
    meta_path = cache_dir / "cache_metadata.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text(encoding="utf-8"))
    return {}


def _duck_conn(cache_dir: pathlib.Path):
    import duckdb
    con = duckdb.connect()
    glob = str(pathlib.Path(cache_dir) / "*.parquet")
    con.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet('{glob}')")
    return con


def compute_t5_from_cache(con, coverage: dict | None = None) -> list:
    """Window comparison via DuckDB time buckets — no full event DataFrame."""
    import numpy as np

    bounds = con.execute(
        """
        SELECT MIN(TRY_CAST(timestamp_parsed AS TIMESTAMP)),
               MAX(TRY_CAST(timestamp_parsed AS TIMESTAMP)),
               COUNT(*) FILTER (
                 WHERE timestamp_parsed IS NOT NULL
                   AND CAST(timestamp_parsed AS VARCHAR) != '')
        FROM events
        """
    ).fetchone()
    tmin, tmax, n_parseable = bounds
    if tmin is None or tmax is None or n_parseable == 0:
        return []

    rows = []
    for ws, interval in _DUCK_WINDOW.items():
        counts = con.execute(
            f"""
            SELECT time_bucket({interval}, TRY_CAST(timestamp_parsed AS TIMESTAMP)) AS b,
                   COUNT(*) AS n,
                   COUNT(DISTINCT NULLIF(host_raw, '')) AS u_hosts,
                   COUNT(DISTINCT NULLIF(process_raw, '')) AS u_procs,
                   COUNT(DISTINCT NULLIF(destination_raw, '')) AS u_dests
            FROM events
            WHERE timestamp_parsed IS NOT NULL AND CAST(timestamp_parsed AS VARCHAR) != ''
            GROUP BY 1
            ORDER BY 1
            """
        ).fetchdf()

        if counts.empty:
            rows.append({
                "window_size": ws, "number_of_windows": 0,
                "median_events_per_window": 0, "mean_events_per_window": 0,
                "empty_window_percent": 100.0,
                "median_unique_hosts": 0, "median_unique_processes": 0,
                "median_unique_destinations": 0,
                "recommendation_primary_backup_no": "pending", "reason": "pending",
            })
            continue

        # Expected window count from span
        delta_s = (tmax - tmin).total_seconds()
        seconds = {"1min": 60, "5min": 300, "15min": 900, "1h": 3600, "1d": 86400}[ws]
        expected = max(1, int(delta_s // seconds) + 1)
        n_nonempty = int(len(counts))
        n_windows = max(expected, n_nonempty)
        empty_pct = round(max(0.0, (n_windows - n_nonempty) / n_windows * 100), 1)

        rows.append({
            "window_size": ws,
            "number_of_windows": n_windows,
            "median_events_per_window": round(float(np.median(counts["n"])), 1),
            "mean_events_per_window": round(float(counts["n"].mean()), 1),
            "empty_window_percent": empty_pct,
            "median_unique_hosts": round(float(np.median(counts["u_hosts"])), 1),
            "median_unique_processes": round(float(np.median(counts["u_procs"])), 1),
            "median_unique_destinations": round(float(np.median(counts["u_dests"])), 1),
            "recommendation_primary_backup_no": "pending",
            "reason": "pending",
        })

    return _apply_window_recommendations(rows, coverage or {"status": "ok"})


def plot_f3_from_cache(con, out_dir, figures_dir, window_label, pilot_label) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    interval = _DUCK_WINDOW.get(window_label, "INTERVAL 15 MINUTE")
    series = con.execute(
        f"""
        SELECT time_bucket({interval}, TRY_CAST(timestamp_parsed AS TIMESTAMP)) AS t,
               COUNT(*) AS n
        FROM events
        WHERE timestamp_parsed IS NOT NULL AND CAST(timestamp_parsed AS VARCHAR) != ''
        GROUP BY 1 ORDER BY 1
        """
    ).fetchdf().dropna()
    if series.empty:
        print("  [F3] No parseable timestamps — skipping.", file=sys.stderr)
        return
    fig, ax = plt.subplots(figsize=(13, 4))
    ax.fill_between(series["t"], series["n"], alpha=0.7, color="#4472C4", step="mid")
    ax.plot(series["t"], series["n"], color="#2B579A", linewidth=0.8)
    ax.set_xlabel("Time (UTC)", fontsize=11)
    ax.set_ylabel(f"Events per {window_label} window", fontsize=11)
    ax.set_title(
        f"F3 — Event Volume Over Time  (window: {window_label})  {pilot_label}\n"
        "[No ground-truth overlay — attack/benign intervals NOT shown]",
        fontsize=10,
    )
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    _save_fig(fig, "F3_event_volume_over_time", out_dir, figures_dir)
    plt.close(fig)


def plot_f4_from_cache(con, out_dir, figures_dir, window_label, pilot_label) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    interval = _DUCK_WINDOW.get(window_label, "INTERVAL 15 MINUTE")
    colors = {"hosts": "#4472C4", "processes": "#ED7D31",
              "destinations": "#70AD47", "users": "#A5A5A5"}
    fig, ax = plt.subplots(figsize=(13, 4))
    any_plotted = False
    for label, col, color in [
        ("hosts", "host_raw", colors["hosts"]),
        ("processes", "process_raw", colors["processes"]),
        ("destinations", "destination_raw", colors["destinations"]),
        ("users", "user_raw", colors["users"]),
    ]:
        s = con.execute(
            f"""
            SELECT time_bucket({interval}, TRY_CAST(timestamp_parsed AS TIMESTAMP)) AS t,
                   COUNT(DISTINCT NULLIF({col}, '')) AS n
            FROM events
            WHERE timestamp_parsed IS NOT NULL AND CAST(timestamp_parsed AS VARCHAR) != ''
            GROUP BY 1 ORDER BY 1
            """
        ).fetchdf().dropna()
        if s.empty or s["n"].sum() == 0:
            continue
        ax.plot(s["t"], s["n"], label=f"unique {label}", color=color,
                linewidth=1.4, marker=".", markersize=3)
        any_plotted = True
    if not any_plotted:
        ax.text(0.5, 0.5, "No entity data available",
                transform=ax.transAxes, ha="center", va="center")
    ax.set_xlabel("Time (UTC)", fontsize=11)
    ax.set_ylabel(f"Unique entities per {window_label} window", fontsize=11)
    ax.set_title(
        f"F4 — Entity Diversity Over Time  (window: {window_label})  {pilot_label}\n"
        "[No ground-truth overlay — attack/benign intervals NOT shown]",
        fontsize=10,
    )
    if any_plotted:
        ax.legend(fontsize=9, loc="upper right")
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    _save_fig(fig, "F4_entity_diversity_over_time", out_dir, figures_dir)
    plt.close(fig)


def run_eda03_cache_mode(args, project_root, out_dir, tables_dir, figures_dir) -> None:
    import json
    import pandas as pd
    from manifest_utils import load_manifest

    cache_dir = pathlib.Path(args.normalized_cache_dir)
    if not cache_dir.exists() or not list(cache_dir.glob("*.parquet")):
        print(f"[ERROR] No parquet cache at {cache_dir}", file=sys.stderr)
        sys.exit(1)
    if args.archives or args.member_name_contains:
        print("[ERROR] Cache mode: do not pass --archives or --member-name-contains.",
              file=sys.stderr)
        sys.exit(1)

    manifest_meta = {}
    if args.manifest_csv:
        mi = load_manifest(pathlib.Path(args.manifest_csv))
        manifest_meta = {
            "manifest_version": mi.manifest_version,
            "manifest_path": str(mi.path),
            "manifest_member_count": mi.member_count,
        }
    cache_meta = _load_cache_metadata(cache_dir)
    pilot_label = (
        f"[CACHE MODE: manifest={manifest_meta.get('manifest_version', 'unknown')}; "
        f"events={cache_meta.get('total_events_written', '?')}]"
    )
    ts_rule = cache_meta.get(
        "timestamp_conversion_rule",
        "Numeric epoch auto-scale; ISO-8601; naive UTC.",
    )

    print(f"\n{'='*60}")
    print(f"EDA 3 — Time Alignment and Window Selection  {pilot_label}")
    print(f"  cache-dir    : {cache_dir}")
    print(f"  manifest-csv : {args.manifest_csv}")
    print(f"  output-dir   : {out_dir}")
    print(f"{'='*60}\n")

    con = _duck_conn(cache_dir)
    n_total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    n_parseable = con.execute(
        """
        SELECT COUNT(*) FROM events
        WHERE timestamp_parsed IS NOT NULL AND CAST(timestamp_parsed AS VARCHAR) != ''
        """
    ).fetchone()[0]
    print(f"[INFO] Cache events: {n_total:,}; parseable timestamps: {n_parseable:,}")

    coverage = assess_coverage_from_cache(con, n_total, n_parseable)
    print(f"[INFO] Coverage gate: {coverage['status']}")
    for cond in coverage.get("failed_conditions") or []:
        print(f"  - failed: {cond}")

    print("\nComputing T5 from cache ...")
    t5_rows = compute_t5_from_cache(con, coverage=coverage)
    t5_df = pd.DataFrame(t5_rows) if t5_rows else pd.DataFrame(columns=[
        "window_size", "number_of_windows", "median_events_per_window",
        "mean_events_per_window", "empty_window_percent",
        "median_unique_hosts", "median_unique_processes", "median_unique_destinations",
        "recommendation_primary_backup_no", "reason",
    ])
    _save_csv(t5_df, out_dir / "T5_window_size_comparison.csv",
              tables_dir / "T5_window_size_comparison.csv")

    primary_row = next(
        (r for r in t5_rows if r.get("recommendation_primary_backup_no") == "primary"),
        None,
    )
    # Figures still generated when review_needed; default plot window 15min.
    primary_ws = primary_row["window_size"] if primary_row else "15min"

    print("\nGenerating F3/F4 from cache ...")
    plot_f3_from_cache(con, out_dir, figures_dir, primary_ws, pilot_label)
    plot_f4_from_cache(con, out_dir, figures_dir, primary_ws, pilot_label)

    if t5_rows:
        primary_ws_final, backup_ws_final = write_n1(
            t5_rows, out_dir, pilot_label, n_total, n_parseable, ts_rule,
            coverage=coverage,
        )
    else:
        primary_ws_final = backup_ws_final = "review_needed"

    # README with cache/manifest info
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "EDA 3 — Time Alignment and Window Selection (CACHE MODE)",
        "=" * 50,
        f"Generated (UTC): {now}",
        f"Pilot label    : {pilot_label}",
        "",
        "Mode: DuckDB aggregates over normalized Parquet cache.",
        "No ground-truth overlay. No attack/benign/MITRE labels.",
        "",
        f"Manifest version : {manifest_meta.get('manifest_version', 'n/a')}",
        f"Manifest path    : {manifest_meta.get('manifest_path', args.manifest_csv)}",
        f"Cache dir        : {cache_dir}",
        f"Events           : {n_total:,} (parseable ts: {n_parseable:,})",
        f"max-events cap   : {cache_meta.get('max_events_safety_cap', 'n/a')}",
        f"Timestamp rule   : {ts_rule}",
        f"Primary window   : {primary_ws_final}",
        f"Backup window    : {backup_ws_final}",
        "",
    ]
    lines += format_coverage_block(coverage)
    lines += [
        "",
        "Primary/backup are issued ONLY when all coverage gates pass;",
        "otherwise review_needed (T5 and figures are still generated).",
    ]
    (out_dir / "README_eda03_time_alignment.txt").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(f"  [README] {out_dir / 'README_eda03_time_alignment.txt'}")
    con.close()

    print(f"\n{'='*60}")
    print(f"EDA 3 COMPLETE  {pilot_label}")
    print(f"  Events total         : {n_total:,}")
    print(f"  Events with valid ts : {n_parseable:,}")
    print(f"  Coverage gate        : {coverage['status']}")
    print(f"  Recommended window   : {primary_ws_final} (backup: {backup_ws_final})")
    print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    import pandas as pd

    args = parse_args()
    project_root = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()

    if args.output_dir:
        out_dir = pathlib.Path(args.output_dir)
    else:
        out_dir = project_root / "outputs" / "eda_03_time"
    tables_dir = project_root / "outputs" / "tables"
    figures_dir = project_root / "outputs" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    if args.normalized_cache_dir:
        run_eda03_cache_mode(args, project_root, out_dir, tables_dir, figures_dir)
        return

    if not args.corrected_dir:
        print("[ERROR] --corrected-dir is required for legacy mode "
              "(or pass --normalized-cache-dir).", file=sys.stderr)
        sys.exit(1)
    if args.manifest_csv and not args.normalized_cache_dir:
        print("[ERROR] --manifest-csv requires --normalized-cache-dir. "
              "Build the cache first.", file=sys.stderr)
        sys.exit(1)

    corrected_dir = pathlib.Path(args.corrected_dir)
    if not corrected_dir.exists():
        print(f"[ERROR] corrected-dir not found: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

    if args.archives:
        archive_paths = [corrected_dir / name for name in args.archives]
        missing = [str(p) for p in archive_paths if not p.exists()]
        if missing:
            print(f"[ERROR] Archives not found: {missing}", file=sys.stderr)
            sys.exit(1)
    else:
        archive_paths = sorted(corrected_dir.glob("*.tar"))
        if not archive_paths:
            print(f"[ERROR] No .tar files in {corrected_dir}", file=sys.stderr)
            sys.exit(1)

    pilot_label = (
        f"[PILOT SAMPLE: max_members={args.max_members}, "
        f"max_events={args.max_events}, "
        f"max_events_per_member={args.max_events_per_member}]"
        if (args.max_members or args.max_events) else "[FULL RUN]"
    )

    print(f"\n{'='*60}")
    print(f"EDA 3 — Time Alignment and Window Selection  {pilot_label}")
    print(f"  corrected-dir : {corrected_dir}")
    print(f"  archives      : {[p.name for p in archive_paths]}")
    print(f"  output-dir    : {out_dir}")
    print(f"{'='*60}\n")

    print("Streaming events ...")
    df, n_total, n_parseable, raw_events = collect_events_df(
        archive_paths,
        max_members=args.max_members,
        max_events=args.max_events,
        max_events_per_member=args.max_events_per_member,
        member_name_contains=args.member_name_contains,
    )

    ts_rule = (
        "Numeric values: epoch_ns→/1e9, epoch_ms→/1e3, epoch_s used as-is. "
        "Strings: tried numeric first, then ISO-8601 (Z replaced with +00:00). "
        "All datetimes normalized to naive UTC."
    )
    _stats, _summary_text = _collection_summary(raw_events, args.max_members)

    if df.empty:
        print("[WARN] No events — T5/F3/F4 will be empty.", file=sys.stderr)

    coverage = assess_coverage_from_df(df, n_total, n_parseable)
    print(f"[INFO] Coverage gate: {coverage['status']}")
    for cond in coverage.get("failed_conditions") or []:
        print(f"  - failed: {cond}")

    print("\nComputing T5 window size comparison ...")
    t5_rows = compute_t5(df, pilot_label, coverage=coverage) if not df.empty else []
    t5_df = pd.DataFrame(t5_rows) if t5_rows else pd.DataFrame(columns=[
        "window_size", "number_of_windows", "median_events_per_window",
        "mean_events_per_window", "empty_window_percent",
        "median_unique_hosts", "median_unique_processes", "median_unique_destinations",
        "recommendation_primary_backup_no", "reason",
    ])
    _save_csv(t5_df,
              out_dir / "T5_window_size_comparison.csv",
              tables_dir / "T5_window_size_comparison.csv")

    primary_row = next(
        (r for r in t5_rows if r.get("recommendation_primary_backup_no") == "primary"),
        None,
    )
    primary_ws = primary_row["window_size"] if primary_row else "15min"

    print("\nGenerating F3 event volume plot ...")
    if not df.empty:
        plot_f3(df, out_dir, figures_dir, primary_ws, pilot_label)
    print("\nGenerating F4 entity diversity plot ...")
    if not df.empty:
        plot_f4(df, out_dir, figures_dir, primary_ws, pilot_label)

    print("\nWriting N1 window recommendation ...")
    if t5_rows:
        primary_ws_final, backup_ws_final = write_n1(
            t5_rows, out_dir, pilot_label, n_total, n_parseable, ts_rule,
            coverage=coverage,
        )
    else:
        primary_ws_final = backup_ws_final = "review_needed"
        (out_dir / "N1_window_recommendation_note.txt").write_text(
            "N1 — Window Size Recommendation\n" + "=" * 40 + "\n"
            "No events parsed; cannot make a recommendation.\n\n"
            + "\n".join(format_coverage_block(coverage)) + "\n",
            encoding="utf-8",
        )

    write_readme(
        out_dir, args, n_total, n_parseable,
        pilot_label, primary_ws_final, backup_ws_final, ts_rule,
        member_summary=_summary_text,
        coverage=coverage,
    )

    print(f"\n{'='*60}")
    print(f"EDA 3 COMPLETE  {pilot_label}")
    print(f"  Events total            : {n_total:,}")
    print(f"  Events with valid ts    : {n_parseable:,}")
    print(f"  Coverage gate           : {coverage['status']}")
    print(f"  Recommended window      : {primary_ws_final}  (backup: {backup_ws_final})")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
