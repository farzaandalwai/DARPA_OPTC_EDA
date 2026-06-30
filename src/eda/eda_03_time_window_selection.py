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

    return df, total_raw, n_parseable


# ── T5: Window Size Comparison ────────────────────────────────────────────

def compute_t5(df, pilot_label: str) -> list:
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
            entity_stats = {}
            for label, col in _ENTITY_COLS.items():
                if col in ts_df.columns:
                    windowed = ts_df[col].resample(freq).agg(lambda s: s[s != ""].nunique())
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

    # ── Recommendation logic ──────────────────────────────────────────
    # Primary: smallest window where empty_window_percent < 50 %
    #          AND median_events_per_window >= 5
    # Backup : next larger qualifying window, or 1h as fallback
    qualify = [
        r for r in rows
        if isinstance(r["empty_window_percent"], float)
        and r["empty_window_percent"] < 50.0
        and isinstance(r["median_events_per_window"], float)
        and r["median_events_per_window"] >= 5.0
    ]

    if not qualify:
        # All sparse — flag as review needed
        for r in rows:
            r["recommendation_primary_backup_no"] = "no"
            r["reason"] = (
                "data too sparse for reliable window selection; "
                "review timestamp quality and increase max_events before recommending"
            )
    else:
        # Recommend smallest qualifying window as primary
        primary_ws   = qualify[0]["window_size"]
        backup_ws    = qualify[1]["window_size"] if len(qualify) > 1 else "1h"

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
                empty_p = r.get("empty_window_percent", "?")
                med_ev  = r.get("median_events_per_window", "?")
                if ws in [_WINDOW_SIZES[i] for i in range(_WINDOW_SIZES.index(primary_ws))]:
                    r["recommendation_primary_backup_no"] = "no"
                    r["reason"] = (
                        f"too fine-grained: {empty_p}% empty windows or "
                        f"<5 median events; primary {primary_ws} is preferred"
                    )
                else:
                    r["recommendation_primary_backup_no"] = "no"
                    r["reason"] = (
                        f"coarser than backup {backup_ws}; "
                        f"use only if dataset is very sparse"
                    )

    return rows


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
             n_events: int, n_parseable: int, ts_rule: str) -> None:
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    primary_row  = next((r for r in t5_rows if r.get("recommendation_primary_backup_no") == "primary"), None)
    backup_row   = next((r for r in t5_rows if r.get("recommendation_primary_backup_no") == "backup"), None)
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
        "Recommendation",
        "--------------",
        f"  Primary window : {primary_ws}",
        f"  Backup window  : {backup_ws}",
        "",
    ]

    if primary_ws == "review_needed":
        lines += [
            "  *** REVIEW NEEDED ***",
            "  The pilot data is too sparse or has too many unparseable timestamps",
            "  to make a reliable window recommendation.  Please:",
            "    1. Increase --max-events (try 500,000+) or --max-members (try 50+).",
            "    2. Verify that timestamp fields are correctly mapped in the parser.",
            "    3. Re-run EDA 3 after acquiring more archive data.",
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
) -> None:
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
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
        f"  member-name-contains   : {args.member_name_contains}",
        "",
        "Timestamp conversion rule",
        "-------------------------",
        f"  {ts_rule}",
        f"  Parseable: {n_parseable:,} / {n_events:,} "
        f"({n_parseable/max(n_events,1)*100:.1f}%)",
        "",
        "Window recommendation",
        "---------------------",
        f"  Primary : {primary_ws}",
        f"  Backup  : {backup_ws}",
        "  (see N1_window_recommendation_note.txt for full rationale)",
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
        f"  * Pilot sample only — {n_events:,} events, ≤{args.max_members} members/archive.",
        "  * Window statistics may shift with larger samples.",
        "  * Gradual drift analysis requires more archives (2019-09-19 through 2019-09-24 pending).",
        "  * Ground-truth alignment and attack-interval annotation are deferred to EDA 10.",
    ]
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
    p.add_argument("--corrected-dir", required=True,
                   help="Directory containing corrected .tar archives")
    p.add_argument("--archives", nargs="+", default=None,
                   help="Archive filenames to process (default: all .tar in corrected-dir)")
    p.add_argument("--output-dir", default=None,
                   help="Output directory (default: <project-root>/outputs/eda_03_time)")
    p.add_argument("--max-members", type=int, default=25,
                   help="Max members to scan per archive (default: 25)")
    p.add_argument("--max-events", type=int, default=50_000,
                   help="Max total events across all archives (default: 50000)")
    p.add_argument("--member-name-contains", default=None,
                   help="Filter: only process members whose name contains this string")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    import pandas as pd

    args = parse_args()

    # Resolve paths
    project_root  = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()
    corrected_dir = pathlib.Path(args.corrected_dir)
    if not corrected_dir.exists():
        print(f"[ERROR] corrected-dir not found: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

    if args.output_dir:
        out_dir = pathlib.Path(args.output_dir)
    else:
        out_dir = project_root / "outputs" / "eda_03_time"

    tables_dir  = project_root / "outputs" / "tables"
    figures_dir = project_root / "outputs" / "figures"

    out_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    # Resolve archive paths
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

    # Pilot label
    pilot_label = (
        f"[PILOT SAMPLE: max_members={args.max_members}, max_events={args.max_events}]"
        if (args.max_members or args.max_events) else "[FULL RUN]"
    )

    print(f"\n{'='*60}")
    print(f"EDA 3 — Time Alignment and Window Selection  {pilot_label}")
    print(f"  corrected-dir : {corrected_dir}")
    print(f"  archives      : {[p.name for p in archive_paths]}")
    print(f"  output-dir    : {out_dir}")
    print(f"{'='*60}\n")

    # ── Collect events ────────────────────────────────────────────────
    print("Streaming events ...")
    df, n_total, n_parseable = collect_events_df(
        archive_paths,
        max_members=args.max_members,
        max_events=args.max_events,
        member_name_contains=args.member_name_contains,
    )

    ts_rule = (
        "Numeric values: epoch_ns→/1e9, epoch_ms→/1e3, epoch_s used as-is. "
        "Strings: tried numeric first, then ISO-8601 (Z replaced with +00:00). "
        "All datetimes normalized to naive UTC."
    )

    if df.empty:
        print("[WARN] No events — T5/F3/F4 will be empty.", file=sys.stderr)

    # ── T5: Window Size Comparison ────────────────────────────────────
    print("\nComputing T5 window size comparison ...")
    t5_rows = compute_t5(df, pilot_label) if not df.empty else []

    t5_df = pd.DataFrame(t5_rows) if t5_rows else pd.DataFrame(columns=[
        "window_size", "number_of_windows", "median_events_per_window",
        "mean_events_per_window", "empty_window_percent",
        "median_unique_hosts", "median_unique_processes", "median_unique_destinations",
        "recommendation_primary_backup_no", "reason",
    ])
    _save_csv(t5_df,
              out_dir    / "T5_window_size_comparison.csv",
              tables_dir / "T5_window_size_comparison.csv")

    # Determine primary/backup window for figure titles
    primary_row = next((r for r in t5_rows if r.get("recommendation_primary_backup_no") == "primary"), None)
    primary_ws  = primary_row["window_size"] if primary_row else "15min"

    # ── F3 / F4: Time-series figures ──────────────────────────────────
    print("\nGenerating F3 event volume plot ...")
    if not df.empty:
        plot_f3(df, out_dir, figures_dir, primary_ws, pilot_label)
    else:
        print("  [F3] skipped — no data.", file=sys.stderr)

    print("\nGenerating F4 entity diversity plot ...")
    if not df.empty:
        plot_f4(df, out_dir, figures_dir, primary_ws, pilot_label)
    else:
        print("  [F4] skipped — no data.", file=sys.stderr)

    # ── N1: Recommendation note ───────────────────────────────────────
    print("\nWriting N1 window recommendation ...")
    if t5_rows:
        primary_ws_final, backup_ws_final = write_n1(
            t5_rows, out_dir, pilot_label, n_total, n_parseable, ts_rule
        )
    else:
        primary_ws_final = backup_ws_final = "review_needed"
        (out_dir / "N1_window_recommendation_note.txt").write_text(
            "N1 — Window Size Recommendation\n" + "=" * 40 + "\n"
            "No events parsed; cannot make a recommendation.\n"
            "Check --corrected-dir and --archives arguments.\n",
            encoding="utf-8",
        )

    # ── README ────────────────────────────────────────────────────────
    write_readme(
        out_dir, args, n_total, n_parseable,
        pilot_label, primary_ws_final, backup_ws_final, ts_rule,
    )

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"EDA 3 COMPLETE  {pilot_label}")
    print(f"  Events total            : {n_total:,}")
    print(f"  Events with valid ts    : {n_parseable:,}")
    print(f"  Recommended window      : {primary_ws_final}  (backup: {backup_ws_final})")
    print(f"\n  Outputs:")
    for f in sorted(out_dir.iterdir()):
        if f.is_file():
            print(f"    {f}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
