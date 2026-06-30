"""
EDA 2 — Schema and Data-Quality Audit (DARPA OpTC)
=====================================================
Streams a pilot sample of events from .tar archives and audits field
reliability, missingness, and data quality issues.

No archives are extracted.  No attack / benign / MITRE claims are made.
No ground-truth overlays are applied.  Outputs are clearly labeled
[PILOT SAMPLE] when --max-members or --max-events limits apply.

Outputs
-------
outputs/eda_02_schema/T3_field_reliability_audit.csv
outputs/eda_02_schema/T4_data_quality_issue_log.csv
outputs/eda_02_schema/F2_timestamp_coverage_plot.png  (.pdf)
outputs/eda_02_schema/README_eda02_schema_quality.txt
(all tables also duplicated to outputs/tables/, figures to outputs/figures/)

Usage
-----
python3 src/eda/eda_02_schema_quality_audit.py \\
    --project-root /content/DARPA_OPTC_EDA_REPO \\
    --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \\
    --archives 2019-09-16.tar \\
    --max-members 25 --max-events 50000
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import pathlib
import shutil
import sys
from typing import Optional

# ── Local import ──────────────────────────────────────────────────────────
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from optc_streaming_parser import stream_from_archives   # type: ignore

# ── Constants ─────────────────────────────────────────────────────────────
# Normalized fields yielded by the streaming parser (excluding provenance)
_AUDIT_FIELDS = [
    "timestamp_raw", "timestamp_parsed",
    "host_raw", "user_raw", "process_raw", "parent_process_raw",
    "action_raw", "object_raw", "destination_raw",
    "source_type",
]
# Provenance / control fields — included in completeness check but kept separate
_PROV_FIELDS = ["archive_name", "member_name", "parse_status", "raw_event_id"]

# Missingness thresholds for keep / review / drop
_KEEP_THRESH   = 20.0   # < 20 % missing → keep candidate
_REVIEW_THRESH = 80.0   # 20–80 % missing → review; > 80 % → drop


# ── Helper utilities ──────────────────────────────────────────────────────

def _is_missing(val) -> bool:
    return val is None or str(val).strip() == ""


def _safe_str(val, maxlen: int = 120) -> str:
    s = str(val) if val is not None else ""
    return s[:maxlen]


def _save_csv(df, *destinations) -> None:
    import pandas as pd   # local import so module remains importable w/o pandas
    for dest in destinations:
        dest = pathlib.Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(dest, index=False)
    print(f"  [CSV] saved to {destinations[0]}")


def _save_fig(fig, base_name: str, *dirs) -> None:
    import matplotlib
    matplotlib.use("Agg")
    for d in dirs:
        d = pathlib.Path(d)
        d.mkdir(parents=True, exist_ok=True)
        for ext in (".png", ".pdf"):
            path = d / (base_name + ext)
            fig.savefig(path, bbox_inches="tight", dpi=150)
    print(f"  [FIG] saved {base_name}.png/.pdf to {dirs[0]}")


# ── T3: Field Reliability Audit ──────────────────────────────────────────

def compute_t3(events: list, source_types: list) -> list:
    """
    For each (source_type, field_name) pair, compute missingness, unique count,
    top-3 values, example value, dominant type, and keep/review/drop decision.
    """
    import pandas as pd

    if not events:
        return []

    df = pd.DataFrame(events)
    rows = []

    for src in sorted(source_types):
        subset = df[df["source_type"] == src] if src != "_all_" else df
        if subset.empty:
            continue

        for field in _AUDIT_FIELDS:
            if field not in subset.columns:
                continue

            col     = subset[field]
            total   = len(col)
            missing = int(col.apply(_is_missing).sum())
            missing_pct = round(missing / max(total, 1) * 100, 1)

            non_null = col[~col.apply(_is_missing)].astype(str)
            unique_count = int(non_null.nunique())

            ctr   = collections.Counter(non_null.tolist())
            top3  = "; ".join(f"{v}({c})" for v, c in ctr.most_common(3))
            example = non_null.iloc[0] if len(non_null) > 0 else ""

            # Dominant raw data type from the original event dicts
            raw_types = [
                type(e.get(field)).__name__
                for e in events
                if e.get("source_type") == src and not _is_missing(e.get(field))
            ][:200]
            if raw_types:
                raw_data_type = collections.Counter(raw_types).most_common(1)[0][0]
            else:
                raw_data_type = "unknown"

            # Parsed data type: for timestamp_parsed → datetime-like; else str
            if field == "timestamp_parsed":
                parsed_data_type = "datetime_str_iso" if unique_count > 1 else "unparseable"
            elif field in ("timestamp_raw",):
                parsed_data_type = "numeric_epoch_or_str"
            else:
                parsed_data_type = "str"

            # Keep / review / drop decision
            if field in ("source_type", "parse_status", "archive_name"):
                decision = "keep"
                reason   = "control/provenance field; always present"
            elif missing_pct > _REVIEW_THRESH:
                decision = "drop"
                reason   = f"{missing_pct}% missing; exceeds drop threshold"
            elif unique_count <= 1 and total > 10:
                decision = "drop"
                reason   = "constant or near-constant field; no discriminative value"
            elif field in ("timestamp_parsed",) and missing_pct > 50.0:
                decision = "review"
                reason   = f"{missing_pct}% unparseable timestamps; time-series reliability at risk"
            elif missing_pct > _KEEP_THRESH:
                decision = "review"
                reason   = f"{missing_pct}% missing; verify field mapping before use"
            else:
                decision = "keep"
                reason   = f"{missing_pct}% missing; {unique_count} unique values"

            rows.append({
                "source_type"                       : src,
                "field_name"                        : field,
                "raw_data_type"                     : raw_data_type,
                "parsed_data_type"                  : parsed_data_type,
                "total_rows"                        : total,
                "missing_percent"                   : missing_pct,
                "unique_count"                      : unique_count,
                "top_3_values"                      : top3[:300],
                "example_value"                     : _safe_str(example, 120),
                "reliability_decision_keep_review_drop": decision,
                "reason"                            : reason,
            })

    return rows


# ── T4: Data Quality Issue Log ────────────────────────────────────────────

def compute_t4(events: list) -> list:
    """
    Detect data quality issues in the event list and return a list of
    issue dicts with the exact T4 column schema.
    """
    if not events:
        return []

    issues = []
    issue_seq = [0]

    def _add_issue(issue_type, source, field, count, example_id, severity, decision):
        issue_seq[0] += 1
        issues.append({
            "issue_id"                : f"ISSUE_{issue_seq[0]:03d}",
            "issue_type"              : issue_type,
            "affected_file_or_source" : source,
            "affected_field"          : field,
            "number_of_rows_affected" : count,
            "example_raw_event_id"    : example_id,
            "severity_high_medium_low": severity,
            "handling_decision"       : decision,
        })

    # 1. JSON parse errors
    parse_errs = [e for e in events if e.get("parse_status") == "json_parse_error"]
    if parse_errs:
        sources = list({e["archive_name"] for e in parse_errs})
        _add_issue(
            "json_parse_error",
            ", ".join(sources[:3]),
            "raw_json",
            len(parse_errs),
            parse_errs[0]["raw_event_id"],
            "high",
            "skip malformed lines; log count; investigate member encoding",
        )

    # Work with parseable events only for subsequent checks
    ok_events = [e for e in events if e.get("parse_status") == "ok"]
    if not ok_events:
        return issues

    # 2. Missing timestamp
    no_ts = [e for e in ok_events if _is_missing(e.get("timestamp_raw"))]
    if no_ts:
        _add_issue(
            "missing_timestamp",
            ", ".join(list({e["archive_name"] for e in no_ts})[:3]),
            "timestamp_raw",
            len(no_ts),
            no_ts[0]["raw_event_id"],
            "high",
            "review raw JSON field names; consider alternative timestamp keys",
        )

    # 3. Timestamp parse failure (raw present but parsed empty)
    ts_fail = [
        e for e in ok_events
        if not _is_missing(e.get("timestamp_raw")) and _is_missing(e.get("timestamp_parsed"))
    ]
    if ts_fail:
        _add_issue(
            "timestamp_parse_failure",
            ", ".join(list({e["archive_name"] for e in ts_fail})[:3]),
            "timestamp_parsed",
            len(ts_fail),
            ts_fail[0]["raw_event_id"],
            "high",
            "attempt additional timestamp format conversions; log scale factor (ms/ns/s)",
        )

    # 4. Duplicate event IDs (only non-generated IDs)
    real_ids = [
        e["raw_event_id"] for e in ok_events
        if not e["raw_event_id"].startswith("gen_")
    ]
    dup_count = len(real_ids) - len(set(real_ids))
    if dup_count > 0:
        dup_id_ctr = collections.Counter(real_ids)
        example_dup = next(k for k, v in dup_id_ctr.items() if v > 1)
        _add_issue(
            "duplicate_event_id",
            "multiple_archives",
            "raw_event_id",
            dup_count,
            example_dup,
            "medium",
            "use (archive_name, member_name, line_number) as composite unique key",
        )

    # 5. Missing host field
    no_host = [e for e in ok_events if _is_missing(e.get("host_raw"))]
    if no_host:
        _add_issue(
            "missing_host",
            ", ".join(list({e["archive_name"] for e in no_host})[:3]),
            "host_raw",
            len(no_host),
            no_host[0]["raw_event_id"],
            "medium",
            "attempt inference from member_name (path often includes host range)",
        )

    # 6. Missing action field
    no_act = [e for e in ok_events if _is_missing(e.get("action_raw"))]
    if no_act:
        _add_issue(
            "missing_action",
            ", ".join(list({e["archive_name"] for e in no_act})[:3]),
            "action_raw",
            len(no_act),
            no_act[0]["raw_event_id"],
            "low",
            "review action/eventType/type key candidates in raw JSON",
        )

    # 7. Negative / large time gaps (per host, where timestamps are parseable)
    try:
        import pandas as pd
        ts_ok = [
            e for e in ok_events
            if not _is_missing(e.get("timestamp_parsed")) and not _is_missing(e.get("host_raw"))
        ]
        if len(ts_ok) > 1:
            df_ts = pd.DataFrame([
                {"host": e["host_raw"],
                 "ts"  : pd.Timestamp(e["timestamp_parsed"]),
                 "eid" : e["raw_event_id"]}
                for e in ts_ok
            ])
            df_ts = df_ts.sort_values(["host", "ts"])
            df_ts["gap_s"] = df_ts.groupby("host")["ts"].diff().dt.total_seconds()

            neg_gaps = df_ts[df_ts["gap_s"] < 0]
            if not neg_gaps.empty:
                _add_issue(
                    "negative_time_gap",
                    "multiple_hosts",
                    "timestamp_parsed",
                    int(len(neg_gaps)),
                    str(neg_gaps.iloc[0]["eid"]),
                    "medium",
                    "possible clock skew or out-of-order log delivery; "
                    "sort by (host, timestamp) before windowing",
                )

            large_thresh_s = 4 * 3600
            large_gaps = df_ts[df_ts["gap_s"] > large_thresh_s]
            if not large_gaps.empty:
                _add_issue(
                    "large_time_gap",
                    "multiple_hosts",
                    "timestamp_parsed",
                    int(len(large_gaps)),
                    str(large_gaps.iloc[0]["eid"]),
                    "low",
                    f"gaps >4 h between consecutive events per host; "
                    "expected for sparse logging or daily-boundary archives; "
                    "use gap-aware window selection in EDA 3",
                )
    except Exception:
        pass   # pandas not available or data insufficient — skip gap checks

    return issues


# ── F2: Timestamp Coverage Plot ───────────────────────────────────────────

def plot_f2(events: list, out_dir: pathlib.Path, figures_dir: pathlib.Path,
            pilot_label: str) -> None:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ts_ok = [
        e["timestamp_parsed"] for e in events
        if not _is_missing(e.get("timestamp_parsed"))
    ]
    if not ts_ok:
        print("  [F2] No parseable timestamps — skipping coverage plot.", file=sys.stderr)
        return

    ts_series = pd.to_datetime(ts_ok, errors="coerce").dropna()
    if ts_series.empty:
        print("  [F2] All timestamps coerced to NaT — skipping.", file=sys.stderr)
        return

    # Bin by hour (or minute if span < 1 hour)
    span_hours = (ts_series.max() - ts_series.min()).total_seconds() / 3600
    freq = "1h" if span_hours >= 1 else "5min"
    binned = ts_series.dt.floor(freq).value_counts().sort_index()

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.bar(binned.index, binned.values, width=pd.Timedelta(freq) * 0.9, color="#4472C4")
    ax.set_xlabel(f"Time (UTC, binned by {freq})", fontsize=11)
    ax.set_ylabel("Event count", fontsize=11)
    ax.set_title(
        f"F2 — Timestamp Coverage {pilot_label}\n"
        f"(No ground-truth overlay  |  {len(ts_ok):,} parseable timestamps)",
        fontsize=11,
    )
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()

    _save_fig(fig, "F2_timestamp_coverage_plot", out_dir, figures_dir)
    plt.close(fig)


# ── README ────────────────────────────────────────────────────────────────

def write_readme(
    out_dir: pathlib.Path,
    args: argparse.Namespace,
    n_events: int,
    n_members_approx: int,
    t3_rows: int,
    t4_rows: int,
    pilot_label: str,
) -> None:
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    lines = [
        "EDA 2 — Schema and Data-Quality Audit",
        "=" * 50,
        f"Generated (UTC): {now}",
        f"Pilot label    : {pilot_label}",
        "",
        "Scope",
        "-----",
        "This audit characterizes the schema of DARPA OpTC corrected archives.",
        "Events are STREAMED from .tar/.json.gz members without extracting archives.",
        "No attack / benign / MITRE claims are made in this script.",
        "No ground-truth overlays are applied (deferred to EDA 10).",
        "",
        "Run parameters",
        "--------------",
        f"  corrected-dir         : {args.corrected_dir}",
        f"  archives processed    : {getattr(args, 'archives', 'all')}",
        f"  max-members per archive: {args.max_members}",
        f"  max-events total      : {args.max_events}",
        f"  member-name-contains  : {args.member_name_contains}",
        "",
        "Collected data",
        "--------------",
        f"  events parsed         : {n_events:,}",
        f"  members scanned (approx): {n_members_approx}",
        "",
        "Outputs",
        "-------",
        f"  T3 field reliability audit  : {t3_rows} rows",
        f"  T4 data quality issue log   : {t4_rows} rows",
        "  F2 timestamp coverage plot  : see F2_timestamp_coverage_plot.png/.pdf",
        "",
        "T3 reliability decision rules",
        "------------------------------",
        "  keep   : < 20% missing AND useful for downstream modeling",
        "  review : 20–80% missing OR inconsistent type OR uncertain semantics",
        "  drop   : > 80% missing OR constant/no-information field",
        "",
        "T4 severity levels",
        "------------------",
        "  high   : blocks time-series analysis (timestamp failures, JSON errors)",
        "  medium : degrades graph / behavioral modeling (missing host, dup IDs)",
        "  low    : cosmetic / informational (large gaps, missing action)",
        "",
        "Important limitations",
        "----------------------",
        f"  * Pilot sample only — {n_events:,} events from up to {args.max_members} members per archive.",
        "  * Schema statistics may shift when more members / archives are processed.",
        "  * Normalized field extraction is best-effort; OpTC ECAR field names vary by version.",
        "  * Ground-truth alignment and attack interval annotation are deferred to EDA 10.",
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "README_eda02_schema_quality.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"  [README] {out_dir / 'README_eda02_schema_quality.txt'}")


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="EDA 2 — DARPA OpTC Schema and Data-Quality Audit (pilot).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--project-root", default=None,
                   help="Project root directory (default: cwd)")
    p.add_argument("--corrected-dir", required=True,
                   help="Directory containing corrected .tar archives")
    p.add_argument("--archives", nargs="+", default=None,
                   help="Archive filenames to process (default: all .tar in corrected-dir)")
    p.add_argument("--output-dir", default=None,
                   help="Output directory (default: <project-root>/outputs/eda_02_schema)")
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
    project_root = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()
    corrected_dir = pathlib.Path(args.corrected_dir)
    if not corrected_dir.exists():
        print(f"[ERROR] corrected-dir not found: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

    if args.output_dir:
        out_dir = pathlib.Path(args.output_dir)
    else:
        out_dir = project_root / "outputs" / "eda_02_schema"

    tables_dir  = project_root / "outputs" / "tables"
    figures_dir = project_root / "outputs" / "figures"

    out_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    # Resolve archive paths
    if args.archives:
        archive_paths = [corrected_dir / name for name in args.archives]
        missing = [p for p in archive_paths if not p.exists()]
        if missing:
            print(f"[ERROR] Archives not found: {[str(m) for m in missing]}", file=sys.stderr)
            sys.exit(1)
    else:
        archive_paths = sorted(corrected_dir.glob("*.tar"))
        if not archive_paths:
            print(f"[ERROR] No .tar files found in {corrected_dir}", file=sys.stderr)
            sys.exit(1)

    # Pilot label
    is_pilot = (args.max_members is not None) or (args.max_events is not None)
    pilot_label = (
        f"[PILOT SAMPLE: max_members={args.max_members}, max_events={args.max_events}]"
        if is_pilot else "[FULL RUN]"
    )
    print(f"\n{'='*60}")
    print(f"EDA 2 — Schema and Data-Quality Audit  {pilot_label}")
    print(f"  corrected-dir : {corrected_dir}")
    print(f"  archives      : {[p.name for p in archive_paths]}")
    print(f"  output-dir    : {out_dir}")
    print(f"{'='*60}\n")

    # ── Collect events ────────────────────────────────────────────────
    print("Streaming events ...")
    events = list(stream_from_archives(
        archive_paths,
        max_members=args.max_members,
        max_events=args.max_events,
        member_name_contains=args.member_name_contains,
        quiet=False,
    ))

    print(f"\n[INFO] {len(events):,} events collected.")

    if not events:
        print("[WARN] No events parsed — T3/T4/F2 will be empty.", file=sys.stderr)

    # ── T3: Field Reliability Audit ───────────────────────────────────
    print("\nComputing T3 field reliability audit ...")
    source_types = sorted({e.get("source_type", "unknown") for e in events})
    t3_rows  = compute_t3(events, source_types)
    t3_df    = pd.DataFrame(t3_rows) if t3_rows else pd.DataFrame(columns=[
        "source_type", "field_name", "raw_data_type", "parsed_data_type",
        "total_rows", "missing_percent", "unique_count", "top_3_values",
        "example_value", "reliability_decision_keep_review_drop", "reason",
    ])
    _save_csv(t3_df,
              out_dir    / "T3_field_reliability_audit.csv",
              tables_dir / "T3_field_reliability_audit.csv")

    # ── T4: Data Quality Issue Log ────────────────────────────────────
    print("\nComputing T4 data quality issues ...")
    t4_rows_data = compute_t4(events)
    t4_df = pd.DataFrame(t4_rows_data) if t4_rows_data else pd.DataFrame(columns=[
        "issue_id", "issue_type", "affected_file_or_source", "affected_field",
        "number_of_rows_affected", "example_raw_event_id",
        "severity_high_medium_low", "handling_decision",
    ])
    _save_csv(t4_df,
              out_dir    / "T4_data_quality_issue_log.csv",
              tables_dir / "T4_data_quality_issue_log.csv")

    # ── F2: Timestamp Coverage Plot ───────────────────────────────────
    print("\nGenerating F2 timestamp coverage plot ...")
    plot_f2(events, out_dir, figures_dir, pilot_label)

    # ── README ────────────────────────────────────────────────────────
    n_members = len({e.get("member_name", "") for e in events})
    write_readme(
        out_dir, args,
        n_events=len(events),
        n_members_approx=n_members,
        t3_rows=len(t3_rows),
        t4_rows=len(t4_rows_data),
        pilot_label=pilot_label,
    )

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"EDA 2 COMPLETE  {pilot_label}")
    print(f"  Events parsed          : {len(events):,}")
    print(f"  T3 rows                : {len(t3_rows)}")
    print(f"  T4 issues detected     : {len(t4_rows_data)}")
    print(f"\n  Outputs:")
    for f in sorted(out_dir.iterdir()):
        if f.is_file():
            print(f"    {f}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
