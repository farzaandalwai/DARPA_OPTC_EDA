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
from optc_streaming_parser import (  # type: ignore
    SLIM_EVENT_COLUMNS,
    stream_from_archives,
)

# ── Constants ─────────────────────────────────────────────────────────────
# Full schema-v2 audit surface (stays synchronized with the parser).
_AUDIT_FIELDS = list(SLIM_EVENT_COLUMNS)

# Field-role taxonomy for T3.
_PROVENANCE_FIELDS = {
    "file_id", "archive_name", "member_name", "line_number",
    "raw_event_id", "parse_status", "parse_error",
}
_CONTROL_FIELDS = {"source_type"}
_CORE_FIELDS = {
    "timestamp_raw", "timestamp_parsed", "host_raw", "action_raw", "object_raw",
}
_ENTITY_FIELDS = {
    "user_raw",
    "object_value_raw", "actor_id_raw", "object_id_raw", "pid_raw", "ppid_raw",
    "tid_raw", "principal_raw",
}
_DISCOVERY_FIELDS = {"properties_keys_raw", "unmapped_property_keys_raw"}

# Object-specific fields → object types where the field is expected to apply.
# Decisions use missingness among applicable rows, not the full sample.
# Derived compatibility fields inherit applicability from their source columns:
#   process_raw ← image_path_raw
#   parent_process_raw ← parent_image_path_raw
#   destination_raw ← dest_ip_raw
_OBJECT_SPECIFIC_APPLICABLE: dict[str, list[str]] = {
    "image_path_raw": ["PROCESS", "FLOW", "FILE", "MODULE", "THREAD", "SHELL"],
    "process_raw": ["PROCESS", "FLOW", "FILE", "MODULE", "THREAD", "SHELL"],
    "parent_image_path_raw": ["PROCESS"],
    "parent_process_raw": ["PROCESS"],
    "command_line_raw": ["PROCESS"],
    "file_path_raw": ["FILE"],
    "module_path_raw": ["MODULE"],
    "registry_key_raw": ["REGISTRY"],
    "registry_value_raw": ["REGISTRY"],
    "registry_data_raw": ["REGISTRY"],
    "registry_type_raw": ["REGISTRY"],
    "generic_path_raw": ["TASK"],
    "info_class_raw": ["FILE", "THREAD"],
    "task_name_raw": ["TASK"],
    "task_pid_raw": ["TASK"],
    "task_process_uuid_raw": ["TASK"],
    "property_name_raw": ["SERVICE"],
    "service_name_raw": ["SERVICE"],
    "service_type_raw": ["SERVICE"],
    "service_start_type_raw": ["SERVICE"],
    "src_ip_raw": ["FLOW"],
    "src_port_raw": ["FLOW"],
    "dest_ip_raw": ["FLOW"],
    "dest_port_raw": ["FLOW"],
    "destination_raw": ["FLOW"],
    "direction_raw": ["FLOW"],
    "protocol_raw": ["FLOW"],
    "shell_payload_raw": ["SHELL"],
    "shell_context_raw": ["SHELL"],
    "logon_id_raw": ["USER_SESSION"],
    "property_user_raw": ["USER_SESSION"],
    "privileges_raw": ["USER_SESSION"],
    "acuity_level_raw": [],  # common across object types; treat as all-rows
    "thread_src_pid_raw": ["THREAD"],
    "thread_src_tid_raw": ["THREAD"],
    "thread_tgt_pid_raw": ["THREAD"],
    "thread_tgt_tid_raw": ["THREAD"],
    # v3 promoted properties
    "property_size_raw": ["FILE", "FLOW"],
    "base_address_raw": ["MODULE"],
    "stack_base_raw": ["THREAD"],
    "subprocess_tag_raw": ["THREAD"],
    "stack_limit_raw": ["THREAD"],
    "start_address_raw": ["THREAD"],
    "user_stack_base_raw": ["THREAD"],
    "user_stack_limit_raw": ["THREAD"],
    "flow_start_time_raw": ["FLOW"],
    "flow_end_time_raw": ["FLOW"],
    "new_path_raw": ["FILE"],
    "process_sid_raw": ["PROCESS"],
    "thread_tgt_pid_uuid_raw": ["THREAD"],
    "requesting_logon_id_raw": ["USER_SESSION"],
    "requesting_domain_raw": ["USER_SESSION"],
    "requesting_user_raw": ["USER_SESSION"],
    "task_user_name_raw": ["TASK"],
}

# Diagnostic / provenance fields kept even when empty by design.
_ALWAYS_KEEP_FIELDS = _PROVENANCE_FIELDS | _CONTROL_FIELDS | {
    "parse_error",  # empty when no parse failures
}

# Missingness thresholds for keep / review / drop
_KEEP_THRESH   = 20.0   # < 20 % missing → keep candidate
_REVIEW_THRESH = 80.0   # 20–80 % missing → review; > 80 % → drop

# Final T3 column order (legacy columns preserved; new columns appended).
T3_COLUMNS = [
    "source_type",
    "field_name",
    "field_role",
    "raw_data_type",
    "parsed_data_type",
    "total_rows",
    "applicable_object_types",
    "applicable_rows",
    "missing_percent",
    "missing_percent_overall",
    "missing_percent_applicable",
    "unique_count",
    "top_3_values",
    "example_value",
    "reliability_decision_keep_review_drop",
    "reason",
]


def field_role(field: str) -> str:
    if field in _PROVENANCE_FIELDS:
        return "provenance"
    if field in _CONTROL_FIELDS:
        return "control"
    if field in _CORE_FIELDS:
        return "core"
    if field in _OBJECT_SPECIFIC_APPLICABLE:
        return "object_specific"
    if field in _ENTITY_FIELDS:
        return "entity"
    if field in _DISCOVERY_FIELDS:
        return "discovery"
    return "entity"


def applicable_object_types_for(field: str) -> list[str]:
    """Return object types where *field* is expected; empty list means ALL rows."""
    if field not in _OBJECT_SPECIFIC_APPLICABLE:
        return []
    return list(_OBJECT_SPECIFIC_APPLICABLE[field])


def _decide_reliability(
    field: str,
    *,
    role: str,
    total_rows: int,
    applicable_rows: int,
    missing_pct_overall: float,
    missing_pct_applicable: float,
    unique_count: int,
    n_hosts: int,
) -> tuple[str, str]:
    """
    Keep / review / drop decision for one field.

    Object-specific fields use applicable-row missingness.  Absent applicable
    object types → review / not assessable (never drop).  Decisions from
    capped or single-host samples are preliminary.
    """
    preliminary = " [preliminary: capped/single-host sample]" if n_hosts <= 1 else ""

    if field in _ALWAYS_KEEP_FIELDS or role in ("provenance", "control"):
        return "keep", (
            f"diagnostic/provenance/control field retained by design "
            f"(overall missing {missing_pct_overall}%){preliminary}"
        )

    if role == "object_specific" and applicable_object_types_for(field):
        if applicable_rows == 0:
            types = ",".join(applicable_object_types_for(field))
            return "review", (
                f"not assessable: no rows with object types [{types}] in sample"
                f"{preliminary}"
            )
        decision_pct = missing_pct_applicable
        pct_label = "applicable"
    else:
        decision_pct = missing_pct_overall
        pct_label = "overall"

    if field == "host_raw" and unique_count <= 1:
        return "keep", (
            f"single-host sample ({unique_count} unique host); "
            f"constant host is not grounds for drop{preliminary}"
        )

    if decision_pct > _REVIEW_THRESH:
        return "drop", (
            f"{decision_pct}% missing ({pct_label}); exceeds drop threshold"
            f"{preliminary}"
        )

    # Constancy: require enough applicable (or overall) rows before dropping.
    constancy_n = (
        applicable_rows
        if role == "object_specific" and applicable_object_types_for(field)
        else total_rows
    )
    if unique_count <= 1 and constancy_n > 10 and field != "host_raw":
        if role == "discovery":
            return "keep", (
                f"discovery field retained; {unique_count} unique non-empty value(s)"
                f"{preliminary}"
            )
        return "drop", (
            f"constant or near-constant field; no discriminative value"
            f"{preliminary}"
        )

    if field == "timestamp_parsed" and missing_pct_overall > 50.0:
        return "review", (
            f"{missing_pct_overall}% unparseable timestamps; "
            f"time-series reliability at risk{preliminary}"
        )

    if decision_pct > _KEEP_THRESH:
        return "review", (
            f"{decision_pct}% missing ({pct_label}); verify field mapping before use"
            f"{preliminary}"
        )

    return "keep", (
        f"{decision_pct}% missing ({pct_label}); {unique_count} unique values"
        f"{preliminary}"
    )


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


# ── Pilot sampling summary ────────────────────────────────────────────────

def _collection_summary(events: list, max_members: int) -> tuple:
    """
    Returns (summary_dict, summary_text) for printing and README inclusion.
    """
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
        "src_counts": dict(src_ctr),
        "top_members": member_ctr.most_common(10),
    }
    return stats, text


# ── T3: Field Reliability Audit ──────────────────────────────────────────

def _object_upper_series(subset):
    """Normalize object_raw for applicability matching."""
    import pandas as pd
    if "object_raw" not in subset.columns:
        return pd.Series([""] * len(subset), index=subset.index)
    return subset["object_raw"].fillna("").astype(str).str.strip().str.upper()


def compute_t3(events: list, source_types: list) -> list:
    """
    For each (source_type, field_name) pair over SLIM_EVENT_COLUMNS, compute
    missingness (overall + applicable), unique count, top-3 values, and a
    keep/review/drop decision.  Object-specific fields are scored on applicable
    object rows only.
    """
    import pandas as pd

    if not events:
        return []

    df = pd.DataFrame(events)
    for col in _AUDIT_FIELDS:
        if col not in df.columns:
            df[col] = ""

    if "host_raw" in df.columns:
        n_hosts = int(
            df["host_raw"].fillna("").astype(str).str.strip()
            .replace("", pd.NA).nunique(dropna=True)
        )
    else:
        n_hosts = 0

    rows = []
    for src in sorted(source_types):
        subset = df[df["source_type"] == src] if src != "_all_" else df
        if subset.empty:
            continue

        obj_upper = _object_upper_series(subset)
        total = len(subset)

        for field in _AUDIT_FIELDS:
            role = field_role(field)
            appl_types = applicable_object_types_for(field)
            appl_types_str = ",".join(appl_types) if appl_types else "ALL"

            col = subset[field]
            missing_overall = int(col.apply(_is_missing).sum())
            missing_pct_overall = round(missing_overall / max(total, 1) * 100, 1)

            if appl_types:
                mask = obj_upper.isin(appl_types)
                applicable_rows = int(mask.sum())
                if applicable_rows > 0:
                    miss_app = int(col[mask].apply(_is_missing).sum())
                    missing_pct_applicable = round(
                        miss_app / applicable_rows * 100, 1
                    )
                else:
                    missing_pct_applicable = 100.0
            else:
                applicable_rows = total
                missing_pct_applicable = missing_pct_overall

            non_null = col[~col.apply(_is_missing)].astype(str)
            unique_count = int(non_null.nunique())
            ctr = collections.Counter(non_null.tolist())
            top3 = "; ".join(f"{v}({c})" for v, c in ctr.most_common(3))
            example = non_null.iloc[0] if len(non_null) > 0 else ""

            raw_types = [
                type(e.get(field)).__name__
                for e in events
                if e.get("source_type") == src and not _is_missing(e.get(field))
            ][:200]
            raw_data_type = (
                collections.Counter(raw_types).most_common(1)[0][0]
                if raw_types else "unknown"
            )

            if field == "timestamp_parsed":
                parsed_data_type = (
                    "datetime_str_iso" if unique_count > 1 else "unparseable"
                )
            elif field == "timestamp_raw":
                parsed_data_type = "numeric_epoch_or_str"
            else:
                parsed_data_type = "str"

            decision, reason = _decide_reliability(
                field,
                role=role,
                total_rows=total,
                applicable_rows=applicable_rows,
                missing_pct_overall=missing_pct_overall,
                missing_pct_applicable=missing_pct_applicable,
                unique_count=unique_count,
                n_hosts=n_hosts,
            )

            rows.append({
                "source_type": src,
                "field_name": field,
                "field_role": role,
                "raw_data_type": raw_data_type,
                "parsed_data_type": parsed_data_type,
                "total_rows": total,
                "applicable_object_types": appl_types_str,
                "applicable_rows": applicable_rows,
                "missing_percent": missing_pct_overall,
                "missing_percent_overall": missing_pct_overall,
                "missing_percent_applicable": missing_pct_applicable,
                "unique_count": unique_count,
                "top_3_values": top3[:300],
                "example_value": _safe_str(example, 120),
                "reliability_decision_keep_review_drop": decision,
                "reason": reason,
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

    # Convert to pd.Series (not DatetimeIndex) so .dt accessor works reliably
    ts_series = pd.to_datetime(pd.Series(ts_ok), errors="coerce").dropna()
    if ts_series.empty:
        print("  [F2] All timestamps coerced to NaT — skipping.", file=sys.stderr)
        return

    # Bin by hour (or 5-min if span < 1 hour)
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
    member_summary: str = "",
) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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
        f"  corrected-dir          : {args.corrected_dir}",
        f"  archives processed     : {getattr(args, 'archives', 'all')}",
        f"  max-members per archive: {args.max_members}",
        f"  max-events total       : {args.max_events}",
        f"  max-events-per-member  : {args.max_events_per_member}",
        f"  member-name-contains   : {args.member_name_contains}",
        "",
        "Collected data",
        "--------------",
        f"  events parsed          : {n_events:,}",
        f"  members with events    : {n_members_approx}",
    ]
    if member_summary:
        lines += ["", "Pilot sampling detail", "---------------------"]
        lines += [f"  {ln}" for ln in member_summary.strip().splitlines()]
    lines += [
        "",
        "Outputs",
        "-------",
        f"  T3 field reliability audit  : {t3_rows} rows",
        f"  T4 data quality issue log   : {t4_rows} rows",
        "  F2 timestamp coverage plot  : see F2_timestamp_coverage_plot.png/.pdf",
        "",
        "T3 reliability decision rules (schema v2 / SLIM_EVENT_COLUMNS)",
        "--------------------------------------------------------------",
        "  Audits every column in SLIM_EVENT_COLUMNS with field_role:",
        "    provenance | control | core | entity | object_specific | discovery",
        "  keep   : < 20% missing (overall, or applicable for object-specific)",
        "  review : 20–80% missing OR not assessable (applicable object absent)",
        "  drop   : > 80% missing OR constant/no-information (non-host) field",
        "  Object-specific fields use missing_percent_applicable, not overall.",
        "  If applicable object types are absent → review / not assessable (never drop).",
        "  host_raw is never dropped merely because a single-host sample is constant.",
        "  Diagnostic/provenance fields (e.g. parse_error) are retained even when empty.",
        "  Decisions from capped or single-host samples are PRELIMINARY.",
        "",
        "T4 severity levels",
        "------------------",
        "  high   : blocks time-series analysis (timestamp failures, JSON errors)",
        "  medium : degrades graph / behavioral modeling (missing host, dup IDs)",
        "  low    : cosmetic / informational (large gaps, missing action)",
        "",
        "Important limitations",
        "----------------------",
        f"  * Pilot sample only — {n_events:,} events from up to {args.max_members} members "
        f"  (max {args.max_events_per_member} events/member).",
        "  * Schema statistics may shift when more members / archives are processed.",
        "  * Keep/review/drop from capped or single-host samples are preliminary only.",
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
    p.add_argument("--corrected-dir", default=None,
                   help="Directory containing corrected .tar archives (required for legacy mode)")
    p.add_argument("--archives", nargs="+", default=None,
                   help="Archive filenames to process (default: all .tar in corrected-dir)")
    p.add_argument("--output-dir", default=None,
                   help="Output directory (default: <project-root>/outputs/eda_02_schema)")
    p.add_argument("--max-members", type=int, default=25,
                   help="Max members to scan per archive (default: 25)")
    p.add_argument("--max-events", type=int, default=50_000,
                   help="Max total events across all archives (default: 50000)")
    p.add_argument("--max-events-per-member", type=int, default=2000,
                   help="Max events per tar member (default: 2000)")
    p.add_argument("--member-name-contains", default=None,
                   help="Filter: only process members whose name contains this string")
    p.add_argument("--manifest-csv", default=None,
                   help="Pilot manifest CSV (required with --normalized-cache-dir)")
    p.add_argument("--normalized-cache-dir", default=None,
                   help="Parquet cache dir from build_normalized_pilot_cache.py")
    return p.parse_args()


# ── Cache-mode helpers (DuckDB; never load full cache into RAM) ────────────

def _load_cache_metadata(cache_dir: pathlib.Path) -> dict:
    meta_path = cache_dir / "cache_metadata.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text(encoding="utf-8"))
    return {}


def _duck_conn(cache_dir: pathlib.Path):
    import duckdb
    con = duckdb.connect()
    glob = str(cache_dir / "*.parquet")
    con.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet('{glob}')")
    return con


def compute_t3_from_cache(con) -> list:
    """T3 via DuckDB aggregates over every SLIM_EVENT_COLUMNS field."""
    # Discover which slim columns are present in the parquet schema.
    present = {r[0] for r in con.execute("DESCRIBE SELECT * FROM events").fetchall()}
    n_hosts = con.execute(
        """
        SELECT COUNT(DISTINCT NULLIF(CAST(host_raw AS VARCHAR), ''))
        FROM events
        """
    ).fetchone()[0] if "host_raw" in present else 0

    srcs = [r[0] for r in con.execute(
        "SELECT DISTINCT source_type FROM events ORDER BY 1"
    ).fetchall()]
    rows = []
    for src in srcs:
        total = con.execute(
            "SELECT COUNT(*) FROM events WHERE source_type = ?", [src]
        ).fetchone()[0]
        if total == 0:
            continue
        for field in _AUDIT_FIELDS:
            role = field_role(field)
            appl_types = applicable_object_types_for(field)
            appl_types_str = ",".join(appl_types) if appl_types else "ALL"

            if field not in present:
                # Column absent from cache parquet — still emit a T3 row.
                decision, reason = _decide_reliability(
                    field,
                    role=role,
                    total_rows=int(total),
                    applicable_rows=0 if appl_types else int(total),
                    missing_pct_overall=100.0,
                    missing_pct_applicable=100.0,
                    unique_count=0,
                    n_hosts=int(n_hosts or 0),
                )
                if appl_types:
                    decision, reason = "review", (
                        "not assessable: column absent from cache parquet"
                        " [preliminary: capped/single-host sample]"
                        if int(n_hosts or 0) <= 1 else
                        "not assessable: column absent from cache parquet"
                    )
                rows.append({
                    "source_type": src,
                    "field_name": field,
                    "field_role": role,
                    "raw_data_type": "unknown",
                    "parsed_data_type": "str",
                    "total_rows": int(total),
                    "applicable_object_types": appl_types_str,
                    "applicable_rows": 0 if appl_types else int(total),
                    "missing_percent": 100.0,
                    "missing_percent_overall": 100.0,
                    "missing_percent_applicable": 100.0,
                    "unique_count": 0,
                    "top_3_values": "",
                    "example_value": "",
                    "reliability_decision_keep_review_drop": decision,
                    "reason": reason,
                })
                continue

            miss = con.execute(
                f"""
                SELECT COUNT(*) FROM events
                WHERE source_type = ?
                  AND ({field} IS NULL OR CAST({field} AS VARCHAR) = '')
                """,
                [src],
            ).fetchone()[0]
            missing_pct_overall = round(miss / max(total, 1) * 100, 1)

            if appl_types:
                type_list = ", ".join(f"'{t}'" for t in appl_types)
                applicable_rows = con.execute(
                    f"""
                    SELECT COUNT(*) FROM events
                    WHERE source_type = ?
                      AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) IN ({type_list})
                    """,
                    [src],
                ).fetchone()[0]
                if applicable_rows > 0:
                    miss_app = con.execute(
                        f"""
                        SELECT COUNT(*) FROM events
                        WHERE source_type = ?
                          AND UPPER(TRIM(CAST(object_raw AS VARCHAR))) IN ({type_list})
                          AND ({field} IS NULL OR CAST({field} AS VARCHAR) = '')
                        """,
                        [src],
                    ).fetchone()[0]
                    missing_pct_applicable = round(
                        miss_app / applicable_rows * 100, 1
                    )
                else:
                    missing_pct_applicable = 100.0
            else:
                applicable_rows = total
                missing_pct_applicable = missing_pct_overall

            unique_count = con.execute(
                f"""
                SELECT COUNT(DISTINCT {field}) FROM events
                WHERE source_type = ?
                  AND {field} IS NOT NULL AND CAST({field} AS VARCHAR) != ''
                """,
                [src],
            ).fetchone()[0]
            top = con.execute(
                f"""
                SELECT CAST({field} AS VARCHAR) AS v, COUNT(*) AS c
                FROM events
                WHERE source_type = ?
                  AND {field} IS NOT NULL AND CAST({field} AS VARCHAR) != ''
                GROUP BY 1 ORDER BY c DESC LIMIT 3
                """,
                [src],
            ).fetchall()
            top3 = "; ".join(f"{v}({c})" for v, c in top)
            example = top[0][0] if top else ""

            if field == "timestamp_parsed":
                parsed_data_type = (
                    "datetime_str_iso" if unique_count > 1 else "unparseable"
                )
                raw_data_type = "str"
            elif field == "timestamp_raw":
                parsed_data_type = "numeric_epoch_or_str"
                raw_data_type = "str"
            else:
                parsed_data_type = "str"
                raw_data_type = "str"

            decision, reason = _decide_reliability(
                field,
                role=role,
                total_rows=int(total),
                applicable_rows=int(applicable_rows),
                missing_pct_overall=missing_pct_overall,
                missing_pct_applicable=missing_pct_applicable,
                unique_count=int(unique_count),
                n_hosts=int(n_hosts or 0),
            )

            rows.append({
                "source_type": src,
                "field_name": field,
                "field_role": role,
                "raw_data_type": raw_data_type,
                "parsed_data_type": parsed_data_type,
                "total_rows": int(total),
                "applicable_object_types": appl_types_str,
                "applicable_rows": int(applicable_rows),
                "missing_percent": missing_pct_overall,
                "missing_percent_overall": missing_pct_overall,
                "missing_percent_applicable": missing_pct_applicable,
                "unique_count": int(unique_count),
                "top_3_values": top3[:300],
                "example_value": _safe_str(example, 120),
                "reliability_decision_keep_review_drop": decision,
                "reason": reason,
            })
    return rows


def compute_t4_from_cache(con) -> list:
    """T4 using aggregated DuckDB counts and bounded example IDs."""
    issues = []
    seq = [0]

    def add(issue_type, source, field, count, example_id, severity, decision):
        if count <= 0:
            return
        seq[0] += 1
        issues.append({
            "issue_id": f"ISSUE_{seq[0]:03d}",
            "issue_type": issue_type,
            "affected_file_or_source": source,
            "affected_field": field,
            "number_of_rows_affected": int(count),
            "example_raw_event_id": example_id or "",
            "severity_high_medium_low": severity,
            "handling_decision": decision,
        })

    n_err, ex_err = con.execute(
        """
        SELECT COUNT(*),
               COALESCE(MAX(CASE WHEN parse_status = 'json_parse_error'
                                 THEN raw_event_id END), '')
        FROM events WHERE parse_status = 'json_parse_error'
        """
    ).fetchone()
    add("json_parse_error", "cache", "parse_status", n_err, ex_err, "high",
        "skip malformed lines; investigate member encoding")

    n_no_ts, ex = con.execute(
        """
        SELECT COUNT(*), COALESCE(ANY_VALUE(raw_event_id), '')
        FROM events
        WHERE parse_status = 'ok'
          AND (timestamp_raw IS NULL OR CAST(timestamp_raw AS VARCHAR) = '')
        """
    ).fetchone()
    add("missing_timestamp", "cache", "timestamp_raw", n_no_ts, ex, "high",
        "review timestamp field mapping")

    n_ts_fail, ex = con.execute(
        """
        SELECT COUNT(*), COALESCE(ANY_VALUE(raw_event_id), '')
        FROM events
        WHERE parse_status = 'ok'
          AND timestamp_raw IS NOT NULL AND CAST(timestamp_raw AS VARCHAR) != ''
          AND (timestamp_parsed IS NULL OR CAST(timestamp_parsed AS VARCHAR) = '')
        """
    ).fetchone()
    add("timestamp_parse_failure", "cache", "timestamp_parsed", n_ts_fail, ex, "high",
        "attempt additional timestamp format conversions")

    n_no_host, ex = con.execute(
        """
        SELECT COUNT(*), COALESCE(ANY_VALUE(raw_event_id), '')
        FROM events
        WHERE parse_status = 'ok'
          AND (host_raw IS NULL OR CAST(host_raw AS VARCHAR) = '')
        """
    ).fetchone()
    add("missing_host", "cache", "host_raw", n_no_host, ex, "medium",
        "attempt inference from member_name")

    n_no_act, ex = con.execute(
        """
        SELECT COUNT(*), COALESCE(ANY_VALUE(raw_event_id), '')
        FROM events
        WHERE parse_status = 'ok'
          AND (action_raw IS NULL OR CAST(action_raw AS VARCHAR) = '')
        """
    ).fetchone()
    add("missing_action", "cache", "action_raw", n_no_act, ex, "low",
        "review action/eventType key candidates")

    return issues


def plot_f2_from_cache(con, out_dir: pathlib.Path, figures_dir: pathlib.Path,
                       pilot_label: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    df = con.execute(
        """
        SELECT date_trunc('hour', TRY_CAST(timestamp_parsed AS TIMESTAMP)) AS hour_bin,
               COUNT(*) AS n
        FROM events
        WHERE timestamp_parsed IS NOT NULL AND CAST(timestamp_parsed AS VARCHAR) != ''
        GROUP BY 1
        ORDER BY 1
        """
    ).fetchdf()
    df = df.dropna(subset=["hour_bin"])
    if df.empty:
        print("  [F2] No parseable timestamps — skipping.", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.bar(df["hour_bin"], df["n"], width=pd.Timedelta("1h") * 0.9, color="#4472C4")
    ax.set_xlabel("Time (UTC, binned by 1h)", fontsize=11)
    ax.set_ylabel("Event count", fontsize=11)
    total_n = int(df["n"].sum())
    ax.set_title(
        f"F2 — Timestamp Coverage {pilot_label}\n"
        f"(No ground-truth overlay  |  {total_n:,} parseable timestamps)",
        fontsize=11,
    )
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    _save_fig(fig, "F2_timestamp_coverage_plot", out_dir, figures_dir)
    plt.close(fig)


def run_eda02_cache_mode(args, project_root, out_dir, tables_dir, figures_dir) -> None:
    import pandas as pd
    from manifest_utils import load_manifest

    cache_dir = pathlib.Path(args.normalized_cache_dir)
    if not cache_dir.exists():
        print(f"[ERROR] normalized-cache-dir not found: {cache_dir}", file=sys.stderr)
        sys.exit(1)
    if not list(cache_dir.glob("*.parquet")):
        print(f"[ERROR] No parquet files in {cache_dir}", file=sys.stderr)
        sys.exit(1)

    # Conflict checks
    if args.archives or args.member_name_contains:
        print(
            "[ERROR] Cache mode uses the normalized cache built from the manifest. "
            "Do not pass --archives or --member-name-contains.",
            file=sys.stderr,
        )
        sys.exit(1)

    manifest_meta = {}
    if args.manifest_csv:
        mi = load_manifest(pathlib.Path(args.manifest_csv))
        manifest_meta = {
            "manifest_version": mi.manifest_version,
            "manifest_path": str(mi.path),
            "manifest_member_count": mi.member_count,
            "manifest_total_gib": mi.total_compressed_gib,
        }

    cache_meta = _load_cache_metadata(cache_dir)
    pilot_label = (
        f"[CACHE MODE: manifest={manifest_meta.get('manifest_version', 'unknown')}; "
        f"events={cache_meta.get('total_events_written', '?')}]"
    )

    print(f"\n{'='*60}")
    print(f"EDA 2 — Schema and Data-Quality Audit  {pilot_label}")
    print(f"  cache-dir     : {cache_dir}")
    print(f"  manifest-csv  : {args.manifest_csv}")
    print(f"  output-dir    : {out_dir}")
    print(f"{'='*60}\n")

    con = _duck_conn(cache_dir)
    n_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"[INFO] Events in cache (DuckDB view): {n_events:,}")

    print("\nComputing T3 from cache ...")
    t3_rows = compute_t3_from_cache(con)
    t3_df = pd.DataFrame(t3_rows)
    if not t3_df.empty:
        t3_df = t3_df.reindex(columns=T3_COLUMNS)
    else:
        t3_df = pd.DataFrame(columns=T3_COLUMNS)
    _save_csv(t3_df, out_dir / "T3_field_reliability_audit.csv",
              tables_dir / "T3_field_reliability_audit.csv")

    print("\nComputing T4 from cache ...")
    t4_rows = compute_t4_from_cache(con)
    t4_df = pd.DataFrame(t4_rows) if t4_rows else pd.DataFrame(columns=[
        "issue_id", "issue_type", "affected_file_or_source", "affected_field",
        "number_of_rows_affected", "example_raw_event_id",
        "severity_high_medium_low", "handling_decision",
    ])
    _save_csv(t4_df, out_dir / "T4_data_quality_issue_log.csv",
              tables_dir / "T4_data_quality_issue_log.csv")

    print("\nGenerating F2 from cache ...")
    plot_f2_from_cache(con, out_dir, figures_dir, pilot_label)

    # README with cache/manifest metadata
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "EDA 2 — Schema and Data-Quality Audit (CACHE MODE)",
        "=" * 50,
        f"Generated (UTC): {now}",
        f"Pilot label    : {pilot_label}",
        "",
        "Mode: normalized Parquet cache via DuckDB (not full in-memory event list).",
        "No attack / benign / MITRE claims. No ground-truth overlays.",
        "",
        "Manifest",
        "--------",
        f"  path             : {manifest_meta.get('manifest_path', args.manifest_csv)}",
        f"  version          : {manifest_meta.get('manifest_version', 'n/a')}",
        f"  member count     : {manifest_meta.get('manifest_member_count', 'n/a')}",
        f"  compressed GiB   : {manifest_meta.get('manifest_total_gib', 'n/a')}",
        "",
        "Cache metadata",
        "--------------",
        f"  cache-dir        : {cache_dir}",
        f"  events written   : {cache_meta.get('total_events_written', n_events)}",
        f"  chunks           : {cache_meta.get('chunks_written', 'n/a')}",
        f"  max-events cap   : {cache_meta.get('max_events_safety_cap', 'n/a')}",
        f"  include_raw_json : {cache_meta.get('include_raw_json', False)}",
        f"  timestamp rule   : {cache_meta.get('timestamp_conversion_rule', 'n/a')}",
        "",
        f"T3 rows: {len(t3_rows)}   T4 issues: {len(t4_rows)}",
        "",
        "T3 notes (schema v2)",
        "--------------------",
        "  Audits every SLIM_EVENT_COLUMNS field with field_role and",
        "  overall + applicable missingness. Object-specific decisions use",
        "  applicable object rows. Absent applicable types → review/not assessable.",
        "  host_raw is not dropped for single-host constancy. Diagnostic fields",
        "  (parse_error, etc.) are retained when empty by design.",
        "  Decisions from capped/single-host samples are PRELIMINARY.",
    ]
    (out_dir / "README_eda02_schema_quality.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"  [README] {out_dir / 'README_eda02_schema_quality.txt'}")
    con.close()

    print(f"\n{'='*60}")
    print(f"EDA 2 COMPLETE  {pilot_label}")
    print(f"  Events (cache) : {n_events:,}")
    print(f"  T3 rows        : {len(t3_rows)}")
    print(f"  T4 issues      : {len(t4_rows)}")
    print(f"{'='*60}")


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    import pandas as pd

    args = parse_args()
    project_root = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()

    if args.output_dir:
        out_dir = pathlib.Path(args.output_dir)
    else:
        out_dir = project_root / "outputs" / "eda_02_schema"
    tables_dir = project_root / "outputs" / "tables"
    figures_dir = project_root / "outputs" / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    # ── Cache mode ────────────────────────────────────────────────────
    if args.normalized_cache_dir:
        run_eda02_cache_mode(args, project_root, out_dir, tables_dir, figures_dir)
        return

    # ── Legacy capped archive mode ────────────────────────────────────
    if not args.corrected_dir:
        print("[ERROR] --corrected-dir is required for legacy mode "
              "(or pass --normalized-cache-dir for cache mode).", file=sys.stderr)
        sys.exit(1)
    if args.manifest_csv and not args.normalized_cache_dir:
        print("[ERROR] --manifest-csv without --normalized-cache-dir is not supported.\n"
              "  Build the cache first with build_normalized_pilot_cache.py, "
              "then pass --normalized-cache-dir.", file=sys.stderr)
        sys.exit(1)

    corrected_dir = pathlib.Path(args.corrected_dir)
    if not corrected_dir.exists():
        print(f"[ERROR] corrected-dir not found: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

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

    is_pilot = (args.max_members is not None) or (args.max_events is not None)
    pilot_label = (
        f"[PILOT SAMPLE: max_members={args.max_members}, "
        f"max_events={args.max_events}, "
        f"max_events_per_member={args.max_events_per_member}]"
        if is_pilot else "[FULL RUN]"
    )
    print(f"\n{'='*60}")
    print(f"EDA 2 — Schema and Data-Quality Audit  {pilot_label}")
    print(f"  corrected-dir : {corrected_dir}")
    print(f"  archives      : {[p.name for p in archive_paths]}")
    print(f"  output-dir    : {out_dir}")
    print(f"{'='*60}\n")

    print("Streaming events ...")
    events = list(stream_from_archives(
        archive_paths,
        max_members=args.max_members,
        max_events=args.max_events,
        max_events_per_member=args.max_events_per_member,
        member_name_contains=args.member_name_contains,
        quiet=False,
    ))

    print(f"\n[INFO] {len(events):,} events collected.")
    _stats, _summary_text = _collection_summary(events, args.max_members)

    if not events:
        print("[WARN] No events parsed — T3/T4/F2 will be empty.", file=sys.stderr)

    print("\nComputing T3 field reliability audit ...")
    source_types = sorted({e.get("source_type", "unknown") for e in events})
    t3_rows = compute_t3(events, source_types)
    t3_df = pd.DataFrame(t3_rows) if t3_rows else pd.DataFrame(columns=T3_COLUMNS)
    if not t3_df.empty:
        t3_df = t3_df.reindex(columns=T3_COLUMNS)
    _save_csv(t3_df,
              out_dir / "T3_field_reliability_audit.csv",
              tables_dir / "T3_field_reliability_audit.csv")

    print("\nComputing T4 data quality issues ...")
    t4_rows_data = compute_t4(events)
    t4_df = pd.DataFrame(t4_rows_data) if t4_rows_data else pd.DataFrame(columns=[
        "issue_id", "issue_type", "affected_file_or_source", "affected_field",
        "number_of_rows_affected", "example_raw_event_id",
        "severity_high_medium_low", "handling_decision",
    ])
    _save_csv(t4_df,
              out_dir / "T4_data_quality_issue_log.csv",
              tables_dir / "T4_data_quality_issue_log.csv")

    print("\nGenerating F2 timestamp coverage plot ...")
    plot_f2(events, out_dir, figures_dir, pilot_label)

    write_readme(
        out_dir, args,
        n_events=len(events),
        n_members_approx=_stats["n_members"],
        t3_rows=len(t3_rows),
        t4_rows=len(t4_rows_data),
        pilot_label=pilot_label,
        member_summary=_summary_text,
    )

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
