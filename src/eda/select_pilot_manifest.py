"""
Pilot-Subset Stage 2 — Deterministic 10 GiB Manifest Selection (DARPA OpTC)
==========================================================================
Selects a reproducible, endpoint-focused pilot subset of approximately
9–10 GiB from T0_member_inventory.csv.

This script does NOT extract archives.  It only selects member paths
from the inventory CSV.  No attack / benign / malicious / MITRE /
ground-truth labels are assigned.

Outputs
-------
configs/pilot_manifest_10gb.csv
outputs/pilot_selection/T0_pilot_manifest_summary_by_date.csv
outputs/pilot_selection/T0_pilot_manifest_summary_by_host.csv
outputs/pilot_selection/T0_pilot_manifest_validation.csv
outputs/pilot_selection/F0_pilot_manifest_size_by_date.png
outputs/pilot_selection/README_pilot_manifest_10gb.txt

Usage
-----
python3 src/eda/select_pilot_manifest.py \\
    --project-root /content/DARPA_OPTC_EDA_REPO \\
    --inventory-csv outputs/pilot_selection/T0_member_inventory.csv \\
    --target-size-gib 9.5 \\
    --random-seed 42
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import pathlib
import sys

import pandas as pd

MANIFEST_VERSION = "pilot_manifest_10gb_v1"
MANIFEST_COLUMNS = [
    "selection_id",
    "archive_date",
    "archive_filename",
    "member_name",
    "inferred_host_or_client",
    "inferred_source_type",
    "member_size_bytes",
    "member_size_gib",
    "sampled_earliest_timestamp",
    "sampled_latest_timestamp",
    "selection_reason",
    "manifest_version",
]


# ── Helpers ───────────────────────────────────────────────────────────────

def _is_missing(val) -> bool:
    if val is None:
        return True
    try:
        if pd.isna(val):
            return True
    except (TypeError, ValueError):
        pass
    return str(val).strip() == ""


def _stable_rank_key(seed: int, *parts) -> str:
    """Deterministic tie-breaker string from seed + identifying parts."""
    payload = "|".join([str(seed)] + [str(p) for p in parts])
    return hashlib.md5(payload.encode("utf-8")).hexdigest()


def _pct(part: float, total: float) -> float:
    return round(100.0 * part / total, 2) if total > 0 else 0.0


# ── Eligibility filter ────────────────────────────────────────────────────

def filter_eligible(df: pd.DataFrame) -> pd.DataFrame:
    """Apply the hard quality gates for pilot selection."""
    out = df.copy()

    # Normalize string columns
    for col in ("readable_yes_no", "sample_parse_status", "member_name",
                "inferred_host_or_client", "inferred_source_type",
                "archive_date", "archive_filename"):
        if col in out.columns:
            out[col] = out[col].astype(str)

    name_ok = out["member_name"].str.endswith(".json.gz")
    readable = out["readable_yes_no"].str.lower() == "yes"
    status_ok = out["sample_parse_status"] == "sample_ok"
    valid_lines = pd.to_numeric(out["sampled_valid_json_lines"], errors="coerce").fillna(0) > 0
    invalid_zero = pd.to_numeric(out["sampled_invalid_json_lines"], errors="coerce").fillna(-1) == 0
    has_earliest = ~out["sampled_earliest_timestamp"].map(_is_missing)
    has_latest = ~out["sampled_latest_timestamp"].map(_is_missing)

    eligible = out[
        name_ok & readable & status_ok & valid_lines & invalid_zero & has_earliest & has_latest
    ].copy()

    eligible["member_size_gib"] = pd.to_numeric(eligible["member_size_gib"], errors="coerce").fillna(0.0)
    eligible["member_size_bytes"] = pd.to_numeric(
        eligible["member_size_bytes"], errors="coerce"
    ).fillna(0).astype(int)
    eligible["inferred_host_or_client"] = eligible["inferred_host_or_client"].fillna("unknown")
    eligible = eligible[eligible["inferred_host_or_client"].str.lower() != "unknown"]
    eligible = eligible.reset_index(drop=True)
    return eligible


# ── Host ranking ──────────────────────────────────────────────────────────

def rank_hosts(eligible: pd.DataFrame, seed: int) -> pd.DataFrame:
    """
    Rank hosts by date coverage (desc), then total size (desc), then
    stable hash tie-breaker.  Endpoint members are preferred for ranking
    weight but date coverage uses all eligible members for that host.
    """
    if eligible.empty:
        return pd.DataFrame(columns=[
            "inferred_host_or_client", "n_dates", "n_members",
            "total_size_gib", "endpoint_size_gib", "tie_key",
        ])

    rows = []
    for host, g in eligible.groupby("inferred_host_or_client"):
        ep = g[g["inferred_source_type"] == "endpoint"]
        rows.append({
            "inferred_host_or_client": host,
            "n_dates": int(g["archive_date"].nunique()),
            "n_members": int(len(g)),
            "total_size_gib": float(g["member_size_gib"].sum()),
            "endpoint_size_gib": float(ep["member_size_gib"].sum()) if not ep.empty else 0.0,
            "tie_key": _stable_rank_key(seed, "host", host),
        })
    ranked = pd.DataFrame(rows)
    ranked = ranked.sort_values(
        by=["n_dates", "endpoint_size_gib", "total_size_gib", "tie_key"],
        ascending=[False, False, False, True],
    ).reset_index(drop=True)
    return ranked


def select_preferred_hosts(
    ranked: pd.DataFrame,
    preferred_host_count: int,
    all_dates: list,
    seed: int,
) -> list:
    """
    Prefer hosts present on all dates; then fill remaining slots from
    highest-coverage hosts.  Seed is already baked into ranked.tie_key.
    """
    if ranked.empty:
        return []

    _ = seed  # retained for API stability; ranking already uses it
    n_dates_total = len(all_dates)
    full_cover = ranked[ranked["n_dates"] >= n_dates_total]
    selected = list(full_cover["inferred_host_or_client"].head(preferred_host_count))

    if len(selected) < preferred_host_count:
        remaining = ranked[~ranked["inferred_host_or_client"].isin(selected)]
        need = preferred_host_count - len(selected)
        selected.extend(list(remaining["inferred_host_or_client"].head(need)))
    return selected


# ── Member selection (deterministic greedy) ───────────────────────────────

def _current_shares(selected: pd.DataFrame) -> tuple:
    total = float(selected["member_size_gib"].sum()) if not selected.empty else 0.0
    by_date = (
        selected.groupby("archive_date")["member_size_gib"].sum().to_dict()
        if not selected.empty else {}
    )
    by_host = (
        selected.groupby("inferred_host_or_client")["member_size_gib"].sum().to_dict()
        if not selected.empty else {}
    )
    return total, by_date, by_host


def _can_add(
    member: pd.Series,
    total: float,
    by_date: dict,
    by_host: dict,
    maximum_size_gib: float,
    max_date_share: float = 0.20,
    max_host_share: float = 0.25,
) -> bool:
    size = float(member["member_size_gib"])
    new_total = total + size
    if new_total > maximum_size_gib + 1e-9:
        return False

    # Soft share caps: enforce only once we have enough mass to make shares meaningful
    if new_total >= 1.0:
        date = member["archive_date"]
        host = member["inferred_host_or_client"]
        date_share = (by_date.get(date, 0.0) + size) / new_total
        host_share = (by_host.get(host, 0.0) + size) / new_total
        if date_share > max_date_share + 1e-9:
            return False
        if host_share > max_host_share + 1e-9:
            return False
    return True


def select_members(
    eligible: pd.DataFrame,
    preferred_hosts: list,
    all_dates: list,
    target_size_gib: float,
    minimum_size_gib: float,
    maximum_size_gib: float,
    seed: int,
) -> pd.DataFrame:
    """
    Deterministic multi-pass selection:

    Pass A — Coverage floor:
        For each preferred host × date with eligible endpoint members,
        pick the median-sized member (stable tie-break) to anchor continuity.

    Pass B — Endpoint fill:
        Greedy add remaining preferred-host endpoint members, preferring
        under-represented dates/hosts and sizes that approach the target.

    Pass C — Size recovery (if below minimum):
        Allow non-endpoint eligible members from preferred hosts, then
        (last resort) high-coverage non-preferred hosts — still no labels.
    """
    if eligible.empty or not preferred_hosts:
        return pd.DataFrame(columns=eligible.columns)

    preferred_set = set(preferred_hosts)

    # Work primarily on endpoint members of preferred hosts
    core = eligible[
        (eligible["inferred_host_or_client"].isin(preferred_set))
        & (eligible["inferred_source_type"] == "endpoint")
    ].copy()

    # Stable sort key for every candidate
    core["_tie"] = core.apply(
        lambda r: _stable_rank_key(seed, r["archive_filename"], r["member_name"]),
        axis=1,
    )
    selected_keys: set = set()
    selected_rows: list = []

    def _key(row) -> str:
        return f"{row['archive_filename']}::{row['member_name']}"

    def _add(row, reason: str) -> bool:
        k = _key(row)
        if k in selected_keys:
            return False
        cur = pd.DataFrame(selected_rows) if selected_rows else pd.DataFrame(columns=core.columns)
        total, by_date, by_host = _current_shares(cur)
        if not _can_add(row, total, by_date, by_host, maximum_size_gib):
            return False
        r = row.copy()
        r["selection_reason"] = reason
        selected_rows.append(r)
        selected_keys.add(k)
        return True

    # ── Pass A: one member per (host, date) for continuity ────────────
    for host in preferred_hosts:
        for date in sorted(all_dates):
            pool = core[
                (core["inferred_host_or_client"] == host)
                & (core["archive_date"] == date)
            ]
            if pool.empty:
                continue
            # Prefer median size (continuity without dumping huge members early)
            pool = pool.sort_values(["member_size_gib", "_tie"])
            mid = pool.iloc[len(pool) // 2]
            _add(mid, "coverage_floor_preferred_host_date")

    # ── Pass B: greedy endpoint fill toward target ────────────────────
    remaining = core[~core.apply(_key, axis=1).isin(selected_keys)].copy()
    rem_list = remaining.to_dict("records")

    def _urgency_score_dict(row: dict, total: float, by_date: dict, by_host: dict) -> tuple:
        """Lower is better. Prefer underfilled dates/hosts; avoid overshoot."""
        date = row["archive_date"]
        host = row["inferred_host_or_client"]
        size = float(row["member_size_gib"])
        new_total = total + size
        date_share = (by_date.get(date, 0.0) + size) / max(new_total, 1e-9)
        host_share = (by_host.get(host, 0.0) + size) / max(new_total, 1e-9)
        overshoot = max(0.0, new_total - target_size_gib)
        undershoot = max(0.0, target_size_gib - new_total)
        return (
            overshoot,
            date_share,
            host_share,
            by_date.get(date, 0.0),
            by_host.get(host, 0.0),
            undershoot,
            row["_tie"],
        )

    # Maintain running totals so we do not rebuild a DataFrame each pick
    total = float(sum(r["member_size_gib"] for r in selected_rows))
    by_date = {}
    by_host = {}
    for r in selected_rows:
        by_date[r["archive_date"]] = by_date.get(r["archive_date"], 0.0) + float(r["member_size_gib"])
        by_host[r["inferred_host_or_client"]] = (
            by_host.get(r["inferred_host_or_client"], 0.0) + float(r["member_size_gib"])
        )

    for _ in range(len(rem_list) + 1):
        if total >= target_size_gib:
            break
        best_i = None
        best_score = None
        for i, row in enumerate(rem_list):
            k = f"{row['archive_filename']}::{row['member_name']}"
            if k in selected_keys:
                continue
            ser = pd.Series(row)
            if not _can_add(ser, total, by_date, by_host, maximum_size_gib):
                continue
            score = _urgency_score_dict(row, total, by_date, by_host)
            if best_score is None or score < best_score:
                best_score = score
                best_i = i
        if best_i is None:
            break
        best = rem_list[best_i]
        if _add(pd.Series(best), "greedy_endpoint_fill_preferred_host"):
            size = float(best["member_size_gib"])
            total += size
            by_date[best["archive_date"]] = by_date.get(best["archive_date"], 0.0) + size
            by_host[best["inferred_host_or_client"]] = (
                by_host.get(best["inferred_host_or_client"], 0.0) + size
            )

    # ── Pass C: size recovery if below minimum ────────────────────────
    cur = pd.DataFrame(selected_rows) if selected_rows else pd.DataFrame(columns=core.columns)
    total, _, _ = _current_shares(cur)

    if total < minimum_size_gib:
        # C1: non-endpoint members from preferred hosts
        extra = eligible[
            (eligible["inferred_host_or_client"].isin(preferred_set))
            & (eligible["inferred_source_type"] != "endpoint")
        ].copy()
        extra["_tie"] = extra.apply(
            lambda r: _stable_rank_key(seed, r["archive_filename"], r["member_name"]),
            axis=1,
        )
        extra = extra.sort_values(["member_size_gib", "_tie"])
        for _, row in extra.iterrows():
            cur = pd.DataFrame(selected_rows)
            total, by_date, by_host = _current_shares(cur)
            if total >= minimum_size_gib:
                break
            if _can_add(row, total, by_date, by_host, maximum_size_gib):
                _add(row, "size_recovery_preferred_host_non_endpoint")

    cur = pd.DataFrame(selected_rows) if selected_rows else pd.DataFrame(columns=core.columns)
    total, _, _ = _current_shares(cur)

    if total < minimum_size_gib:
        # C2: last resort — other high-coverage hosts (endpoint only)
        other_hosts = [
            h for h in rank_hosts(eligible, seed)["inferred_host_or_client"].tolist()
            if h not in preferred_set
        ]
        for host in other_hosts:
            if total >= minimum_size_gib:
                break
            pool = eligible[
                (eligible["inferred_host_or_client"] == host)
                & (eligible["inferred_source_type"] == "endpoint")
            ].copy()
            pool["_tie"] = pool.apply(
                lambda r: _stable_rank_key(seed, r["archive_filename"], r["member_name"]),
                axis=1,
            )
            pool = pool.sort_values(["archive_date", "member_size_gib", "_tie"])
            for _, row in pool.iterrows():
                cur = pd.DataFrame(selected_rows)
                total, by_date, by_host = _current_shares(cur)
                if total >= minimum_size_gib:
                    break
                # Slightly relax date share in recovery to allow finishing
                if _can_add(row, total, by_date, by_host, maximum_size_gib,
                            max_date_share=0.22, max_host_share=0.25):
                    _add(row, "size_recovery_additional_host_endpoint")

    if not selected_rows:
        return pd.DataFrame(columns=list(eligible.columns) + ["selection_reason"])

    result = pd.DataFrame(selected_rows)
    # Drop helper cols if present
    drop_cols = [c for c in result.columns if c.startswith("_")]
    return result.drop(columns=drop_cols, errors="ignore")


# ── Manifest assembly ─────────────────────────────────────────────────────

def build_manifest(selected: pd.DataFrame) -> pd.DataFrame:
    if selected.empty:
        return pd.DataFrame(columns=MANIFEST_COLUMNS)

    rows = []
    selected = selected.sort_values(
        ["archive_date", "inferred_host_or_client", "member_name"]
    ).reset_index(drop=True)

    for i, row in selected.iterrows():
        rows.append({
            "selection_id": f"P10_{i+1:05d}",
            "archive_date": row["archive_date"],
            "archive_filename": row["archive_filename"],
            "member_name": row["member_name"],
            "inferred_host_or_client": row["inferred_host_or_client"],
            "inferred_source_type": row["inferred_source_type"],
            "member_size_bytes": int(row["member_size_bytes"]),
            "member_size_gib": round(float(row["member_size_gib"]), 6),
            "sampled_earliest_timestamp": row["sampled_earliest_timestamp"],
            "sampled_latest_timestamp": row["sampled_latest_timestamp"],
            "selection_reason": row.get("selection_reason", "selected"),
            "manifest_version": MANIFEST_VERSION,
        })
    return pd.DataFrame(rows, columns=MANIFEST_COLUMNS)


# ── Summaries & validation ────────────────────────────────────────────────

def summary_by_date(manifest: pd.DataFrame) -> pd.DataFrame:
    if manifest.empty:
        return pd.DataFrame(columns=[
            "archive_date", "member_count", "total_size_gib", "size_share_percent",
            "n_hosts", "n_source_types",
        ])
    total = float(manifest["member_size_gib"].sum())
    g = manifest.groupby("archive_date", as_index=False).agg(
        member_count=("member_name", "count"),
        total_size_gib=("member_size_gib", "sum"),
        n_hosts=("inferred_host_or_client", "nunique"),
        n_source_types=("inferred_source_type", "nunique"),
    )
    g["total_size_gib"] = g["total_size_gib"].round(4)
    g["size_share_percent"] = g["total_size_gib"].apply(lambda x: _pct(x, total))
    return g.sort_values("archive_date")


def summary_by_host(manifest: pd.DataFrame) -> pd.DataFrame:
    if manifest.empty:
        return pd.DataFrame(columns=[
            "inferred_host_or_client", "member_count", "total_size_gib",
            "size_share_percent", "n_dates", "dates_list",
        ])
    total = float(manifest["member_size_gib"].sum())
    rows = []
    for host, g in manifest.groupby("inferred_host_or_client"):
        dates = sorted(g["archive_date"].unique().tolist())
        size = float(g["member_size_gib"].sum())
        rows.append({
            "inferred_host_or_client": host,
            "member_count": int(len(g)),
            "total_size_gib": round(size, 4),
            "size_share_percent": _pct(size, total),
            "n_dates": len(dates),
            "dates_list": ";".join(dates),
        })
    return pd.DataFrame(rows).sort_values(
        ["n_dates", "total_size_gib"], ascending=[False, False]
    )


def build_validation(
    manifest: pd.DataFrame,
    eligible: pd.DataFrame,
    all_dates: list,
    minimum_size_gib: float,
    maximum_size_gib: float,
    preferred_hosts: list,
) -> pd.DataFrame:
    total = float(manifest["member_size_gib"].sum()) if not manifest.empty else 0.0
    dates_present = sorted(manifest["archive_date"].unique().tolist()) if not manifest.empty else []
    missing_dates = [d for d in all_dates if d not in dates_present]

    # Join back to inventory quality fields via keys
    if not manifest.empty and not eligible.empty:
        key_cols = ["archive_filename", "member_name"]
        merged = manifest.merge(
            eligible[key_cols + [
                "readable_yes_no", "sample_parse_status",
                "sampled_valid_json_lines", "sampled_invalid_json_lines",
                "sampled_earliest_timestamp", "sampled_latest_timestamp",
            ]],
            on=key_cols, how="left", suffixes=("", "_inv"),
        )
        all_readable = bool((merged["readable_yes_no"].astype(str).str.lower() == "yes").all())
        all_sample_ok = bool((merged["sample_parse_status"] == "sample_ok").all())
        all_valid_json = bool((pd.to_numeric(merged["sampled_valid_json_lines"], errors="coerce") > 0).all())
        all_invalid_zero = bool((pd.to_numeric(merged["sampled_invalid_json_lines"], errors="coerce") == 0).all())
        all_have_ts = bool(
            (~merged["sampled_earliest_timestamp"].map(_is_missing)).all()
            and (~merged["sampled_latest_timestamp"].map(_is_missing)).all()
        )
    else:
        all_readable = all_sample_ok = all_valid_json = all_invalid_zero = all_have_ts = False

    dup_count = 0
    if not manifest.empty:
        dup_count = int(
            manifest.duplicated(subset=["archive_filename", "member_name"]).sum()
        )

    date_sum = summary_by_date(manifest)
    host_sum = summary_by_host(manifest)
    max_date_share = float(date_sum["size_share_percent"].max()) if not date_sum.empty else 0.0
    max_host_share = float(host_sum["size_share_percent"].max()) if not host_sum.empty else 0.0

    n_hosts = int(manifest["inferred_host_or_client"].nunique()) if not manifest.empty else 0
    hosts_all_dates = 0
    if not host_sum.empty and all_dates:
        hosts_all_dates = int((host_sum["n_dates"] >= len(all_dates)).sum())

    # Repeated hosts = hosts appearing on >= 2 dates
    repeated_hosts = int((host_sum["n_dates"] >= 2).sum()) if not host_sum.empty else 0

    checks = [
        ("total_size_gib", round(total, 4),
         "pass" if minimum_size_gib <= total <= maximum_size_gib else "fail",
         f"must be in [{minimum_size_gib}, {maximum_size_gib}] GiB"),
        ("all_inventory_dates_represented",
         f"{len(dates_present)}/{len(all_dates)}; missing={missing_dates or 'none'}",
         "pass" if not missing_dates and len(all_dates) > 0 else "fail",
         "every archive_date in eligible inventory must appear"),
        ("selected_members_readable", str(all_readable),
         "pass" if all_readable else "fail",
         "readable_yes_no must be yes"),
        ("selected_members_valid_sampled_json", str(all_valid_json and all_sample_ok and all_invalid_zero),
         "pass" if (all_valid_json and all_sample_ok and all_invalid_zero) else "fail",
         "sample_ok with valid JSON lines and zero invalid lines"),
        ("selected_members_have_sampled_timestamps", str(all_have_ts),
         "pass" if all_have_ts else "fail",
         "sampled_earliest_timestamp and sampled_latest_timestamp required"),
        ("no_duplicate_archive_member", str(dup_count == 0),
         "pass" if dup_count == 0 else "fail",
         f"duplicate rows: {dup_count}"),
        ("maximum_date_size_share_percent", max_date_share,
         "pass" if max_date_share <= 20.0 + 1e-6 else "fail",
         "no date may exceed 20% of selected size"),
        ("maximum_host_size_share_percent", max_host_share,
         "pass" if max_host_share <= 25.0 + 1e-6 else "fail",
         "no host may exceed 25% of selected size"),
        ("number_of_selected_hosts", n_hosts, "info",
         f"preferred_hosts={preferred_hosts}"),
        ("number_of_repeated_hosts", repeated_hosts, "info",
         "hosts present on >= 2 dates"),
        ("number_of_hosts_present_across_all_dates", hosts_all_dates, "info",
         f"hosts covering all {len(all_dates)} inventory dates"),
        ("member_count", int(len(manifest)), "info", ""),
        ("manifest_version", MANIFEST_VERSION, "info", ""),
    ]

    return pd.DataFrame(checks, columns=["check_name", "observed_value", "status", "criterion"])


# ── Figure ────────────────────────────────────────────────────────────────

def plot_size_by_date(date_summary: pd.DataFrame, out_path: pathlib.Path,
                      total_gib: float) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if date_summary.empty:
        print("  [F0] No data — skipping figure.", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(date_summary["archive_date"], date_summary["total_size_gib"],
           color="#4472C4", width=0.7)
    ax.axhline(y=0.20 * total_gib, color="#C00000", linestyle="--", linewidth=1.2,
               label=f"20% share cap ({0.20 * total_gib:.2f} GiB)")
    ax.set_xlabel("Archive date", fontsize=11)
    ax.set_ylabel("Selected member size (GiB)", fontsize=11)
    ax.set_title(
        f"F0 — Pilot Manifest Size by Archive Date  (total={total_gib:.2f} GiB)\n"
        "[No ground-truth overlay | no attack/benign labels]",
        fontsize=10,
    )
    ax.legend(fontsize=9)
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"  [FIG] {out_path}")


# ── README ────────────────────────────────────────────────────────────────

def write_readme(
    out_dir: pathlib.Path,
    args: argparse.Namespace,
    manifest: pd.DataFrame,
    preferred_hosts: list,
    validation: pd.DataFrame,
    all_dates: list,
    n_eligible: int,
) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total = float(manifest["member_size_gib"].sum()) if not manifest.empty else 0.0
    n_pass = int((validation["status"] == "pass").sum()) if not validation.empty else 0
    n_fail = int((validation["status"] == "fail").sum()) if not validation.empty else 0

    lines = [
        "Pilot-Subset Stage 2 — Deterministic 10 GiB Manifest",
        "=" * 55,
        f"Generated (UTC)   : {now}",
        f"Manifest version  : {MANIFEST_VERSION}",
        f"Random seed       : {args.random_seed}  (tie-breaker only)",
        "",
        "Purpose",
        "-------",
        "Select a reproducible endpoint-focused pilot subset of approximately",
        "9–10 GiB from T0_member_inventory.csv for later streaming analysis.",
        "This script does NOT extract archives and does NOT assign attack,",
        "benign, malicious, MITRE, or ground-truth labels.",
        "",
        "Eligibility gates (from inventory)",
        "---------------------------------",
        "  * member_name ends with .json.gz",
        "  * readable_yes_no = yes",
        "  * sample_parse_status = sample_ok",
        "  * sampled_valid_json_lines > 0",
        "  * sampled_invalid_json_lines = 0",
        "  * sampled_earliest_timestamp and sampled_latest_timestamp present",
        "  * inferred_host_or_client != unknown",
        "",
        "Selection algorithm",
        "-------------------",
        "  1. Rank hosts by number of archive dates covered (prefer all dates),",
        "     then endpoint size, then total size; MD5(seed|host) breaks ties.",
        f"  2. Select up to {args.preferred_host_count} preferred hosts.",
        "  3. Pass A — coverage floor: one endpoint member per preferred",
        "     (host, date) for temporal continuity.",
        "  4. Pass B — greedy endpoint fill toward target size while enforcing",
        "     date share ≤ 20% and host share ≤ 25%.",
        "  5. Pass C — size recovery only if below minimum: preferred-host",
        "     non-endpoint members, then additional high-coverage hosts.",
        "",
        "Run parameters",
        "--------------",
        f"  inventory-csv       : {args.inventory_csv}",
        f"  target-size-gib     : {args.target_size_gib}",
        f"  minimum-size-gib    : {args.minimum_size_gib}",
        f"  maximum-size-gib    : {args.maximum_size_gib}",
        f"  minimum-dates       : {args.minimum_dates}",
        f"  preferred-host-count: {args.preferred_host_count}",
        f"  random-seed         : {args.random_seed}",
        "",
        "Results",
        "-------",
        f"  eligible inventory members : {n_eligible:,}",
        f"  inventory dates            : {len(all_dates)} → {all_dates}",
        f"  preferred hosts            : {preferred_hosts}",
        f"  selected members           : {len(manifest):,}",
        f"  selected total size        : {total:.4f} GiB",
        f"  validation pass / fail     : {n_pass} / {n_fail}",
        "",
        "Outputs",
        "-------",
        "  configs/pilot_manifest_10gb.csv",
        "  outputs/pilot_selection/T0_pilot_manifest_summary_by_date.csv",
        "  outputs/pilot_selection/T0_pilot_manifest_summary_by_host.csv",
        "  outputs/pilot_selection/T0_pilot_manifest_validation.csv",
        "  outputs/pilot_selection/F0_pilot_manifest_size_by_date.png",
        "  outputs/pilot_selection/README_pilot_manifest_10gb.txt",
        "",
        "Command example",
        "---------------",
        "  python3 src/eda/select_pilot_manifest.py \\",
        "      --project-root /content/DARPA_OPTC_EDA_REPO \\",
        "      --inventory-csv outputs/pilot_selection/T0_member_inventory.csv \\",
        "      --target-size-gib 9.5 \\",
        "      --random-seed 42",
        "",
        "Important limitations",
        "---------------------",
        "  * Selection operates on inventory metadata only; no data is extracted.",
        "  * Timestamps used for eligibility are sample-based (first N lines).",
        "  * Member sizes are stored/compressed .json.gz sizes from tar headers.",
        "  * If the eligible inventory is smaller than the minimum target, the",
        "    manifest will reflect what is available and validation will fail",
        "    the size check — re-run inventory on more archives first.",
        "  * No attack / benign / MITRE / ground-truth claims are made.",
    ]
    path = out_dir / "README_pilot_manifest_10gb.txt"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [README] {path}")


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Select a deterministic ~10 GiB OpTC pilot manifest from T0 inventory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--project-root", default=None,
                   help="Project root (default: cwd)")
    p.add_argument("--inventory-csv", required=True,
                   help="Path to T0_member_inventory.csv")
    p.add_argument("--target-size-gib", type=float, default=9.5)
    p.add_argument("--minimum-size-gib", type=float, default=9.0)
    p.add_argument("--maximum-size-gib", type=float, default=10.0)
    p.add_argument("--minimum-dates", type=int, default=10,
                   help="Expected minimum number of archive dates (warn if fewer)")
    p.add_argument("--preferred-host-count", type=int, default=6)
    p.add_argument("--output-dir", default=None,
                   help="Output dir (default: <project-root>/outputs/pilot_selection)")
    p.add_argument("--random-seed", type=int, default=42,
                   help="Deterministic tie-breaker seed (default: 42)")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    project_root = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()
    inventory_csv = pathlib.Path(args.inventory_csv)
    if not inventory_csv.is_absolute():
        inventory_csv = project_root / inventory_csv
    if not inventory_csv.exists():
        print(f"[ERROR] Inventory CSV not found: {inventory_csv}", file=sys.stderr)
        sys.exit(1)

    out_dir = (pathlib.Path(args.output_dir) if args.output_dir
               else project_root / "outputs" / "pilot_selection")
    out_dir.mkdir(parents=True, exist_ok=True)
    configs_dir = project_root / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print("Pilot-Subset Stage 2 — Deterministic 10 GiB Manifest")
    print(f"  inventory-csv : {inventory_csv}")
    print(f"  target size   : {args.target_size_gib} GiB "
          f"[{args.minimum_size_gib}, {args.maximum_size_gib}]")
    print(f"  preferred hosts: {args.preferred_host_count}")
    print(f"  random-seed   : {args.random_seed}")
    print(f"  output-dir    : {out_dir}")
    print(f"{'='*60}\n")

    inv = pd.read_csv(inventory_csv)
    print(f"[INFO] Inventory rows loaded: {len(inv):,}")

    eligible = filter_eligible(inv)
    print(f"[INFO] Eligible members after quality gates: {len(eligible):,}")
    if eligible.empty:
        print("[ERROR] No eligible members. Re-run member inventory with sampling.",
              file=sys.stderr)
        sys.exit(1)

    all_dates = sorted(eligible["archive_date"].unique().tolist())
    print(f"[INFO] Eligible archive dates ({len(all_dates)}): {all_dates}")
    if len(all_dates) < args.minimum_dates:
        print(
            f"[WARN] Only {len(all_dates)} dates available "
            f"(--minimum-dates={args.minimum_dates}). "
            "Selection will use all available dates.",
            file=sys.stderr,
        )

    ranked = rank_hosts(eligible, args.random_seed)
    print("\nTop host candidates by date coverage:")
    for _, r in ranked.head(12).iterrows():
        print(f"  {r['inferred_host_or_client']:<20s}  "
              f"dates={r['n_dates']:>2}  "
              f"endpoint_gib={r['endpoint_size_gib']:.3f}  "
              f"total_gib={r['total_size_gib']:.3f}")

    preferred_hosts = select_preferred_hosts(
        ranked, args.preferred_host_count, all_dates, args.random_seed,
    )
    print(f"\n[INFO] Preferred hosts ({len(preferred_hosts)}): {preferred_hosts}")

    selected = select_members(
        eligible,
        preferred_hosts,
        all_dates,
        target_size_gib=args.target_size_gib,
        minimum_size_gib=args.minimum_size_gib,
        maximum_size_gib=args.maximum_size_gib,
        seed=args.random_seed,
    )
    print(f"[INFO] Selected members: {len(selected):,}  "
          f"({selected['member_size_gib'].sum():.4f} GiB)" if not selected.empty
          else "[WARN] Selection produced zero members.")

    manifest = build_manifest(selected)
    date_sum = summary_by_date(manifest)
    host_sum = summary_by_host(manifest)
    validation = build_validation(
        manifest, eligible, all_dates,
        args.minimum_size_gib, args.maximum_size_gib, preferred_hosts,
    )

    # Write outputs
    manifest_path = configs_dir / "pilot_manifest_10gb.csv"
    manifest.to_csv(manifest_path, index=False)
    # Also keep a copy under pilot_selection for convenience
    manifest.to_csv(out_dir / "pilot_manifest_10gb.csv", index=False)
    print(f"\n  [CSV] {manifest_path}")

    date_path = out_dir / "T0_pilot_manifest_summary_by_date.csv"
    date_sum.to_csv(date_path, index=False)
    print(f"  [CSV] {date_path}")

    host_path = out_dir / "T0_pilot_manifest_summary_by_host.csv"
    host_sum.to_csv(host_path, index=False)
    print(f"  [CSV] {host_path}")

    val_path = out_dir / "T0_pilot_manifest_validation.csv"
    validation.to_csv(val_path, index=False)
    print(f"  [CSV] {val_path}")

    total = float(manifest["member_size_gib"].sum()) if not manifest.empty else 0.0
    plot_size_by_date(date_sum, out_dir / "F0_pilot_manifest_size_by_date.png", total)

    write_readme(
        out_dir, args, manifest, preferred_hosts, validation, all_dates, len(eligible),
    )

    # Terminal validation report
    print(f"\n{'='*60}")
    print("MANIFEST VALIDATION")
    for _, row in validation.iterrows():
        flag = {"pass": "PASS", "fail": "FAIL", "info": "INFO"}[row["status"]]
        print(f"  [{flag}] {row['check_name']}: {row['observed_value']}")
    print(f"{'='*60}")

    n_fail = int((validation["status"] == "fail").sum())
    if n_fail:
        print(f"\n[WARN] {n_fail} validation check(s) failed. "
              "Inspect T0_pilot_manifest_validation.csv before using the manifest.")
        # Do not hard-exit: still write artifacts so the user can diagnose.
    else:
        print("\n[OK] All hard validation checks passed.")


if __name__ == "__main__":
    main()
