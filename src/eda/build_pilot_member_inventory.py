"""
Pilot-Subset Stage 1 — Tar Member Inventory (DARPA OpTC)
=========================================================
Builds a complete inventory of the internal members of corrected OpTC
.tar archives so that a later fixed 5-10 GB pilot manifest can be selected
on an evidence basis.

This script does NOT select the pilot subset itself.

Key guarantees:
    - Archives are NEVER fully extracted to disk.
    - Members are enumerated from tar headers only.
    - Lightweight inspection streams only the first N decompressed JSON
      lines per member (default 20); the member is never fully loaded
      into RAM.
    - No attack / benign / malicious / MITRE claims are made.
      Ground-truth-like member names are flagged as *candidates* only.

Outputs (default outputs/pilot_selection/):
    T0_member_inventory.csv
    T0_member_summary_by_date_source_host.csv
    T0_ground_truth_candidate_files.csv
    F0_member_size_by_date_source.png
    README_pilot_member_inventory.txt

Usage
-----
python3 src/eda/build_pilot_member_inventory.py \\
    --project-root /content/DARPA_OPTC_EDA_REPO \\
    --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \\
    --archives 2019-09-16.tar \\
    --sample-lines-per-member 20
"""

from __future__ import annotations

import argparse
import datetime
import gzip
import json
import pathlib
import re
import sys
import tarfile
from typing import Optional

# ── Reuse conservative helpers from the streaming parser ──────────────────
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from optc_streaming_parser import (   # type: ignore
    infer_source_type_from_member,
    _parse_timestamp,
    _extract_first,
    _TIMESTAMP_KEYS,
)

# ── Regexes for conservative name-based inference ─────────────────────────
_DATE_RE   = re.compile(r"(\d{4}-\d{2}-\d{2})")
# OpTC endpoint members commonly embed host tokens like SysClient0201 or
# sysclient0201.systemia.com; also accept generic hostNNN tokens.
_HOST_RE   = re.compile(r"(sysclient\d+|dc\d+|host[\-_]?\d+)", re.IGNORECASE)
_GT_KEYWORDS = ("ground_truth", "groundtruth", "truth", "label", "redteam")

# Cap for the observed_top_level_fields cell so the CSV stays readable
_MAX_FIELDS_STR = 400


def infer_source_type(member_name: str) -> str:
    """
    Conservative source-type from member path only.
    Maps the parser's 'ground_truth' to 'ground_truth_candidate' because
    name-based inference cannot confirm actual ground-truth content.
    """
    base = infer_source_type_from_member(member_name)
    return "ground_truth_candidate" if base == "ground_truth" else base


def infer_host_or_client(member_name: str) -> str:
    m = _HOST_RE.search(member_name)
    return m.group(1).lower() if m else "unknown"


def infer_date(member_name: str) -> str:
    m = _DATE_RE.search(member_name)
    return m.group(1) if m else "unknown"


def ground_truth_flag(member_name: str) -> str:
    n = member_name.lower()
    return "yes" if any(k in n for k in _GT_KEYWORDS) else "no"


def archive_date_from_name(archive_name: str) -> str:
    m = _DATE_RE.search(archive_name)
    return m.group(1) if m else "unknown"


# ── Lightweight member sampling ───────────────────────────────────────────

def sample_member(tf: tarfile.TarFile, member: tarfile.TarInfo,
                  n_lines: int) -> dict:
    """
    Stream the first n_lines decompressed lines of a .json.gz (or plain
    .json/.jsonl) member.  Decompression is streamed directly from the tar
    file object — the member is never fully read into RAM and nothing is
    written to disk.

    Returns a dict with sampling results.
    """
    result = {
        "readable_yes_no"            : "no",
        "sample_parse_status"        : "",
        "sampled_lines"              : 0,
        "sampled_valid_json_lines"   : 0,
        "sampled_invalid_json_lines" : 0,
        "sampled_earliest_timestamp" : "",
        "sampled_latest_timestamp"   : "",
        "observed_top_level_fields"  : "",
        "notes"                      : "",
    }

    fobj = tf.extractfile(member)
    if fobj is None:
        result["sample_parse_status"] = "member_not_extractable"
        return result

    name_lower = member.name.lower()
    is_gz = name_lower.endswith(".gz")

    earliest: Optional[datetime.datetime] = None
    latest:   Optional[datetime.datetime] = None
    fields:   set = set()

    try:
        # gzip.open on the tar file object performs STREAMING decompression:
        # only the bytes needed for the requested lines are read.
        if is_gz:
            reader = gzip.open(fobj, "rt", encoding="utf-8", errors="replace")
        else:
            import io
            reader = io.TextIOWrapper(fobj, encoding="utf-8", errors="replace")

        with reader:
            for line in reader:
                if result["sampled_lines"] >= n_lines:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                result["sampled_lines"] += 1

                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    result["sampled_invalid_json_lines"] += 1
                    continue
                if not isinstance(obj, dict):
                    result["sampled_invalid_json_lines"] += 1
                    continue

                result["sampled_valid_json_lines"] += 1
                fields.update(obj.keys())

                _, ts_raw = _extract_first(obj, _TIMESTAMP_KEYS)
                ts = _parse_timestamp(ts_raw)
                if ts is not None:
                    if earliest is None or ts < earliest:
                        earliest = ts
                    if latest is None or ts > latest:
                        latest = ts

        result["readable_yes_no"] = "yes"
        if result["sampled_lines"] == 0:
            result["sample_parse_status"] = "readable_but_empty"
        elif result["sampled_valid_json_lines"] == 0:
            result["sample_parse_status"] = "readable_but_no_valid_json_in_sample"
        else:
            result["sample_parse_status"] = "sample_ok"

    except Exception as exc:
        result["sample_parse_status"] = f"read_failed:{type(exc).__name__}:{str(exc)[:120]}"
        result["notes"] = "member could not be streamed; possible corruption or unexpected format"
        return result

    if earliest is not None:
        result["sampled_earliest_timestamp"] = earliest.isoformat()
    if latest is not None:
        result["sampled_latest_timestamp"] = latest.isoformat()

    fields_str = ";".join(sorted(fields))
    if len(fields_str) > _MAX_FIELDS_STR:
        fields_str = fields_str[:_MAX_FIELDS_STR] + ";..."
    result["observed_top_level_fields"] = fields_str
    result["notes"] = "sampled_first_lines_only; member_not_extracted"
    return result


# ── Inventory build ───────────────────────────────────────────────────────

def inventory_archive(
    archive_path: pathlib.Path,
    sample_lines: int,
    max_members: Optional[int],
    include_pattern: str,
) -> list:
    """
    Enumerate members of one archive via tar headers and lightly sample
    members matching include_pattern.  Returns list of inventory row dicts.
    """
    archive_name = archive_path.name
    archive_date = archive_date_from_name(archive_name)
    rows = []

    try:
        tf = tarfile.open(archive_path, "r:*")
    except Exception as exc:
        print(f"[ERROR] Cannot open {archive_path}: {exc}", file=sys.stderr)
        return rows

    sampled_count = 0
    with tf:
        for member in tf:
            if not member.isfile():
                continue

            size_b = int(member.size)
            name   = member.name
            suffixes = pathlib.Path(name).suffixes
            ext = "".join(suffixes[-2:]) if suffixes else ""

            row = {
                "archive_date"              : archive_date,
                "archive_filename"          : archive_name,
                "member_name"               : name,
                "member_extension"          : ext,
                "member_size_bytes"         : size_b,
                "member_size_mb"            : round(size_b / (1024 ** 2), 3),
                "member_size_gib"           : round(size_b / (1024 ** 3), 4),
                "inferred_source_type"      : infer_source_type(name),
                "inferred_host_or_client"   : infer_host_or_client(name),
                "inferred_date"             : infer_date(name),
                "ground_truth_keyword_flag" : ground_truth_flag(name),
            }

            matches_pattern = include_pattern in name
            under_member_cap = (max_members is None) or (sampled_count < max_members)

            if matches_pattern and under_member_cap:
                sampled_count += 1
                if sampled_count % 25 == 0:
                    print(f"  ... sampled {sampled_count} members "
                          f"(current: {pathlib.Path(name).name})", flush=True)
                row.update(sample_member(tf, member, sample_lines))
            else:
                reason = ("pattern_mismatch" if not matches_pattern
                          else "max_members_reached")
                row.update({
                    "readable_yes_no"            : "not_checked",
                    "sample_parse_status"        : f"not_sampled_{reason}",
                    "sampled_lines"              : 0,
                    "sampled_valid_json_lines"   : 0,
                    "sampled_invalid_json_lines" : 0,
                    "sampled_earliest_timestamp" : "",
                    "sampled_latest_timestamp"   : "",
                    "observed_top_level_fields"  : "",
                    "notes"                      : "enumerated_from_tar_header_only; member_not_extracted",
                })

            rows.append(row)

    print(f"  [{archive_name}] {len(rows)} file members enumerated, "
          f"{sampled_count} sampled.")
    return rows


# ── Outputs ───────────────────────────────────────────────────────────────

def build_summary(df):
    """Group by (archive_date, inferred_source_type, inferred_host_or_client)."""
    grouped = df.groupby(
        ["archive_date", "inferred_source_type", "inferred_host_or_client"],
        as_index=False,
    ).agg(
        member_count               =("member_name", "count"),
        total_member_size_mb       =("member_size_mb", "sum"),
        total_member_size_gib      =("member_size_gib", "sum"),
        readable_member_count      =("readable_yes_no", lambda s: int((s == "yes").sum())),
        sampled_valid_json_lines   =("sampled_valid_json_lines", "sum"),
        sampled_invalid_json_lines =("sampled_invalid_json_lines", "sum"),
    )
    grouped["total_member_size_mb"]  = grouped["total_member_size_mb"].round(2)
    grouped["total_member_size_gib"] = grouped["total_member_size_gib"].round(4)
    return grouped.sort_values(
        ["archive_date", "inferred_source_type", "inferred_host_or_client"]
    )


def plot_f0(df, out_path: pathlib.Path) -> None:
    """Stacked bar chart: total member size (GiB) per archive_date, by source type."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pivot = df.pivot_table(
        index="archive_date",
        columns="inferred_source_type",
        values="member_size_gib",
        aggfunc="sum",
        fill_value=0.0,
    ).sort_index()

    if pivot.empty:
        print("  [F0] No data — skipping figure.", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(11, 5))
    pivot.plot(kind="bar", stacked=True, ax=ax, width=0.7)
    ax.set_xlabel("Archive date", fontsize=11)
    ax.set_ylabel("Total internal member size (GiB, stored .json.gz size)", fontsize=11)
    ax.set_title(
        "F0 — Internal Tar Member Size by Archive Date and Inferred Source Type\n"
        "(tar headers only; archives not extracted; no ground-truth overlay)",
        fontsize=10,
    )
    ax.legend(title="inferred_source_type", fontsize=9)
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", dpi=150)
    plt.close(fig)
    print(f"  [FIG] {out_path}")


def write_readme(out_dir: pathlib.Path, args: argparse.Namespace,
                 n_archives: int, n_members: int, n_sampled: int,
                 n_gt_candidates: int, total_gib: float) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "Pilot-Subset Stage 1 — Tar Member Inventory",
        "=" * 55,
        f"Generated (UTC): {now}",
        "",
        "What this is",
        "------------",
        "A complete internal member inventory of the CORRECTED DARPA OpTC",
        "daily .tar archives.  Its only purpose is to support the later,",
        "evidence-based selection of a fixed 5-10 GB pilot manifest.",
        "The pilot subset itself is NOT selected by this script.",
        "",
        "Method statements",
        "-----------------",
        "* The corrected OpTC archives were inspected (not the original release).",
        "* Archives were NOT fully extracted; members were enumerated from tar",
        "  headers only.",
        "* member_size_bytes/mb/gib refer to the INTERNAL STORED .json.gz file",
        "  size inside the tar (i.e. the compressed member size), not the",
        "  decompressed event data size.",
        "* Field and timestamp observations come ONLY from lightweight sampling",
        f"  of the first {args.sample_lines_per_member} decompressed JSON lines",
        "  per member, streamed without loading the member into RAM.",
        "* No benign, attack, malicious, or MITRE labels were assigned.",
        "  Members whose names contain ground-truth-like keywords are flagged",
        "  as ground_truth_candidate ONLY; content was not verified.",
        "",
        "Run parameters",
        "--------------",
        f"  corrected-dir           : {args.corrected_dir}",
        f"  archives                : {args.archives or 'all .tar in corrected-dir'}",
        f"  sample-lines-per-member : {args.sample_lines_per_member}",
        f"  max-members             : {args.max_members if args.max_members is not None else 'unlimited'}",
        f"  include-pattern         : {args.include_pattern}",
        "",
        "Results",
        "-------",
        f"  archives inspected              : {n_archives}",
        f"  file members enumerated         : {n_members:,}",
        f"  members sampled                 : {n_sampled:,}",
        f"  ground-truth candidate members  : {n_gt_candidates}",
        f"  total internal member size      : {total_gib:.2f} GiB (stored/compressed)",
        "",
        "Outputs",
        "-------",
        "  T0_member_inventory.csv                     full per-member inventory",
        "  T0_member_summary_by_date_source_host.csv   grouped summary",
        "  T0_ground_truth_candidate_files.csv         name-flagged candidates only",
        "  F0_member_size_by_date_source.png           size by date and source type",
        "",
        "Command example",
        "---------------",
        "  python3 src/eda/build_pilot_member_inventory.py \\",
        "      --project-root /content/DARPA_OPTC_EDA_REPO \\",
        "      --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \\",
        "      --archives 2019-09-16.tar \\",
        "      --sample-lines-per-member 20",
        "",
        "Next step",
        "---------",
        "Use T0_member_inventory.csv and the summary table to select a fixed",
        "5-10 GB pilot manifest (a later, separate step).  Selection criteria",
        "should balance archive dates, source types, and host coverage.",
    ]
    (out_dir / "README_pilot_member_inventory.txt").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(f"  [README] {out_dir / 'README_pilot_member_inventory.txt'}")


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Pilot-subset stage 1 — internal tar member inventory (DARPA OpTC).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--project-root", default=None,
                   help="Project root directory (default: cwd)")
    p.add_argument("--corrected-dir", required=True,
                   help="Directory containing corrected .tar archives")
    p.add_argument("--archives", nargs="+", default=None,
                   help="Archive filenames to inspect (default: all .tar in corrected-dir)")
    p.add_argument("--output-dir", default=None,
                   help="Output directory (default: <project-root>/outputs/pilot_selection)")
    p.add_argument("--sample-lines-per-member", type=int, default=20,
                   help="Decompressed JSON lines to sample per member (default: 20)")
    p.add_argument("--max-members", type=int, default=None,
                   help="Max members to SAMPLE per archive (default: unlimited); "
                        "all members are still enumerated from tar headers")
    p.add_argument("--include-pattern", default=".json.gz",
                   help="Only members whose name contains this string are sampled "
                        "(default: .json.gz)")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────

def main() -> None:
    import pandas as pd

    args = parse_args()

    project_root  = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()
    corrected_dir = pathlib.Path(args.corrected_dir)
    if not corrected_dir.exists():
        print(f"[ERROR] corrected-dir not found: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

    out_dir = (pathlib.Path(args.output_dir) if args.output_dir
               else project_root / "outputs" / "pilot_selection")
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.archives:
        archive_paths = [corrected_dir / a for a in args.archives]
        missing = [str(p) for p in archive_paths if not p.exists()]
        if missing:
            print(f"[ERROR] Archives not found: {missing}", file=sys.stderr)
            sys.exit(1)
    else:
        archive_paths = sorted(corrected_dir.glob("*.tar"))
        if not archive_paths:
            print(f"[ERROR] No .tar files in {corrected_dir}", file=sys.stderr)
            sys.exit(1)

    print(f"\n{'='*60}")
    print("Pilot-Subset Stage 1 — Tar Member Inventory")
    print(f"  corrected-dir           : {corrected_dir}")
    print(f"  archives                : {[p.name for p in archive_paths]}")
    print(f"  sample-lines-per-member : {args.sample_lines_per_member}")
    print(f"  max-members (sampled)   : {args.max_members if args.max_members is not None else 'unlimited'}")
    print(f"  include-pattern         : {args.include_pattern}")
    print(f"  output-dir              : {out_dir}")
    print(f"{'='*60}\n")

    # ── Build inventory ───────────────────────────────────────────────
    all_rows = []
    for ap in archive_paths:
        print(f"Inspecting {ap.name} ...")
        all_rows.extend(inventory_archive(
            ap, args.sample_lines_per_member, args.max_members, args.include_pattern,
        ))

    inv_columns = [
        "archive_date", "archive_filename", "member_name", "member_extension",
        "member_size_bytes", "member_size_mb", "member_size_gib",
        "inferred_source_type", "inferred_host_or_client", "inferred_date",
        "ground_truth_keyword_flag", "readable_yes_no", "sample_parse_status",
        "sampled_lines", "sampled_valid_json_lines", "sampled_invalid_json_lines",
        "sampled_earliest_timestamp", "sampled_latest_timestamp",
        "observed_top_level_fields", "notes",
    ]
    inv_df = pd.DataFrame(all_rows, columns=inv_columns)

    inv_path = out_dir / "T0_member_inventory.csv"
    inv_df.to_csv(inv_path, index=False)
    print(f"\n  [CSV] {inv_path}  ({len(inv_df):,} rows)")

    # ── Summary table ─────────────────────────────────────────────────
    if not inv_df.empty:
        summary_df = build_summary(inv_df)
    else:
        summary_df = pd.DataFrame(columns=[
            "archive_date", "inferred_source_type", "inferred_host_or_client",
            "member_count", "total_member_size_mb", "total_member_size_gib",
            "readable_member_count", "sampled_valid_json_lines",
            "sampled_invalid_json_lines",
        ])
    summary_path = out_dir / "T0_member_summary_by_date_source_host.csv"
    summary_df.to_csv(summary_path, index=False)
    print(f"  [CSV] {summary_path}  ({len(summary_df):,} rows)")

    # ── Ground-truth candidate table ──────────────────────────────────
    gt_df = inv_df[inv_df["ground_truth_keyword_flag"] == "yes"].copy()
    gt_path = out_dir / "T0_ground_truth_candidate_files.csv"
    gt_df.to_csv(gt_path, index=False)
    print(f"  [CSV] {gt_path}  ({len(gt_df):,} rows)")

    # ── Figure ────────────────────────────────────────────────────────
    if not inv_df.empty:
        plot_f0(inv_df, out_dir / "F0_member_size_by_date_source.png")

    # ── README ────────────────────────────────────────────────────────
    n_sampled = int((~inv_df["sample_parse_status"].str.startswith("not_sampled")).sum()) \
        if not inv_df.empty else 0
    write_readme(
        out_dir, args,
        n_archives=len(archive_paths),
        n_members=len(inv_df),
        n_sampled=n_sampled,
        n_gt_candidates=len(gt_df),
        total_gib=float(inv_df["member_size_gib"].sum()) if not inv_df.empty else 0.0,
    )

    # ── Terminal summary ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("MEMBER INVENTORY COMPLETE")
    print(f"  Archives inspected       : {len(archive_paths)}")
    print(f"  Members enumerated       : {len(inv_df):,}")
    print(f"  Members sampled          : {n_sampled:,}")
    print(f"  GT candidate members     : {len(gt_df)}")
    if not inv_df.empty:
        print(f"  Total stored member size : {inv_df['member_size_gib'].sum():.2f} GiB")
        print("\n  Size by source type (GiB):")
        by_src = inv_df.groupby("inferred_source_type")["member_size_gib"].sum()
        for src, gib in by_src.items():
            print(f"    {src:<24s}: {gib:.2f}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
