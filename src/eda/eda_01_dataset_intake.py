"""
EDA 1 — Dataset Intake and Version Control
DARPA OpTC EDA Project

Purpose : Catalog every file under --raw-data-dir, assess readability,
          produce a dataset intake ledger (T1), an analysis scope table (T2),
          and a file-coverage bar chart (F1).

Usage (local Mac):
  python3 src/eda/eda_01_dataset_intake.py \\
      --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \\
      --raw-data-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected

Usage (Colab):
  python3 src/eda/eda_01_dataset_intake.py \\
      --project-root /content/drive/MyDrive/DARPA_OPTC_EDA_REPO \\
      --raw-data-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives

Scope limitations (strictly enforced):
  - No attack analysis
  - No final dataset statistics
  - No MITRE label assignment
  - No suspicious / malicious classification
  - .tar archives are opened for member-name listing only — never extracted
"""

import argparse
import csv
import json
import hashlib
import pathlib
import sys
import tarfile
import datetime
import re

import pandas as pd
import matplotlib
matplotlib.use("Agg")          # non-interactive backend — safe for scripts
import matplotlib.pyplot as plt

# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# MODULE-LEVEL CONSTANTS  (not runtime-configurable; change here if needed)
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

LEDGER_FILENAME  = "T1_dataset_intake_ledger.csv"
SCOPE_FILENAME   = "T2_analysis_scope_table.csv"
CHART_FILENAME   = "F1_file_coverage_chart.png"
README_FILENAME  = "README_eda01_intake.txt"
TAR_PEEK_MEMBERS = 20          # members peeked during tar smoke test

# Full set of corrected daily-archive dates from the official OpTC catalog.
# Used to detect gaps and avoid implying continuous temporal coverage.
_CORRECTED_CATALOG_DATES = [f"2019-09-{d:02d}" for d in range(16, 26)]


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# CLI ARGUMENT PARSING
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="EDA 1 — Dataset Intake and Version Control (DARPA OpTC)"
    )
    p.add_argument(
        "--project-root", default=None,
        help=(
            "Project root directory. Outputs are written under "
            "<project-root>/outputs/. Defaults to current working directory."
        ),
    )
    p.add_argument(
        "--raw-data-dir", required=True,
        help=(
            "Directory to scan recursively for dataset files. "
            "E.g. /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives"
        ),
    )
    p.add_argument(
        "--output-dir", default=None,
        help=(
            "Override the primary output directory. "
            "Default: <project-root>/outputs/eda_01_intake"
        ),
    )
    p.add_argument(
        "--dataset-version", default="corrected",
        choices=["corrected", "original", "both", "review_all"],
        help="Dataset version to include. Default: corrected",
    )
    p.add_argument(
        "--checksum", action=argparse.BooleanOptionalAction, default=False,
        help="Compute streaming SHA-256 checksum for each file. Slow for large archives. Default: off",
    )
    p.add_argument(
        "--tar-smoke-test", action=argparse.BooleanOptionalAction, default=True,
        help=f"Run tar smoke test (peek at first {TAR_PEEK_MEMBERS} members). Default: on",
    )
    return p.parse_args()


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# INFERENCE HELPERS  (pure functions — no globals)
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def _lp(path: pathlib.Path) -> str:
    """Lower-cased full path string for keyword matching."""
    return str(path).lower()


def infer_dataset_version(path: pathlib.Path) -> str:
    """Return 'corrected', 'original', or 'unknown_review_needed'."""
    lp = _lp(path)
    if "corrected" in lp:
        return "corrected"
    if "original" in lp:
        return "original"
    return "unknown_review_needed"


def infer_source_type(path: pathlib.Path) -> str:
    """Classify the file. .tar files are always 'daily_archive'."""
    suffix = path.suffix.lower()
    lp     = _lp(path)

    if suffix == ".tar" or suffix in (".tar.gz", ".tgz"):
        return "daily_archive"

    gt_kw = ["ground_truth", "ground-truth", "groundtruth",
              "gt_labels", "truth", "annotation", "label"]
    if any(kw in lp for kw in gt_kw):
        return "ground_truth"

    net_kw = ["netflow", "pcap", "flow", "bro", "zeek",
               "suricata", "snort", "packet", "network"]
    if any(kw in lp for kw in net_kw):
        return "network"

    ep_kw = ["ecar", "endpoint", "edr", "process", "file_event",
              "registry", "sysmon", "sysclient", "host"]
    if any(kw in lp for kw in ep_kw):
        return "endpoint"

    return "unknown"


def infer_date_label(path: pathlib.Path) -> str:
    """Extract the first ISO date (YYYY-MM-DD) found in the path string."""
    text = str(path)

    m = re.search(r"\d{4}-\d{2}-\d{2}", text)
    if m:
        return m.group(0)

    m = re.search(r"\b(20\d{6})\b", text)
    if m:
        return m.group(1)

    m = re.search(r"(week\d+|day\d+|[a-z]{3,4}\d{1,2})", text, re.IGNORECASE)
    if m:
        return m.group(1).lower()

    return "unknown"


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# SMOKE-TEST PARSERS
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def smoke_test_parse(filepath: pathlib.Path) -> tuple[str, str]:
    """
    Readability check only — no statistics or content analysis.
    Returns (parser_name, parse_status).

    .tar  → open with tarfile, peek at first TAR_PEEK_MEMBERS names, close
    .csv/.tsv → pd.read_csv with nrows=5
    .json/.jsonl → read first 5 lines
    other → not_attempted
    """
    suffix = filepath.suffix.lower()

    if suffix == ".tar":
        try:
            with tarfile.open(filepath, "r:*") as tf:
                names = []
                for member in tf:
                    names.append(member.name)
                    if len(names) >= TAR_PEEK_MEMBERS:
                        break
            return "tar_smoke_parser", "tar_open_success"
        except Exception as exc:
            return "tar_smoke_parser", f"tar_open_failed: {str(exc)[:120]}"

    if suffix in (".csv", ".tsv"):
        sep = "\t" if suffix == ".tsv" else ","
        try:
            pd.read_csv(filepath, sep=sep, nrows=5, low_memory=False)
            return "pandas_csv_tsv", "readable_smoke_test_passed"
        except Exception as exc:
            return "pandas_csv_tsv", f"parse_error: {str(exc)[:120]}"

    if suffix in (".json", ".jsonl"):
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for _ in range(5):
                    line = fh.readline()
                    if not line:
                        break
                    json.loads(line.strip())
            return "json_line_reader", "readable_smoke_test_passed"
        except json.JSONDecodeError as exc:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    json.load(fh)
                return "json_full_reader", "readable_smoke_test_passed"
            except Exception:
                return "json_line_reader", f"parse_error: {str(exc)[:120]}"
        except Exception as exc:
            return "json_line_reader", f"parse_error: {str(exc)[:120]}"

    return "not_attempted", "not_attempted_or_unknown_format"


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# CHECKSUM
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def compute_sha256(filepath: pathlib.Path, chunk: int = 1 << 20) -> str:
    """Streaming SHA-256 in 1 MB chunks — never loads the whole file."""
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                sha.update(block)
        return sha.hexdigest()
    except Exception:
        return "error_computing_checksum"


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# INCLUSION GATE
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def is_included(
    filepath: pathlib.Path,
    parse_status: str,
    inferred_version: str,
    selected_version: str,
) -> tuple[str, str]:
    """
    Returns (included_yes_no, exclusion_reason).

    Values for included_yes_no:
      "yes"    — passes all checks
      "no"     — structurally invalid or wrong version
      "review" — readable but version is ambiguous

    Checks in order:
      1. Hidden / temp file               → "no"
      2. Zero-byte                        → "no"
      3. Parse error on a known format    → "no"
      4. Version gate
    """
    name = filepath.name

    if name.startswith(".") or name.startswith("~"):
        return "no", "hidden_or_temp_file"

    try:
        if filepath.stat().st_size == 0:
            return "no", "empty_file_zero_bytes"
    except Exception:
        return "no", "stat_error"

    if parse_status.startswith("parse_error") or parse_status.startswith("tar_open_failed"):
        return "no", "parse_error_on_known_format"

    if selected_version == "review_all":
        return "yes", ""

    if inferred_version == "unknown_review_needed":
        return "review", "dataset_version_unknown_needs_manual_review"

    if selected_version == "both":
        return "yes", ""

    if inferred_version != selected_version:
        return "no", "wrong_dataset_version"

    return "yes", ""


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# LEDGER BUILDER
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def build_ledger(
    raw_data_dir: pathlib.Path,
    selected_version: str,
    do_checksum: bool,
    do_smoke_test: bool,
) -> pd.DataFrame:
    """
    Walk raw_data_dir recursively, apply all inference and gate logic,
    return the full dataset intake ledger as a DataFrame.
    Exits with an informative error if the directory is empty.
    """
    root = raw_data_dir.resolve()
    if not root.exists():
        print(f"[ERROR] --raw-data-dir does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    records  = []
    file_id  = 0

    print(f"\n[EDA-01] Scanning: {root}")
    print(f"         Dataset version filter : {selected_version}")
    print(f"         Checksum               : {'on' if do_checksum else 'off (pass --checksum to enable)'}")
    print(f"         Tar smoke test         : {'on' if do_smoke_test else 'off'}\n")

    for filepath in sorted(root.rglob("*")):
        if not filepath.is_file():
            continue

        file_id += 1
        rel = filepath.relative_to(root)
        print(f"  [{file_id:04d}] {rel}", end=" … ", flush=True)

        try:
            size_mb = round(filepath.stat().st_size / (1024 ** 2), 4)
        except Exception:
            size_mb = None

        version     = infer_dataset_version(filepath)
        source_type = infer_source_type(filepath)
        date_label  = infer_date_label(filepath)

        # Smoke test
        if do_smoke_test:
            parser_name, parse_status = smoke_test_parse(filepath)
        else:
            suffix = filepath.suffix.lower()
            if suffix == ".tar":
                parser_name, parse_status = "tar_smoke_parser", "not_run_smoke_test_disabled"
            else:
                parser_name, parse_status = "not_attempted", "smoke_test_disabled"

        included, excl_reason = is_included(
            filepath, parse_status, version, selected_version
        )

        # Checksum
        if do_checksum:
            checksum = compute_sha256(filepath)
        else:
            checksum = "not_computed_checksum_disabled"

        print(f"[{included}]  {parse_status}")

        records.append({
            "file_id"                              : file_id,
            "file_name"                            : filepath.name,
            "folder_path"                          : str(filepath.parent),
            "dataset_version_original_or_corrected": version,
            "source_type"                          : source_type,
            "date_label"                           : date_label,
            "file_size_mb"                         : size_mb,
            "included_yes_no"                      : included,
            "exclusion_reason"                     : excl_reason or "none",
            "parser_name"                          : parser_name,
            "parse_status"                         : parse_status,
            "checksum_if_available"                : checksum,
            "manual_review_note"                   : "not_applicable",
        })

    if not records:
        print(
            f"\n[ERROR] No files found in --raw-data-dir: {root}\n"
            f"        Check that the path is correct and the directory is not empty.",
            file=sys.stderr,
        )
        sys.exit(1)

    return pd.DataFrame(records)


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# T2 — ANALYSIS SCOPE TABLE
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def build_scope_table(
    ledger: pd.DataFrame,
    selected_version: str,
) -> pd.DataFrame:
    """Six-row scope summary derived dynamically from the ledger."""
    has_data = not ledger.empty and "source_type" in ledger.columns

    if has_data:
        known_dates = sorted(
            ledger.loc[ledger["date_label"] != "unknown", "date_label"].unique().tolist()
        )
        # Intersect with the known corrected catalog to identify what is
        # available vs what is still pending download.
        available_dates = [d for d in known_dates if d in _CORRECTED_CATALOG_DATES]
        pending_dates   = [d for d in _CORRECTED_CATALOG_DATES if d not in known_dates]

        if available_dates:
            avail_str = ", ".join(available_dates)
            catalog_start = _CORRECTED_CATALOG_DATES[0]
            catalog_end   = _CORRECTED_CATALOG_DATES[-1]
            date_val = (
                f"available corrected archive dates: {avail_str}; "
                f"corrected catalog range under intake plan: "
                f"{catalog_start} through {catalog_end}"
            )
        else:
            date_val = "unknown — no corrected catalog dates found in scanned files"

        if pending_dates:
            date_limitation = (
                "continuous temporal coverage not yet achieved; "
                f"missing corrected archives remain pending download: "
                f"{', '.join(pending_dates)}"
            )
        else:
            date_limitation = (
                "all corrected catalog dates accounted for in this scan; "
                "verify archive contents before claiming full temporal coverage"
            )
    else:
        date_val       = "unknown — no date tokens found"
        date_limitation = (
            "continuous temporal coverage not yet achieved; "
            "missing corrected archives remain pending download"
        )

    if has_data:
        src_types = sorted(ledger["source_type"].unique().tolist())
        src_val   = ", ".join(src_types) if src_types else "none detected"
    else:
        src_val = "none detected"

    has_gt = has_data and "ground_truth" in ledger["source_type"].values
    gt_val = "present in ledger" if has_gt else "not detected in scanned files"

    rows = [
        {
            "scope_item"    : "dataset_version",
            "selected_value": selected_version,
            "reason"        : "Avoid mixing original and corrected OpTC files unless explicitly justified",
            "limitation"    : ("Files marked unknown_review_needed require manual review; "
                               "pass --dataset-version review_all to bypass filter"),
        },
        {
            "scope_item"    : "date_range",
            "selected_value": date_val,
            "reason"        : "Inferred from folder/filename tokens during intake scan",
            "limitation"    : date_limitation,
        },
        {
            "scope_item"    : "event_sources",
            "selected_value": (
                "archive-level daily tar files; "
                "detailed row-level source profiling deferred to EDA 2; "
                "lightweight tar-member coverage may be computed in EDA 1 "
                "without full extraction"
            ),
            "reason"        : (
                "Archive not extracted at EDA-01 level; "
                "tar member names can be inspected for source classification "
                "using eda_01_master_archive_inventory.py --estimate-extracted-size"
            ),
            "limitation"    : (
                "Row-level source breakdown and field-level profiling "
                "require extraction; deferred to EDA-02"
            ),
        },
        {
            "scope_item"    : "ground_truth_source",
            "selected_value": gt_val,
            "reason"        : "Detected via keyword matching (ground_truth, label, etc.)",
            "limitation"    : "Ground-truth files identified by keyword matching only; content not validated in EDA-01",
        },
        {
            "scope_item"    : "host_subset",
            "selected_value": "not selected at EDA-01 archive level",
            "reason"        : "Host-level selection requires extraction; not applicable to .tar intake",
            "limitation"    : "Host-level filtering deferred to later EDA phases",
        },
        {
            "scope_item"    : "sampling_rule",
            "selected_value": f"no sampling; tar smoke test reads only first {TAR_PEEK_MEMBERS} archive members",
            "reason"        : "EDA-01 is an intake scan; no rows are sampled or dropped",
            "limitation"    : "Row-level sampling rules deferred to later EDA phases",
        },
    ]
    return pd.DataFrame(rows)


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# F1 — FILE COVERAGE CHART
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def plot_file_coverage(ledger: pd.DataFrame, out_path: pathlib.Path) -> None:
    """
    Bar chart: total file_size_mb per source_type, grouped by included_yes_no.
    Works correctly even when the ledger has only one file.
    """
    if ledger.empty or "file_size_mb" not in ledger.columns:
        print("  [WARNING] Ledger is empty — skipping chart.")
        return

    ledger = ledger.copy()
    ledger["file_size_mb"] = ledger["file_size_mb"].fillna(0)

    agg = (
        ledger
        .groupby(["source_type", "included_yes_no"], as_index=False)["file_size_mb"]
        .sum()
    )

    source_types = sorted(agg["source_type"].unique())
    status_vals  = sorted(agg["included_yes_no"].unique())

    n_groups = len(source_types)
    n_bars   = len(status_vals)

    bar_w = min(0.35, 0.8 / max(n_bars, 1))
    fig_w = max(8, n_groups * 2.5)

    colors = {"yes": "#4C9BE8", "no": "#E87C4C", "review": "#F0C040"}
    labels = {"yes": "Included", "no": "Excluded", "review": "Needs Review"}

    fig, ax = plt.subplots(figsize=(fig_w, 5))
    x = list(range(n_groups))

    for i, status in enumerate(status_vals):
        subset  = agg[agg["included_yes_no"] == status]
        vals    = [
            float(subset.loc[subset["source_type"] == st, "file_size_mb"].sum())
            for st in source_types
        ]
        offsets = [xi + (i - n_bars / 2 + 0.5) * bar_w for xi in x]
        ax.bar(offsets, vals,
               width=bar_w,
               label=labels.get(status, status),
               color=colors.get(status, "#999999"),
               edgecolor="white", linewidth=0.7)
        for ox, v in zip(offsets, vals):
            if v > 0:
                ax.text(ox, v + max(vals) * 0.01, f"{v:.0f} MB",
                        ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(source_types, rotation=20, ha="right", fontsize=10)
    ax.set_xlabel("Source Type", fontsize=11)
    ax.set_ylabel("Total File Size (MB)", fontsize=11)
    ax.set_title(
        "F1 — File Coverage by Source Type\n(Included vs Excluded / Review)",
        fontsize=13, fontweight="bold",
    )
    ax.legend(title="Status", fontsize=10)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

    if agg["file_size_mb"].max() == 0:
        ax.set_ylim(0, 1)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Chart saved → {out_path}")


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# README WRITER
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def write_readme(
    ledger: pd.DataFrame,
    out_dir: pathlib.Path,
    run_ts: str,
    raw_data_dir: pathlib.Path,
    selected_version: str,
    do_checksum: bool,
) -> None:
    """Write a plain-text README documenting this intake run."""
    if not ledger.empty and "included_yes_no" in ledger.columns:
        n_total    = len(ledger)
        n_included = int((ledger["included_yes_no"] == "yes").sum())
        n_review   = int((ledger["included_yes_no"] == "review").sum())
        n_excluded = int((ledger["included_yes_no"] == "no").sum())
    else:
        n_total = n_included = n_review = n_excluded = 0

    checksum_note = (
        "Streaming SHA-256 computed for each file."
        if do_checksum
        else "Checksum disabled (pass --checksum to enable)."
    )

    w = 65
    lines = [
        "=" * w,
        "  DARPA OpTC — EDA 1: Dataset Intake and Version Control",
        "  README — Intake Run Summary",
        "=" * w,
        "",
        f"  Run timestamp        : {run_ts}",
        f"  Raw data directory   : {raw_data_dir}",
        f"  Selected version     : {selected_version}",
        f"  Checksum             : {checksum_note}",
        "",
        "-" * w,
        "SELECTED DATASET VERSION",
        "-" * w,
        "",
        f'  --dataset-version {selected_version}',
        "",
        "  Allowed values:",
        "    corrected  — include only files containing 'corrected' in path/name",
        "    original   — include only files containing 'original' in path/name",
        "    both       — include both; unknown-version files still flagged 'review'",
        "    review_all — no version filter; every readable file is included",
        "",
        "-" * w,
        "INCLUSION RULE",
        "-" * w,
        "",
        "  A file receives included_yes_no = 'yes' only when ALL of:",
        "    1. Filename does not start with '.' or '~' (not hidden/temp).",
        "    2. File is not zero bytes.",
        "    3. Smoke-test parser did not raise a parse / open error.",
        "    4. Inferred dataset version matches --dataset-version.",
        "",
        "  included_yes_no = 'no':  fails any of 1–3, or confirmed wrong version.",
        "  included_yes_no = 'review':  readable but version is ambiguous.",
        "    Fill in manual_review_note column after inspecting.",
        "",
        "-" * w,
        "SMOKE-TEST PARSING — READABILITY ONLY",
        "-" * w,
        "",
        "  The smoke test confirms a file can be opened and parsed.",
        "  It does NOT count rows, compute statistics, assess data",
        "  quality, or perform any content or attack analysis.",
        "",
        "  .tar files:",
        f"    Opens archive, peeks at first {TAR_PEEK_MEMBERS} member names, closes immediately.",
        "    The archive is NEVER extracted.",
        "",
        "  .csv / .tsv  : reads first 5 rows via pandas.",
        "  .json / .jsonl : reads first 5 lines via json.loads.",
        "  Other formats  : not_attempted_or_unknown_format.",
        "",
        "-" * w,
        "TAR ARCHIVE POLICY",
        "-" * w,
        "",
        "  The .tar archive was NOT extracted at EDA-01 stage.",
        "  Internal file types are catalogued inside the archive in EDA-02.",
        "",
        "-" * w,
        "SCOPE BOUNDARIES — WHAT THIS SCRIPT DOES NOT DO",
        "-" * w,
        "",
        "  - No attack analysis",
        "  - No final dataset statistics",
        "  - No MITRE label assignment",
        "  - No suspicious / malicious classification",
        "  - No host-level or row-level filtering",
        "  - No sampling",
        "",
        "-" * w,
        "FILE COUNTS FOR THIS RUN",
        "-" * w,
        "",
        f"  Total files catalogued : {n_total}",
        f"  Included (yes)         : {n_included}",
        f"  Needs review (review)  : {n_review}",
        f"  Excluded (no)          : {n_excluded}",
        "",
        "-" * w,
        "OUTPUTS",
        "-" * w,
        "",
        f"  {LEDGER_FILENAME:<35} — one row per file",
        f"  {SCOPE_FILENAME:<35} — scope summary table",
        f"  {CHART_FILENAME:<35} — bar chart: MB by source type",
        f"  {README_FILENAME:<35} — this file",
        "",
        "=" * w,
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / README_FILENAME
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  README saved → {out_path}")


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# OUTPUT HELPERS
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def save_csv(df: pd.DataFrame, filename: str, *dest_dirs: pathlib.Path) -> None:
    for dest in dest_dirs:
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / filename
        df.to_csv(out, index=False, quoting=csv.QUOTE_ALL)
        print(f"  Saved → {out}")


def copy_file(src: pathlib.Path, *dest_dirs: pathlib.Path) -> None:
    import shutil
    for dest in dest_dirs:
        dest.mkdir(parents=True, exist_ok=True)
        dst = dest / src.name
        if dst.resolve() != src.resolve():
            shutil.copy2(src, dst)
            print(f"  Copied → {dst}")


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# ENTRY POINT
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def main() -> None:
    args = parse_args()

    # ── Resolve paths ─────────────────────────────────────────────────
    raw_data_dir = pathlib.Path(args.raw_data_dir).resolve()
    project_root = (
        pathlib.Path(args.project_root).resolve()
        if args.project_root
        else pathlib.Path.cwd()
    )
    output_eda01 = (
        pathlib.Path(args.output_dir).resolve()
        if args.output_dir
        else project_root / "outputs" / "eda_01_intake"
    )
    output_tables = project_root / "outputs" / "tables"
    output_figs   = project_root / "outputs" / "figures"

    selected_version = args.dataset_version
    do_checksum      = args.checksum
    do_smoke_test    = args.tar_smoke_test

    started = datetime.datetime.now()
    run_ts  = started.strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 65)
    print("  DARPA OpTC — EDA 1: Dataset Intake and Version Control")
    print(f"  Started : {run_ts}")
    print("=" * 65)

    for d in (output_eda01, output_tables, output_figs):
        d.mkdir(parents=True, exist_ok=True)

    # ── STEP 1 — Dataset Intake Ledger (T1) ──────────────────────────
    print("\n[STEP 1/4] Building dataset intake ledger (T1) …")
    ledger = build_ledger(raw_data_dir, selected_version, do_checksum, do_smoke_test)

    n_total    = len(ledger)
    n_included = int((ledger["included_yes_no"] == "yes").sum())
    n_review   = int((ledger["included_yes_no"] == "review").sum())
    n_excluded = int((ledger["included_yes_no"] == "no").sum())

    print(f"\n  Files catalogued : {n_total}")
    print(f"  Included         : {n_included}")
    print(f"  Needs review     : {n_review}")
    print(f"  Excluded         : {n_excluded}")
    print(f"  Dataset version  : {selected_version}")

    save_csv(ledger, LEDGER_FILENAME, output_eda01, output_tables)

    # ── STEP 2 — Analysis Scope Table (T2) ───────────────────────────
    print("\n[STEP 2/4] Building analysis scope table (T2) …")
    scope = build_scope_table(ledger, selected_version)
    save_csv(scope, SCOPE_FILENAME, output_eda01, output_tables)

    # ── STEP 3 — File Coverage Chart (F1) ────────────────────────────
    print("\n[STEP 3/4] Generating file coverage chart (F1) …")
    primary_chart = output_eda01 / CHART_FILENAME
    plot_file_coverage(ledger, primary_chart)
    if primary_chart.exists():
        copy_file(primary_chart, output_figs)
    else:
        print("  Chart skipped (no data).")

    # ── STEP 4 — README ───────────────────────────────────────────────
    print("\n[STEP 4/4] Writing intake README …")
    write_readme(ledger, output_eda01, run_ts, raw_data_dir, selected_version, do_checksum)

    finished = datetime.datetime.now()
    elapsed  = (finished - started).total_seconds()
    print("\n" + "=" * 65)
    print("  EDA 1 complete.")
    print(f"  Finished : {finished.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Elapsed  : {elapsed:.1f}s")
    print("=" * 65)


if __name__ == "__main__":
    main()
