"""
EDA 1 — Master Corrected-Archive Inventory
DARPA OpTC EDA Project

Purpose : Produce a broad archive-level inventory across all 10 corrected
          OpTC daily archives, whether downloaded or not.  Generates:

            T1B_master_archive_inventory.csv  — one row per archive
            S1_storage_feasibility_report.txt — local-storage assessment

          Also appends a new section to README_eda01_intake.txt.

Usage (local Mac):
  python3 src/eda/eda_01_master_archive_inventory.py \\
      --project-root /Users/farzu/Desktop/DARPA_OPTC_EDA \\
      --corrected-dir /Users/farzu/Desktop/DARPA_OPTC_EDA/data/corrected

Usage (Colab):
  python3 src/eda/eda_01_master_archive_inventory.py \\
      --project-root /content/drive/MyDrive/DARPA_OPTC_EDA_REPO \\
      --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives

Optional flags:
  --checksum                  compute SHA-256 per archive (slow; default: off)
  --no-tar-smoke-test         skip smoke test (default: on)
  --estimate-extracted-size   iterate all members to sum sizes (default: off)

Scope limitations (strictly enforced):
  - No archive extraction
  - No event-level statistics
  - No attack analysis
  - No MITRE label assignment
  - No malicious-behaviour inference
"""

import argparse
import csv
import collections
import datetime
import hashlib
import pathlib
import re
import shutil
import sys
import tarfile

# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# MODULE-LEVEL CONSTANTS
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

TAR_PEEK_MEMBERS = 20          # members peeked during smoke test

T1B_FILENAME    = "T1B_master_archive_inventory.csv"
S1_FILENAME     = "S1_storage_feasibility_report.txt"
README_FILENAME = "README_eda01_intake.txt"

# Official corrected-archive catalog (filename, official_compressed_size_gb)
# Source: OpTC dataset release notes.
OFFICIAL_CATALOG = [
    ("2019-09-16.tar",   12.5),
    ("2019-09-17.tar",   87.2),
    ("2019-09-18.tar",   64.9),
    ("2019-09-19.tar",  116.0),
    ("2019-09-20.tar",   83.7),
    ("2019-09-21.tar",  115.3),
    ("2019-09-22.tar",  115.8),
    ("2019-09-23.tar",  112.0),
    ("2019-09-24.tar",  104.3),
    ("2019-09-25.tar",   63.1),
]

INVENTORY_COLUMNS = [
    "Archive Date",
    "Archive Filename",
    "Compressed Size",
    "Estimated Extracted Size",
    "Checksum Status",
    "Tar Smoke-Test Status",
    "File Coverage Summary",
    "Ground-Truth Overlap",
    "Benign Candidate",
    "Attack Candidate",
    "Storage Priority",
    "Processing Priority",
    "Notes",
]


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# CLI ARGUMENT PARSING
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="EDA 1 — Master Corrected-Archive Inventory (DARPA OpTC)"
    )
    p.add_argument(
        "--project-root", default=None,
        help=(
            "Project root directory. Outputs written under <project-root>/outputs/. "
            "Defaults to current working directory."
        ),
    )
    p.add_argument(
        "--corrected-dir", required=True,
        help=(
            "Directory containing corrected OpTC .tar archives. "
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
        "--checksum", action=argparse.BooleanOptionalAction, default=False,
        help="Compute streaming SHA-256 per archive. Slow for large files. Default: off",
    )
    p.add_argument(
        "--tar-smoke-test", action=argparse.BooleanOptionalAction, default=True,
        help=f"Open each archive and peek at first {TAR_PEEK_MEMBERS} member names. Default: on",
    )
    p.add_argument(
        "--estimate-extracted-size", action=argparse.BooleanOptionalAction, default=False,
        help=(
            "Iterate all tar members to sum member.size (estimated extracted size). "
            "Slow for large archives. Default: off"
        ),
    )
    return p.parse_args()


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# TAR HELPERS  (never extract — metadata only)
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

_GT_KW  = ["ground_truth", "ground-truth", "groundtruth", "redteam",
            "red_team", "label", "truth", "annotation", "gt_"]
_NET_KW = ["netflow", "pcap", "flow", "bro", "zeek",
            "suricata", "snort", "packet", "network"]
_EP_KW  = ["ecar", "endpoint", "edr", "process", "file_event",
            "registry", "sysmon", "sysclient", "host"]
_DOC_KW = ["readme", "manifest", "changelog", "meta",
            ".txt", ".pdf", ".md"]


def _classify_member(name_lower: str) -> str:
    if any(k in name_lower for k in _GT_KW):
        return "ground_truth"
    if any(k in name_lower for k in _NET_KW):
        return "network"
    if any(k in name_lower for k in _EP_KW):
        return "endpoint"
    if any(k in name_lower for k in _DOC_KW):
        return "docs_metadata"
    return "unknown"


def tar_smoke_test(filepath: pathlib.Path) -> str:
    """
    Open the tar, peek at the first TAR_PEEK_MEMBERS member names, close.
    Returns 'tar_open_success' or 'tar_open_failed:<error>'.
    Never extracts.
    """
    try:
        with tarfile.open(filepath, "r:*") as tf:
            for i, _ in enumerate(tf):
                if i >= TAR_PEEK_MEMBERS - 1:
                    break
        return "tar_open_success"
    except Exception as exc:
        return f"tar_open_failed: {str(exc)[:100]}"


def tar_member_analysis(filepath: pathlib.Path) -> tuple[str, str, int]:
    """
    Iterate all tar members (no extraction).  Returns:
      coverage_summary  — compact string of group counts
      gt_overlap        — ground-truth overlap assessment
      total_size_bytes  — sum of member.size (estimated extracted size)
    """
    counts     = collections.Counter()
    total_size = 0
    has_gt     = False

    with tarfile.open(filepath, "r:*") as tf:
        for m in tf:
            if not m.isfile():
                continue
            total_size += max(m.size, 0)
            cat = _classify_member(m.name.lower())
            counts[cat] += 1
            if cat == "ground_truth":
                has_gt = True

    ordered = ["endpoint", "network", "ground_truth", "docs_metadata", "unknown"]
    parts   = [f"{cat}:{counts.get(cat, 0)} files" for cat in ordered]
    summary = "; ".join(parts)

    gt_overlap = (
        "possible_ground_truth_file_present"
        if has_gt
        else "unknown_pending_ground_truth_alignment"
    )
    return summary, gt_overlap, total_size


def compute_sha256_streaming(filepath: pathlib.Path, chunk: int = 1 << 20) -> str:
    """
    Streaming SHA-256 in 1 MB chunks — never loads the whole file.
    Returns 'sha256_computed:<first_16_chars>' on success.
    """
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                sha.update(block)
        return f"sha256_computed:{sha.hexdigest()[:16]}"
    except Exception as exc:
        return f"checksum_error: {str(exc)[:80]}"


def storage_priority(compressed_gb: float) -> str:
    """Assign download priority based on compressed archive size only."""
    if compressed_gb < 70:
        return "high"
    if compressed_gb <= 100:
        return "medium"
    return "low"


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# INVENTORY BUILDER
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def build_inventory(
    corrected_dir: pathlib.Path,
    do_smoke: bool,
    do_checksum: bool,
    do_estimate: bool,
) -> list[dict]:
    """
    Process each archive in the official catalog.
    For archives present locally: run requested tests.
    For missing archives: fill pending placeholders.
    """
    rows = []

    print(f"\n[INV] Scanning catalog against: {corrected_dir}")
    print(f"      Smoke test       : {'on' if do_smoke else 'off'}")
    print(f"      Checksum         : {'on' if do_checksum else 'off'}")
    print(f"      Estimate size    : {'on' if do_estimate else 'off'}\n")

    for filename, catalog_gb in OFFICIAL_CATALOG:
        filepath     = corrected_dir / filename
        local_exists = filepath.is_file()

        m = re.search(r"(\d{4}-\d{2}-\d{2})", filename)
        archive_date = m.group(1) if m else "unknown"

        compressed_label = f"{catalog_gb} GB (official catalog)"
        print(f"  {filename}", end="")

        # Determine location label for Notes based on the path prefix
        _in_drive = str(corrected_dir).startswith("/content/drive/")
        _exist_label = "file_exists_in_google_drive" if _in_drive else "file_exists_in_configured_dir"
        _path_label  = "drive_path"                  if _in_drive else "dir_path"

        if local_exists:
            local_mb = round(filepath.stat().st_size / (1024 ** 2), 1)
            print(f"  [{local_mb} MB]")

            # Smoke test
            if do_smoke:
                print("    smoke test …", end=" ", flush=True)
                smoke_status = tar_smoke_test(filepath)
                print(smoke_status)
            else:
                smoke_status = "not_run_smoke_test_disabled"

            # Member analysis (coverage + estimated extracted size)
            if do_estimate:
                print("    member analysis …", end=" ", flush=True)
                coverage, gt_overlap, raw_bytes = tar_member_analysis(filepath)
                est_extracted = f"{round(raw_bytes / (1024**3), 2)} GB (from tar member metadata)"
                print(f"done  ({raw_bytes // (1024**2)} MB estimated)")
            else:
                coverage      = "pending_member_coverage_scan"
                gt_overlap    = "unknown_pending_ground_truth_alignment"
                est_extracted = "not_computed_estimate_disabled"

            # Checksum
            if do_checksum:
                print("    checksum …", end=" ", flush=True)
                checksum_status = compute_sha256_streaming(filepath)
                print(checksum_status)
            else:
                checksum_status = "not_computed_checksum_disabled"

            notes = (
                f"{_exist_label}; "
                f"{_path_label}={filepath}; "
                f"local_size={local_mb} MB; "
                f"archive_not_extracted"
            )
            storage_prio = storage_priority(catalog_gb)

        else:
            print("  [NOT DOWNLOADED]")
            smoke_status    = "not_run_file_not_downloaded"
            checksum_status = "not_computed_file_not_downloaded"
            est_extracted   = "pending_not_downloaded"
            coverage        = "pending_not_downloaded"
            gt_overlap      = "unknown_pending_ground_truth_alignment"
            notes           = "file_not_downloaded; archive_not_extracted"
            storage_prio    = "pending_download_if_storage_allows"

        rows.append({
            "Archive Date"            : archive_date,
            "Archive Filename"        : filename,
            "Compressed Size"         : compressed_label,
            "Estimated Extracted Size": est_extracted,
            "Checksum Status"         : checksum_status,
            "Tar Smoke-Test Status"   : smoke_status,
            "File Coverage Summary"   : coverage,
            "Ground-Truth Overlap"    : gt_overlap,
            "Benign Candidate"        : "not_assessed_eda1",
            "Attack Candidate"        : "not_assessed_eda1",
            "Storage Priority"        : storage_prio,
            "Processing Priority"     : "pending_scientific_selection",
            "Notes"                   : notes,
        })

    return rows


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# STORAGE FEASIBILITY REPORT
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def write_storage_report(
    rows: list[dict],
    out_path: pathlib.Path,
    run_ts: str,
    project_root: pathlib.Path,
    corrected_dir: pathlib.Path,
) -> None:
    """Write S1_storage_feasibility_report.txt."""
    usage    = shutil.disk_usage(str(project_root))
    avail_gb = round(usage.free  / (1024 ** 3), 1)
    total_gb = round(usage.total / (1024 ** 3), 1)
    used_gb  = round(usage.used  / (1024 ** 3), 1)

    catalog_total_gb = sum(gb for _, gb in OFFICIAL_CATALOG)

    local_files = {f: sz for f, sz in OFFICIAL_CATALOG
                   if (corrected_dir / f).is_file()}
    n_local      = len(local_files)
    local_gb     = sum(sz for sz in local_files.values())

    remaining_catalog_gb = catalog_total_gb - local_gb
    shortfall_gb         = max(0, remaining_catalog_gb - avail_gb)
    feasible             = shortfall_gb == 0

    w = 65
    lines = [
        "=" * w,
        "  DARPA OpTC — EDA 1: Storage Feasibility Report",
        f"  Generated : {run_ts}",
        "=" * w,
        "",
        "-" * w,
        "LOCAL FILESYSTEM",
        "-" * w,
        "",
        f"  Filesystem root assessed : {project_root}",
        f"  Total disk capacity      : {total_gb} GB",
        f"  Used                     : {used_gb} GB",
        f"  Available                : {avail_gb} GB",
        "",
        "-" * w,
        "OFFICIAL CORRECTED-ARCHIVE CATALOG",
        "-" * w,
        "",
    ]

    for fname, gb in OFFICIAL_CATALOG:
        tag = "[LOCAL]  " if fname in local_files else "[PENDING]"
        lines.append(f"  {tag}  {fname:<22}  {gb:>6.1f} GB")

    lines += [
        "",
        f"  Total official catalog size  : {catalog_total_gb:.1f} GB",
        "",
        "-" * w,
        "LOCAL ARCHIVE STATUS",
        "-" * w,
        "",
        f"  Archives downloaded locally  : {n_local} / {len(OFFICIAL_CATALOG)}",
        f"  Local archive storage used   : {local_gb:.1f} GB",
        f"  Remaining catalog to download: {remaining_catalog_gb:.1f} GB",
        "",
        "-" * w,
        "STORAGE FEASIBILITY ASSESSMENT",
        "-" * w,
        "",
    ]

    if feasible:
        lines += [
            "  STATUS : FEASIBLE",
            f"  Available disk ({avail_gb} GB) is sufficient to download",
            f"  all remaining corrected archives ({remaining_catalog_gb:.1f} GB).",
        ]
    else:
        lines += [
            "  STATUS : INSUFFICIENT STORAGE",
            f"  WARNING: Available disk space is {avail_gb} GB.",
            f"  Remaining archives require {remaining_catalog_gb:.1f} GB.",
            f"  Shortfall: {shortfall_gb:.1f} GB.",
            "",
            "  Options:",
            "    1. Free disk space before downloading remaining archives.",
            "    2. Download a subset (see Storage Priority in T1B).",
            "    3. Use external storage for larger archives.",
        ]

    lines += [
        "",
        "-" * w,
        "ESTIMATED EXTRACTED SIZE NOTES",
        "-" * w,
        "",
        "  If --estimate-extracted-size was passed, sizes were computed from",
        "  tar member metadata (sum of member.size) without extracting files.",
        "  This method is accurate for uncompressed tar archives.",
        "  For .tar.gz archives the actual extracted size may differ.",
        "",
        "  If --estimate-extracted-size was not passed, the column shows",
        "  'not_computed_estimate_disabled'.",
        "",
        "-" * w,
        "SCOPE LIMITATIONS",
        "-" * w,
        "",
        "  - No archive was extracted",
        "  - No event-level statistics computed",
        "  - No attack analysis performed",
        "  - No MITRE labels assigned",
        "  - Benign / Attack Candidate columns are intake placeholders only",
        "  - Processing Priority deferred to scientific selection phase",
        "",
        "=" * w,
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Storage report saved → {out_path}")


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# README SECTION APPENDER
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def append_readme_section(out_dir: pathlib.Path, run_ts: str) -> None:
    """Append the 'Master archive inventory expansion' section to README."""
    readme_path = out_dir / README_FILENAME
    w = 65

    section = "\n".join([
        "",
        "=" * w,
        "  MASTER ARCHIVE INVENTORY EXPANSION",
        f"  Added by eda_01_master_archive_inventory.py  —  {run_ts}",
        "=" * w,
        "",
        "  EDA 1 has moved from single-archive validation to a broad",
        "  corrected-archive inventory covering all 10 official OpTC",
        "  daily archives (2019-09-16 through 2019-09-25).",
        "",
        "-" * w,
        "WHAT CHANGED",
        "-" * w,
        "",
        "  T1B_master_archive_inventory.csv lists all 10 corrected archives.",
        "  Archives that have been downloaded receive (if flags were passed):",
        "    - SHA-256 checksum (streaming, no full load)",
        "    - Tar smoke test (peek at 20 member names)",
        "    - File coverage summary (all members classified by path keyword)",
        "    - Estimated extracted size (sum of tar member metadata sizes)",
        "  Archives not yet downloaded are listed with pending placeholders.",
        "",
        "-" * w,
        "WHAT HAS NOT BEEN DONE",
        "-" * w,
        "",
        "  - No archive has been fully extracted",
        "  - No event rows have been read or counted",
        "  - No event-level statistics have been computed",
        "  - No attack or benign claims have been made",
        "  - No MITRE labels have been assigned",
        "  - Final modeling dates have not been selected",
        "    (Processing Priority = pending_scientific_selection for all)",
        "",
        "-" * w,
        "BENIGN / ATTACK CANDIDATE COLUMNS",
        "-" * w,
        "",
        '  Both columns contain "candidate_only_needs_gt_review" for',
        "  every archive. This is an intake placeholder, not a verified",
        "  classification. Ground-truth alignment is deferred to EDA-02.",
        "",
        "-" * w,
        "STORAGE NOTE",
        "-" * w,
        "",
        "  See S1_storage_feasibility_report.txt for the full assessment.",
        "",
        "=" * w,
        "",
    ])

    out_dir.mkdir(parents=True, exist_ok=True)
    with open(readme_path, "a", encoding="utf-8") as fh:
        fh.write(section)
    print(f"  README updated → {readme_path}")


# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──
# ENTRY POINT
# ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

def main() -> None:
    args = parse_args()

    # ── Resolve paths ─────────────────────────────────────────────────
    corrected_dir = pathlib.Path(args.corrected_dir).resolve()
    project_root  = (
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

    if not corrected_dir.exists():
        print(f"[ERROR] --corrected-dir does not exist: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

    started = datetime.datetime.now()
    run_ts  = started.strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 65)
    print("  DARPA OpTC — EDA 1: Master Archive Inventory")
    print(f"  Started : {run_ts}")
    print("=" * 65)

    for d in (output_eda01, output_tables):
        d.mkdir(parents=True, exist_ok=True)

    # ── STEP 1 — Build inventory rows ────────────────────────────────
    print("\n[STEP 1/4] Processing catalog archives …")
    rows = build_inventory(
        corrected_dir,
        do_smoke    = args.tar_smoke_test,
        do_checksum = args.checksum,
        do_estimate = args.estimate_extracted_size,
    )

    # ── STEP 2 — Save T1B ────────────────────────────────────────────
    print("\n[STEP 2/4] Saving T1B master archive inventory …")
    for dest in (output_eda01, output_tables):
        out = dest / T1B_FILENAME
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=INVENTORY_COLUMNS,
                                    quoting=csv.QUOTE_ALL)
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Saved → {out}")

    # ── STEP 3 — Storage feasibility report ──────────────────────────
    print("\n[STEP 3/4] Writing storage feasibility report (S1) …")
    write_storage_report(rows, output_eda01 / S1_FILENAME, run_ts,
                         project_root, corrected_dir)

    # ── STEP 4 — Append README section ───────────────────────────────
    print("\n[STEP 4/4] Appending master-inventory section to README …")
    append_readme_section(output_eda01, run_ts)

    # ── Summary ───────────────────────────────────────────────────────
    n_local   = sum(1 for r in rows if "file_exists_locally" in r["Notes"])
    n_pending = len(rows) - n_local

    finished = datetime.datetime.now()
    elapsed  = (finished - started).total_seconds()

    print("\n" + "=" * 65)
    print("  EDA 1 master inventory complete.")
    print(f"  Archives in catalog    : {len(rows)}")
    print(f"  Downloaded locally     : {n_local}")
    print(f"  Pending (not local)    : {n_pending}")
    print(f"  Finished : {finished.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Elapsed  : {elapsed:.1f}s")
    print("=" * 65)


if __name__ == "__main__":
    main()
