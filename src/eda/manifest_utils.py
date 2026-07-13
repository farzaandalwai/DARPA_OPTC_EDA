"""
Shared pilot-manifest loading and validation for DARPA OpTC EDA.
"""

from __future__ import annotations

import pathlib
import sys
import tarfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import pandas as pd

REQUIRED_MANIFEST_COLUMNS = [
    "archive_filename",
    "member_name",
    "archive_date",
    "inferred_host_or_client",
    "member_size_gib",
    "manifest_version",
]


@dataclass
class ManifestInfo:
    """Validated pilot manifest metadata and exact member allowlist."""

    path: pathlib.Path
    df: pd.DataFrame
    archive_filenames: List[str]
    allowlist: Dict[str, Set[str]]  # archive_filename -> exact member_name set
    member_count: int
    dates: List[str]
    hosts: List[str]
    total_compressed_gib: float
    manifest_version: str
    notes: List[str] = field(default_factory=list)

    def all_member_keys(self) -> Set[str]:
        """Return 'archive_filename::member_name' keys."""
        keys: Set[str] = set()
        for arch, members in self.allowlist.items():
            for m in members:
                keys.add(f"{arch}::{m}")
        return keys


def load_manifest(manifest_csv: pathlib.Path) -> ManifestInfo:
    """
    Load and validate a pilot manifest CSV.
    Raises SystemExit with a clear message on hard failures.
    """
    manifest_csv = pathlib.Path(manifest_csv)
    if not manifest_csv.exists():
        print(f"[ERROR] Manifest CSV not found: {manifest_csv}", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(manifest_csv)
    missing_cols = [c for c in REQUIRED_MANIFEST_COLUMNS if c not in df.columns]
    if missing_cols:
        print(
            f"[ERROR] Manifest missing required columns: {missing_cols}\n"
            f"  Found columns: {list(df.columns)}",
            file=sys.stderr,
        )
        sys.exit(1)

    if df.empty:
        print(f"[ERROR] Manifest is empty: {manifest_csv}", file=sys.stderr)
        sys.exit(1)

    # Normalize string columns
    for col in ("archive_filename", "member_name", "archive_date",
                "inferred_host_or_client", "manifest_version"):
        df[col] = df[col].astype(str).str.strip()

    df["member_size_gib"] = pd.to_numeric(df["member_size_gib"], errors="coerce").fillna(0.0)

    # Duplicate archive/member pairs
    dup_mask = df.duplicated(subset=["archive_filename", "member_name"], keep=False)
    if dup_mask.any():
        dups = df.loc[dup_mask, ["archive_filename", "member_name"]].drop_duplicates()
        print(
            f"[ERROR] Manifest contains duplicate archive/member pairs "
            f"({len(dups)} unique pairs):\n{dups.head(10).to_string(index=False)}",
            file=sys.stderr,
        )
        sys.exit(1)

    versions = sorted(df["manifest_version"].unique().tolist())
    if len(versions) != 1:
        print(
            f"[WARN] Manifest has multiple manifest_version values: {versions}. "
            f"Using first: {versions[0]}",
            file=sys.stderr,
        )
    manifest_version = versions[0]

    allowlist: Dict[str, Set[str]] = {}
    for arch, g in df.groupby("archive_filename", sort=False):
        allowlist[str(arch)] = set(g["member_name"].tolist())

    # Preserve first-seen archive order
    archive_filenames = list(dict.fromkeys(df["archive_filename"].tolist()))

    return ManifestInfo(
        path=manifest_csv.resolve(),
        df=df,
        archive_filenames=archive_filenames,
        allowlist=allowlist,
        member_count=int(len(df)),
        dates=sorted(df["archive_date"].unique().tolist()),
        hosts=sorted(df["inferred_host_or_client"].unique().tolist()),
        total_compressed_gib=float(df["member_size_gib"].sum()),
        manifest_version=manifest_version,
    )


def resolve_manifest_archives(
    manifest: ManifestInfo,
    corrected_dir: pathlib.Path,
) -> List[pathlib.Path]:
    """
    Map manifest archive filenames to paths under corrected_dir.
    Fails if any archive file is missing.
    """
    corrected_dir = pathlib.Path(corrected_dir)
    if not corrected_dir.exists():
        print(f"[ERROR] corrected-dir not found: {corrected_dir}", file=sys.stderr)
        sys.exit(1)

    paths: List[pathlib.Path] = []
    missing: List[str] = []
    for name in manifest.archive_filenames:
        p = corrected_dir / name
        if not p.exists():
            missing.append(name)
        else:
            paths.append(p)

    if missing:
        print(
            f"[ERROR] Manifest references archives not found in {corrected_dir}:\n"
            + "\n".join(f"  - {m}" for m in missing),
            file=sys.stderr,
        )
        sys.exit(1)
    return paths


def verify_manifest_members_in_archives(
    manifest: ManifestInfo,
    archive_paths: List[pathlib.Path],
) -> dict:
    """
    Open each archive (headers only) and confirm every allowlisted member exists.
    Returns a status dict; exits on missing members.
    """
    path_by_name = {p.name: p for p in archive_paths}
    found: Dict[str, Set[str]] = {a: set() for a in manifest.allowlist}
    missing_rows: List[dict] = []

    for arch_name, wanted in manifest.allowlist.items():
        ap = path_by_name.get(arch_name)
        if ap is None:
            for m in sorted(wanted):
                missing_rows.append({"archive_filename": arch_name, "member_name": m,
                                     "reason": "archive_path_missing"})
            continue
        try:
            with tarfile.open(ap, "r:*") as tf:
                present = {m.name for m in tf.getmembers() if m.isfile()}
        except Exception as exc:
            print(f"[ERROR] Cannot open archive {ap}: {exc}", file=sys.stderr)
            sys.exit(1)

        for m in wanted:
            if m in present:
                found[arch_name].add(m)
            else:
                missing_rows.append({
                    "archive_filename": arch_name,
                    "member_name": m,
                    "reason": "member_not_found_in_tar",
                })

    matched = sum(len(v) for v in found.values())
    missing_count = len(missing_rows)
    if missing_count:
        print(
            f"[ERROR] {missing_count} manifest member(s) not found inside archives "
            f"(matched {matched}/{manifest.member_count}). Examples:",
            file=sys.stderr,
        )
        for row in missing_rows[:10]:
            print(f"  - {row['archive_filename']} :: {row['member_name']} "
                  f"({row['reason']})", file=sys.stderr)
        sys.exit(1)

    return {
        "matched_member_count": matched,
        "missing_member_count": missing_count,
        "found": found,
    }


def reject_conflicting_selection_args(args, *, mode_label: str = "manifest/cache") -> None:
    """
    In manifest/cache mode, reject legacy member-selection flags that would
    conflict with exact allowlist selection.
    """
    conflicts = []
    if getattr(args, "archives", None):
        conflicts.append("--archives")
    if getattr(args, "max_members", None) not in (None, 25) and getattr(args, "manifest_csv", None):
        # Only flag if user explicitly changed from default in a way that matters;
        # safer: if max_members is set AND manifest mode, warn/reject when combined
        # with member-name-contains or when they pass max_members intending selection.
        pass
    if getattr(args, "member_name_contains", None):
        conflicts.append("--member-name-contains")
    # Explicit max_members with manifest is confusing for selection — reject if not default
    # Actually user said: reject conflicting member-selection options.
    # --archives and --member-name-contains clearly conflict.
    # --max-members and --max-events-per-member conflict with exact selection intent.
    if getattr(args, "max_events_per_member", None) not in (None, 2000):
        # Legacy default is 2000 for EDA2/3; for cache builder default is None.
        # Only reject if clearly passed for selection control in manifest mode.
        pass

    hard = []
    if getattr(args, "archives", None):
        hard.append("--archives")
    if getattr(args, "member_name_contains", None):
        hard.append("--member-name-contains")

    # Detect "user overrode max_members for selection" via a sentinel attribute
    # set by callers, OR reject whenever max_members / max_events_per_member
    # were explicitly provided. argparse doesn't tell us easily; use:
    # if hasattr and not None for cache builder; for EDA scripts check a flag.
    if getattr(args, "_reject_max_members", False) and getattr(args, "max_members", None) is not None:
        hard.append("--max-members")
    if getattr(args, "_reject_max_events_per_member", False) and getattr(args, "max_events_per_member", None) is not None:
        hard.append("--max-events-per-member")

    if hard:
        print(
            f"[ERROR] {mode_label} mode uses exact manifest member selection. "
            f"Do not combine with: {', '.join(hard)}.\n"
            f"  --max-events is still allowed as a safety cap.",
            file=sys.stderr,
        )
        sys.exit(1)


def duckdb_parquet_glob(cache_dir: pathlib.Path) -> str:
    """Return a DuckDB-friendly glob for parquet files under cache_dir."""
    return str(pathlib.Path(cache_dir) / "*.parquet")
