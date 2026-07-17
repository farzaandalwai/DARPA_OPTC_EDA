"""
Build a slim chunked Parquet cache of normalized OpTC events from a
fixed pilot manifest — without loading full members or full raw JSON
into RAM.

Usage
-----
python3 src/eda/build_normalized_pilot_cache.py \\
    --project-root /content/DARPA_OPTC_EDA_REPO \\
    --corrected-dir /content/drive/MyDrive/DARPA_OPTC_EDA/corrected_archives \\
    --manifest-csv /path/to/pilot_manifest_10gb.csv \\
    --cache-dir outputs/cache/pilot_normalized_events \\
    --chunk-size 100000 \\
    --max-events 100000 \\
    --overwrite
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import shutil
import sys
from typing import Optional

import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from manifest_utils import (  # type: ignore
    load_manifest,
    resolve_manifest_archives,
    verify_manifest_members_in_archives,
)
from optc_streaming_parser import (  # type: ignore
    SCHEMA_VERSION,
    SLIM_EVENT_COLUMNS,
    stream_from_archives,
)

TIMESTAMP_RULE = (
    "Numeric: epoch_ns→/1e9, epoch_ms→/1e3, epoch_s as-is. "
    "ISO-8601: timezone-aware values are converted to UTC via astimezone(); "
    "timezone-naive ISO values are assumed to already be UTC. "
    "Stored timestamp_parsed is naive UTC."
)

SCHEMA_NOTES = (
    "Schema optc_normalized_v2 selectively normalizes nested OpTC "
    "properties.* keys into dedicated columns. Unmapped property keys are "
    "recorded in unmapped_property_keys_raw. Derived compatibility fields: "
    "process_raw=properties.image_path (event-associated image path; not "
    "definitive target process for every object type); "
    "parent_process_raw=properties.parent_image_path; "
    "destination_raw=properties.dest_ip; "
    "user_raw=principal or else properties.user (never actorID). "
    "Full raw_json is excluded; raw events remain recoverable via "
    "archive_name / member_name / line_number / raw_event_id."
)

# Max parse-error evidence rows kept in a side CSV
_MAX_ERROR_EXAMPLES = 500

_SAMPLING_LIMITATION = (
    "Head-per-member (and global-head) sampling is useful for schema/coverage "
    "inspection but is not temporally representative for final EDA 3 window "
    "selection. Prefer a full uncapped cache before issuing primary/backup windows."
)


def sampling_strategy_for(
    max_events: Optional[int],
    max_events_per_member: Optional[int],
) -> str:
    """
    Resolve documented sampling_strategy label.
    head_per_member takes precedence when both caps are set.
    """
    if max_events_per_member is not None:
        return "head_per_member"
    if max_events is not None:
        return "global_head"
    return "full"


def validate_positive_optional_int(name: str, value: Optional[int]) -> None:
    if value is None:
        return
    if value <= 0:
        print(
            f"[ERROR] {name} must be a positive integer (got {value}).",
            file=sys.stderr,
        )
        sys.exit(1)


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build slim normalized Parquet cache from pilot manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--project-root", default=None)
    p.add_argument("--corrected-dir", required=True)
    p.add_argument("--manifest-csv", required=True)
    p.add_argument("--cache-dir", default=None,
                   help="Default: <project-root>/outputs/cache/pilot_normalized_events")
    p.add_argument("--chunk-size", type=int, default=100_000)
    p.add_argument("--max-events", type=int, default=None,
                   help="Optional global safety cap (default: unlimited)")
    p.add_argument(
        "--max-events-per-member",
        type=int,
        default=None,
        help=(
            "Optional deterministic head-per-member sample size "
            "(default: unlimited). May coexist with --max-events."
        ),
    )
    p.add_argument(
        "--trust-preverified-manifest",
        action="store_true",
        help=(
            "Skip tar-member verification for this run because the caller "
            "declares the fixed manifest already preverified. Default is to "
            "fully verify every allowlisted member."
        ),
    )
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--compression", default="zstd",
                   choices=["zstd", "snappy", "gzip", "none"],
                   help="Parquet compression (default: zstd)")
    return p.parse_args(argv)


def _disk_free_bytes(path: pathlib.Path) -> Optional[int]:
    try:
        usage = shutil.disk_usage(path)
        return int(usage.free)
    except Exception:
        return None


def _write_chunk(
    rows: list,
    cache_dir: pathlib.Path,
    chunk_idx: int,
    archive_date_hint: str,
    compression: str,
) -> pathlib.Path:
    """Write one Parquet chunk; returns path."""
    df = pd.DataFrame(rows)
    # Ensure slim schema only
    for col in SLIM_EVENT_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    # Drop raw_json / error_snippet from cache (evidence goes elsewhere)
    keep = [c for c in SLIM_EVENT_COLUMNS if c in df.columns]
    df = df[keep]

    date_token = archive_date_hint.replace("-", "") if archive_date_hint else "unknown"
    fname = f"chunk_{chunk_idx:05d}_date_{date_token}.parquet"
    out = cache_dir / fname
    comp = None if compression == "none" else compression
    df.to_parquet(out, index=False, compression=comp, engine="pyarrow")
    return out


def main() -> None:
    args = parse_args()
    validate_positive_optional_int("--max-events-per-member", args.max_events_per_member)
    validate_positive_optional_int("--max-events", args.max_events)

    project_root = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()
    corrected_dir = pathlib.Path(args.corrected_dir)
    cache_dir = (pathlib.Path(args.cache_dir) if args.cache_dir
                 else project_root / "outputs" / "cache" / "pilot_normalized_events")
    evidence_dir = project_root / "outputs" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if cache_dir.exists() and any(cache_dir.glob("*.parquet")):
        if not args.overwrite:
            print(f"[ERROR] Cache dir already has parquet files: {cache_dir}\n"
                  f"  Re-run with --overwrite to replace.", file=sys.stderr)
            sys.exit(1)
        for p in cache_dir.glob("*.parquet"):
            p.unlink()
        for p in cache_dir.glob("cache_*.json"):
            p.unlink()
        for p in cache_dir.glob("cache_*.csv"):
            p.unlink()
        for p in cache_dir.glob("README*.txt"):
            p.unlink()

    cache_dir.mkdir(parents=True, exist_ok=True)

    sampling_strategy = sampling_strategy_for(args.max_events, args.max_events_per_member)
    start = datetime.datetime.now(datetime.timezone.utc)
    print(f"\n{'='*60}")
    print("Build Normalized Pilot Cache")
    print(f"  manifest-csv           : {args.manifest_csv}")
    print(f"  corrected-dir          : {corrected_dir}")
    print(f"  cache-dir              : {cache_dir}")
    print(f"  chunk-size             : {args.chunk_size}")
    print(f"  max-events             : {args.max_events if args.max_events is not None else 'unlimited'}")
    print(f"  max-events-per-member  : "
          f"{args.max_events_per_member if args.max_events_per_member is not None else 'unlimited'}")
    print(f"  sampling_strategy      : {sampling_strategy}")
    print(f"  trust-preverified      : {bool(args.trust_preverified_manifest)}")
    print(f"  compression            : {args.compression}")
    print(f"{'='*60}\n")

    manifest = load_manifest(pathlib.Path(args.manifest_csv))
    archive_paths = resolve_manifest_archives(manifest, corrected_dir)

    if args.trust_preverified_manifest:
        print(
            "\n"
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
            "[WARN] --trust-preverified-manifest is set.\n"
            "       Member verification against tar archives was SKIPPED\n"
            "       because the caller declared this fixed manifest\n"
            "       already preverified. Members were NOT verified in\n"
            "       this run.\n"
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
            flush=True,
        )
        member_verification_performed = False
        member_verification_mode = "trusted_preverified"
        verify = {
            "matched_member_count": None,
            "missing_member_count": None,
            "verification_skipped": True,
        }
        print(f"[INFO] Manifest version : {manifest.manifest_version}")
        print(f"[INFO] Members          : {manifest.member_count}")
        print(f"[INFO] Dates            : {manifest.dates}")
        print(f"[INFO] Hosts            : {len(manifest.hosts)}")
        print(f"[INFO] Compressed size  : {manifest.total_compressed_gib:.4f} GiB")
        print("[INFO] Member verification: SKIPPED (trusted_preverified)")
    else:
        verify = verify_manifest_members_in_archives(manifest, archive_paths)
        member_verification_performed = True
        member_verification_mode = "verified_this_run"
        print(f"[INFO] Manifest version : {manifest.manifest_version}")
        print(f"[INFO] Members          : {manifest.member_count}")
        print(f"[INFO] Dates            : {manifest.dates}")
        print(f"[INFO] Hosts            : {len(manifest.hosts)}")
        print(f"[INFO] Compressed size  : {manifest.total_compressed_gib:.4f} GiB")
        print(f"[INFO] Matched members  : {verify['matched_member_count']} "
              f"(verified_this_run)")

    # Build allowlist map for parser
    allowlist = manifest.allowlist

    # Map archive → date from manifest for chunk naming
    arch_date = (
        manifest.df.groupby("archive_filename")["archive_date"]
        .first().to_dict()
    )

    buffer: list = []
    chunk_idx = 0
    chunk_paths: list = []
    total_events = 0
    total_ok = 0
    total_err = 0
    error_examples: list = []
    events_per_member: dict = {}
    current_member = None
    member_event_count = 0
    member_summaries: list = []

    def flush_member_progress(member_key: str, count: int) -> None:
        print(f"    → member done: {count:,} events from {member_key}", flush=True)

    def flush_chunk(date_hint: str) -> None:
        nonlocal buffer, chunk_idx
        if not buffer:
            return
        path = _write_chunk(buffer, cache_dir, chunk_idx, date_hint, args.compression)
        chunk_paths.append(path)
        print(f"  [CHUNK {chunk_idx:05d}] wrote {len(buffer):,} rows → {path.name}",
              flush=True)
        chunk_idx += 1
        buffer = []

    last_date_hint = "unknown"

    for event in stream_from_archives(
        archive_paths,
        max_events=args.max_events,
        max_events_per_member=args.max_events_per_member,
        allowed_members_by_archive=allowlist,
        include_raw_json=False,
        quiet=False,
    ):
        # Track per-member progress
        mkey = f"{event['archive_name']}::{event['member_name']}"
        if current_member is None:
            current_member = mkey
            member_event_count = 0
        elif mkey != current_member:
            flush_member_progress(current_member, member_event_count)
            events_per_member[current_member] = member_event_count
            member_summaries.append({
                "archive_filename": current_member.split("::", 1)[0],
                "member_name": current_member.split("::", 1)[1],
                "events_written": member_event_count,
            })
            current_member = mkey
            member_event_count = 0

        member_event_count += 1
        total_events += 1

        if event.get("parse_status") == "ok":
            total_ok += 1
        else:
            total_err += 1
            if len(error_examples) < _MAX_ERROR_EXAMPLES:
                error_examples.append({
                    "archive_name": event.get("archive_name", ""),
                    "member_name": event.get("member_name", ""),
                    "line_number": event.get("line_number", ""),
                    "raw_event_id": event.get("raw_event_id", ""),
                    "parse_status": event.get("parse_status", ""),
                    "parse_error": event.get("parse_error", ""),
                    "error_snippet": event.get("error_snippet", "")[:300],
                })

        # Slim row for cache
        slim = {c: event.get(c, "") for c in SLIM_EVENT_COLUMNS}
        buffer.append(slim)

        last_date_hint = arch_date.get(event.get("archive_name", ""), "unknown")

        if len(buffer) >= args.chunk_size:
            flush_chunk(str(last_date_hint))

    # Final member / chunk
    if current_member is not None:
        flush_member_progress(current_member, member_event_count)
        events_per_member[current_member] = member_event_count
        member_summaries.append({
            "archive_filename": current_member.split("::", 1)[0],
            "member_name": current_member.split("::", 1)[1],
            "events_written": member_event_count,
        })
    flush_chunk(str(last_date_hint))

    end = datetime.datetime.now(datetime.timezone.utc)

    # Cache size on disk
    cache_bytes = sum(p.stat().st_size for p in cache_dir.glob("*.parquet"))
    cache_mib = cache_bytes / (1024 ** 2)

    # Smoke-test projection when capped
    projection = {}
    if args.max_events is not None and total_events > 0:
        avg_bytes = cache_bytes / total_events
        proj_1m = avg_bytes * 1_000_000
        projection = {
            "avg_compressed_cache_bytes_per_event": round(avg_bytes, 2),
            "projected_cache_bytes_for_1m_events": int(proj_1m),
            "projected_cache_gib_for_1m_events": round(proj_1m / (1024 ** 3), 4),
            "note": (
                "Projection from capped sample only; full event count unknown. "
                "Not an exact full-cache size estimate."
            ),
        }
        free = _disk_free_bytes(cache_dir)
        if free is not None and proj_1m > 0.5 * free:
            print(
                f"[WARN] Projected 1M-event cache (~{proj_1m/(1024**3):.2f} GiB) "
                f"may strain free disk ({free/(1024**3):.2f} GiB free).",
                file=sys.stderr,
            )

    # Members selected but produced zero events (still matched in tar)
    processed_keys = set(events_per_member.keys())
    expected_keys = manifest.all_member_keys()
    zero_event_members = sorted(expected_keys - processed_keys)
    # If max_events cut off early, many members may be unprocessed — record that
    capped_early = args.max_events is not None and total_events >= args.max_events

    metadata = {
        "manifest_path": str(manifest.path),
        "manifest_version": manifest.manifest_version,
        "schema_version": SCHEMA_VERSION,
        "manifest_member_count": manifest.member_count,
        "matched_member_count": verify.get("matched_member_count"),
        "missing_member_count": verify.get("missing_member_count"),
        "member_verification_performed": member_verification_performed,
        "member_verification_mode": member_verification_mode,
        "members_with_events": len(events_per_member),
        "members_without_events_or_not_reached": len(zero_event_members),
        "capped_early_by_max_events": capped_early,
        "dates": manifest.dates,
        "hosts": manifest.hosts,
        "compressed_manifest_size_gib": manifest.total_compressed_gib,
        "total_events_written": total_events,
        "events_ok": total_ok,
        "parse_errors": total_err,
        "chunks_written": len(chunk_paths),
        "chunk_files": [p.name for p in chunk_paths],
        "cache_size_bytes": cache_bytes,
        "cache_size_mib": round(cache_mib, 2),
        "start_time_utc": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time_utc": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "max_events_safety_cap": args.max_events,
        "max_events_per_member": args.max_events_per_member,
        "sampling_strategy": sampling_strategy,
        "sampling_limitation": _SAMPLING_LIMITATION,
        "chunk_size": args.chunk_size,
        "compression": args.compression,
        "include_raw_json": False,
        "schema_columns": SLIM_EVENT_COLUMNS,
        "schema_notes": SCHEMA_NOTES,
        "timestamp_conversion_rule": TIMESTAMP_RULE,
        "smoke_test_projection": projection,
    }
    (cache_dir / "cache_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    summary_df = pd.DataFrame(member_summaries)
    summary_path = cache_dir / "cache_build_summary.csv"
    summary_df.to_csv(summary_path, index=False)

    err_path = evidence_dir / "cache_parse_error_examples.csv"
    pd.DataFrame(error_examples).to_csv(err_path, index=False)

    # README
    lines = [
        "Normalized Pilot Event Cache",
        "=" * 50,
        f"Generated (UTC): {metadata['end_time_utc']}",
        f"Schema version: {SCHEMA_VERSION}",
        "",
        "This cache stores SLIM normalized events only (no full raw_json).",
        "Evidence locators (archive_name, member_name, line_number, raw_event_id)",
        "allow reopening the original tar member line if needed.",
        "Archives were not extracted to disk; members were streamed.",
        "No attack / benign / MITRE / ground-truth labels were assigned.",
        "",
        "Schema notes",
        "------------",
        f"  {SCHEMA_NOTES}",
        "",
        f"Manifest: {manifest.path}",
        f"Manifest version: {manifest.manifest_version}",
        f"Members in manifest: {manifest.member_count}",
        f"Events written: {total_events:,}",
        f"Parse errors: {total_err:,}",
        f"Chunks: {len(chunk_paths)}",
        f"Cache size: {cache_mib:.2f} MiB",
        f"max-events cap: {args.max_events}",
        f"max-events-per-member: {args.max_events_per_member}",
        f"sampling_strategy: {sampling_strategy}",
        f"sampling_limitation: {_SAMPLING_LIMITATION}",
        f"member_verification_performed: {member_verification_performed}",
        f"member_verification_mode: {member_verification_mode}",
        "",
        "Timestamp rule:",
        f"  {TIMESTAMP_RULE}",
        "",
        "Schema columns:",
        f"  {', '.join(SLIM_EVENT_COLUMNS)}",
    ]
    if projection:
        lines += [
            "",
            "Smoke-test size projection (from capped sample):",
            f"  avg cache bytes/event: {projection['avg_compressed_cache_bytes_per_event']}",
            f"  projected 1M events:   {projection['projected_cache_gib_for_1m_events']} GiB",
            f"  note: {projection['note']}",
        ]
    (cache_dir / "README_normalized_pilot_cache.txt").write_text(
        "\n".join(lines), encoding="utf-8"
    )

    print(f"\n{'='*60}")
    print("CACHE BUILD COMPLETE")
    print(f"  Events written              : {total_events:,} (ok={total_ok:,}, err={total_err:,})")
    print(f"  Chunks                      : {len(chunk_paths)}")
    print(f"  Cache size                  : {cache_mib:.2f} MiB")
    print(f"  sampling_strategy           : {sampling_strategy}")
    print(f"  max_events_per_member       : {args.max_events_per_member}")
    print(f"  max_events_safety_cap       : {args.max_events}")
    print(f"  member_verification_performed: {member_verification_performed}")
    print(f"  member_verification_mode    : {member_verification_mode}")
    print(f"  Metadata                    : {cache_dir / 'cache_metadata.json'}")
    print(f"  Summary CSV                 : {summary_path}")
    print(f"  Error examples              : {err_path}")
    if sampling_strategy != "full":
        print(f"  [NOTE] {_SAMPLING_LIMITATION}")
    if capped_early:
        print("  [NOTE] Stopped early due to --max-events; not all members may appear.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
