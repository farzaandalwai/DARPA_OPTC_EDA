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
    ResumeVerificationError,
    stream_from_archives,
)
from cache_resume import (  # type: ignore
    RESUME_VERSION,
    ResumeError,
    aggregate_preexisting_chunks,
    atomic_write_json,
    atomic_write_parquet_chunk,
    atomic_write_text,
    merge_resume_aggregates,
    prepare_resume_context,
    require_commit_checkpoint,
    write_resume_state,
)

TIMESTAMP_RULE = (
    "Numeric: epoch_ns→/1e9, epoch_ms→/1e3, epoch_s as-is. "
    "ISO-8601: timezone-aware values are converted to UTC via astimezone(); "
    "timezone-naive ISO values are assumed to already be UTC. "
    "Stored timestamp_parsed is naive UTC."
)

SCHEMA_NOTES = (
    "Schema optc_normalized_v3 selectively normalizes nested OpTC "
    "properties.* keys into dedicated columns. Unmapped property keys are "
    "recorded in unmapped_property_keys_raw. Derived compatibility fields: "
    "process_raw=properties.image_path (event-associated image path; not "
    "definitive target process for every object type); "
    "parent_process_raw=properties.parent_image_path; "
    "destination_raw=properties.dest_ip; "
    "user_raw=principal or else properties.user (never actorID). "
    "v3 promotions from evidence-backed formerly-unmapped keys: "
    "FILE/FLOW size (property_size_raw); MODULE base_address; "
    "THREAD stack/address/tag fields (stack_base/limit, start_address, "
    "user_stack_base/limit, subprocess_tag, tgt_pid_uuid); "
    "FLOW start_time/end_time; FILE new_path; PROCESS sid; "
    "USER_SESSION requesting_logon_id/domain/user; TASK user_name. "
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
    p.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume an interrupted cache build from finalized Parquet chunks "
            "in --cache-dir. Mutually exclusive with --overwrite. "
            "Incompatible with --max-events / --max-events-per-member."
        ),
    )
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
    """Write one Parquet chunk atomically (temp + validate + rename)."""
    return atomic_write_parquet_chunk(
        rows, cache_dir, chunk_idx, archive_date_hint, compression
    )


def _validate_resume_cli(args: argparse.Namespace) -> None:
    """Fail fast on illegal --resume combinations before touching outputs."""
    if not args.resume:
        return
    if args.overwrite:
        print(
            "[ERROR] --resume and --overwrite are mutually exclusive.",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.max_events is not None:
        print(
            "[ERROR] --resume cannot be combined with --max-events "
            "(failing before modifying the output directory).",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.max_events_per_member is not None:
        print(
            "[ERROR] --resume cannot be combined with --max-events-per-member "
            "(failing before modifying the output directory).",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    args = parse_args()
    # Validate resume conflicts BEFORE any output-directory mutation.
    _validate_resume_cli(args)
    validate_positive_optional_int("--max-events-per-member", args.max_events_per_member)
    validate_positive_optional_int("--max-events", args.max_events)

    project_root = pathlib.Path(args.project_root) if args.project_root else pathlib.Path.cwd()
    corrected_dir = pathlib.Path(args.corrected_dir)
    cache_dir = (pathlib.Path(args.cache_dir) if args.cache_dir
                 else project_root / "outputs" / "cache" / "pilot_normalized_events")
    evidence_dir = project_root / "outputs" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    resume_ctx = None
    preexisting_events = 0
    preexisting_chunks = 0
    preexisting_agg = None
    resume_initial_checkpoint = None
    new_events = 0
    new_ok = 0
    new_err = 0
    first_new_chunk_index = 0

    if args.resume:
        if not cache_dir.exists():
            print(f"[ERROR] --resume requires an existing cache dir: {cache_dir}",
                  file=sys.stderr)
            sys.exit(1)
        # Load manifest first so checkpoint can be validated against it,
        # but only after resume CLI conflicts are rejected (already done).
        manifest = load_manifest(pathlib.Path(args.manifest_csv))
        archive_paths = resolve_manifest_archives(manifest, corrected_dir)
        try:
            resume_ctx = prepare_resume_context(cache_dir, manifest)
            # One vectorized pass over preexisting chunks only (footer total
            # is authoritative). Never rescanned at completion.
            preexisting_agg = aggregate_preexisting_chunks(
                resume_ctx["chunks"],
                error_example_limit=_MAX_ERROR_EXAMPLES,
                expected_footer_total=resume_ctx["preexisting_events"],
            )
        except ResumeError as exc:
            print(f"[ERROR] Resume validation failed (no files modified): {exc}",
                  file=sys.stderr)
            sys.exit(1)
        preexisting_events = resume_ctx["preexisting_events"]
        preexisting_chunks = resume_ctx["preexisting_chunks"]
        first_new_chunk_index = resume_ctx["next_chunk_index"]
        resume_initial_checkpoint = dict(resume_ctx["checkpoint"])
        for name in resume_ctx.get("leftover_temps") or []:
            print(f"[WARN] Leftover temp chunk file left in place (not deleted): {name}",
                  flush=True)
        print(
            f"[INFO] Resume prepared: preexisting_chunks={preexisting_chunks}, "
            f"preexisting_events={preexisting_events}, "
            f"next_chunk_index={first_new_chunk_index}, "
            f"legacy_inferred={resume_ctx['inferred_legacy']}",
            flush=True,
        )
        print(
            f"[INFO] Checkpoint: {resume_ctx['checkpoint']['archive_name']} :: "
            f"{resume_ctx['checkpoint']['member_name']}:"
            f"{resume_ctx['checkpoint']['line_number']} "
            f"id={resume_ctx['checkpoint']['raw_event_id']}",
            flush=True,
        )
    else:
        if cache_dir.exists() and any(cache_dir.glob("*.parquet")):
            if not args.overwrite:
                print(f"[ERROR] Cache dir already has parquet files: {cache_dir}\n"
                      f"  Re-run with --overwrite to replace, or --resume to continue.",
                      file=sys.stderr)
                sys.exit(1)
            for p in cache_dir.glob("*.parquet"):
                p.unlink()
            for p in cache_dir.glob(".*parquet.tmp"):
                # Fresh overwrite: remove temps from a prior failed write attempt
                # only when explicitly overwriting a cache rebuild.
                p.unlink()
            for p in cache_dir.glob("cache_*.json"):
                p.unlink()
            for p in cache_dir.glob("cache_*.csv"):
                p.unlink()
            for p in cache_dir.glob("README*.txt"):
                p.unlink()
            rs = cache_dir / "cache_resume_state.json"
            if rs.exists():
                rs.unlink()

        cache_dir.mkdir(parents=True, exist_ok=True)
        manifest = load_manifest(pathlib.Path(args.manifest_csv))
        archive_paths = resolve_manifest_archives(manifest, corrected_dir)

    sampling_strategy = sampling_strategy_for(args.max_events, args.max_events_per_member)
    start = datetime.datetime.now(datetime.timezone.utc)
    print(f"\n{'='*60}")
    print("Build Normalized Pilot Cache" + (" [RESUME]" if args.resume else ""))
    print(f"  manifest-csv           : {args.manifest_csv}")
    print(f"  corrected-dir          : {corrected_dir}")
    print(f"  cache-dir              : {cache_dir}")
    print(f"  chunk-size             : {args.chunk_size}")
    print(f"  max-events             : {args.max_events if args.max_events is not None else 'unlimited'}")
    print(f"  max-events-per-member  : "
          f"{args.max_events_per_member if args.max_events_per_member is not None else 'unlimited'}")
    print(f"  sampling_strategy      : {sampling_strategy}")
    print(f"  trust-preverified      : {bool(args.trust_preverified_manifest)}")
    print(f"  resume                 : {bool(args.resume)}")
    print(f"  compression            : {args.compression}")
    print(f"{'='*60}\n")

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

    allowlist = manifest.allowlist
    arch_date = (
        manifest.df.groupby("archive_filename")["archive_date"]
        .first().to_dict()
    )

    buffer: list = []
    chunk_idx = first_new_chunk_index
    new_chunk_paths: list = []
    error_examples: list = []
    events_per_member: dict = {}
    current_member = None
    member_event_count = 0
    member_summaries: list = []
    combined_events_so_far = preexisting_events
    # Tracks the latest committed chunk checkpoint (final after resume).
    # resume_initial_checkpoint is frozen at prepare time and never overwritten.
    last_committed_checkpoint = (
        dict(resume_initial_checkpoint) if resume_initial_checkpoint is not None else None
    )

    def flush_member_progress(member_key: str, count: int) -> None:
        print(f"    → member done: {count:,} events from {member_key}", flush=True)

    def flush_chunk(date_hint: str) -> None:
        nonlocal buffer, chunk_idx, combined_events_so_far, last_committed_checkpoint
        if not buffer:
            return
        # Validate final row BEFORE any Parquet or state write. Never invent file_id.
        ckpt = require_commit_checkpoint(buffer[-1])
        n_buf = len(buffer)
        path = _write_chunk(buffer, cache_dir, chunk_idx, date_hint, args.compression)
        # Only after final Parquet name is committed, update resume state.
        combined_events_so_far += n_buf
        write_resume_state(
            cache_dir,
            last_committed_chunk_index=chunk_idx,
            combined_events=combined_events_so_far,
            checkpoint=ckpt,
        )
        last_committed_checkpoint = ckpt
        new_chunk_paths.append(path)
        print(f"  [CHUNK {chunk_idx:05d}] wrote {n_buf:,} rows → {path.name}",
              flush=True)
        chunk_idx += 1
        buffer = []

    last_date_hint = "unknown"
    resume_kwargs = {}
    if resume_ctx is not None:
        ck = resume_ctx["checkpoint"]
        resume_kwargs["resume_checkpoint"] = {
            "archive_name": ck["archive_name"],
            "member_name": ck["member_name"],
            "line_number": ck["line_number"],
            "raw_event_id": ck["raw_event_id"],
            "next_file_id": resume_ctx["next_file_id"],
        }

    try:
        for event in stream_from_archives(
            archive_paths,
            max_events=args.max_events,
            max_events_per_member=args.max_events_per_member,
            allowed_members_by_archive=allowlist,
            include_raw_json=False,
            quiet=False,
            **resume_kwargs,
        ):
            mkey = f"{event['archive_name']}::{event['member_name']}"
            if current_member is None:
                current_member = mkey
                member_event_count = 0
            elif mkey != current_member:
                flush_member_progress(current_member, member_event_count)
                events_per_member[current_member] = (
                    events_per_member.get(current_member, 0) + member_event_count
                )
                member_summaries.append({
                    "archive_filename": current_member.split("::", 1)[0],
                    "member_name": current_member.split("::", 1)[1],
                    "events_written": member_event_count,
                })
                current_member = mkey
                member_event_count = 0

            member_event_count += 1
            new_events += 1

            if event.get("parse_status") == "ok":
                new_ok += 1
            else:
                new_err += 1
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

            slim = {c: event.get(c, "") for c in SLIM_EVENT_COLUMNS}
            buffer.append(slim)
            last_date_hint = arch_date.get(event.get("archive_name", ""), "unknown")
            if len(buffer) >= args.chunk_size:
                flush_chunk(str(last_date_hint))

        if current_member is not None:
            flush_member_progress(current_member, member_event_count)
            events_per_member[current_member] = (
                events_per_member.get(current_member, 0) + member_event_count
            )
            member_summaries.append({
                "archive_filename": current_member.split("::", 1)[0],
                "member_name": current_member.split("::", 1)[1],
                "events_written": member_event_count,
            })
        flush_chunk(str(last_date_hint))
    except (ResumeVerificationError, ResumeError) as exc:
        print(
            f"[ERROR] Resume aborted before committing a new chunk: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    end = datetime.datetime.now(datetime.timezone.utc)

    # Fresh builds: keep live counters — never rescan the completed cache.
    # Resume: merge the single preexisting pass with live new-event counters.
    # Never rescan newly written chunks.
    if args.resume:
        assert preexisting_agg is not None and resume_ctx is not None
        merged = merge_resume_aggregates(
            preexisting_agg,
            new_events=new_events,
            new_events_per_member=events_per_member,
            new_ok=new_ok,
            new_err=new_err,
            new_error_examples=error_examples,
            error_example_limit=_MAX_ERROR_EXAMPLES,
        )
        member_summaries = merged["member_summaries"]
        events_per_member = merged["events_per_member"]
        total_ok = merged["events_ok"]
        total_err = merged["parse_errors"]
        total_events = merged["total_events"]
        error_examples = merged["error_examples"]
        all_chunks = list(resume_ctx["chunks"])
        for p in new_chunk_paths:
            idx = int(p.name.split("_")[1])
            all_chunks.append((idx, p))
    else:
        total_ok = new_ok
        total_err = new_err
        total_events = new_events
        all_chunks = []
        for p in new_chunk_paths:
            idx = int(p.name.split("_")[1])
            all_chunks.append((idx, p))

    cache_bytes = sum(p.stat().st_size for _, p in all_chunks)
    cache_mib = cache_bytes / (1024 ** 2)

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

    processed_keys = set(events_per_member.keys())
    expected_keys = manifest.all_member_keys()
    zero_event_members = sorted(expected_keys - processed_keys)
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
        "chunks_written": len(all_chunks),
        "chunk_files": [p.name for _, p in all_chunks],
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
        "resumed": bool(args.resume),
        "resume_mode_version": RESUME_VERSION if args.resume else None,
        "resume_preexisting_chunks": preexisting_chunks if args.resume else 0,
        "resume_preexisting_events": preexisting_events if args.resume else 0,
        "resume_initial_checkpoint": resume_initial_checkpoint if args.resume else None,
        "resume_final_checkpoint": last_committed_checkpoint if args.resume else None,
        "resume_first_new_chunk_index": first_new_chunk_index if args.resume else None,
        "resume_newly_written_chunks": len(new_chunk_paths) if args.resume else 0,
        "resume_newly_written_events": new_events if args.resume else 0,
        "resume_combined_chunks": len(all_chunks),
        "resume_combined_events": total_events,
        "resume_inferred_from_legacy_cache": (
            bool(resume_ctx["inferred_legacy"]) if args.resume else False
        ),
    }
    atomic_write_json(cache_dir / "cache_metadata.json", metadata)

    summary_df = pd.DataFrame(member_summaries)
    summary_path = cache_dir / "cache_build_summary.csv"
    tmp_summary = cache_dir / f".cache_build_summary.{start.timestamp()}.csv.tmp"
    summary_df.to_csv(tmp_summary, index=False)
    tmp_summary.replace(summary_path)

    err_path = evidence_dir / "cache_parse_error_examples.csv"
    tmp_err = evidence_dir / f".cache_parse_error_examples.{start.timestamp()}.csv.tmp"
    pd.DataFrame(error_examples).to_csv(tmp_err, index=False)
    tmp_err.replace(err_path)

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
        f"Chunks: {len(all_chunks)}",
        f"Cache size: {cache_mib:.2f} MiB",
        f"max-events cap: {args.max_events}",
        f"max-events-per-member: {args.max_events_per_member}",
        f"sampling_strategy: {sampling_strategy}",
        f"sampling_limitation: {_SAMPLING_LIMITATION}",
        f"member_verification_performed: {member_verification_performed}",
        f"member_verification_mode: {member_verification_mode}",
        f"resumed: {bool(args.resume)}",
    ]
    if args.resume:
        lines += [
            f"resume_mode_version: {RESUME_VERSION}",
            f"resume_preexisting_chunks: {preexisting_chunks}",
            f"resume_preexisting_events: {preexisting_events}",
            f"resume_first_new_chunk_index: {first_new_chunk_index}",
            f"resume_newly_written_chunks: {len(new_chunk_paths)}",
            f"resume_newly_written_events: {new_events}",
            f"resume_inferred_from_legacy_cache: {resume_ctx['inferred_legacy']}",
            f"resume_initial_checkpoint: {resume_initial_checkpoint}",
            f"resume_final_checkpoint: {last_committed_checkpoint}",
        ]
    lines += [
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
    atomic_write_text(
        cache_dir / "README_normalized_pilot_cache.txt",
        "\n".join(lines) + "\n",
    )

    print(f"\n{'='*60}")
    print("CACHE BUILD COMPLETE" + (" [RESUME]" if args.resume else ""))
    print(f"  Events written              : {total_events:,} (ok={total_ok:,}, err={total_err:,})")
    print(f"  Chunks                      : {len(all_chunks)}")
    print(f"  Cache size                  : {cache_mib:.2f} MiB")
    print(f"  sampling_strategy           : {sampling_strategy}")
    print(f"  max_events_per_member       : {args.max_events_per_member}")
    print(f"  max_events_safety_cap       : {args.max_events}")
    print(f"  member_verification_performed: {member_verification_performed}")
    print(f"  member_verification_mode    : {member_verification_mode}")
    if args.resume:
        print(f"  resume_preexisting_chunks   : {preexisting_chunks}")
        print(f"  resume_newly_written_chunks : {len(new_chunk_paths)}")
        print(f"  resume_first_new_chunk_index: {first_new_chunk_index}")
        print(f"  resume_legacy_inferred      : {resume_ctx['inferred_legacy']}")
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
